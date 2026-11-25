"""Native owner policies are the only authorization source for signed offline batches."""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from privacyidea.lib.amfa_offline_entitlement import OfflineEntitlementError, offline_grant_for_token, require_owner_policy


class TestOfflineEntitlement(unittest.TestCase):
    def setUp(self):
        self.user = SimpleNamespace(resolver="local-users", uid="user-42", realm="local", login="operator")
        self.fido = SimpleNamespace(type="webauthn", user=self.user, get_serial=lambda: "FID-42")
        self.hotp = SimpleNamespace(type="hotp", user=self.user, get_serial=lambda: "HOTP-42")
        self.resolver = SimpleNamespace(get_user_info=lambda *_: {"username": "operator"})
        self.resolver_patch = patch("privacyidea.lib.amfa_offline_entitlement.get_resolver_object",
                                    return_value=self.resolver)
        self.resolver_mock = self.resolver_patch.start()
        self.addCleanup(self.resolver_patch.stop)
        self.policy_patch = patch("privacyidea.lib.amfa_offline_entitlement._policy_allows", return_value=True)
        self.policy = self.policy_patch.start()
        self.addCleanup(self.policy_patch.stop)

    def test_local_account_without_ad_or_flags(self):
        self.assertEqual("fido2", offline_grant_for_token(self.fido))
        self.policy.assert_called_once_with(self.user, "fido2", {"username": "operator"}, self.fido)

    def test_hotp_independent_of_fido2(self):
        self.policy.side_effect = lambda user, grant, info, token: grant == "hotp"
        self.assertEqual("hotp", offline_grant_for_token(self.hotp))
        with self.assertRaises(OfflineEntitlementError):
            offline_grant_for_token(self.fido)

    def test_no_policy_or_deny(self):
        self.policy.return_value = False
        with self.assertRaises(OfflineEntitlementError):
            offline_grant_for_token(self.fido)

    def test_resolver_unavailable(self):
        self.resolver_mock.return_value = None
        with self.assertRaises(OfflineEntitlementError):
            offline_grant_for_token(self.fido)
        self.policy.assert_not_called()

    def test_no_owner(self):
        self.fido.user = None
        with self.assertRaises(OfflineEntitlementError):
            offline_grant_for_token(self.fido)

    def test_owner_deleted(self):
        self.resolver.get_user_info = lambda *_: {}
        with self.assertRaises(OfflineEntitlementError):
            offline_grant_for_token(self.fido)
        self.policy.assert_not_called()

    def test_policy_error_fails_closed(self):
        self.policy.side_effect = RuntimeError("policy unavailable")
        with self.assertRaises(OfflineEntitlementError):
            offline_grant_for_token(self.fido)

    def test_unsupported_token(self):
        self.hotp.type = "totp"
        with self.assertRaises(OfflineEntitlementError):
            offline_grant_for_token(self.hotp)

    def test_key_only_policy_is_independent_of_fido2_offline(self):
        self.policy.side_effect = lambda user, grant, info, token: grant == "key_only"
        require_owner_policy(self.fido, "key_only", expected_sid=self.user.uid)
        with self.assertRaises(OfflineEntitlementError):
            offline_grant_for_token(self.fido)

    def test_key_only_cannot_use_another_account_sid(self):
        with self.assertRaises(OfflineEntitlementError):
            require_owner_policy(self.fido, "key_only", expected_sid="S-1-5-21-999")
        self.policy.assert_not_called()
