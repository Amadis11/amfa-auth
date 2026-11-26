"""Native owner policies are the only authorization source for signed offline batches.

The signed batch carries the AD subject (SID, realm, canonical account name), so
entitlement and subject come from the SAME fresh directory read of the token owner.
"""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from privacyidea.lib.amfa_offline_entitlement import (OfflineEntitlementError,
                                                      offline_claims_for_token,
                                                      offline_grant_for_token,
                                                      require_owner_policy)

SID = "S-1-5-21-3586658243-726035841-601138147-1150"


class TestOfflineEntitlement(unittest.TestCase):
    def setUp(self):
        self.user = SimpleNamespace(resolver="ad", uid=SID, realm="amitronic.test", login="operator")
        self.fido = SimpleNamespace(type="webauthn", user=self.user, get_serial=lambda: "FID-42")
        self.hotp = SimpleNamespace(type="hotp", user=self.user, get_serial=lambda: "HOTP-42")
        self.resolver = SimpleNamespace(uidtype="objectSid",
                                        get_user_info=lambda *_: {"username": "operator"})
        self.resolver_patch = patch("privacyidea.lib.amfa_offline_entitlement.get_resolver_object",
                                    return_value=self.resolver)
        self.resolver_mock = self.resolver_patch.start()
        self.addCleanup(self.resolver_patch.stop)
        self.policy_patch = patch("privacyidea.lib.amfa_offline_entitlement._policy_allows", return_value=True)
        self.policy = self.policy_patch.start()
        self.addCleanup(self.policy_patch.stop)

    def test_claims_carry_the_signed_subject(self):
        self.assertEqual({"account_sid": SID, "realm": "amitronic.test",
                          "offline_grant": "fido2", "username": "operator"},
                         offline_claims_for_token(self.fido))
        self.policy.assert_called_once_with(self.user, "fido2", {"username": "operator"}, self.fido)

    def test_grant_helper_stays_a_thin_wrapper(self):
        self.assertEqual("fido2", offline_grant_for_token(self.fido))

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

    def test_cached_ldap_allow_does_not_mint_a_new_grant(self):
        self.resolver.get_user_info = lambda *_: self.fail("cached lookup must not be used")
        self.resolver.get_user_info_uncached = lambda *_: {"username": "operator", "groups": []}
        self.policy.side_effect = lambda _user, _grant, info, _token: "offline" in info["groups"]
        with self.assertRaises(OfflineEntitlementError):
            offline_grant_for_token(self.fido)
        self.policy.assert_called_once_with(
            self.user, "fido2", {"username": "operator", "groups": []}, self.fido)

    def test_failed_fresh_lookup_does_not_fall_back_to_cache(self):
        self.resolver.get_user_info = lambda *_: self.fail("cached lookup must not be used")

        def unavailable(*_):
            raise RuntimeError("LDAP unavailable")

        self.resolver.get_user_info_uncached = unavailable
        with self.assertRaises(OfflineEntitlementError):
            offline_grant_for_token(self.fido)
        self.policy.assert_not_called()

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

    def test_subject_is_refused_when_the_directory_owner_is_not_an_ad_sid(self):
        # A resolver that is not objectSid-based cannot bind an AD subject, so it
        # must not receive a signed offline batch at all.
        self.resolver.uidtype = "objectGUID"
        with self.assertRaises(OfflineEntitlementError):
            offline_claims_for_token(self.fido)

    def test_missing_account_name_is_refused(self):
        self.resolver.get_user_info = lambda *_: {"groups": ["x"]}
        with self.assertRaises(OfflineEntitlementError):
            offline_claims_for_token(self.fido)

    def test_key_only_policy_is_independent_of_fido2_offline(self):
        self.policy.side_effect = lambda user, grant, info, token: grant == "key_only"
        require_owner_policy(self.fido, "key_only", expected_sid=self.user.uid)
        with self.assertRaises(OfflineEntitlementError):
            offline_grant_for_token(self.fido)

    def test_key_only_cannot_use_another_account_sid(self):
        with self.assertRaises(OfflineEntitlementError):
            require_owner_policy(self.fido, "key_only", expected_sid="S-1-5-21-999")
        self.policy.assert_not_called()

    def test_require_owner_policy_returns_the_fresh_record(self):
        self.assertEqual({"username": "operator"},
                         require_owner_policy(self.fido, "fido2"))


if __name__ == "__main__":
    unittest.main()
