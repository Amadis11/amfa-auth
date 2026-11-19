"""Regression tests for #1605: AD eligibility is checked at ONLINE issue/refill.

Only the signer can authorise an offline route. A successful online login with
an excluded account may succeed, but must NOT create an offline batch.
"""
import base64
import datetime
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from privacyidea.lib.amfa_offline_entitlement import (
    EXPECTED_KID, POLICY_FILE, PUBLIC_KEY_FILE, OfflineEntitlementError,
    offline_grant_for_token,
)


class TestOfflineEntitlement(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.dir = Path(self.tempdir.name)
        self.flags = {"offline_fido2_groups": ["AMFA-haslo-fido"],
                      "offline_hotp_groups": ["AMFA-hotp"],
                      "offline_hotp_allowed": True}
        self.user = SimpleNamespace(resolver="ad", uid="user-42")
        self.fido = SimpleNamespace(type="webauthn", user=self.user)
        self.hotp = SimpleNamespace(type="hotp", user=self.user)
        self.resolver = SimpleNamespace(
            group_attribute_mapping_key="groups",
            get_available_info_keys=lambda: ["groups"],
            get_user_info=lambda _uid, attributes: {"groups": ["AMFA-haslo-fido"]},
        )
        self.save_policy()
        self.patcher = patch.dict(os.environ, {
            POLICY_FILE: str(self.dir / "flags.json"),
            PUBLIC_KEY_FILE: str(self.dir / "public.pem"),
            EXPECTED_KID: "issuer-1",
        })
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def save_policy(self, *, bad_signature=False, expired=False):
        document = {
            "format_version": 1, "type": "deployment-flags",
            "valid_until": (datetime.date.today() + datetime.timedelta(
                days=-1 if expired else 7)).isoformat(),
            "flags": self.flags,
        }
        payload = json.dumps(document, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False).encode("utf-8")
        signature = self.key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
        if bad_signature:
            signature = signature[:-1] + bytes([signature[-1] ^ 1])
        (self.dir / "flags.json").write_text(json.dumps({
            "document": document,
            "signature": {"algorithm": "rsa-sha256", "key_id": "issuer-1",
                          "value": base64.b64encode(signature).decode("ascii")},
        }), encoding="utf-8")
        (self.dir / "public.pem").write_bytes(self.key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))

    def test_fido_issue_allowed_by_group(self):
        with patch("privacyidea.lib.amfa_offline_entitlement.get_resolver_object",
                   return_value=self.resolver):
            self.assertEqual("fido2", offline_grant_for_token(self.fido))

    def test_hotp_group_must_be_independently_allowed(self):
        with patch("privacyidea.lib.amfa_offline_entitlement.get_resolver_object",
                   return_value=self.resolver):
            with self.assertRaises(OfflineEntitlementError):
                offline_grant_for_token(self.hotp)

    def test_group_removed_prevents_next_issue(self):
        self.resolver.get_user_info = lambda *_args, **_kwargs: {"groups": []}
        with patch("privacyidea.lib.amfa_offline_entitlement.get_resolver_object",
                   return_value=self.resolver):
            with self.assertRaises(OfflineEntitlementError):
                offline_grant_for_token(self.fido)

    def test_missing_group_data_fails_closed(self):
        self.resolver.get_user_info = lambda *_args, **_kwargs: {}
        with patch("privacyidea.lib.amfa_offline_entitlement.get_resolver_object",
                   return_value=self.resolver):
            with self.assertRaises(OfflineEntitlementError):
                offline_grant_for_token(self.fido)

    def test_tampered_policy_rejected(self):
        self.save_policy(bad_signature=True)
        with self.assertRaises(Exception):
            offline_grant_for_token(self.fido)

    def test_expired_policy_rejected(self):
        self.save_policy(expired=True)
        with self.assertRaises(OfflineEntitlementError):
            offline_grant_for_token(self.fido)

    def test_missing_policy_rejected(self):
        with patch.dict(os.environ, {POLICY_FILE: ""}):
            with self.assertRaises(OfflineEntitlementError):
                offline_grant_for_token(self.fido)

    def test_qualified_group_never_matches_short_name(self):
        self.flags["offline_fido2_groups"] = ["DOMAIN\\AMFA-haslo-fido"]
        self.save_policy()
        with patch("privacyidea.lib.amfa_offline_entitlement.get_resolver_object",
                   return_value=self.resolver):
            with self.assertRaises(OfflineEntitlementError):
                offline_grant_for_token(self.fido)


if __name__ == "__main__":
    unittest.main()
