"""Regression tests for #1605: AD eligibility is checked at ONLINE issue/refill.

Only the signer can authorise an offline route. A successful online login with
an excluded account may succeed, but must NOT create an offline batch.
"""
import base64
import datetime
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from privacyidea.lib.amfa_offline_entitlement import (
    CA_FILE, EXPECTED_KID, POLICY_FILE, PUBLIC_KEY_FILE, OfflineEntitlementError,
    offline_grant_for_token,
)


class TestOfflineEntitlement(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.dir = Path(self.tempdir.name)
        self.flags = {"offline_fido2_allowed": True, "offline_hotp_allowed": True}
        self.user = SimpleNamespace(resolver="ad", uid="user-42", realm="local", login="operator")
        self.fido = SimpleNamespace(type="webauthn", user=self.user)
        self.hotp = SimpleNamespace(type="hotp", user=self.user)
        self.resolver = SimpleNamespace(
            group_attribute_mapping_key="groups",
            get_available_info_keys=lambda: ["groups"],
            get_user_info=lambda _uid, attributes=None: {"groups": ["AMFA-haslo-fido"]},
        )
        self.save_policy()
        self.policy = patch("privacyidea.lib.amfa_offline_entitlement._policy_allows", return_value=True)
        self.policy_mock = self.policy.start()
        self.addCleanup(self.policy.stop)
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

    def _issue(self, token=None):
        with patch("privacyidea.lib.amfa_offline_entitlement.get_resolver_object", return_value=self.resolver):
            return offline_grant_for_token(token or self.fido)

    def test_explicit_policy_without_groups(self):
        self.resolver.get_user_info = lambda *_: {"username": "operator"}
        self.assertEqual("fido2", self._issue())
        self.policy_mock.assert_called_once()

    def test_denied_policy_does_not_issue(self):
        self.policy_mock.return_value = False
        with self.assertRaises(OfflineEntitlementError):
            self._issue()

    def test_hotp_switch_independent(self):
        self.flags["offline_hotp_allowed"] = False
        self.save_policy()
        self.assertEqual("fido2", self._issue())
        with self.assertRaises(OfflineEntitlementError):
            self._issue(self.hotp)

    def test_disabled_fido2_never_issues(self):
        self.flags["offline_fido2_allowed"] = False
        self.save_policy()
        with self.assertRaises(OfflineEntitlementError):
            self._issue()

    def test_missing_owner_fails_closed(self):
        self.resolver.get_user_info = lambda *_: {}
        with self.assertRaises(OfflineEntitlementError):
            self._issue()

    def test_tampered_policy_rejected(self):
        self.save_policy(bad_signature=True)
        with self.assertRaises(OfflineEntitlementError):
            self._issue()

    def test_expired_policy_rejected(self):
        self.save_policy(expired=True)
        with self.assertRaises(OfflineEntitlementError):
            self._issue()

    def test_missing_policy_rejected(self):
        with patch.dict(os.environ, {POLICY_FILE: ""}):
            with self.assertRaises(OfflineEntitlementError):
                self._issue()

    def test_removed_group_fields_rejected(self):
        self.flags["offline_fido2_groups"] = ["obsolete"]
        self.save_policy()
        with self.assertRaises(OfflineEntitlementError):
            self._issue()


class TestOfflineEntitlementCustomerCA(unittest.TestCase):
    """#1550 form: the envelope carries a leaf certificate issued by the customer CA.

    The engine must accept the very document the workstations accept, so a customer
    deployment that signs with its own CA is not silently left without offline access.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.dir = Path(self.tempdir.name)
        self.utc = datetime.timezone.utc
        self.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.ca = self._certificate(
            self.ca_key, subject="AMFA-Lab-CA", issuer_key=self.ca_key, ca=True,
            not_before=datetime.datetime(2026, 1, 1, tzinfo=self.utc),
            not_after=datetime.datetime(2031, 1, 1, tzinfo=self.utc),
            digital_signature=False)
        (self.dir / "ca.pem").write_bytes(
            self.ca.public_bytes(serialization.Encoding.PEM))
        self.leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.leaf = self._certificate(
            self.leaf_key, subject="AMFA-Flagi-2026", issuer_key=self.ca_key, ca=False,
            not_before=datetime.datetime(2026, 1, 1, tzinfo=self.utc),
            not_after=datetime.datetime(2031, 1, 1, tzinfo=self.utc))
        self.flags = {"offline_fido2_allowed": True, "offline_hotp_allowed": True}
        self.user = SimpleNamespace(resolver="ad", uid="user-42", realm="local", login="operator")
        self.fido = SimpleNamespace(type="webauthn", user=self.user)
        self.resolver = SimpleNamespace(
            group_attribute_mapping_key="groups",
            get_available_info_keys=lambda: ["groups"],
            get_user_info=lambda _uid, attributes=None: {"groups": ["AMFA-haslo-fido"]},
        )
        self.policy = patch("privacyidea.lib.amfa_offline_entitlement._policy_allows", return_value=True)
        self.policy.start()
        self.addCleanup(self.policy.stop)
        self.patcher = patch.dict(os.environ, {
            POLICY_FILE: str(self.dir / "flags.json"),
            CA_FILE: str(self.dir / "ca.pem"),
            PUBLIC_KEY_FILE: "",
            EXPECTED_KID: "",
        })
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def _certificate(self, key, *, subject, issuer_key, ca, not_before, not_after,
                     digital_signature=True):
        builder = (x509.CertificateBuilder()
                   .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
                   .issuer_name(x509.Name([x509.NameAttribute(
                       NameOID.COMMON_NAME, "AMFA-Lab-CA" if issuer_key is self.ca_key else subject)]))
                   .public_key(key.public_key())
                   .serial_number(4096 if ca else 8192)
                   .not_valid_before(not_before)
                   .not_valid_after(not_after)
                   .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
                   .add_extension(x509.KeyUsage(
                       digital_signature=digital_signature, content_commitment=False,
                       key_encipherment=False, data_encipherment=False, key_agreement=False,
                       key_cert_sign=ca, crl_sign=ca, encipher_only=False,
                       decipher_only=False), critical=True))
        return builder.sign(issuer_key, hashes.SHA256())

    def _write_flags(self, *, signer_key=None, signer_certificate=None, key_id=None,
                     revision=7, valid_days=7, tampered=False, document=None):
        signer_key = signer_key if signer_key is not None else self.leaf_key
        signer_certificate = signer_certificate if signer_certificate is not None else self.leaf
        document = document if document is not None else {
            "format_version": 1, "type": "deployment-flags",
            "valid_until": (datetime.date.today() + datetime.timedelta(days=valid_days)).isoformat(),
            "revision": revision,
            "flags": self.flags,
        }
        payload = json.dumps(document, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False).encode("utf-8")
        value = signer_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
        if tampered:
            value = value[:-1] + bytes([value[-1] ^ 1])
        der = signer_certificate.public_bytes(serialization.Encoding.DER)
        envelope = {"document": document, "signature": {
            "algorithm": "rsa-sha256",
            "value": base64.b64encode(value).decode("ascii"),
            "cert_base64": base64.b64encode(der).decode("ascii"),
            "key_id": key_id or "cert-sha256:" + hashlib.sha256(der).hexdigest(),
        }}
        (self.dir / "flags.json").write_text(json.dumps(envelope), encoding="utf-8")

    def _issue(self):
        with patch("privacyidea.lib.amfa_offline_entitlement.get_resolver_object",
                   return_value=self.resolver):
            return offline_grant_for_token(self.fido)

    def test_customer_ca_signed_document_authorises_issue(self):
        self._write_flags()
        self.assertEqual("fido2", self._issue())

    def test_certificate_from_another_ca_is_rejected(self):
        other_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        foreign = self._certificate(
            other_ca_key, subject="Foreign-Flagi", issuer_key=other_ca_key, ca=False,
            not_before=datetime.datetime(2026, 1, 1, tzinfo=self.utc),
            not_after=datetime.datetime(2031, 1, 1, tzinfo=self.utc))
        self._write_flags(signer_key=other_ca_key, signer_certificate=foreign)
        with self.assertRaises(OfflineEntitlementError):
            self._issue()

    def test_ca_certificate_may_not_sign_directly(self):
        self._write_flags(signer_key=self.ca_key, signer_certificate=self.ca)
        with self.assertRaises(OfflineEntitlementError):
            self._issue()

    def test_certificate_fingerprint_must_match_key_id(self):
        self._write_flags(key_id="cert-sha256:" + "0" * 64)
        with self.assertRaises(OfflineEntitlementError):
            self._issue()

    def test_signer_without_digital_signature_is_rejected(self):
        weak_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        weak = self._certificate(
            weak_key, subject="AMFA-NoDigitalSignature", issuer_key=self.ca_key, ca=False,
            not_before=datetime.datetime(2026, 1, 1, tzinfo=self.utc),
            not_after=datetime.datetime(2031, 1, 1, tzinfo=self.utc),
            digital_signature=False)
        self._write_flags(signer_key=weak_key, signer_certificate=weak)
        with self.assertRaises(OfflineEntitlementError):
            self._issue()

    def test_expired_signing_certificate_is_rejected(self):
        stale_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        stale = self._certificate(
            stale_key, subject="AMFA-Stale", issuer_key=self.ca_key, ca=False,
            not_before=datetime.datetime(2020, 1, 1, tzinfo=self.utc),
            not_after=datetime.datetime(2021, 1, 1, tzinfo=self.utc))
        self._write_flags(signer_key=stale_key, signer_certificate=stale)
        with self.assertRaises(OfflineEntitlementError):
            self._issue()

    def test_tampered_document_is_rejected(self):
        self._write_flags(tampered=True)
        with self.assertRaises(OfflineEntitlementError):
            self._issue()

    def test_expired_document_is_rejected(self):
        self._write_flags(valid_days=-1)
        with self.assertRaises(OfflineEntitlementError):
            self._issue()

    def test_customer_signature_requires_a_monotonic_revision(self):
        document = {"format_version": 1, "type": "deployment-flags",
                    "valid_until": (datetime.date.today()
                                    + datetime.timedelta(days=7)).isoformat(),
                    "flags": self.flags}
        self._write_flags(document=document)
        with self.assertRaises(OfflineEntitlementError):
            self._issue()

    def test_customer_certificate_without_the_pinned_ca_is_refused(self):
        self._write_flags()
        with patch.dict(os.environ, {CA_FILE: ""}):
            with self.assertRaises(OfflineEntitlementError):
                self._issue()


if __name__ == "__main__":
    unittest.main()
