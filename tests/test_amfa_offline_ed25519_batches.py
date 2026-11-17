"""AMFA signed offline batches (#1156): wire, expiry and fail-closed tests."""
from __future__ import annotations

import base64
import os
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Load the pure signing module without executing privacyidea.lib.__init__,
# which imports Flask/SQLAlchemy dependencies irrelevant to this crypto test.
import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "amfa_offline_signatures",
    Path(__file__).resolve().parents[1] / "privacyidea/lib/amfa_offline_signatures.py",
)
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)
SIGNING_CONTEXT = _module.SIGNING_CONTEXT
OfflineSigningError = _module.OfflineSigningError
canonical_item = _module.canonical_item
sign_item = _module.sign_item
signed_auth_items = _module.signed_auth_items

# RFC 8032 test-only seed (public knowledge). NEVER reuse for an installation!
SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
TEST_KEY = Ed25519PrivateKey.from_private_bytes(SEED)
TEST_PUBLIC = TEST_KEY.public_key()
TEST_ITEM = {
    "serial": "TEST1", "username": "alice", "refilltoken": "refill-test",
    "response": {"0": "hash0", "1": "hash1"},
}


class SignedOfflineBatchTests(unittest.TestCase):
    def test_deterministic_canonical_json(self):
        self.assertEqual(
            canonical_item({"response": {"1": "b", "0": "a"},
                            "refilltoken": "t", "serial": "S"}),
            b'{"refilltoken":"t","response":{"0":"a","1":"b"},"serial":"S"}',
        )

    def test_verify_and_detect_tamper(self):
        with patch.dict(os.environ, {"AMFA_OFFLINE_ED25519_TTL_SECONDS": "3600"}):
            signed = sign_item(TEST_ITEM, TEST_KEY, "test-only")
        blob = base64.b64decode(signed["signed_payload"], validate=True)
        sig = base64.b64decode(signed["signature"], validate=True)
        TEST_PUBLIC.verify(sig, SIGNING_CONTEXT + blob)
        decoded = __import__("json").loads(blob)
        self.assertEqual(decoded["serial"], "TEST1")
        self.assertGreater(decoded["expiration"], __import__("time").time())
        self.assertEqual(decoded["format_version"], 1)
        with self.assertRaises(Exception):
            TEST_PUBLIC.verify(sig, SIGNING_CONTEXT + blob.replace(b"hash0", b"evil0"))

    def test_cpp_cross_language_fixture(self):
        # Exact bytes checked by tests/ParserTests/main.cpp in the Windows repo.
        # Freeze time so the issued expiry is 1800000000 (test only).
        with patch.dict(os.environ, {"AMFA_OFFLINE_ED25519_TTL_SECONDS": "3600"}):
            with patch.object(_module.time, "time",
                       return_value=1799996400):
                envelope = sign_item(TEST_ITEM, TEST_KEY, "test-only")
        self.assertEqual(envelope["signed_payload"],
            "eyJleHBpcmF0aW9uIjoxODAwMDAwMDAwLCJmb3JtYXRfdmVyc2lvbiI6MSwicmVmaWxsdG9rZW4iOi"
            "JyZWZpbGwtdGVzdCIsInJlc3BvbnNlIjp7IjAiOiJoYXNoMCIsIjEiOiJoYXNoMSJ9LCJzZXJpYWwi"
            "OiJURVNUMSIsInVzZXJuYW1lIjoiYWxpY2UifQ==")
        self.assertEqual(envelope["signature"],
            "t94EvyT0n8YghZrzFSHp9A/5+Jf5h5e7yihfRFz/IioNvRNeM7/j0UdfLN5zjHpOD7T6M17sgu8vXgcGosAAAw==")

    def test_no_cross_protocol_reuse(self):
        signed = sign_item(TEST_ITEM, TEST_KEY, "test-only")
        blob = base64.b64decode(signed["signed_payload"])
        sig = base64.b64decode(signed["signature"])
        with self.assertRaises(Exception):
            TEST_PUBLIC.verify(sig, blob)

    def test_fail_closed_invalid_ttl_and_keys(self):
        for ttl in ("0", "-1", "3888001", "notanint"):
            with self.subTest(ttl=ttl), patch.dict(os.environ, {"AMFA_OFFLINE_ED25519_TTL_SECONDS": ttl}):
                with self.assertRaises((OfflineSigningError, ValueError)):
                    sign_item(TEST_ITEM, TEST_KEY, "test-only")
        with self.assertRaises(OfflineSigningError):
            sign_item(TEST_ITEM, TEST_KEY, "bad key id!")
        with self.assertRaises(OfflineSigningError):
            canonical_item({"serial": "X", "response": {}})

    def test_signer_rejects_payloads_windows_client_cannot_use(self):
        # OfflineSignedBatch::VerifyEnvelopeWithKey on Windows requires
        # nonempty identity and rejects payloads larger than 256 KiB.
        for bad in (
            dict(TEST_ITEM, username=""),
            dict(TEST_ITEM, username=None),
            dict(TEST_ITEM, username="   "),
            dict(TEST_ITEM, username="bad\\nuser"),
            dict(TEST_ITEM, serial=""),
            dict(TEST_ITEM, refilltoken=""),
            dict(TEST_ITEM, refilltoken=1),
            dict(TEST_ITEM, username="u" * 257),
            dict(TEST_ITEM, response={"0": "x" * (256 * 1024)}),
        ):
            with self.subTest(bad_keys=list(bad)):
                with self.assertRaises(OfflineSigningError):
                    sign_item(bad, TEST_KEY, "test-only")

    def test_legacy_mode_unchanged_until_enabled(self):
        with patch.dict(os.environ, {"AMFA_OFFLINE_ED25519_ENABLED": "0"}):
            original = {"offline": [dict(TEST_ITEM)]}
            self.assertEqual(signed_auth_items(original), original)

    def test_enabled_key_missing_never_emits_unsigned(self):
        with patch.dict(os.environ, {"AMFA_OFFLINE_ED25519_ENABLED": "1"}, clear=True):
            with self.assertRaises(OfflineSigningError):
                signed_auth_items({"offline": [dict(TEST_ITEM)]})

    def test_private_signing_key_must_be_owner_only_and_not_a_symlink(self):
        """A compromised group-readable key must not silently sign offline access."""
        with tempfile.TemporaryDirectory() as tmp:
            keypath = os.path.join(tmp, "amfa-ed25519.pem")
            with open(keypath, "wb") as fh:
                fh.write(TEST_KEY.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ))
            os.chmod(keypath, 0o600)
            vars = {
                "AMFA_OFFLINE_ED25519_ENABLED": "1",
                "AMFA_OFFLINE_ED25519_PRIVATE_KEY_FILE": keypath,
                "AMFA_OFFLINE_ED25519_KEY_ID": "installation-2026",
            }
            with patch.dict(os.environ, vars):
                # Positive control: true private file signs normally.
                self.assertEqual(len(signed_auth_items(
                    {"offline": [dict(TEST_ITEM)]})["offline"]), 1)
                for mode in (0o640, 0o644, 0o666, 0o400):
                    os.chmod(keypath, mode)
                    with self.subTest(mode=oct(mode)):
                        if mode == 0o400:
                            self.assertEqual(len(signed_auth_items(
                                {"offline": [dict(TEST_ITEM)]})["offline"]), 1)
                        else:
                            with self.assertRaises(OfflineSigningError):
                                signed_auth_items({"offline": [dict(TEST_ITEM)]})
                os.chmod(keypath, 0o600)
                link = os.path.join(tmp, "key-symlink.pem")
                os.symlink(keypath, link)
                with patch.dict(os.environ, {"AMFA_OFFLINE_ED25519_PRIVATE_KEY_FILE": link}):
                    with self.assertRaises(OfflineSigningError):
                        signed_auth_items({"offline": [dict(TEST_ITEM)]})
                with patch.dict(os.environ, {"AMFA_OFFLINE_ED25519_PRIVATE_KEY_FILE": tmp}):
                    with self.assertRaises(OfflineSigningError):
                        signed_auth_items({"offline": [dict(TEST_ITEM)]})

    def test_signer_rejects_unreadable_or_invalid_key_and_never_emits_unsigned(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad_path = os.path.join(tmp, "bad.pem")
            with open(bad_path, "wb") as fh:
                fh.write(b"not a valid private signing key")
            os.chmod(bad_path, 0o600)
            with patch.dict(os.environ, {
                "AMFA_OFFLINE_ED25519_ENABLED": "1",
                "AMFA_OFFLINE_ED25519_PRIVATE_KEY_FILE": bad_path,
                "AMFA_OFFLINE_ED25519_KEY_ID": "installation-2026",
            }):
                with self.assertRaises(OfflineSigningError):
                    signed_auth_items({"offline": [dict(TEST_ITEM)]})

    def test_enabled_signs_every_item_or_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            keypath = os.path.join(tmp, "test-key.pem")
            with open(keypath, "wb") as fh:
                fh.write(TEST_KEY.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ))
            os.chmod(keypath, 0o600)  # required release condition; open() uses umask
            environment = {
                "AMFA_OFFLINE_ED25519_ENABLED": "1",
                "AMFA_OFFLINE_ED25519_PRIVATE_KEY_FILE": keypath,
                "AMFA_OFFLINE_ED25519_KEY_ID": "test-only",
            }
            with patch.dict(os.environ, environment):
                wrapped = signed_auth_items({"offline": [
                    dict(TEST_ITEM),
                    dict(TEST_ITEM, serial="TEST2"),
                ]})
                self.assertEqual(len(wrapped["offline"]), 2)
                for item in wrapped["offline"]:
                    TEST_PUBLIC.verify(
                        base64.b64decode(item["signature"]),
                        SIGNING_CONTEXT + base64.b64decode(item["signed_payload"]),
                    )
                with self.assertRaises(OfflineSigningError):
                    signed_auth_items({"offline": [dict(TEST_ITEM), {"serial": "BAD"}]})


if __name__ == "__main__":
    unittest.main()
