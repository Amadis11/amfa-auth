"""AMFA signed offline batches (#1156): wire, expiry and fail-closed tests."""
from __future__ import annotations

import base64
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Load the pure signing module without executing privacyidea.lib.__init__,
# which imports Flask/SQLAlchemy dependencies irrelevant to this crypto test.
import importlib.util
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from amfa_offline_lab_anchor import anchor_environment  # noqa: E402

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
    "response": {"0": "hash0", "1": "hash1"}, "offline_grant": "hotp",
    "realm": "a.test", "account_sid": "S-1-5-21-1-2-3-1001",
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
        self.assertEqual(decoded["format_version"], 3)
        self.assertEqual(decoded["offline_grant"], "hotp")
        with self.assertRaises(Exception):
            TEST_PUBLIC.verify(sig, SIGNING_CONTEXT + blob.replace(b"hash0", b"evil0"))

    def test_cpp_cross_language_fixture(self):
        # Exact v3 bytes (signed AD subject) verified by the Windows and portable CP harnesses.
        with patch.dict(os.environ, {"AMFA_OFFLINE_ED25519_TTL_SECONDS": "3600"}):
            with patch.object(_module.time, "time_ns", return_value=1799996400 * 1_000_000_000):
                envelope = sign_item(TEST_ITEM, TEST_KEY, "test-only")
        self.assertEqual(envelope["signed_payload"],
                         "eyJhY2NvdW50X3NpZCI6IlMtMS01LTIxLTEtMi0zLTEwMDEiLCJleHBpcmF0aW9uIjoxODAwMDAwMDAwLCJmb3JtYXRfdmVyc2lvbiI6MywiaXNzdWVkX2F0X3VzIjoxNzk5OTk2NDAwMDAwMDAwLCJvZmZsaW5lX2dyYW50IjoiaG90cCIsInJlYWxtIjoiYS50ZXN0IiwicmVmaWxsdG9rZW4iOiJyZWZpbGwtdGVzdCIsInJlc3BvbnNlIjp7IjAiOiJoYXNoMCIsIjEiOiJoYXNoMSJ9LCJzZXJpYWwiOiJURVNUMSIsInVzZXJuYW1lIjoiYWxpY2UifQ==")
        self.assertEqual(envelope["signature"],
                         "6gjBtXREKbuhBxsR326Bh90vFqV0BO3cpZ2OeOoVVMw30RUUokDDB/VTSZm1mYAdjO7M9irI8i7nXnQcXaaaCg==")

    def test_issuer_time_is_signed_and_not_caller_controlled(self):
        now_ns = 1_800_000_000_123_456_000
        with patch.dict(os.environ, {"AMFA_OFFLINE_ED25519_TTL_SECONDS": "2592000"}), \
                patch.object(_module.time, "time_ns", return_value=now_ns):
            signed = sign_item(dict(TEST_ITEM, issued_at_us=1, expiration=2),
                               TEST_KEY, "test-only")
        blob = base64.b64decode(signed["signed_payload"], validate=True)
        TEST_PUBLIC.verify(base64.b64decode(signed["signature"]), SIGNING_CONTEXT + blob)
        decoded = __import__("json").loads(blob)
        self.assertEqual(decoded["issued_at_us"], now_ns // 1000)
        self.assertEqual(decoded["expiration"] - decoded["issued_at_us"] // 1_000_000,
                         30 * 24 * 3600)

    def test_signed_batch_carries_the_ad_subject(self):
        with patch.dict(os.environ, {"AMFA_OFFLINE_ED25519_TTL_SECONDS": "3600"}):
            signed = sign_item(TEST_ITEM, TEST_KEY, "test-only")
        decoded = __import__("json").loads(base64.b64decode(signed["signed_payload"], validate=True))
        self.assertEqual(decoded["format_version"], 3)
        self.assertEqual(decoded["account_sid"], TEST_ITEM["account_sid"])
        self.assertEqual(decoded["realm"], TEST_ITEM["realm"])
        self.assertEqual(decoded["username"], TEST_ITEM["username"])

    def test_missing_or_wrong_subject_denied(self):
        for field in ("realm", "account_sid", "username"):
            item = dict(TEST_ITEM)
            item.pop(field)
            with self.subTest(field=field), self.assertRaises(OfflineSigningError):
                sign_item(item, TEST_KEY, "test-only")
        for bad_sid in ("S-1-5-18", "S-1-5-21-1-2-3-4294967296"):
            with self.subTest(sid=bad_sid), self.assertRaises(OfflineSigningError):
                sign_item(dict(TEST_ITEM, account_sid=bad_sid), TEST_KEY, "test-only")
        signed = sign_item(TEST_ITEM, TEST_KEY, "test-only")
        blob = base64.b64decode(signed["signed_payload"])
        sig = base64.b64decode(signed["signature"])
        with self.assertRaises(Exception):
            TEST_PUBLIC.verify(sig, SIGNING_CONTEXT + blob.replace(b"a.test", b"b.test"))
        with self.assertRaises(Exception):
            TEST_PUBLIC.verify(sig, SIGNING_CONTEXT + blob.replace(b"1-2-3-1001", b"4-5-6-1001"))

    def test_two_refills_within_one_second_have_distinct_signed_order(self):
        # Expiry has one-second precision and MUST NOT be used as a
        # freshness/anti-replay sequence number across HA refill calls.
        with patch.dict(os.environ, {"AMFA_OFFLINE_ED25519_TTL_SECONDS": "3600"}):
            with patch.object(_module.time, "time", return_value=1799996400.001):
                first = sign_item(TEST_ITEM, TEST_KEY, "test-only")
            with patch.object(_module.time, "time", return_value=1799996400.002):
                second = sign_item(dict(TEST_ITEM, refilltoken="next"), TEST_KEY, "test-only")
        first_item = __import__("json").loads(base64.b64decode(first["signed_payload"]))
        second_item = __import__("json").loads(base64.b64decode(second["signed_payload"]))
        self.assertEqual(first_item["expiration"], second_item["expiration"])
        self.assertLess(first_item["issued_at_us"], second_item["issued_at_us"])
        self.assertNotEqual(first["signed_payload"], second["signed_payload"])
        for envelope in (first, second):
            TEST_PUBLIC.verify(
                base64.b64decode(envelope["signature"]),
                SIGNING_CONTEXT + base64.b64decode(envelope["signed_payload"]),
            )

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
            dict(TEST_ITEM, username="bad\nuser"),
            dict(TEST_ITEM, serial=""),
            dict(TEST_ITEM, refilltoken=""),
            dict(TEST_ITEM, refilltoken=1),
            dict(TEST_ITEM, username="u" * 257),
            dict(TEST_ITEM, response={"0": "x" * (256 * 1024)}),
        ):
            with self.subTest(bad_keys=list(bad)):
                with self.assertRaises(OfflineSigningError):
                    sign_item(bad, TEST_KEY, "test-only")

    def test_missing_or_wrong_issuance_grant_fails_closed(self):
        with self.assertRaises(OfflineSigningError):
            sign_item(dict(TEST_ITEM, offline_grant=""), TEST_KEY, "test-only")
        with self.assertRaises(OfflineSigningError):
            sign_item(dict(TEST_ITEM, offline_grant="fido2"), TEST_KEY, "test-only")
        without_grant = dict(TEST_ITEM)
        without_grant.pop("offline_grant")
        with self.assertRaises(OfflineSigningError):
            sign_item(without_grant, TEST_KEY, "test-only")

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
            # #1692: signing turns on only with a root-signed anchor, so the
            # control group needs one too (a throwaway root, never the product's).
            vars.update(anchor_environment(tmp, TEST_KEY, "installation-2026"))
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
            # #1692: podpisywanie wlacza sie tylko z kotwica podpisana kluczem root.
            # Test mieli wlasna pare root i podpisuje nia kotwice dla swojego klucza.
            os.chmod(keypath, 0o600)  # required release condition; open() uses umask
            environment = {
                "AMFA_OFFLINE_ED25519_ENABLED": "1",
                "AMFA_OFFLINE_ED25519_PRIVATE_KEY_FILE": keypath,
                "AMFA_OFFLINE_ED25519_KEY_ID": "test-only",
            }
            environment.update(anchor_environment(tmp, TEST_KEY, "test-only"))
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
