"""Release contract: no AMFA offline batch may be signed for over 30 days.

This tests the actual signing function, including the expiry embedded inside
the immutable Ed25519-signed payload. It does not simulate Windows LogonUI.
"""
import base64
import json
import os
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from privacyidea.lib import amfa_offline_signatures as signatures

NOW = 1_700_000_000
THIRTY_DAYS = 30 * 24 * 3600


class SignedOfflineTTL30Days(unittest.TestCase):
    def setUp(self):
        self.private_key = Ed25519PrivateKey.generate()
        self.offline_item = {
            "serial": "WAN-TEST",
            "refilltoken": "local-test-refill-only",
            "response": {"pubKey": "test", "credentialId": "test", "rpId": "test.local"},
        }

    def sign_with_ttl(self, ttl):
        with patch.dict(os.environ):
            if ttl is None:
                os.environ.pop("AMFA_OFFLINE_ED25519_TTL_SECONDS", None)
            else:
                os.environ["AMFA_OFFLINE_ED25519_TTL_SECONDS"] = str(ttl)
            with patch.object(signatures.time, "time", return_value=NOW):
                signed = signatures.sign_item(self.offline_item, self.private_key, "test-key")
        item = json.loads(base64.b64decode(signed["signed_payload"]))
        return signed, item

    def test_default_is_30_days(self):
        _, item = self.sign_with_ttl(None)
        self.assertEqual(item["expiration"], NOW + THIRTY_DAYS)

    def test_shorter_signed_ttl_is_allowed(self):
        _, item = self.sign_with_ttl(3600)
        self.assertEqual(item["expiration"], NOW + 3600)

    def test_exact_maximum_is_allowed(self):
        signed, item = self.sign_with_ttl(THIRTY_DAYS)
        self.assertEqual(item["expiration"], NOW + THIRTY_DAYS)
        self.assertEqual(signed["alg"], "Ed25519")

    def test_exceeding_maximum_is_rejected(self):
        with self.assertRaises(signatures.OfflineSigningError):
            self.sign_with_ttl(THIRTY_DAYS + 1)

    def test_below_minimum_is_rejected(self):
        with self.assertRaises(signatures.OfflineSigningError):
            self.sign_with_ttl(59)


if __name__ == "__main__":
    unittest.main()
