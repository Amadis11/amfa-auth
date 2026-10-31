"""Regression: /validate/offlinerefill must keep its row lock through one commit.

A SELECT FOR UPDATE is ineffective if token.check_otp(), token.inc_otp_counter()
or token.write_tokeninfo() commits while the refilltoken is being rotated.
The lock is held by the Flask SQLAlchemy transaction, not the Python object.

This unit suite checks the non-committing HOTP path. A two-connection
PostgreSQL/MariaDB concurrency test remains mandatory before deployment.
"""
from __future__ import annotations

import pathlib
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from privacyidea.lib.applications import offline as offline_module
from privacyidea.lib.error import ValidateError

ROOT = pathlib.Path(__file__).resolve().parents[1]


class FakeHOTP:
    type = "hotp"
    hashlib = "sha1"

    def __init__(self):
        self.token = SimpleNamespace(count=25, otplen=6, get_otpkey=lambda: b"test-secret")
        self.writes = []

    def split_pin_pass(self, password):
        assert password == "PIN123456"
        return True, "PIN", "123456"

    def get_hashlib(self, name):
        assert name == "sha1"
        return object()

    def check_otp(self, *args, **kwargs):
        raise AssertionError("atomic refill must NOT call the committing check_otp()")

    def set_otp_count(self, *args, **kwargs):
        raise AssertionError("atomic refill must NOT call the committing set_otp_count()")

    def get_multi_otp(self, *, count, counter_index):
        assert counter_index and count == 3
        return True, "OK", {"otp": {25: "123456", 26: "234567", 27: "345678"}}

    def inc_otp_counter(self, *, increment, commit_db_session=True):
        self.writes.append(("counter", increment, commit_db_session))

    def write_tokeninfo(self, key, value, commit_db_session=True):
        self.writes.append(("info", key, value, commit_db_session))

    def get_serial(self):
        return "OATHTEST"


class RefillTransactionTests(unittest.TestCase):
    def test_hotp_refill_never_commits_intermediate_counter_or_info(self):
        token = FakeHOTP()
        with patch.object(offline_module, "HmacOtp") as verifier, \
             patch.object(offline_module, "get_prepend_pin", return_value=False):
            verifier.return_value.checkOtp.return_value = 17
            result = offline_module.MachineApplication.get_refill(
                token, "PIN123456", {"count": 10, "rounds": 1}, atomic=True,
            )
            self.assertEqual(verifier.call_count, 1)
            self.assertEqual(verifier.return_value.checkOtp.call_args.args, ("123456", 10))
        self.assertEqual(len(result), 3)
        self.assertEqual(
            token.writes,
            [("counter", 3, False), ("info", "offline_counter", 10, False)],
        )

    def test_bad_otp_cannot_commit_or_rotate_anything(self):
        token = FakeHOTP()
        with patch.object(offline_module, "HmacOtp") as verifier:
            verifier.return_value.checkOtp.return_value = -1
            with self.assertRaises(ValidateError):
                offline_module.MachineApplication.get_refill(
                    token, "PIN123456", {"count": 10, "rounds": 1}, atomic=True,
                )
        self.assertEqual(token.writes, [])

    def test_new_refilltoken_can_be_stored_without_releasing_the_lock(self):
        token = FakeHOTP()
        with patch.object(offline_module, "geturandom", return_value="refill-test"):
            value = offline_module.MachineApplication.generate_new_refilltoken(
                token, commit_db_session=False,
            )
        self.assertEqual(value, "refill-test")
        self.assertEqual(token.writes, [("info", "refilltoken", "refill-test", False)])

    def test_handler_commits_after_refill_counter_and_token_rotation(self):
        src = (ROOT / "privacyidea/api/validate.py").read_text(encoding="utf-8")
        start = src.index("def offlinerefill():")
        end = src.index("\ndef _conditional_access_identity():", start)
        handler = src[start:end]
        ordered = [
            "with_for_update()",
            'db.session.expire(token.token, ["info_list"])',
            'refilltoken_stored = token.get_tokeninfo("refilltoken")',
            "MachineApplication.get_refill(token, password, options, atomic=True)",
            "commit_db_session=False,",
            "response = send_result(True)",
            "content[\"auth_items\"] = signed_auth_items(",
            "response.set_data(json.dumps(content))",
            "db.session.commit()",
        ]
        offsets = [handler.index(item) for item in ordered]
        self.assertEqual(offsets, sorted(offsets))
        self.assertEqual(handler.count("db.session.commit()"), 1)

    def test_noncommitting_tokenclass_helpers_cover_failcounter_cleanup(self):
        source = (ROOT / "privacyidea/lib/tokenclass.py").read_text(encoding="utf-8")
        self.assertIn("def inc_otp_counter(self, counter=None, increment=1, reset=True, commit_db_session: bool = True)", source)
        self.assertIn("self.set_failcount(0, commit_db_session=commit_db_session)", source)
        self.assertIn("self.remove_tokeninfo(FAILCOUNTER_EXCEEDED, commit_db_session=commit_db_session)", source)
        self.assertIn("if commit_db_session:\n            self.token.save()\n        else:\n            db.session.add(self.token)", source)


if __name__ == "__main__":
    unittest.main()
