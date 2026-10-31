"""Initial offline HOTP issuance must not commit before signing succeeds (#91)."""
from __future__ import annotations

import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from flask import Flask, g

from privacyidea.api.lib import postpolicy
from privacyidea.lib.applications import offline as offline_module
from privacyidea.lib.amfa_offline_signatures import OfflineSigningError


class FakeResponse:
    def __init__(self):
        self.json = {"result": {"value": True}, "detail": {"serial": "HOTPX"}}
        self.data = None

    def set_data(self, data):
        self.data = data


class OfflineSigningTransactionTests(unittest.TestCase):
    def _request(self):
        return SimpleNamespace(all_data={"pass": "PIN123456"},
                               user_agent=SimpleNamespace(string="AMFA-CP/1"),
                               User=None)

    def _run(self, signer, *, failing_serialization=False, fail_commit=False):
        app = Flask(__name__)
        response = FakeResponse()
        events = []
        if failing_serialization:
            def bad_serialize(_content):
                events.append("serialize")
                raise ValueError("cannot serialize response")
            response.set_data = bad_serialize
        else:
            original = response.set_data
            def serialize(content):
                events.append("serialize")
                original(content)
            response.set_data = serialize
        with app.test_request_context("/"):
            g.client_ip = "127.0.0.1"
            with patch.object(postpolicy, "get_user_verification_requirement", return_value="preferred"), \
                 patch.object(postpolicy, "get_auth_items", return_value={
                     "offline": [{"serial": "HOTPX", "response": {"1": "hash"}, "refilltoken": "refill"}]
                 }) as items, \
                 patch("privacyidea.lib.amfa_offline_signatures.signed_auth_items",
                       side_effect=signer), \
                 patch.object(postpolicy, "db") as db:
                def commit():
                    events.append("commit")
                    if fail_commit:
                        raise RuntimeError("database commit failed")
                db.session.commit.side_effect = commit
                db.session.rollback.side_effect = lambda: events.append("rollback")
                result = postpolicy.offline_info(self._request(), response)
                self.assertIs(result, response)
                self.assertTrue(result.json["result"]["value"])
                self.assertTrue(items.call_args.kwargs["defer_offline_commit"])
                return events, response, db.session.commit.call_count, db.session.rollback.call_count

    def test_signing_failure_rolls_back_and_preserves_online_success(self):
        def signer(_items):
            raise OfflineSigningError("missing signing key")
        events, response, commits, rollbacks = self._run(signer)
        self.assertEqual(events, ["rollback"])
        self.assertEqual(commits, 0)
        self.assertEqual(rollbacks, 1)
        self.assertIsNone(response.data)

    def test_valid_signed_payload_is_serialized_before_commit(self):
        def signer(items):
            events_seen.append("sign")
            return items
        events_seen = []
        events, response, commits, rollbacks = self._run(signer)
        self.assertEqual(events, ["serialize", "commit"])
        self.assertEqual(events_seen, ["sign"])
        self.assertEqual(commits, 1)
        self.assertEqual(rollbacks, 0)
        self.assertIn("auth_items", json.loads(response.data))

    def test_response_serialization_failure_uses_rollback(self):
        events, response, commits, rollbacks = self._run(lambda items: items, failing_serialization=True)
        self.assertEqual(events, ["serialize", "rollback"])
        self.assertEqual(commits, 0)
        self.assertEqual(rollbacks, 1)

    def test_commit_failure_removes_signed_bag_from_online_response(self):
        events, response, commits, rollbacks = self._run(lambda items: items, fail_commit=True)
        self.assertEqual(events, ["serialize", "commit", "rollback", "serialize"])
        self.assertEqual(commits, 1)
        self.assertEqual(rollbacks, 1)
        self.assertTrue(json.loads(response.data)["result"]["value"])
        self.assertNotIn("auth_items", json.loads(response.data))

    def test_initial_hotp_bundle_can_defer_commit(self):
        token = SimpleNamespace(token=SimpleNamespace(id=42),
                                check_all=lambda messages: True,
                                get_tokeninfo=lambda key: "existing-refill")
        with patch.object(offline_module, "db") as db, \
             patch.object(offline_module.MachineApplication, "get_offline_otps",
                          return_value={"42": "hash"}):
            result = offline_module.MachineApplication._reserve_initial_hotp_bundle(
                token, "PIN", 1, 1, commit_db_session=False)
            self.assertEqual(result, ("existing-refill", {"42": "hash"}))
            db.session.commit.assert_not_called()
            offline_module.MachineApplication._reserve_initial_hotp_bundle(
                token, "PIN", 1, 1, commit_db_session=True)
            db.session.commit.assert_called_once()


if __name__ == "__main__":
    unittest.main()
