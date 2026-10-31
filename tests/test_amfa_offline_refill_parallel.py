"""End-to-end two-session offline refill race on real PostgreSQL/MariaDB.

The winning request holds SELECT FOR UPDATE through counter advance,
TokenInfo writes and rotating the refilltoken. The waiting request must
re-read the rotated token and fail with the old authorization secret.
SQLite cannot provide the required row-lock semantics, so it is skipped.
"""
from __future__ import annotations

import threading
from unittest.mock import patch

from sqlalchemy import event

from privacyidea.lib.applications.offline import MachineApplication
from privacyidea.lib.machine import attach_token
from privacyidea.lib.machineresolver import save_resolver as save_machine_resolver
from privacyidea.lib.token import get_one_token
from privacyidea.lib.tokens.hotptoken import HotpTokenClass
from privacyidea.lib.user import User
from privacyidea.models import Token, db

from .api_validate_common import HOSTSFILE
from .base import MyApiTestCase


class ParallelOfflineRefillTests(MyApiTestCase):
    def test_two_offline_refills_with_one_secret_have_only_one_winner(self):
        if db.engine.dialect.name not in ("postgresql", "mysql", "mariadb"):
            self.skipTest("requires real database row locks, not SQLite")

        self.setUp_user_realms()
        serial = "AMFA-REFILL-RACE-2"
        record = Token(serial, tokentype="hotp")
        record.update_otpkey(self.otpkey)
        record.save()
        obj = HotpTokenClass(record)
        obj.add_user(User("cornelius", self.realm1))
        obj.set_pin("pin")

        save_machine_resolver({
            "name": "refill-race-hosts", "type": "hosts", "filename": HOSTSFILE,
            "type.filename": "string", "desc.filename": "hosts",
            "pw": "secret", "type.pw": "password",
        })
        attach_token(
            serial, "offline", hostname="pippin", resolver_name="refill-race-hosts",
            options={"count": 100},
        )

        with self.app.test_request_context(
            "/validate/check", method="POST",
            data={"user": "cornelius", "pass": "pin287082"},
            environ_base={"REMOTE_ADDR": "192.168.0.2"},
        ):
            response = self.app.full_dispatch_request()
            self.assertEqual(response.status_code, 200, response.json)
            self.assertTrue(response.json["result"]["value"], response.json)
            prior = response.json["auth_items"]["offline"][0]["refilltoken"]

        first_paused = threading.Event()
        second_lock_attempt = threading.Event()
        release_first = threading.Event()
        results = []
        failures = []
        original_generate = MachineApplication.generate_new_refilltoken

        def controlled_generate(token, user_agent=None, **kwargs):
            if threading.current_thread().name == "first-refill":
                first_paused.set()
                if not release_first.wait(15):
                    raise AssertionError("timed out holding first refill before token rotation")
            return original_generate(token, user_agent, **kwargs)

        def observe_sql(conn, cursor, statement, parameters, context, executemany):
            if (threading.current_thread().name == "second-refill"
                    and "FOR UPDATE" in statement.upper()
                    and "token" in statement.lower()):
                second_lock_attempt.set()

        def worker():
            try:
                with self.app.test_request_context(
                    "/validate/offlinerefill", method="POST",
                    data={"serial": serial, "pass": "pin338314", "refilltoken": prior},
                    environ_base={"REMOTE_ADDR": "192.168.0.2"},
                ):
                    response = self.app.full_dispatch_request()
                    results.append((response.status_code, response.json))
                    db.session.remove()
            except BaseException as exc:
                failures.append(exc)

        first = threading.Thread(target=worker, name="first-refill", daemon=True)
        second = threading.Thread(target=worker, name="second-refill", daemon=True)
        event.listen(db.engine, "before_cursor_execute", observe_sql)
        try:
            with patch.object(
                MachineApplication, "generate_new_refilltoken",
                side_effect=controlled_generate,
            ):
                first.start()
                self.assertTrue(first_paused.wait(15), "first refill did not reach token rotation")
                second.start()
                self.assertTrue(second_lock_attempt.wait(15), "second refill did not reach FOR UPDATE")
                release_first.set()
        finally:
            release_first.set()
            if first.ident is not None:
                first.join(timeout=20)
            if second.ident is not None:
                second.join(timeout=20)
            event.remove(db.engine, "before_cursor_execute", observe_sql)

        self.assertFalse(first.is_alive(), "first refill worker deadlocked")
        self.assertFalse(second.is_alive(), "second refill worker deadlocked")
        self.assertEqual(failures, [], f"refill workers raised: {failures!r}")
        self.assertEqual(sorted(status for status, _ in results), [200, 400], results)
        self.assertEqual(
            get_one_token(serial=serial).token.count, 105,
            "counter must be advanced exactly once (102 before refill, +3)",
        )
        self.assertNotEqual(get_one_token(serial=serial).get_tokeninfo("refilltoken"), prior)
