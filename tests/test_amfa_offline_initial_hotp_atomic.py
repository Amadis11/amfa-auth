"""First offline HOTP issuance: two online logins cannot receive overlapping OTPs.

The test runs on real PostgreSQL and MariaDB: two separate application
contexts, two SQL connections, one first writer held after locking Token,
and a second writer waiting in SELECT FOR UPDATE. SQLite is not proof of
cross-process serialization and is explicitly skipped.
"""
from __future__ import annotations

import threading
from unittest.mock import patch

from sqlalchemy import event

from privacyidea.lib.applications.offline import MachineApplication
from privacyidea.lib.token import get_one_token
from privacyidea.models import Token, db

from .base import MyTestCase


class InitialHOTPBatchRaceTests(MyTestCase):
    def test_failed_signed_issuance_rolls_back_counter_and_refilltoken_on_real_sql(self):
        if db.engine.dialect.name not in ("postgresql", "mysql", "mariadb"):
            self.skipTest("requires real PostgreSQL/MariaDB rollback semantics")
        serial = "AMFA-FIRST-HOTP-BATCH-ROLLBACK"
        record = Token(serial, tokentype="hotp")
        record.update_otpkey(self.otpkey)
        record.save()

        token = get_one_token(serial=serial)
        refill, bag = MachineApplication._reserve_initial_hotp_bundle(
            token, "", 3, 1, "AMFA-test", commit_db_session=False,
        )
        self.assertTrue(refill)
        self.assertEqual(len(bag), 3)
        self.assertEqual(token.token.count, 3, "batch is staged before sign()")
        # The caller failed to sign the offline item: request transaction aborts.
        db.session.rollback()
        db.session.expire_all()
        restored = get_one_token(serial=serial)
        self.assertEqual(restored.token.count, 0, "unpublished HOTP counters must remain usable")
        self.assertFalse(restored.get_tokeninfo("refilltoken"),
                         "unpublished first refilltoken must not survive signing failure")

    def test_two_initial_issuances_have_disjoint_counters_and_one_refilltoken(self):
        if db.engine.dialect.name not in ("postgresql", "mysql", "mariadb"):
            self.skipTest("requires real PostgreSQL/MariaDB SELECT FOR UPDATE")
        serial = "AMFA-FIRST-HOTP-BATCH-LOCK"
        record = Token(serial, tokentype="hotp")
        record.update_otpkey(self.otpkey)
        record.save()

        first_locked = threading.Event()
        second_lock_attempt = threading.Event()
        release_first = threading.Event()
        responses = []
        errors = []
        original = MachineApplication.get_offline_otps

        def pause_before_first_batch(token, otppin, count, rounds, **kwargs):
            if threading.current_thread().name == "initial-bag-first":
                first_locked.set()
                if not release_first.wait(15):
                    raise AssertionError("first issuance timed out after acquiring the token lock")
            return original(token, otppin, count, rounds, **kwargs)

        def observe_sql(conn, cursor, statement, parameters, context, executemany):
            if (threading.current_thread().name == "initial-bag-second"
                    and "FOR UPDATE" in statement.upper()
                    and "token" in statement.lower()):
                second_lock_attempt.set()

        def worker():
            try:
                with self.app.app_context():
                    token = get_one_token(serial=serial)
                    refill, bag = MachineApplication._reserve_initial_hotp_bundle(
                        token, "", 3, 1, "AMFA-test",
                    )
                    responses.append((refill, set(bag)))
                    db.session.remove()
            except BaseException as exc:
                errors.append(exc)

        first = threading.Thread(target=worker, name="initial-bag-first", daemon=True)
        second = threading.Thread(target=worker, name="initial-bag-second", daemon=True)
        event.listen(db.engine, "before_cursor_execute", observe_sql)
        try:
            with patch.object(MachineApplication, "get_offline_otps", side_effect=pause_before_first_batch):
                first.start()
                self.assertTrue(first_locked.wait(15), "first offline bag did not acquire lock")
                second.start()
                self.assertTrue(second_lock_attempt.wait(15), "second offline bag did not attempt row lock")
                self.assertEqual(responses, [], "issuer committed before the gate was released")
                release_first.set()
        finally:
            release_first.set()
            if first.ident is not None:
                first.join(timeout=20)
            if second.ident is not None:
                second.join(timeout=20)
            event.remove(db.engine, "before_cursor_execute", observe_sql)

        self.assertFalse(first.is_alive(), "first issuer deadlocked")
        self.assertFalse(second.is_alive(), "second issuer deadlocked")
        self.assertEqual(errors, [], f"parallel HOTP issuance errors: {errors!r}")
        self.assertEqual(len(responses), 2, responses)
        self.assertEqual(responses[0][0], responses[1][0], "the refilltoken was rotated by initial issue")
        self.assertFalse(responses[0][1] & responses[1][1], "two bags reused the same HOTP counter")
        self.assertEqual(responses[0][1] | responses[1][1], set(range(6)))
        db.session.expire_all()
        token = get_one_token(serial=serial)
        self.assertEqual(token.token.count, 6)
        self.assertEqual(token.get_tokeninfo("refilltoken"), responses[0][0])
