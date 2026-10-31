"""Concurrent first offline refilltoken must not create two incompatible secrets.

Only real PostgreSQL or MariaDB exercise SELECT ... FOR UPDATE semantics;
SQLite skips this test rather than pretending to prove cross-process safety.
"""
from __future__ import annotations

import threading
from unittest.mock import patch

from sqlalchemy import event

from privacyidea.lib.applications.offline import MachineApplication
from privacyidea.lib.token import get_one_token
from privacyidea.models import Token, db
from .base import MyTestCase


class FirstOfflineRefillTokenRaceTests(MyTestCase):
    def test_two_first_logins_get_same_persisted_refilltoken(self):
        if db.engine.dialect.name not in ("postgresql", "mysql", "mariadb"):
            self.skipTest("requires real PostgreSQL or MariaDB row locks")
        serial = "AMFA-FIRST-REFILL-RACE"
        token = Token(serial, tokentype="hotp")
        token.update_otpkey(self.otpkey)
        token.save()

        generator_entered = threading.Event()
        second_attempt = threading.Event()
        release_generator = threading.Event()
        results = []
        errors = []
        original = MachineApplication.generate_new_refilltoken

        def controlled_generate(token_class, user_agent=None, **kwargs):
            if threading.current_thread().name == "first-refill-worker":
                generator_entered.set()
                if not release_generator.wait(10):
                    raise AssertionError("test timed out waiting for second first-login request")
            return original(token_class, user_agent, **kwargs)

        def worker():
            try:
                with self.app.app_context():
                    item = get_one_token(serial=serial)
                    secret = MachineApplication.existing_or_new_refilltoken(item, user_agent="AMFA-test")
                    results.append(secret)
                    db.session.remove()
            except BaseException as error:
                errors.append(error)

        first = threading.Thread(target=worker, name="first-refill-worker", daemon=True)
        second = threading.Thread(target=worker, name="second-refill-worker", daemon=True)

        def observe_sql(conn, cursor, statement, parameters, context, executemany):
            if (threading.current_thread().name == "second-refill-worker"
                    and "FOR UPDATE" in statement.upper() and "token" in statement.lower()):
                # The second session reached its locking query while the
                # first writer is still paused with the parent row locked.
                second_attempt.set()

        event.listen(db.engine, "before_cursor_execute", observe_sql)
        try:
            with patch.object(MachineApplication, "generate_new_refilltoken", side_effect=controlled_generate):
                first.start()
                self.assertTrue(generator_entered.wait(10), "first writer never acquired the token lock")
                second.start()
                self.assertTrue(second_attempt.wait(10), "second writer did not attempt the token row lock")
                self.assertFalse(any(results), "first token generated before test released the lock")
                release_generator.set()
        finally:
            release_generator.set()
            if first.ident is not None:
                first.join(timeout=15)
            if second.ident is not None:
                second.join(timeout=15)
            event.remove(db.engine, "before_cursor_execute", observe_sql)
        self.assertFalse(first.is_alive(), "first worker deadlocked")
        self.assertFalse(second.is_alive(), "second worker deadlocked")
        self.assertEqual(errors, [], f"parallel first-login failed: {errors!r}")
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0], results[1], "a client received an obsolete refilltoken")
        db.session.expire_all()
        current = get_one_token(serial=serial).get_tokeninfo("refilltoken")
        self.assertEqual(current, results[0])
