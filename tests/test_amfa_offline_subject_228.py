"""Unit coverage for the offline subject contract (CP #228)."""
from types import SimpleNamespace
import unittest

from privacyidea.lib.amfa_offline_subject import offline_subject


class OfflineSubjectTest(unittest.TestCase):
    def test_distinct_domain_sids(self):
        resolver = SimpleNamespace(uidtype="objectSid")
        a = SimpleNamespace(uid="S-1-5-21-1-2-3-1001", realm="a.test")
        b = SimpleNamespace(uid="S-1-5-21-4-5-6-1001", realm="b.test")
        self.assertEqual(offline_subject(a, resolver),
                         {"account_sid": a.uid, "realm": a.realm})
        self.assertNotEqual(offline_subject(a, resolver),
                            offline_subject(b, resolver))

    def test_refuses_invalid_or_unresolved_subject(self):
        resolver = SimpleNamespace(uidtype="objectSid")
        for sid in (None, "", "admin", "S-1-5-18",
                    "S-1-5-21-01-2-3-1001", "S-1-5-21-4294967296-2-3-1001"):
            with self.subTest(sid=sid), self.assertRaises(ValueError):
                offline_subject(SimpleNamespace(uid=sid, realm="a.test"), resolver)
        for realm in (None, "", " a.test"):
            with self.subTest(realm=realm), self.assertRaises(ValueError):
                offline_subject(SimpleNamespace(uid="S-1-5-21-1-2-3-1001", realm=realm), resolver)

    def test_refuses_non_sid_resolver(self):
        with self.assertRaises(ValueError):
            offline_subject(SimpleNamespace(uid="S-1-5-21-1-2-3-1001", realm="a.test"),
                            SimpleNamespace(uidtype="objectGUID"))
