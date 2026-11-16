# License: LGPL-3
"""Audit-chain compatibility tests.

These assert that the in-Odoo verifier stays byte-for-byte compatible with the
erp-agent-guard gateway. The golden vector below was produced by the gateway's
own hashing; if Odoo ever drifts from it, verification of real logs would
silently pass bad data, so this test is the guard on that contract.
"""

from odoo.tests import TransactionCase, tagged

from ..models.audit_chain import GENESIS, entry_hash, verify_lines

# Frozen 2-entry chain (fixed timestamps) and its expected head hash.
LINE1 = (
    '{"agent": "sales-ops", "count": 2, "event": "search_read", '
    '"hash": "f9badf505bb0534527fd704dca821da7e15c2f93a404fc8fdd6f8ea52ccae618", '
    '"model": "res.partner", '
    '"prev": "0000000000000000000000000000000000000000000000000000000000000000", '
    '"ts": 1000.0}'
)
LINE2 = (
    '{"agent": "sales-ops", "event": "commit", '
    '"hash": "17ecdb17d8c04c4edce8ba017a948c4f893af325192337c4d229797a9f25024b", '
    '"model": "res.partner", "op": "write", '
    '"prev": "f9badf505bb0534527fd704dca821da7e15c2f93a404fc8fdd6f8ea52ccae618", '
    '"ts": 1001.0, "written": [2]}'
)
HEAD = "17ecdb17d8c04c4edce8ba017a948c4f893af325192337c4d229797a9f25024b"


@tagged("post_install", "-at_install")
class TestAuditChain(TransactionCase):
    def test_golden_vector_intact(self):
        ok, n, msg, bad = verify_lines([LINE1, LINE2])
        self.assertTrue(ok)
        self.assertEqual(n, 2)
        self.assertIsNone(bad)
        self.assertIn("head=%s" % HEAD[:16], msg)

    def test_hash_matches_gateway(self):
        import json

        self.assertEqual(json.loads(LINE1)["hash"], entry_hash(json.loads(LINE1)))
        self.assertEqual(json.loads(LINE2)["hash"], entry_hash(json.loads(LINE2)))

    def test_edit_is_caught(self):
        import json

        obj = json.loads(LINE1)
        obj["count"] = 9999  # keep its (now stale) hash
        tampered = json.dumps(obj, sort_keys=True, ensure_ascii=False)
        ok, _, msg, bad = verify_lines([tampered, LINE2])
        self.assertFalse(ok)
        self.assertEqual(bad, 1)
        self.assertIn("content hash mismatch", msg)

    def test_reorder_is_caught(self):
        ok, _, msg, bad = verify_lines([LINE2, LINE1])
        self.assertFalse(ok)
        self.assertEqual(bad, 1)
        self.assertIn("chain broken", msg)

    def test_blank_lines_ignored(self):
        ok, n, _, bad = verify_lines(["", LINE1, "   ", LINE2, ""])
        self.assertTrue(ok)
        self.assertEqual(n, 2)
        self.assertIsNone(bad)

    def test_empty_is_genesis(self):
        ok, n, _, bad = verify_lines([])
        self.assertTrue(ok)
        self.assertEqual(n, 0)
        self.assertEqual(GENESIS, "0" * 64)
