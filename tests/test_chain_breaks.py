"""Laws for counting and for acknowledged breaks.

Both come from real data: counts() reported "proved 1, failed 1" for 2 proved and 17 failed because
it counted GROUPS, and the chain carries a permanent break that must not blind it to the next one.
"""
import os, sys, tempfile, unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "runtime"))
try:
    import receipts as R
except ImportError:
    from swarm import receipts as R


def db():
    return R.connect(tempfile.mktemp(suffix=".db"))


class CountsAreRows(unittest.TestCase):
    def test_counts_are_rows_not_groups(self):
        """The defect: 17 failed and 2 proved were reported as failed 1, proved 1 - two groups."""
        c = db()
        for i in range(17):
            seq, _ = R.begin(c, "a", "contact", f"https://x.example/{i}", {})
            R.settle(c, seq, {"status": 500}, False)
        for i in range(2):
            seq, _ = R.begin(c, "a", "contact", f"https://ok.example/{i}", {})
            R.settle(c, seq, {"status": 200}, True)
        R.begin(c, "a", "contact", "https://pending.example", {})
        self.assertEqual(R.counts(c)["contact"], {"proved": 2, "failed": 17, "unsettled": 1})


class AnAcknowledgedBreakDoesNotBlindTheChain(unittest.TestCase):
    def _break_at(self, c, seq):
        c.execute("DELETE FROM receipts WHERE seq=?", (seq,))

    def test_an_unacknowledged_break_is_still_reported(self):
        c = db()
        for i in range(5):
            R.begin(c, "a", "commit", f"r{i}", {"n": i})
        self._break_at(c, 3)
        self.assertIsNotNone(R.verify_chain(c))

    def test_acknowledging_a_break_silences_only_that_one(self):
        c = db()
        for i in range(6):
            R.begin(c, "a", "commit", f"r{i}", {"n": i})
        self._break_at(c, 3)
        first = R.verify_chain(c)
        R.note_break(c, first, "known: deleted by a dry-run bug")
        self.assertIsNone(R.verify_chain(c), "the acknowledged break should be quiet")

        # A NEW break, after the acknowledged one, must still be caught. This is the whole point.
        c.execute("UPDATE receipts SET target='tampered' WHERE seq=5")
        self.assertEqual(R.verify_chain(c), 5)

    def test_a_break_carries_its_reason(self):
        c = db()
        R.begin(c, "a", "commit", "r", {})
        R.note_break(c, 99, "because X")
        self.assertEqual([b["seq"] for b in R.breaks(c)], [99])
        self.assertIn("because X", R.breaks(c)[0]["reason"])

    def test_nothing_is_acknowledged_by_default(self):
        """A fresh ledger must not start life forgiving anything."""
        c = db()
        self.assertEqual(R.breaks(c), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
