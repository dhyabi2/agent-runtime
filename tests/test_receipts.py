"""Laws for the receipt chain: the agent's word is not evidence.

Each law is written to fail against the thing it replaces - a journal the agent writes freely.
"""
import json, os, subprocess, sys, tempfile, time, unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "runtime"))
import receipts as R


def db():
    return R.connect(tempfile.mktemp(suffix=".db"))


def a_repo():
    d = tempfile.mkdtemp()
    run = lambda *c: subprocess.run(c, cwd=d, capture_output=True, text=True)
    run("git", "init", "-q", "-b", "main")
    run("git", "config", "user.email", "t@t")
    run("git", "config", "user.name", "t")
    with open(os.path.join(d, "a.txt"), "w") as f:
        f.write("one\n")
    run("git", "add", "-A")
    run("git", "commit", "-qm", "first")
    return d


class TheChainCannotBeRewritten(unittest.TestCase):
    def test_a_fresh_chain_verifies(self):
        c = db()
        for i in range(3):
            seq, _ = R.begin(c, "a01", "commit", "repo", {"n": i})
            R.settle(c, seq, {"sha": "x" * 40}, True)
        self.assertIsNone(R.verify_chain(c))

    def test_editing_a_hashed_field_breaks_the_chain_from_that_point(self):
        """A record nobody can quietly improve after the fact — for the fields the hash covers."""
        c = db()
        for i in range(3):
            seq, _ = R.begin(c, "a01", "contact", f"https://example.com/{i}", {"n": i})
            R.settle(c, seq, {"status": 200}, True)
        c.execute("UPDATE receipts SET target='https://example.com/lie' WHERE seq=2")
        self.assertEqual(R.verify_chain(c), 2)

    def test_the_chain_covers_the_intent_and_not_the_settlement(self):
        """Where the tamper-evidence stops, pinned so the claim and the code cannot drift apart.

        `row_hash` is computed in `begin`, from the fields that exist before the act. `proof` and
        `ok` arrive afterwards from `settle`, so they are outside it: a failed act can be rewritten
        as a proved one and `verify_chain` sees nothing. The module docstring and the README say so
        in as many words; this law is why they cannot quietly stop saying it.

        Should the settlement ever be brought inside the hash, this law is the thing that fails and
        tells you to correct both documents — it describes a boundary, not a desirable property.
        """
        c = db()
        seq, _ = R.begin(c, "a01", "push", "them/repo", {"branch": "main"})
        R.settle(c, seq, {"in_sync": False, "remote_sha": ""}, False)
        self.assertIsNone(R.verify_chain(c))
        self.assertEqual(R.counts(c)["push"], {"proved": 0, "failed": 1, "unsettled": 0})

        c.execute("UPDATE receipts SET proof=?, ok=1 WHERE seq=?",
                  ('{"in_sync": true, "remote_sha": "' + "a" * 40 + '"}', seq))
        self.assertIsNone(R.verify_chain(c), "if this now reports a break, the hash covers the "
                                             "settlement: update the docstring and the README")
        self.assertEqual(R.counts(c)["push"], {"proved": 1, "failed": 0, "unsettled": 0},
                         "counts reports the edited value, which is the reason to say so plainly")

    def test_deleting_a_row_breaks_the_chain(self):
        c = db()
        for i in range(3):
            R.begin(c, "a01", "tip", f"nano_{i}", {"n": i})
        c.execute("DELETE FROM receipts WHERE seq=2")
        self.assertIsNotNone(R.verify_chain(c))

    def test_inserting_a_row_that_never_happened_breaks_the_chain(self):
        c = db()
        seq, _ = R.begin(c, "a01", "commit", "repo", {"n": 1})
        R.settle(c, seq, {"sha": "a" * 40}, True)
        c.execute("INSERT INTO receipts(ts,agent,kind,target,idem,intent,proof,ok,prev_hash,row_hash) "
                  "VALUES (?,?,?,?,?,?,?,?,?,?)",
                  (time.time(), "a01", "tip", "nano_invented", "made-up", "{}", "{}", 1, "z" * 64, "y" * 64))
        self.assertIsNotNone(R.verify_chain(c))


class AnIntentIsWrittenBeforeTheAct(unittest.TestCase):
    def test_the_same_act_twice_is_one_row_and_the_second_call_is_told_it_is_done(self):
        """This is the resume mechanism: a turn that died after acting must not act again."""
        c = db()
        seq1, done1 = R.begin(c, "a01", "tip", "nano_abc", {"raw": "1000000000000000000000000"})
        self.assertIsNone(done1, "a brand new act must not report itself finished")
        R.settle(c, seq1, {"block": "ABC123"}, True)
        seq2, done2 = R.begin(c, "a01", "tip", "nano_abc", {"raw": "1000000000000000000000000"})
        self.assertEqual(seq1, seq2)
        self.assertIsNotNone(done2, "the act already happened and must not happen again")
        self.assertEqual(done2["proof"]["block"], "ABC123")
        self.assertEqual(c.execute("SELECT COUNT(*) FROM receipts").fetchone()[0], 1)

    def test_a_crash_between_act_and_record_is_visible_not_silent(self):
        """An unsettled intent is the signature of a crash. It must be counted, not dropped."""
        c = db()
        R.begin(c, "a01", "push", "repo", {"branch": "main"})
        self.assertEqual(R.counts(c)["push"], {"proved": 0, "failed": 0, "unsettled": 1})

    def test_counts_separate_proved_from_failed_from_unsettled(self):
        c = db()
        s1, _ = R.begin(c, "a01", "contact", "https://a.example", {})
        R.settle(c, s1, {"status": 200}, True)
        s2, _ = R.begin(c, "a01", "contact", "https://b.example", {})
        R.settle(c, s2, {"status": 500}, False)
        R.begin(c, "a01", "contact", "https://c.example", {})
        self.assertEqual(R.counts(c)["contact"], {"proved": 1, "failed": 1, "unsettled": 1})


class TheProofComesFromTheWorld(unittest.TestCase):
    def test_a_commit_proof_is_read_from_git_not_from_the_agent(self):
        d = a_repo()
        p = R.commit_proof(d)
        self.assertTrue(p["exists"])
        self.assertEqual(len(p["sha"]), 40)
        self.assertEqual(p["subject"], "first")
        self.assertIn("a.txt", p["files"])

    def test_a_commit_proof_names_the_files_the_commit_actually_holds(self):
        """A proof log that names a file the commit does not contain is not a proof.

        `git show --name-only` is not a list of paths: under core.quotePath a path holding a
        non-ASCII byte comes back quoted and octal-escaped, and splitting the output on whitespace
        turns a path holding a space into two. Both shapes were recorded as fact.
        """
        d = a_repo()
        run = lambda *c: subprocess.run(c, cwd=d, capture_output=True, text=True)
        written = ["src/my notes.py", "caf\u00e9.py", "plain.py"]
        os.mkdir(os.path.join(d, "src"))
        for name in written:
            with open(os.path.join(d, name), "w") as f:
                f.write("x\n")
        run("git", "add", "-A")
        run("git", "commit", "-qm", "paths a list cannot survive")
        files = R.commit_proof(d)["files"]
        # every recorded path is a path that is really in the commit, and none is lost.
        # a.txt is not expected: it belongs to the first commit, and this proof is of HEAD.
        self.assertEqual(sorted(files), sorted(written))
        for name in files:
            self.assertTrue(os.path.exists(os.path.join(d, name)),
                            f"the proof names {name!r}, which is not in the tree")

    def test_an_unpushed_branch_is_not_in_sync_however_it_is_described(self):
        """`git push` exiting 0 is not proof; the remote's SHA is."""
        d = a_repo()
        remote = tempfile.mkdtemp()
        subprocess.run(["git", "init", "-q", "--bare", remote], capture_output=True)
        subprocess.run(["git", "remote", "add", "origin", remote], cwd=d, capture_output=True)
        self.assertFalse(R.push_proof(d)["in_sync"], "nothing has been pushed yet")
        subprocess.run(["git", "push", "-q", "origin", "main"], cwd=d, capture_output=True)
        p = R.push_proof(d)
        self.assertTrue(p["in_sync"])
        self.assertEqual(p["remote_sha"], p["local_sha"])

    def test_a_contact_proof_hashes_what_the_other_end_actually_said(self):
        p = R.contact_proof("https://example.com", 200, b"hello")
        self.assertEqual(p["status"], 200)
        self.assertEqual(p["bytes"], 5)
        self.assertNotEqual(p["body_sha256"], R.contact_proof("https://example.com", 200, b"hellp")["body_sha256"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
