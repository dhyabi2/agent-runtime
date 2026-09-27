"""Laws for record_commits: the agent's own commit subjects must not be able to end its turn.

The defect: `git log --format=%H%x1f%ct%x1f%s` output was cut up with `str.splitlines()`, which
breaks on \v, \f, \x1c-\x1e, \x85, U+2028 and U+2029 as well as on \n. git ends a record with \n and
nothing else, so a subject carrying one of those characters became two lines, and the tail carried no
\x1f -- `sha, cts, subject = line.split("\x1f", 2)` then raised ValueError.

Why it mattered more than a parse error: turn() calls record_commits() unguarded, AFTER it has
emitted run/ok. The raise therefore escaped turn(), so a turn whose work had SUCCEEDED exited
non-zero -- which the run loop reads as a failed run -- while that batch of commit facts, the push
receipt and the push fact were all silently dropped.

These laws run against a real git repository, because the bug lives in how git's bytes are cut up:
a hand-written fixture string could be made to pass with the broken code.
"""
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "lib"))
sys.path.insert(0, os.path.join(ROOT, "runtime"))
import agent  # noqa: E402
import journal  # noqa: E402

GIT_FORMAT = "%H%x1f%ct%x1f%s"

# Characters git does NOT treat as a record separator but str.splitlines() does. Each is built by
# chr() rather than written into the source, so this file stays readable in any editor.
LINE_BREAKERS = {
    "vertical tab": chr(0x0B),
    "form feed": chr(0x0C),
    "next line": chr(0x85),
    "line separator": chr(0x2028),
    "paragraph separator": chr(0x2029),
}


def repo_with_subject(subject):
    """A real one-commit git repository whose commit subject is exactly ``subject``."""
    d = tempfile.mkdtemp()
    run = lambda *a: subprocess.run(a, cwd=d, check=True, capture_output=True)
    run("git", "init", "-q", ".")
    run("git", "config", "user.email", "law@example.com")
    run("git", "config", "user.name", "law")
    with open(os.path.join(d, "f"), "w") as f:
        f.write("x\n")
    run("git", "add", "f")
    run("git", "commit", "-q", "-m", subject)
    return d


def git_log(repo):
    return subprocess.run(["git", "-C", repo, "log", "--since=1.hour", "--no-merges",
                           "--format=" + GIT_FORMAT],
                          capture_output=True, text=True, timeout=20).stdout


def record_into(repo):
    """Run the SHIPPED record_commits() against ``repo``, into a throwaway journal.

    The module's constants are redirected, not the environment: agent.py binds HOME and JOURNAL_DB at
    import time, so setting the env vars inside a test is too late once anything has imported it.
    Returns the commit rows the function actually journalled.
    """
    db_path = tempfile.mktemp(suffix=".db")
    db = sqlite3.connect(db_path, isolation_level=None)
    db.execute("CREATE TABLE events(seq INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, kind TEXT, data TEXT)")
    db.close()
    old_home, old_db, old_receipts = agent.HOME, agent.JOURNAL_DB, os.environ.get("SWARM_RECEIPTS_DB")
    agent.HOME, agent.JOURNAL_DB = repo, db_path
    # The push half asks a remote this repository does not have; it is already wrapped so that a
    # receipt it cannot write does not take the turn down. Point it at a throwaway file regardless,
    # so a law can never touch a real receipts database.
    os.environ["SWARM_RECEIPTS_DB"] = tempfile.mktemp(suffix=".db")
    try:
        agent.record_commits()
    finally:
        agent.HOME, agent.JOURNAL_DB = old_home, old_db
        if old_receipts is None:
            os.environ.pop("SWARM_RECEIPTS_DB", None)
        else:
            os.environ["SWARM_RECEIPTS_DB"] = old_receipts
    db = sqlite3.connect(db_path)
    rows = [json.loads(r[0]) for r in
            db.execute("SELECT data FROM events WHERE kind='commit' ORDER BY seq").fetchall()]
    db.close()
    return rows


class OneCommitIsOneRecord(unittest.TestCase):
    def test_a_subject_python_would_split_still_parses(self):
        """The law that fails against splitlines(): record_commits() must journal exactly one row
        per commit, with the subject whole, for every character git does not end a record with.
        Against the old code this raises ValueError out of record_commits() instead."""
        for name, ch in LINE_BREAKERS.items():
            with self.subTest(character=name):
                subject = "fix: handle" + ch + "a stubborn case"
                rows = record_into(repo_with_subject(subject))
                self.assertEqual(len(rows), 1,
                                 f"a subject holding a {name} produced {len(rows)} records, not 1")
                self.assertIn("a stubborn case", rows[0]["subject"],
                              f"the tail of the subject was lost past the {name}")

    def test_splitlines_is_what_broke_and_split_is_what_fixes_it(self):
        """Pins the difference itself, so nobody reintroduces splitlines() believing it equivalent.
        Against the same real git output, splitlines() over-counts and the unpack raises."""
        out = git_log(repo_with_subject("fix: handle" + chr(0x0B) + "a stubborn case"))
        self.assertEqual(len([l for l in out.split("\n") if l.strip()]), 1)
        self.assertEqual(len([l for l in out.splitlines() if l.strip()]), 2)
        with self.assertRaises(ValueError):
            for line in out.splitlines():
                if not line.strip():
                    continue
                _sha, _cts, _subject = line.split("\x1f", 2)

    def test_the_ordinary_subject_is_unaffected(self):
        """The fix must not change the common case: a plain subject still yields one intact row."""
        rows = record_into(repo_with_subject("docs: an ordinary subject"))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["subject"], "docs: an ordinary subject")
        self.assertEqual(len(rows[0]["sha"]), 12)


class TheSourceDoesNotUseSplitlinesHere(unittest.TestCase):
    def test_record_commits_cuts_git_output_on_newline_only(self):
        """The laws above test the loop; this one pins that the shipped function is that loop.
        record_commits() imports journal and a real journal path, so it is read rather than run."""
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "runtime", "agent.py")
        with open(path, encoding="utf-8") as f:
            src = f.read()
        body = src.split("def record_commits(", 1)[1].split("\n    # Did any of it leave the box?", 1)[0]
        self.assertIn('out.split("\\n")', body,
                      "record_commits must cut git's records on newline")
        self.assertNotIn("out.splitlines()", body,
                         "record_commits must not use splitlines() on git output")


if __name__ == "__main__":
    unittest.main()
