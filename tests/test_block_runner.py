"""Laws for the block runner: a shell block is a script.

Each case is one of the failures the journal actually recorded under the line-per-process runner.
"""
import os, subprocess, sys, tempfile, unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "runtime"))
import agent

_LIVE = agent.JOURNAL_DB
_LIVE_HOME = agent.HOME


def setUpModule():
    """Point the module's constant, not the env var: agent binds JOURNAL_DB at import time, so an
    env change here arrives too late whenever something imported agent first. These tests run real
    commands through run_tool, which emits - without this they write fixtures into the live journal
    and into the numbers used to judge the agent.

    HOME needs the same treatment and did not get it: run_tool passes `cwd=str(HOME)`, whose default
    /srv/swarm/<name> exists only on a provisioned box, so every case here raised FileNotFoundError on
    a clone. It went unseen because the module could not be imported at all."""
    import pathlib, tempfile
    agent.JOURNAL_DB = tempfile.mktemp(suffix=".db")
    agent.HOME = pathlib.Path(tempfile.mkdtemp())
    assert agent.JOURNAL_DB != _LIVE


def tearDownModule():
    agent.JOURNAL_DB = _LIVE
    agent.HOME = _LIVE_HOME


class ABlockIsAScript(unittest.TestCase):
    def run_block(self, script):
        return agent.run_tool(script, timeout=30)

    def test_cd_persists_within_a_block(self):
        """103 of 368 calls were `cd`. Under the old runner every one of them was a no-op."""
        r = self.run_block("cd /tmp\npwd")
        self.assertTrue(r["ok"], r)
        self.assertIn("/tmp", r["output"])

    def test_a_variable_set_on_one_line_is_visible_on_the_next(self):
        """`JOURNAL_FILE=...` used to run as a command named JOURNAL_FILE and exit 2."""
        r = self.run_block("JOURNAL_FILE=/var/lib/swarm/journal.db\necho \"[$JOURNAL_FILE]\"")
        self.assertTrue(r["ok"], r)
        self.assertIn("[/var/lib/swarm/journal.db]", r["output"])

    def test_a_heredoc_survives(self):
        """`import sqlite3` used to be handed to bash on its own and exit 127, 24 times."""
        r = self.run_block("python3 - <<'EOF'\nimport sqlite3\nprint('heredoc', sqlite3.sqlite_version_info[0])\nEOF")
        self.assertTrue(r["ok"], r)
        self.assertIn("heredoc", r["output"])

    def test_a_loop_survives(self):
        r = self.run_block("for i in 1 2 3; do echo \"n$i\"; done")
        self.assertTrue(r["ok"], r)
        for n in ("n1", "n2", "n3"):
            self.assertIn(n, r["output"])

    def test_the_guard_still_sees_every_line_of_the_block(self):
        """A block must not become a way to smuggle a refused line past the guard."""
        r = self.run_block("echo fine\ncat /root/.swarm/wallet.json\necho also fine")
        self.assertFalse(r["ok"], r)
        self.assertIn("refused", r, r)

    def test_a_refused_block_runs_nothing_at_all(self):
        """Not even the safe lines before the bad one: the old runner executed them first."""
        probe = os.path.join(tempfile.gettempdir(), "swarm_block_law_probe")
        if os.path.exists(probe):
            os.remove(probe)
        r = self.run_block(f"touch {probe}\ncat /etc/swarm/env")
        self.assertFalse(r["ok"], r)
        self.assertFalse(os.path.exists(probe), "a refused block still wrote to disk")

    def test_the_bound_on_blocks_is_announced_not_silent(self):
        self.assertTrue(hasattr(agent, "MAX_BLOCKS"))
        self.assertGreaterEqual(agent.MAX_BLOCKS, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TheTestsCannotReachTheLiveJournal(unittest.TestCase):
    def test_emitting_during_a_test_does_not_touch_the_live_database(self):
        """Proven, not asserted by convention: run a command and check the live file did not grow."""
        import os as _os
        live = _LIVE
        before = _os.path.getsize(live) if _os.path.exists(live) else None
        agent.run_tool("echo isolation-probe", timeout=20)
        after = _os.path.getsize(live) if _os.path.exists(live) else None
        self.assertEqual(before, after, "a test wrote to the live journal")
