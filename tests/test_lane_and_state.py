"""Laws for the parts of the turn that decide WHAT the agent does and WHAT it knows.

The owner set 50% self-improvement / 50% outward work. A split measured from the wrong rows is not
that split, and nothing would ever have said so.
"""
import os, sqlite3, sys, tempfile, time, unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lib"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "runtime"))
import agent


def journal_with(events):
    """A real journal file holding exactly these (lane, status) run events, all recent."""
    path = tempfile.mktemp(suffix=".db")
    db = sqlite3.connect(path, isolation_level=None)
    db.execute("CREATE TABLE events(seq INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, kind TEXT, data TEXT)")
    now = time.time()
    for lane, status in events:
        db.execute("INSERT INTO events(ts, kind, data) VALUES (?,?,?)",
                   (now - 60, "run", '{"lane": "%s", "status": "%s"}' % (lane, status)))
    db.close()
    return path


class TheSplitIsMeasured(unittest.TestCase):
    def test_a_deferred_turn_is_not_work_done(self):
        """The defect: an outage during self turns counted as self work and pushed the agent to work.

        Six deferred self turns are six turns that did nothing, so the record is empty and the agent
        goes outward - the same answer as a fresh agent. Under the old rule they counted as 100% self
        work, which pinned the agent in the work lane for a day after any outage. The discriminating
        part is the mixture below: one real work turn beside six deferred self turns must send the
        agent to SELF, because the only thing that actually happened was outward work.
        """
        self.assertEqual(agent.pick_lane(journal_with([("self", "deferred")] * 6)), "work")
        mixed = journal_with([("self", "deferred")] * 6 + [("work", "ok")])
        self.assertEqual(agent.pick_lane(mixed), "self",
                         "six failed self turns were counted as self work")

    def test_a_start_event_alone_does_not_count(self):
        """Every turn emits start, so counting it doubles everything and counts turns that never ended.

        Four starts with no endings read as nothing having finished - identical to an empty journal.
        The discriminating case is a start in one lane beside a finished turn in the other.
        """
        self.assertEqual(agent.pick_lane(journal_with([("self", "start")] * 4)), "work")
        self.assertEqual(agent.pick_lane(journal_with([("self", "start")] * 4 + [("work", "ok")])), "self")

    def test_finished_turns_hold_the_split_at_fifty_fifty(self):
        self.assertEqual(agent.pick_lane(journal_with([("self", "ok")] * 3 + [("work", "ok")])), "work")
        self.assertEqual(agent.pick_lane(journal_with([("work", "ok")] * 3 + [("self", "ok")])), "self")
        self.assertEqual(agent.pick_lane(journal_with([("self", "ok"), ("work", "ok")])), "work",
                         "at exactly 50% the agent does outward work, not more self-improvement")

    def test_an_empty_or_missing_journal_sends_the_agent_outward(self):
        """The first turn of a new agent must do the mission, not navel-gaze."""
        self.assertEqual(agent.pick_lane(journal_with([])), "work")
        self.assertEqual(agent.pick_lane("/nonexistent/journal.db"), "work")

    def test_the_share_is_configurable_and_defaults_to_half(self):
        self.assertEqual(agent.SELF_SHARE, 0.5)


class StateComesFromDisk(unittest.TestCase):
    def test_the_first_turn_says_so_rather_than_sending_nothing(self):
        old = agent.HOME
        try:
            agent.HOME = __import__("pathlib").Path(tempfile.mkdtemp())
            self.assertIn("first turn", agent.read_state())
        finally:
            agent.HOME = old

    def test_memory_is_bounded_so_a_months_old_agent_still_fits_in_a_turn(self):
        """Continuity on disk is only cheap if reading it is bounded."""
        import pathlib
        old = agent.HOME
        try:
            agent.HOME = pathlib.Path(tempfile.mkdtemp())
            (agent.HOME / "MEMORY.md").write_text("x" * 50000)
            got = agent.read_state()
            self.assertLess(len(got), 9000, "unbounded memory would grow every turn's cost for ever")
            self.assertIn("MEMORY.md", got)
        finally:
            agent.HOME = old


class ModeldFailureIsRetryable(unittest.TestCase):
    def test_an_unreachable_modeld_defers_the_turn_instead_of_crashing_the_agent(self):
        old = agent.SOCK
        try:
            agent.SOCK = "/nonexistent/modeld.sock"
            r = agent.ask([{"role": "user", "content": "hi"}])
            self.assertFalse(r["ok"])
            self.assertTrue(r.get("retryable"), r)
        finally:
            agent.SOCK = old


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TheMissionFileIsConfigurationNotAFormatString(unittest.TestCase):
    """The mission is the one thing a new project is meant to change (README: `AGENT_MISSION_FILE`).

    `str.format` reads every brace in that file as a field of its own, so an ordinary mission —
    a JSON example, a shell variable, a jq filter — raised inside `turn()` after the run/start
    event was journalled and before any model call. Every turn died, and the only trace was a
    turn that started and never ended.
    """

    FILLED = dict(name="a01", lane="work", home="/srv/swarm/a01", state="(no memory yet)")

    def test_a_brace_the_operator_did_not_mean_as_a_field_is_left_alone(self):
        for label, body in [
            ("a JSON example", 'Record it as {"url": "https://x", "pays_in": "USDC"}.'),
            ("a shell variable", "Your workspace is ${HOME}."),
            ("a jq filter", "Run: jq '{sha: .sha}' out.json"),
            ("an empty brace", "Fill in {} yourself."),
        ]:
            with self.subTest(label):
                out = agent.render_mission("You are {name}. " + body + "\n{state}", **self.FILLED)
                self.assertIn(body, out, f"{label} was altered or dropped")
                self.assertTrue(out.startswith("You are a01. "), "the real field was not filled")
                self.assertTrue(out.endswith("(no memory yet)"), "the real field was not filled")

    def test_a_value_is_never_substituted_into_a_second_time(self):
        """One pass. A field's value carrying another field's name must survive as text."""
        out = agent.render_mission("{name} then {state}", **dict(self.FILLED, name="{state}"))
        self.assertEqual(out, "{state} then (no memory yet)")

    def test_every_documented_field_is_filled_and_none_is_left_behind(self):
        template = "\n".join("{" + k + "}" for k in agent.MISSION_FIELDS)
        out = agent.render_mission(template, **self.FILLED)
        self.assertEqual(out.splitlines(), [self.FILLED[k] for k in agent.MISSION_FIELDS])
        for k in agent.MISSION_FIELDS:
            self.assertNotIn("{" + k + "}", out)

    def test_the_shipped_default_mission_still_renders(self):
        out = agent.render_mission(agent.DEFAULT_MISSION, **self.FILLED)
        self.assertIn("a01", out)
        self.assertIn("(no memory yet)", out)
        for k in agent.MISSION_FIELDS:
            self.assertNotIn("{" + k + "}", out)

    def test_a_mission_file_that_is_not_utf8_does_not_take_the_turn_down(self):
        """UnicodeDecodeError is a ValueError, so it escaped the OSError guard in mission_template."""
        path = tempfile.mktemp(suffix=".md")
        with open(path, "wb") as f:
            f.write(b"You are {name}. Pay the caf\xe9 bot.\n{state}\n")
        old = agent.MISSION_FILE
        agent.MISSION_FILE = path
        try:
            out = agent.render_mission(agent.mission_template(), **self.FILLED)
        finally:
            agent.MISSION_FILE = old
        self.assertIn("You are a01.", out)
        self.assertIn("(no memory yet)", out)
