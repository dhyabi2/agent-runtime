"""The agent must import both ways it is actually started.

systemd runs `python <install>/runtime/agent.py` - a script, with no parent package. The test suite
imports `from runtime import agent` - a package. A relative import satisfies the second and raises
ImportError on the first, before the agent's first turn, and the suite stays green while production
cannot start. That happened on 2026-09-19 and was caught by reading the unit file, not by a test.
"""
import os, subprocess, sys, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


class ItStartsBothWays(unittest.TestCase):
    def _env(self):
        e = dict(os.environ)
        e.update({"SWARM_AGENT_HOME": tempfile.mkdtemp(),
                  "SWARM_JOURNAL_DB": tempfile.mktemp(suffix=".db"),
                  "SWARM_RECEIPTS_DB": tempfile.mktemp(suffix=".db"),
                  "NANO_PULSE_LIB": os.path.join(ROOT, "lib")})
        return e

    def test_it_imports_as_a_script_the_way_systemd_runs_it(self):
        path = os.path.join(ROOT, "runtime", "agent.py")
        # systemd puts the script's own directory on sys.path; reproduce that, or this law tests a
        # condition production never has.
        rt = os.path.join(ROOT, "runtime")
        code = (f"import sys; sys.path.insert(0, {rt!r}); "
                f"import runpy; runpy.run_path({path!r}, run_name='not_main')")
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                           env=self._env(), timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr[-600:])

    def test_it_imports_as_a_package_the_way_the_tests_do(self):
        r = subprocess.run([sys.executable, "-c", "import agent; print(agent.NAME)"],
                           capture_output=True, text=True, cwd=os.path.join(ROOT, "runtime"), env=self._env(), timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr[-600:])

    def test_it_imports_on_a_fresh_clone_with_nothing_configured(self):
        """A clone is all a reader has. Every other law here hands the agent NANO_PULSE_LIB pointing at
        this checkout's own lib/, so none of them could see that the DEFAULT named an install path no
        clone contains - `import agent` raised ModuleNotFoundError: No module named 'journal' before a
        single line of configuration could be read."""
        e = dict(os.environ)
        for k in ("NANO_PULSE_LIB", "SWARM_AGENT_HOME", "SWARM_JOURNAL_DB", "SWARM_RECEIPTS_DB"):
            e.pop(k, None)
        e["SWARM_AGENT_HOME"] = tempfile.mkdtemp()
        r = subprocess.run([sys.executable, "-c", "import agent; print(agent.journal.__file__)"],
                           capture_output=True, text=True, cwd=os.path.join(ROOT, "runtime"),
                           env=e, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr[-600:])
        self.assertEqual(os.path.realpath(r.stdout.strip()),
                         os.path.realpath(os.path.join(ROOT, "lib", "journal.py")),
                         "an unconfigured agent must load the journal shipped beside it")

    def test_the_unit_file_and_the_test_agree_on_the_entry_point(self):
        """If the unit ever stops running it as a script, this law should be revisited, not silently wrong."""
        unit = os.path.join(ROOT, "systemd", "swarm-agent@.service")
        if not os.path.exists(unit):
            self.skipTest("unit file not in this checkout")
        with open(unit) as f:
            text = f.read()
        self.assertIn("agent.py", text)
        self.assertNotIn("-m swarm.agent", text,
                         "the unit now runs it as a module; the script law above must be revisited")


if __name__ == "__main__":
    unittest.main(verbosity=2)
