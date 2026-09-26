"""Laws for the pre-push secret gate.

This file is the thing standing between an unattended 3am push and a public repository, and until now
it had no laws at all. The first one below is the defect that prompted them: the seed pattern was
uppercase-only, so the same 32 bytes were refused in one case and published in the other.

Every fixture here is built by concatenation or generated at runtime, never written out as a literal,
so that this file cannot itself become the reason a push is refused.
"""
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "runtime"))
import secret_scan  # noqa: E402


def scan_text(text):
    path = tempfile.mktemp(suffix=".txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    try:
        return secret_scan.scan([path])
    finally:
        os.unlink(path)


class TheGateRefusesASeed(unittest.TestCase):
    # A seed is 32 bytes. This one is fixed so the law is deterministic, and it is built from a
    # repeated nibble pattern rather than written out, so no literal key-shaped string is committed.
    SEED = ("1a2b3c4d" * 8)

    def test_a_seed_is_refused_in_either_case(self):
        """secrets.token_hex(32) - the way Python makes a seed - returns LOWERCASE. The pattern was
        `[0-9A-F]{64}` with no re.IGNORECASE, so a lowercase seed was not a finding and was
        published, while the identical value uppercased was refused."""
        for case, text in (("lower", self.SEED.lower()), ("upper", self.SEED.upper())):
            with self.subTest(case=case):
                hits = scan_text("NANO_AGENT_SEED=" + text + "\n")
                self.assertEqual(len(hits), 1, f"a {case}case seed was not refused")
                self.assertEqual(hits[0][2], "nano seed/private key")

    def test_the_two_cases_of_one_seed_are_never_judged_differently(self):
        """Whatever the gate decides about a seed, it must decide the same thing about its own
        uppercase. A difference here is a publishable secret by definition."""
        lo = scan_text(self.SEED.lower())
        up = scan_text(self.SEED.upper())
        self.assertEqual(bool(lo), bool(up),
                         "the same 32 bytes were judged differently by case")

    def test_a_generated_seed_is_refused(self):
        """Not the fixture above, but one made the way the runtime would actually make one."""
        import secrets
        hits = scan_text("seed = " + secrets.token_hex(32) + "\n")
        self.assertEqual(len(hits), 1)

    def test_it_never_reports_the_value_it_matched(self):
        """A finding names the file, the line and the kind. Printing the match would copy the secret
        into a log and a CI transcript, which is where it would then live."""
        hits = scan_text("NANO_AGENT_SEED=" + self.SEED.lower() + "\n")
        for finding in hits:
            self.assertNotIn(self.SEED.lower(), str(finding))
            self.assertNotIn(self.SEED.upper(), str(finding))

    def test_an_ordinary_line_is_not_a_finding(self):
        """A gate that refuses everything is turned off within the week."""
        self.assertEqual(scan_text("the agent pushed to origin/main and the remote SHA matched\n"), [])

    def test_the_published_tree_passes_its_own_gate(self):
        """Whatever the patterns are, this repository must be publishable by them - otherwise the
        hook that runs before every push refuses every push."""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cwd = os.getcwd()
        os.chdir(root)
        try:
            tracked = secret_scan.tracked()
        finally:
            os.chdir(cwd)
        if not tracked:
            self.skipTest("not a git checkout")
        hits = secret_scan.scan([os.path.join(root, p) for p in tracked])
        self.assertEqual([(p, ln, k) for p, ln, k in hits], [])

class TheGateNeverReportsCleanWithoutScanning(unittest.TestCase):
    """Three ways the gate used to pass a push it had not actually checked.

    Every one of them ends the same way: `hits == []`, exit 0, and the push goes out. For a hook whose
    stated reason to exist is that nobody is watching at 3am, a silent skip is the worst failure it
    has, because it is indistinguishable from a clean tree.
    """

    SEED = ("1a2b3c4d" * 8)

    def _repo_with(self, filename):
        """A git checkout holding one tracked file, named `filename`, carrying a seed."""
        d = tempfile.mkdtemp()
        for cmd in (["git", "init", "-q", "."],
                    ["git", "config", "user.email", "a@b.c"],
                    ["git", "config", "user.name", "t"]):
            subprocess.run(cmd, cwd=d, check=True, capture_output=True)
        with open(os.path.join(d, filename), "w", encoding="utf-8") as f:
            f.write("SEED=" + self.SEED.lower() + "\n")
        subprocess.run(["git", "add", "-A"], cwd=d, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-qm", "x"], cwd=d, check=True, capture_output=True)
        return d

    def _scan_tracked_in(self, d):
        cwd = os.getcwd()
        os.chdir(d)
        try:
            paths = secret_scan.tracked()
        finally:
            os.chdir(cwd)
        return paths, secret_scan.scan([os.path.join(d, p) for p in paths])

    def test_a_path_git_quotes_is_still_scanned(self):
        """`git ls-files` applies core.quotePath, so any non-ASCII byte in a name comes back octal-
        escaped and in quotes. open() cannot find that, the old code swallowed the OSError, and a file
        holding a seed was reported clean. `-z` output is never quoted."""
        for filename in ("caf\u00e9.py", "\u0440\u0430\u0439.py", "notes \u2014 draft.py"):
            with self.subTest(filename=filename):
                d = self._repo_with(filename)
                paths, hits = self._scan_tracked_in(d)
                self.assertEqual(paths, [filename], f"tracked() mangled the path: {paths}")
                self.assertEqual([k for _, _, k in hits], ["nano seed/private key"], hits)

    def test_a_path_with_a_space_is_still_scanned(self):
        """Spaces never triggered quoting, so this already worked. Pinned so the -z change cannot
        regress the ordinary case while fixing the exotic one."""
        d = self._repo_with("my notes.py")
        paths, hits = self._scan_tracked_in(d)
        self.assertEqual(paths, ["my notes.py"])
        self.assertEqual([k for _, _, k in hits], ["nano seed/private key"], hits)

    def test_a_path_that_cannot_be_read_is_a_finding_not_a_skip(self):
        """A present-but-unreadable path was `continue`d, so the gate reported clean for content it
        had never seen. It is refused instead.

        A directory is used as the always-available case: opening one raises IsADirectoryError, an
        OSError that is not FileNotFoundError, for every user including root. The chmod-000 case is
        the one a deployment actually hits, and is skipped when the test user can read anything.
        """
        d = tempfile.mkdtemp()
        hits = secret_scan.scan([d])            # a directory: OSError for anyone
        self.assertEqual(len(hits), 1, hits)
        self.assertIn("unscanned", hits[0][2])

        unreadable = os.path.join(d, "locked.py")
        with open(unreadable, "w", encoding="utf-8") as f:
            f.write("SEED=" + self.SEED.lower() + "\n")
        os.chmod(unreadable, 0o000)
        try:
            if os.access(unreadable, os.R_OK):
                self.skipTest("the directory case passed; this user can read a chmod-000 file")
            hits = secret_scan.scan([unreadable])
            self.assertEqual(len(hits), 1, hits)
            self.assertIn("unscanned", hits[0][2])
            self.assertNotIn(self.SEED.lower(), str(hits))   # and never the file's contents
        finally:
            os.chmod(unreadable, 0o600)

    def test_a_missing_file_is_not_a_finding(self):
        """Tracked but deleted from the working tree carries nothing to publish, so refusing it would
        turn the gate off within the week."""
        self.assertEqual(secret_scan.scan([os.path.join(tempfile.mkdtemp(), "gone.py")]), [])

    def test_no_listing_is_refused_rather_than_read_as_clean(self):
        """`tracked()` ignored git's exit code and returned []. Outside a checkout, or with git
        failing for any reason, that read as 'nothing to scan' and let the push through."""
        d = tempfile.mkdtemp()          # not a git repository
        cwd = os.getcwd()
        os.chdir(d)
        try:
            with self.assertRaises(secret_scan.ScanFailed):
                secret_scan.tracked()
        finally:
            os.chdir(cwd)


if __name__ == "__main__":
    unittest.main(verbosity=2)
