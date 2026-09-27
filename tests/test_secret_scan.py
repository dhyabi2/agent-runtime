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

    def test_a_placeholder_elsewhere_on_the_line_does_not_excuse_a_real_seed(self):
        """The allow list was searched against the WHOLE LINE, and three of its patterns describe the
        shape of a fake value rather than saying anything about intent: `<[a-z-]+>` matches any bare
        HTML tag, `xxx+` matches an `XXX` todo marker, `0{16,}` matches any raw XNO amount. So a real
        seed was published for sharing a line with `<code>`, `<br>`, `XXX`, or an amount in raw."""
        for label, line in (
            ("<code> wrapper", "<code>SEED=" + self.SEED.lower() + "</code>"),
            ("trailing <br>", "seed: " + self.SEED.lower() + "<br>"),
            ("XXX todo", "seed = " + self.SEED.lower() + "  # XXX rotate this later"),
            ("raw amount", "seed " + self.SEED.lower() + " tip 1000000000000000000000000 raw"),
        ):
            with self.subTest(case=label):
                hits = scan_text(line + "\n")
                self.assertEqual(len(hits), 1, f"a seed beside {label} was not refused")
                self.assertEqual(hits[0][2], "nano seed/private key")

    def test_a_redacted_value_is_still_not_a_finding(self):
        """The other half of the same law. A placeholder that IS the match stays exempt, otherwise
        every README that shows a key's shape refuses the next push."""
        for label, line in (
            ("redacted github token", "GITHUB_TOKEN=ghp_" + "x" * 24),
            ("all-zero test seed", "seed = " + "0" * 64),
        ):
            with self.subTest(case=label):
                self.assertEqual(scan_text(line + "\n"), [], f"{label} should not be a finding")

    def test_an_annotation_still_exempts_its_whole_line(self):
        """`# test-fixture: a PUBLIC key, never a seed` is how the swarm marks a deliberate value, and
        it is a statement about the line, not about the shape of what is on it. That stays line-wide."""
        self.assertEqual(
            scan_text("public_key = " + self.SEED.lower() + "  # test-fixture: a PUBLIC key\n"), [])

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


def repo_with(files):
    """A real git repository with ``files`` ({name: text}) added to the index.

    Real, because this defect is about how git DISPLAYS a path, not about anything a fixture list of
    strings can express: core.quotePath is what produces the unopenable path, and only git produces it.
    """
    d = tempfile.mkdtemp()
    run = lambda *a: subprocess.run(a, cwd=d, check=True, capture_output=True)
    run("git", "init", "-q", ".")
    run("git", "config", "user.email", "law@example.com")
    run("git", "config", "user.name", "law")
    for name, text in files.items():
        with open(os.path.join(d, name), "w", encoding="utf-8") as f:
            f.write(text)
    run("git", "add", "-A")
    return d


def gate(repo):
    """Run the gate exactly as the pre-push hook does: as a script, in the repository."""
    r = subprocess.run([sys.executable, os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "runtime", "secret_scan.py")],
        cwd=repo, capture_output=True, text=True)
    return r.returncode, r.stderr


# Built at runtime, never written out as a literal, so this file cannot itself trip the gate.
A_GITHUB_TOKEN = "TOKEN = \"" + "gh" + "p_" + ("AbCdEfGhIjKlMnOpQrStUvWx") + "\"\n"


class TheGateNeverFailsOpen(unittest.TestCase):
    """The defect: `git ls-files` without -z applies core.quotePath, so a path holding a non-ASCII
    byte came back as `"caf\303\251.py"` -- quoted, octal-escaped, and unopenable. scan() answered an
    unopenable path with a bare `continue`, so that file was never scanned and nothing said so: the
    gate exited 0 on a tracked file holding a token matching its own pattern."""

    def test_a_secret_in_a_non_ascii_filename_is_refused(self):
        rc, err = gate(repo_with({"café.py": A_GITHUB_TOKEN}))
        self.assertEqual(rc, 1, f"the gate allowed a push with a token in a non-ASCII filename:\n{err}")
        self.assertIn("caf", err)

    def test_the_same_secret_is_judged_the_same_whatever_the_filename(self):
        """Whatever the gate decides about a token, the filename must not change that decision."""
        verdicts = {}
        for label, name in (("ascii", "plain.py"), ("non-ascii", "café.py"),
                            ("with a space", "two words.py")):
            with self.subTest(filename=label):
                rc, _ = gate(repo_with({name: A_GITHUB_TOKEN}))
                verdicts[label] = rc
                self.assertEqual(rc, 1, f"a token in a {label} filename was not refused")
        self.assertEqual(len(set(verdicts.values())), 1, f"the gate disagreed with itself: {verdicts}")

    def test_tracked_returns_paths_that_open(self):
        """The root cause, pinned directly: every path tracked() names must be openable from the
        repository. A quoted or octal-escaped path is not."""
        repo = repo_with({"café.py": "ok\n", "two words.py": "ok\n", "plain.py": "ok\n"})
        cwd = os.getcwd()
        os.chdir(repo)
        try:
            paths = secret_scan.tracked()
        finally:
            os.chdir(cwd)
        self.assertEqual(len(paths), 3, f"tracked() named {len(paths)} of 3 files: {paths}")
        for p in paths:
            with self.subTest(path=p):
                self.assertFalse(p.startswith('"'), f"tracked() returned a quoted path: {p!r}")
                self.assertTrue(os.path.exists(os.path.join(repo, p)),
                                f"tracked() named a path that does not exist: {p!r}")

    def test_a_clean_repository_still_passes(self):
        """The fix must not turn the gate into one that refuses everything."""
        rc, err = gate(repo_with({"café.py": "print('hello')\n", "plain.py": "x = 1\n"}))
        self.assertEqual(rc, 0, f"the gate refused a clean repository:\n{err}")

    def test_an_unreadable_path_is_reported_and_refused_not_skipped(self):
        """scan() must hand back what it could not read, and the gate must refuse on it. A file the
        gate cannot open is not a file without secrets, and that was the whole of the defect."""
        unreadable = []
        hits = secret_scan.scan([os.path.join(tempfile.mkdtemp(), "does-not-exist.py")], unreadable)
        self.assertEqual(hits, [])
        self.assertEqual(len(unreadable), 1, "an unopenable path was skipped in silence")

    def test_scan_still_works_without_the_unreadable_argument(self):
        """Callers that pass only paths keep working: the argument is optional."""
        self.assertEqual(secret_scan.scan([os.path.join(tempfile.mkdtemp(), "nope.py")]), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
