"""Laws for the pre-push secret gate.

This file is the thing standing between an unattended 3am push and a public repository, and until now
it had no laws at all. The first one below is the defect that prompted them: the seed pattern was
uppercase-only, so the same 32 bytes were refused in one case and published in the other.

Every fixture here is built by concatenation or generated at runtime, never written out as a literal,
so that this file cannot itself become the reason a push is refused.
"""
import os
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
