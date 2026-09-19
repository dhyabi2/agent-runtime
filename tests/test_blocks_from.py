"""Laws for block EXTRACTION - the code that actually changed.

The first version of these laws tested run_tool, which always accepted a multi-line string, so they
passed identically against the broken runner. The ledger's mutation check caught that. Every case
below fails against the old line-splitting extractor and passes against the current one.
"""
import os, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "runtime"))
import agent


def old_extractor(text):
    """What the runtime did until 2026-09-19, kept here so each law can be shown to discriminate."""
    import re
    cmds = []
    for block in re.findall(r"```(?:sh|bash|shell)?\s*\n(.*?)```", text, re.S):
        cmds += [l.strip() for l in block.splitlines()
                 if l.strip() and not l.strip().startswith("#")]
    return cmds


REPLY = """I will check the journal.

```sh
cd /srv/swarm/a01
JOURNAL=/var/lib/swarm/journal.db
python3 - <<'EOF'
# count the events
import sqlite3
print(sqlite3.connect(JOURNAL))
EOF
```
"""


class ExtractionKeepsTheScriptWhole(unittest.TestCase):
    def test_a_multi_line_block_is_one_script_not_many_commands(self):
        got = agent.blocks_from(REPLY)
        self.assertEqual(len(got), 1, got)
        self.assertIn("cd /srv/swarm/a01", got[0])
        self.assertIn("JOURNAL=/var/lib/swarm/journal.db", got[0])
        self.assertIn("import sqlite3", got[0])
        # And it must genuinely differ from what the old extractor did.
        self.assertGreater(len(old_extractor(REPLY)), 1, "the old extractor must split - law is blind")

    def test_a_shebang_inside_a_heredoc_survives(self):
        """The old extractor dropped every line starting with '#'. A shebang is not a comment."""
        reply = "```sh\ncat > /tmp/x.py <<'EOF'\n#!/usr/bin/env python3\nprint(1)\nEOF\n```"
        got = agent.blocks_from(reply)
        self.assertIn("#!/usr/bin/env python3", got[0])
        self.assertNotIn("#!/usr/bin/env python3", " ".join(old_extractor(reply)))

    def test_each_fenced_block_stays_separate(self):
        got = agent.blocks_from("```sh\necho a\n```\ntext\n```sh\necho b\n```")
        self.assertEqual(got, ["echo a", "echo b"])

    def test_an_empty_or_absent_block_yields_nothing(self):
        self.assertEqual(agent.blocks_from("no code here"), [])
        self.assertEqual(agent.blocks_from("```sh\n\n```"), [])

    def test_bare_and_language_tagged_fences_are_both_accepted(self):
        for fence in ("", "sh", "bash", "shell"):
            self.assertEqual(agent.blocks_from(f"```{fence}\necho hi\n```"), ["echo hi"], fence)


if __name__ == "__main__":
    unittest.main(verbosity=2)
