"""Laws for the README's install path.

The README is the only instruction a reader has, and its first two commands were both wrong: it
cloned from an account that answers 403, and it claimed the runtime is stdlib only while hub.py
imports `websockets`. Neither is the kind of mistake a reader can debug - the first fails before
there is a checkout to look at, and the second fails much later, at the one command that starts the
live feed.

Both laws below are derived from the tree rather than restated from it, so they go on being true
after the next dependency or the next rename.
"""
import ast
import inspect
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def readme():
    with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as f:
        return f.read()


def third_party_imports():
    """Every module this repository imports that Python does not ship."""
    found = set()
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in (".git", "tests", "audits")]
        for name in filenames:
            if not name.endswith(".py"):
                continue
            path = os.path.join(dirpath, name)
            with open(path, encoding="utf-8") as f:
                try:
                    tree = ast.parse(f.read(), path)
                except SyntaxError:  # pragma: no cover - a parse failure is a different law's job
                    continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    found.update(a.name.split(".")[0] for a in node.names)
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    found.add(node.module.split(".")[0])
    # Modules that live in this checkout are not dependencies.
    local = {"guard", "journal", "receipts", "agent", "modeld", "secret_scan", "hub", "runtime", "lib"}
    return {m for m in found if m not in local and m not in sys.stdlib_module_names}


class TheReadmeCanBeFollowed(unittest.TestCase):
    def test_the_clone_url_names_the_repository_this_is(self):
        """`git clone https://github.com/PANDeveloper001/agent-runtime` answers 403. A reader who
        copies the first line of the install section never gets a checkout at all."""
        urls = re.findall(r"https://github\.com/([\w.-]+/[\w.-]+?)(?:\.git)?(?=[\s/)\"']|$)", readme())
        clones = [u for u in urls if u.endswith("/agent-runtime")]
        self.assertTrue(clones, "the README no longer tells a reader where to clone from")
        for u in clones:
            self.assertEqual(u, "dhyabi2/agent-runtime",
                             f"the README sends readers to {u}, which is not this repository")

    def test_every_dependency_the_code_has_is_one_the_readme_installs(self):
        """The install block said `pip install ''  # stdlib only`, and hub.py opens with
        `from websockets.asyncio.server import serve`. Following the README gave a reader a venv that
        cannot run the live feed, and a ModuleNotFoundError at the command that starts it."""
        text = readme()
        missing = sorted(m for m in third_party_imports() if m not in text)
        self.assertEqual(missing, [],
                         f"the code imports {missing}, which the README never tells anyone to install")

    def test_every_unit_the_readme_starts_is_one_the_repository_ships(self):
        """The install path ended on `systemctl enable --now agent-modeld.service agent@a01.timer`,
        and `cp systemd/*` installs `swarm-modeld.service`, `swarm-agent@.service` and
        `swarm-agent@.timer`. Neither name existed, so the last command a reader runs answered
        `Unit agent-modeld.service not found.`"""
        shipped = set(os.listdir(os.path.join(ROOT, "systemd")))
        named = re.findall(r"\b([\w.@-]+\.(?:service|timer))\b", readme())
        self.assertTrue(named, "the README no longer tells a reader which units to start")
        for unit in named:
            # a template instance (foo@a01.timer) is shipped as its template (foo@.timer)
            template = re.sub(r"@[^.]*\.", "@.", unit)
            self.assertTrue(unit in shipped or template in shipped,
                            f"the README starts {unit}, which `cp systemd/*` never installs")

    def test_the_readme_installs_under_the_roots_the_units_run_from(self):
        """The units are production's, verbatim, so their absolute paths are the install's contract:
        ExecStart runs /opt/swarm/venv/bin/python on /opt/swarm/swarm/agent.py, WorkingDirectory is
        /srv/swarm/%i, NANO_PULSE_LIB is /opt/swarm/lib. The README cloned to /opt/agent and made
        /srv/agents/a01 instead, so every path the units need was missing after following it.

        The roots are compared rather than the full paths: the install has to put the checkout and
        the agent's home where the units look, and is free not to spell out each file beneath them."""
        roots = set()
        unitdir = os.path.join(ROOT, "systemd")
        for name in sorted(os.listdir(unitdir)):
            with open(os.path.join(unitdir, name), encoding="utf-8") as f:
                for line in f:
                    if line.startswith(("ExecStart=", "WorkingDirectory=", "Environment=NANO_PULSE_LIB=")):
                        roots.update("/".join(p.split("/")[:3])
                                     for p in re.findall(r"/(?:opt|srv)/[\w./@%-]+", line))
        self.assertTrue(roots, "the units no longer name any absolute path")
        text = readme()
        missing = sorted(r for r in roots if r not in text)
        self.assertEqual(missing, [],
                         f"the units run from {missing}, which the README's install never creates")

    def test_both_documents_name_the_columns_the_chain_does_not_cover(self):
        """`receipts.py` is the part the README tells a reader to steal, and its claim was wider than
        the code: "the chain cannot be edited afterwards without breaking from that row on". `row_hash`
        is computed in `begin`, from `_hash`'s arguments; `settle` writes `proof` and `ok` afterwards,
        so those two are outside it. A failed push can be rewritten as a proved one and `verify_chain`
        returns None — demonstrated in `test_the_chain_covers_the_intent_and_not_the_settlement`.

        Derived, not restated: the columns come from `settle`'s own SQL and the covered set from
        `_hash`'s signature, so bringing the settlement inside the hash, or settling a different
        column, changes what this law demands of the prose rather than leaving it stale."""
        from runtime import receipts

        covered = set(inspect.signature(receipts._hash).parameters)
        sql = re.search(r"UPDATE\s+receipts\s+SET\s+(.*?)\s+WHERE",
                        inspect.getsource(receipts.settle), re.S | re.I)
        self.assertIsNotNone(sql, "settle no longer updates receipts; this law needs rewriting")
        settled = {c.split("=")[0].strip() for c in sql.group(1).split(",")}
        self.assertTrue(settled, "settle writes no column")

        uncovered = sorted(settled - covered)
        self.assertEqual(uncovered, sorted(settled),
                         "settle now writes a hashed column — say so in both documents and fix this law")

        for where, text in (("README.md", readme()),
                            ("receipts.py's docstring", receipts.__doc__ or "")):
            unnamed = [c for c in uncovered if f"`{c}`" not in text]
            self.assertEqual(unnamed, [],
                             f"{where} promises the chain covers the record but never names {unnamed} "
                             f"as outside it, which is where a reader would be misled")


if __name__ == "__main__":
    unittest.main(verbosity=2)
