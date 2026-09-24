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


if __name__ == "__main__":
    unittest.main(verbosity=2)
