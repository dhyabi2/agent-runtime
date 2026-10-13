"""A law for the browser demo's run loop: clicking Run while a Step is animating must not hang.

`assets/js/app.js` is the repository's site entry page (README, "Browser demo"), so a reader's first
contact with this runtime is that page. `runAll` guarded re-entry with `autoRunning` alone, and
`runOneStep` returns immediately while `running` is set -- so with a step in flight the loop called
it, awaited an already-resolved promise, and went round again. The event loop drains every microtask
before it runs a timer, so the step's own 820ms `setTimeout` never fired, `pointer` never advanced,
and the loop spun forever: the tab froze, permanently, on Step-then-Run.

The law RUNS THE SHIPPED FUNCTIONS rather than asserting on their text -- the two are lifted out of
`app.js` verbatim and given stubs for the DOM they touch -- so it goes on being true after the next
edit, and a static guard put back the wrong way cannot satisfy it.
"""
import os
import re
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_JS = os.path.join(ROOT, "assets", "js", "app.js")

# The demo runs in a browser; node is only how this law exercises it. Where node is absent the law
# skips rather than passes, because a law that cannot run has proved nothing.
NODE = shutil.which("node")


def source_of(name):
    """One top-level `async function <name>` from app.js, verbatim, braces and all."""
    with open(APP_JS, encoding="utf-8") as f:
        src = f.read()
    m = re.search(r"^async function %s\(\) \{.*?^\}" % re.escape(name), src, re.S | re.M)
    if not m:
        raise AssertionError(f"app.js no longer defines a top-level `async function {name}()`")
    return m.group(0)


# Stubs for everything the two functions touch, and nothing else. A stub that did any real work
# would be testing the stub.
HARNESS = """
const SCENARIOS = [1, 2, 3, 4, 5, 6];   // app.js ships six; only the count matters here
const CARD_TRAVEL_PADDING = 20;
let pointer = 0, running = false, autoRunning = false, runToken = 0;
const card = { clientWidth: 10, style: { setProperty() {} },
               classList: { add() {}, remove() {} }, dataset: {} };
const lane = { clientWidth: 100 };
const document = { getElementById: () => card, querySelectorAll: () => [] };
function updateVerdict() {}
function applyResult() {}
function syncModeDisabled() {}

%(runOneStep)s

%(runAll)s

// What a user does: click Step, then click Run while the 820ms card animation is still going.
runOneStep();
runAll();
// If the loop starves the event loop this timer never fires and the process spins until it is
// killed. The Python side supplies that kill, as a test timeout.
setTimeout(() => { console.log("TIMER_FIRED pointer=" + pointer); process.exit(0); }, 2500);
"""


class DemoRunLoop(unittest.TestCase):
    @unittest.skipUnless(NODE, "node is not installed")
    def test_run_after_step_does_not_starve_the_event_loop(self):
        script = HARNESS % {"runOneStep": source_of("runOneStep"), "runAll": source_of("runAll")}
        try:
            done = subprocess.run([NODE, "--input-type=commonjs", "-"], input=script,
                                  capture_output=True, text=True, timeout=20)
        except subprocess.TimeoutExpired:
            self.fail("runAll spun without yielding: a timer scheduled by runOneStep never fired, "
                      "which in a browser is a frozen tab. Guard runAll on `running` as well as "
                      "`autoRunning`.")
        self.assertIn("TIMER_FIRED", done.stdout,
                      f"the demo's own timer did not fire (stderr: {done.stderr.strip()[:400]})")


if __name__ == "__main__":
    unittest.main()
