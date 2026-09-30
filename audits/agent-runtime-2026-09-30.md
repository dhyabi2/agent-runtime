# agent-runtime — audit, 2026-09-30

Audited at `f8fbd8c` (head of `main`). Python 3.11.15, node v22.22.2, stdlib plus `pytest`.

Baseline on a bare checkout: **95 passed, 1 skipped, 31 subtests.** Green before the change
below and green after it, so the new law is the difference and nothing else is.

## What was checked

- `assets/js/app.js`, `index.html`, `assets/css/style.css` — the browser demo the README names
  as the site entry page. Every `getElementById` in the script cross-checked against the ids the
  page actually defines (all twelve present), then the run loop read for what a user can do to it.
- `runtime/receipts.py` — the chain, the idempotency key, `push_proof`, `commit_proof`, `counts`.
- `runtime/agent.py` — `blocks_from`, `run_tool`, `pick_lane`, `render_mission`, `record_commits`,
  and `turn()`'s DONE detection.
- `runtime/secret_scan.py` — run over the whole tracked tree: **clean, exit 0.** Its patterns read
  for the reverse failure too (a real secret excused by a placeholder that is not the match).
- `record_commits`' `git log --since=1.hour`: measured against a repository built for it, three
  commits at now / −30 min / 2020. `1.hour`, `1 hour ago` and `1.hours.ago` all select the same two
  commits, so git's approxidate reads the dotted form correctly and the window is the one intended.
  (An unparseable value is read as *now*, which is worth knowing but is not what is written here.)

## Found and fixed (this pull request)

**Clicking Run while a Step is animating froze the tab, permanently and every time.**

`runAll` guarded re-entry on `autoRunning` alone:

    async function runAll() {
      if (autoRunning) return;
      ...
      while (pointer < SCENARIOS.length && localToken === runToken) {
        await runOneStep();
      }

and `runOneStep` returns at its first line while `running` is set. So with a step in flight the
loop called it, got a promise that was already resolved, and awaited that — a **microtask**. The
event loop drains every microtask before it runs a timer, so the step's own
`setTimeout(resolve, 820)` could never fire, `running` could never clear, `pointer` could never
advance, and the loop went round forever at full CPU.

Reproduced outside the browser, with the two functions lifted out of `app.js` verbatim and given
stubs for the DOM they touch: a 2.5-second timer scheduled alongside them **never fires** — the
process spins until it is killed. With the guard, it fires and `pointer` is 1.

Two ways a user reaches it, both ordinary: *Step* then *Run* inside the 820 ms animation, and
*Run* → *Reset* → *Run*, where `resetState` clears `autoRunning` while the in-flight step still
holds `running`.

The fix is the one word the guard was missing, `if (autoRunning || running) return;`. The Run
button becomes a no-op for the length of one animation, which is what the Step button already does.

`tests/test_demo_loop.py` pins it by **running the shipped functions** rather than asserting on
their text, so the law survives the next edit and a guard put back the wrong way cannot satisfy it.
It fails against the unfixed file exactly as described (the subprocess has to be killed on a
timeout) and passes against the fixed one in 2.6 s. It skips, rather than passes, where node is
absent.

## Found, not changed

- **`turn()` discards a shell block that arrives in the same reply as `DONE`.** The DONE check runs
  before `blocks_from`, and its guard only asks that no <code>```</code> fence appears *after* the
  last `DONE` — so a reply of "block, then `DONE` committed it" breaks out with the block never run
  and nothing journalled to say so. The heredoc collision is handled correctly (a `DONE` terminator
  inside a fence leaves a fence behind it, so the guard declines), and the mission text does tell
  the agent that DONE means the work is already committed. Making a block run before DONE is
  honoured is a change to what a turn means, not a fix, so it is reported.
- **`push_proof` ignores `git ls-remote`'s exit code.** An unreachable remote and a remote that has
  never seen the branch both yield `remote_sha == ""` and `in_sync: False`. The verdict is right
  either way, so nothing is wrong today; but the proof cannot say *which*, and a proof log's value
  is that it can be re-checked. Adding a third state is a schema decision, not a fix.

## Secrets

Clean. `runtime/secret_scan.py` over every tracked path: no findings, exit 0. Nothing in this
change carries a value of any kind.
