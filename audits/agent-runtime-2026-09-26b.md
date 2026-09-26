# agent-runtime — audit, 2026-09-26 (second pass)

A clone of `main` at `c4f67fd`, Python 3.11. **69 tests, OK** before any change. The three earlier
notes between them covered `secret_scan.py`, the README's install path, `hub.py`, `lib/journal.py`,
`guard.py`, `extras/nano_keys.py` and `receipts.py`. That left `runtime/agent.py` and
`runtime/modeld.py`, which had been read for imports but never audited on their own, so this pass
took those two — plus the one item the 2026-09-25 note wrote down as found-and-not-fixed.

## What was checked

- The full suite before and after each change, and each new law against the unchanged file it
  accuses, so the difference is the fix and not the test.
- `runtime/agent.py` end to end: `emit`, `ask`'s framing loop, `blocks_from`, `run_tool`'s guard
  ordering, `read_state`, `pick_lane`, `mission_template`, `turn`'s loop and DONE detection, and
  `record_commits`.
- `runtime/modeld.py` end to end: `_key`, `_spend_today`, `_budget_ok`'s cache, `_note_failure`'s
  hard/soft split and backoff growth, `handle`'s health, backoff, budget and error branches.
- `receipts.commit_proof`, re-read against the 2026-09-25 finding.
- A secret sweep of the tree with the published scanner: **clean, 0 findings.**

## Found and fixed

**1. An ordinary mission file killed every turn, and the fault was on the one path the README tells
a new project to use.** `agent.py:213` passed the mission through `str.format`, which reads every
brace in the file as a field of its own. `MISSION_FILE` is operator-written configuration
(`AGENT_MISSION_FILE`, a documented variable with its own README row), and the comment above it has
always said *"anything else you put in it is passed through untouched"* — which `.format()` does not
do:

```
{"url": "x", "pays_in": "USDC"}   KeyError: '"url"'
${HOME}                           KeyError: 'HOME'
jq '{sha: .sha}'                  KeyError: 'sha'
fill in {} yourself               IndexError: Replacement index 0 out of range
```

The README's own four-placeholder example survives, which is why this had never shown up here. Any
mission carrying a JSON shape, a shell variable or a jq filter did not. Run against a real journal
with a mission holding one JSON example, the whole turn is:

```
turn() RAISED: KeyError: '"url"'
run    {"lane":"work","status":"start","agent":"a01"}
status {"text":"a01: starting a work turn","lane":"work","agent":"a01"}
```

It raises after the `run`/`start` event and before `ask()`, so there is no `deferred`, no `ok` and
no model call — a turn that started and never ended, which is the label this swarm has already paid
to diagnose twice, and it would have repeated every turn for ever.

`render_mission` replaces exactly the four named fields in one pass and cannot raise. Behaviour
change worth naming: there is no `{{` escape any more, so `{{name}}` renders as `{a01}` where it
used to render as the literal `{name}`. Neither `DEFAULT_MISSION` nor the README's example uses that
form, and it is the price of the file being configuration rather than a format string.

Also in the same function: `mission_template()` caught only `OSError`, and `UnicodeDecodeError` is a
`ValueError`, so a mission file with one undecodable byte escaped the guard and ended the turn the
same way. It reads with `errors="replace"` now — a mission is instructions to be read, and one bad
byte is not a reason to stop working.

**2. `commit_proof` named files the commit does not contain** — the item the 2026-09-25 note recorded
as found-and-not-fixed. `git show --name-only` split on whitespace is not a list of paths: under
`core.quotePath` a non-ASCII path comes back quoted and octal-escaped, and a path with a space
becomes two entries. One commit of three files recorded as
`['"caf\303\251.py"', 'plain.py', 'src/my', 'notes.py']` — four entries, two of which are not
files. Fixed with `-z` and a NUL split, with `errors="surrogateescape"` so an undecodable filename
round-trips instead of raising inside a proof builder; checked through `settle()` on a real
repository holding `bad\xff.py`, where `json.dumps` escapes the surrogate before SQLite sees it.

## Read and found sound

- **`modeld.py`.** The hard/soft failure split is right: 402 is believed at once, everything else
  needs `FAIL_THRESHOLD` in a row and then waits `min(BACKOFF_S, 30·over)`, and a success clears the
  run. `_budget_ok` fails closed when the spend lookup returns `None`, and caches for 60 s, so a
  provider blip cannot spend the cap. An empty completion is counted a failure, not an answer.
  `_key()` reads the env file rather than an argv, and a commented-out key does not match.
- **`blocks_from`.** A fence labelled with any other language does not match, a block with no label
  does, and a block is never split into lines — the three things its docstring claims.
- **`run_tool`.** `guard.refuse()` is the first statement, before any subprocess, and a refusal is
  journalled with its reason. There is no path to `subprocess.run` that skips it.
- **`pick_lane`.** Counts finished turns only, and `total == 0` starts in the work lane.
- **`record_commits`.** Dedupes on the same 12-character prefix it stores, and a receipt that cannot
  be written is journalled rather than allowed to end the turn.

## Found, not fixed

- **`record_commits` splits `git log` output with `str.splitlines()`** (`agent.py:273`), which breaks
  on `\v`, `\f`, `\x85`, `U+2028` and `U+2029` where git breaks only on `\n`. A commit subject
  holding one of those yields a short line and `line.split("\x1f", 2)` raises `ValueError`,
  uncaught, after the run/ok event. Same family as the two fixed above; left for its own change
  rather than widened into either, and exotic enough that no commit in this tree triggers it.
- **`modeld.main` chmods the socket after binding**, so its mode is the umask's for a moment. At the
  default umask that interval is 0o755, which still refuses a connect, so this is only reachable
  where the unit runs with `umask 000`. Recorded, not changed: it is the unit's business.
- **`_mul` is not constant-time** and **the chain does not cover `proof`/`ok`** — both already on the
  record from 2026-09-25, both unchanged, both deliberate.

## Not verified

- **No live provider, network or chain call was made.** `modeld.py`'s provider path is still
  exercised only through `test_modeld_backoff.py`'s fakes; `_spend_today`'s parsing of a real
  nano-gpt `/usage` body has never been checked against one, and its two field names
  (`netCostUsd`, `costUsd`) are the part most likely to be wrong in a way no test here can see.
- **The README's measured footprint** (27.7 MB per turn, 19.7 MB for modeld, 9.6 MB for the hub)
  still needs the deployed box, not a clone.
- **`hub.py` still has no laws**, because it imports `websockets`, which is not in the tree.
- **PRs #5 and #7 are still open and were not revisited here.** Both change `secret_scan.py`, which
  is the pre-push publishing gate, so neither is self-merged — the same call both earlier passes
  made. They want a person's eye.
