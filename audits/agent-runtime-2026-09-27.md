# agent-runtime — audit 2026-09-27

Third pass. The 2026-09-26 note left `record_commits`'s line splitting on the record as found-but-not-fixed,
"exotic enough that no commit in this tree triggers it". It is fixed here, because the consequence is worse
than a parse error, and because a second defect in the same family turned out to sit in the pre-push secret
gate, where it fails *open*.

## What was checked

- `python3 -m pytest tests -q` on a clean clone: **75 passed, 6 subtests** before any change.
- Every `splitlines()` and every `\x1f` record parse in `runtime/`, `lib/`, `hub.py` and `extras/`, read
  against what the producing command actually writes.
- `runtime/secret_scan.py` end to end against a real git repository, as a pre-push hook would run it.
- `runtime/agent.py`'s turn loop, `record_commits` and the push-receipt half.

## Fixed

- **`runtime/agent.py:304` — a commit subject the agent writes itself could end its own turn.**
  `git log --format=%H%x1f%ct%x1f%s` output was cut with `str.splitlines()`, which breaks on `\v`, `\f`,
  `\x1c`–`\x1e`, `\x85`, U+2028 and U+2029 as well as on `\n`. git ends a record with `\n` and nothing else,
  so such a subject became two lines and the tail carried no `\x1f`; `sha, cts, subject = line.split("\x1f", 2)`
  raised `ValueError`.

  Shown against a real repository: one commit with a vertical tab in its subject, `git log` writes **one**
  record (`od -c` ends it with a single `\n`), `split("\n")` finds one line, `splitlines()` finds two, and the
  second raises `not enough values to unpack (expected 3, got 1)`.

  Why it was worse than a parse error: `turn()` calls `record_commits()` **unguarded, after** emitting
  `run`/`ok`. The raise escaped `turn()`, so a turn whose work had **succeeded** exited non-zero — which the
  run loop reads as a failed run, and three of those in a row invent corrections — while that batch of commit
  facts, the push receipt and the push fact were all dropped. The agent's proof that it committed and pushed
  disappeared exactly when it had.

  Fix: `out.split("\n")`. `%H` and `%ct` cannot hold `\x1f` or a newline and git folds newlines out of `%s`,
  so on a real record the unpack is now total. Nothing else changed.

  Laws: `tests/test_record_commits.py`, 4 laws / 5 subtests, run against **real git repositories** — a
  hand-written fixture string can be made to pass with the broken code, git's own bytes cannot. Three of them
  call the shipped `record_commits()` (constants redirected, not the environment, per this repo's own lesson)
  and assert the journalled rows; one pins the `splitlines()`/`split` difference itself so nobody reintroduces
  it believing them equivalent. **Before: 6 failed, 78 passed. After: 79 passed, 11 subtests.**

## Found, NOT fixed — and the first is the most serious thing in this tree

- **`runtime/secret_scan.py:42` — the pre-push secret gate silently skips a file it cannot open, and
  `tracked()` hands it paths that cannot be opened.** `git ls-files` is read without `-z`, so `core.quotePath`
  (on by default) returns a path holding any non-ASCII byte **quoted and octal-escaped**: `"caf\303\251.py"`,
  with literal double quotes. `scan()` then does `except OSError: continue` — so that file is never scanned and
  nothing says so. `splitlines()` on line 42 is a second route to the same place: a tracked filename holding
  `\v` or U+2028 becomes two paths that do not exist.

  Shown: a git repository holding `café.py` whose only content is `TOKEN = "ghp_…"` (24 chars, matching the
  gate's own `github token` pattern). `tracked()` returns `'"caf\\303\\251.py"'`; `scan()` returns `[]`; the
  gate **exits 0** — "nothing found, push allowed" — with the token sitting in a tracked file. The same token
  in `plain.py` is refused correctly, which is what makes the skip invisible: the gate looks like it works.

  This is `commit_proof`'s bug, already fixed in `runtime/receipts.py:168-172`, whose comment names
  `core.quotePath` and `"caf\303\251.py"` by name — the same lesson never reached the file where failing open
  publishes a secret.

  **Not fixed here on purpose.** `secret_scan.py` is the pre-push publishing gate, and this audit does not
  self-merge a change to it — the same call the 2026-09-25 and 2026-09-26 passes made for PRs #5 and #7. A
  pull request is opened and **left open for a person**: a gate that has been failing open wants an eye, not a
  bot's merge. If those three are reviewed together, do this one first.

- **`runtime/receipts.py:164` — `commit_proof` picks the subject by line index.** `git show --stat
  --format=%H%n%an%n%s` is cut with `splitlines()` and the subject read as `lines[2]`. An **author name**
  holding one of the same characters shifts every later line, so `subject` becomes half an author name — a
  proof log naming something the commit does not say, which is the one thing the comment four lines below
  says a proof must not do. Same family, different file and different consequence (a wrong field, not a
  crash); left for its own change rather than widened into this one.

- **`_mul` is not constant-time**, and **the receipt chain does not cover `proof`/`ok`** — both on the record
  since 2026-09-25, both unchanged, both deliberate.

- **`modeld.main` chmods the socket after binding.** Unchanged from 2026-09-26: reachable only under
  `umask 000`, and the unit's business.

## Not verified

- **No live provider, network or chain call.** `modeld.py`'s provider path is still exercised only through
  `test_modeld_backoff.py`'s fakes, and `_spend_today`'s `netCostUsd` / `costUsd` field names have still never
  been read against a real nano-gpt `/usage` body — the part most likely to be wrong in a way no test here
  can see.
- **The README's measured footprint** (27.7 MB per turn, 19.7 MB modeld, 9.6 MB hub) still needs the deployed
  box, not a clone.
- **`hub.py` still has no laws**, because it imports `websockets`, which is not in the tree.
- **The secret-gate fix was not merged and so is not in effect.** Until that pull request is reviewed, a
  tracked file with a non-ASCII name is not being scanned before a push.
