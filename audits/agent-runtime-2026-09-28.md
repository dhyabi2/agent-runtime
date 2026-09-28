# agent-runtime — audit 2026-09-28

Tree audited at `9f42251` (branch `main`). Environment: Python 3.11.15, pytest from the
sandbox image; no virtualenv is needed — the runtime is stdlib-only.

## Baseline

`pytest -q` — **92 passed, 1 skipped, 26 subtests passed**, before any change.

## What was checked

- **Every pull request earlier audits left open for a person has since been merged**
  (`#3`–`#12`). In particular `#12` landed the `secret_scan` fix for a tracked file whose
  name git quotes, so the 09-27 note's standing warning — "a tracked file with a non-ASCII
  name is not being scanned before a push" — no longer holds. `git ls-files -z` and a NUL
  split are in `runtime/secret_scan.py:97`. There are **no open pull requests** on this
  repository.
- `runtime/receipts.py` in full: the chain hash, `verify_chain`, `note_break`, `counts`,
  and all three proof builders. **One defect found and fixed — see below.**
- `runtime/secret_scan.py`, `runtime/guard.py`, `runtime/modeld.py`, `lib/journal.py`,
  `hub.py`, `extras/nano_keys.py` read for shell and path handling: **no `shell=True`, no
  `os.system`, no `eval`, no `exec` anywhere in `runtime/`, `lib/`, `hub.py` or `extras/`.**
  All seven `subprocess` call sites pass an argument list.
- `tests/test_readme.py`'s five laws still hold, so the README's clone URL, dependency list,
  unit names and install roots still match the tree.

## Found and fixed

**`runtime/receipts.py:164` — `commit_proof` reported a subject the commit does not have,
when the commit's AUTHOR NAME held a character git does not treat as a line break.**

The function cuts `git show --stat --format=%H%n%an%n%s` with `splitlines()` and reads the
subject as `lines[2]`. An author name is caller data, and `str.splitlines()` breaks on far
more than `\n`: a vertical tab, a form feed, U+0085, U+2028 or U+2029 is accepted by git in
an ident and split by Python, so every later line shifts by one and `subject` becomes the
tail of the author's own name.

Shown against real git, before the fix — a commit authored by `Ada<VT>Lovelace` with the
subject `the real subject`:

    lines[0..4]: ['d5d9cf09…', 'Ada', 'Lovelace', 'the real subject', '']
    commit_proof would report subject = 'Lovelace'

and across the whole set:

    character  splitlines()               split("\n")
    newline    'the real subject'         'the real subject'
    U+2028     'Lovelace'                 'the real subject'
    NEL x85    'Lovelace'                 'the real subject'

A proof log naming something the commit does not say is the one thing the comment four
lines below in this same function says a proof must not do. It is also the lesson
`tests/test_record_commits.py` already pins for `record_commits`, with the same
`LINE_BREAKERS` set — it had never reached this function.

**The change** is one line plus its reason: `splitlines()` → `split("\n")`. `\n` itself
cannot appear in `%an` or `%s`, because git strips it from an ident and a subject is by
definition the message's first line, so splitting on `\n` alone is both sufficient and
exact. The `files` half of the same function was already correct (`-z`, split on NUL) and
is untouched, as is every other line of the module.

**The law**:
`tests/test_receipts.py::TheProofComesFromTheWorld::test_a_commit_proof_reports_the_subject_the_commit_really_has`
builds a real one-commit repository per character and requires the subject back whole. It
fails on the tree without the fix — **5 SUBFAILED, one per character** — and passes with it.

After: `pytest -q` — **93 passed, 1 skipped, 31 subtests passed**.

## Found, not fixed

- **`_mul` is not constant-time**, and **the receipt chain does not cover `proof`/`ok`** —
  both on the record since 2026-09-25, both unchanged, both deliberate.
- **`modeld.main` chmods the socket after binding.** Unchanged: reachable only under
  `umask 000`, and the unit's business.

## Not verified

- **No live provider, network or chain call.** `modeld.py`'s provider path is exercised only
  through `test_modeld_backoff.py`'s fakes, and `_spend_today`'s `netCostUsd` / `costUsd`
  field names have still never been read against a real nano-gpt `/usage` body — the part
  most likely to be wrong in a way no test here can see.
- **The README's measured footprint** (27.7 MB per turn, 19.7 MB modeld, 9.6 MB hub) still
  needs the deployed box, not a clone.
- **`hub.py` still has no laws**, because it imports `websockets`, which is not in the tree.
