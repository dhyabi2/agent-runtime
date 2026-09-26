# agent-runtime — audit, 2026-09-26

A clone of `main` at `c4f67fd`, Python 3.11. Fourth pass. The three earlier notes covered
`receipts.py`, `agent.py`, `modeld.py` and the README, so this one went to the two places they left
unread: `hub.py` (read but never executed, and still with no laws) and every place the runtime shells
out. The finding is in the pre-push secret gate.

## What was checked

- `python3 -m unittest discover -s tests -t .` — **69 tests, OK**, before any change.
- `runtime/secret_scan.py` in full, driven against real throwaway git checkouts.
- `hub.py` in full: `process_request`, `client_ip`, the connection caps and their release, the
  replay/live handoff in `handler`, and `poll`'s fan-out.
- Every `subprocess` call site in the tree (`agent.py:99,264`, `receipts.py:150-165`,
  `secret_scan.py:41`) for an unchecked exit code or a shell-quoting assumption.
- `lib/journal.py`'s schema against what `hub.frame()` assumes about the `data` column.

## Found and fixed — the gate that stands in front of every push failed open, three ways

`secret_scan.py`'s own docstring says why it exists: *"the repository is PUBLIC and the agent pushes
to it unattended … the reason it is a hook and not a guideline is that nobody is watching at 3am."*
All three faults below end identically — `hits == []`, exit 0, the push goes out — which for this hook
is the worst failure it has, because it is indistinguishable from a clean tree.

**1. A file whose name holds any non-ASCII byte was never scanned.** `tracked()` read `git ls-files`
line by line, and `git ls-files` applies `core.quotePath`: such a name comes back quoted and
octal-escaped. `open()` cannot find that path, `scan()` swallowed the `OSError` with `continue`, and
the gate reported clean. Demonstrated on a real checkout holding one file named `café.py` carrying a
seed-shaped 64-hex string:

```
--- git ls-files, as tracked() read it ---
"caf\303\251.py"
my notes.py
--- git ls-files -z ---
café.py
my notes.py

tracked() returned: ['"caf\\303\\251.py"', 'my notes.py']
findings: [('my notes.py', 1, 'nano seed/private key')]

VERDICT: the gate reports CLEAN for a file that plainly holds a 64-hex seed.
```

The 2026-09-25b note flagged whitespace splitting in `commit_proof`; this is not that. A space never
triggers quoting, so `splitlines()` handled `my notes.py` correctly — it is the escaping that hides a
file. `git ls-files -z` is never quoted and never escaped.

**2. A present-but-unreadable file was silently skipped.** The same `except OSError: continue` covered
a permission error and a path that is a directory, so the gate reported clean for content it had never
read. It is now a finding — `unreadable, so unscanned (PermissionError)` — and the push is refused.
A file that is *missing* stays a non-event: tracked-but-deleted carries nothing to publish, and
refusing it would get the hook turned off within the week.

**3. No listing read as "nothing to scan".** `tracked()` ignored git's exit code, so outside a
checkout, or with git failing for any reason, it returned `[]`, `scan([])` found nothing, and the hook
exited 0 having scanned not one byte. It now raises `ScanFailed`, and `__main__` exits 2 with
*"refusing to push: the secret scan could not run"*.

## After

`python3 -m unittest discover -s tests -t .` → **74 tests, OK (1 skipped)**, from 69. The five new
laws fail against `secret_scan.py` as published:

```
FAIL  test_a_path_git_quotes_is_still_scanned [café.py]        ['"caf\303\251.py"'] != ['café.py']
FAIL  test_a_path_git_quotes_is_still_scanned [рай.py]         ['"\321\200\320\260\320\271.py"'] != ['рай.py']
FAIL  test_a_path_git_quotes_is_still_scanned [notes — draft]  ['"notes \342\200\224 draft.py"'] != [...]
FAIL  test_a_path_that_cannot_be_read_is_a_finding_not_a_skip  0 != 1 : []
ERROR test_no_listing_is_refused_rather_than_read_as_clean     no attribute 'ScanFailed'
FAILED (failures=4, errors=1)
```

They also pin what must not change: a path with a space still scans (the ordinary case the `-z` change
could have regressed), a missing file is still not a finding, and a finding still never carries the
matched text.

The one skip is the `chmod 000` half of law 2, which this sandbox runs as root and root can read
anything. The branch itself is verified in the same law by the directory case, which raises
`IsADirectoryError` for every user including root, so the behaviour is covered; only that one variant
is unexercised here.

## Left open deliberately

This is the pre-push hook — the publishing path — so it is not self-merged even with the suite green,
which is the same call the 2026-09-25 note made about **PR #5** (`fix/secret-scan-line-wide-allow`,
still open). The two are independent concerns in one file: #5 changes how the allow list is applied to
a line, this changes which files get read at all. Expect a small conflict only if both land; neither
depends on the other, and each only ever refuses more than the current gate does.

## Read and found sound

- `hub.py`'s connection caps are counted in `process_request` before the handshake with no `await`
  between check and increment, and released from `connection_lost_waiter`, so parallel handshakes
  cannot exceed them. `client_ip` prefers `X-Real-IP` and otherwise takes the **last** hop of
  `X-Forwarded-For`, which is the one Caddy appends — the correct end to trust.
- `hub.frame()` interpolates the journal's `data` column into JSON unquoted, which would emit a
  malformed frame to every client for a non-JSON value. `journal.py`'s schema declares
  `data TEXT NOT NULL` and every writer goes through `append`, so there is no path that stores one.
- `handler` parses `since` defensively (`ValueError` → 0, clamped at 0) and a large `since` collapses
  to `snap` rather than over-reading.
- `push_proof` ignores `git ls-remote`'s exit code, but a failure leaves `remote_sha` empty and
  `in_sync` false, so it fails safe.

## Found, not fixed — carried forward

- **`commit_proof` splits the file list on whitespace** (`receipts.py:151`), so a committed path with
  a space is recorded as two files in the proof. Carried from 2026-09-25b, still unfixed, still one
  concern of its own; `--name-only -z` is the fix.
- **`_mul` is not constant-time** (`extras/nano_keys.py`) — the standard trade for a dependency-free
  pure-Python signer, recorded so the trade stays on the record.
- **`hub.py` still has no laws and is still never executed by the suite.** It imports `websockets`,
  which is not in the tree and which the README's install does not provide, so its request handling,
  replay bound and per-IP cap remain unexercised. Reading them was this run's substitute, not a
  replacement.

## Not verified

- `hub.py` end to end, for the reason above.
- `modeld.py`'s provider path beyond `test_modeld_backoff.py`'s fakes. No live provider call was made,
  and none should be from an audit.
- The README's measured footprint (27.7 MB per turn, 19.7 MB for modeld, 9.6 MB for the hub). That
  needs the deployed box, not a clone.
