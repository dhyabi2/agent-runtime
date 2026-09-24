# agent-runtime — audit, 2026-09-24

Audited as published: `git clone --depth 1` of `master`/`main`, nothing else on the box, Python 3.11.
The question asked throughout was the one a reader actually faces — *does this work for someone who
clones it today?* — because the README's own claim is "this is the code that actually runs, not a
cleaned-up version of it. Diff it against production."

## What was checked

- Every module imported on a bare checkout: `runtime/agent.py`, `modeld.py`, `guard.py`,
  `receipts.py`, `secret_scan.py`, `lib/journal.py`, `hub.py`, `extras/nano_keys.py`.
- The full suite, `python3 -m unittest discover -s tests -t .`, before and after each change.
- The README's install path, command by command, including the clone URL and the dependency claim.
- `guard.refuse()` — the split on `&&`/`||`/`;`/`|`/newline, the secret-variable and rails patterns,
  and the `SECRET_SAFE_RE` exemption.
- `receipts.py` — the hash chain, `begin`/`settle` ordering, the fsync-before-the-act claim, and
  `verify_chain`'s handling of acknowledged breaks.
- `secret_scan.py` — every pattern, and the `ALLOW` exemption.
- A secret sweep of the tree: seed-shaped hex, `nano_` addresses, `ghp_`/`sk-`/`vck_` tokens, private
  key blocks. **Nothing found.** The only 64-character and `nano_`-shaped strings in the tree are in
  `extras/nano_keys.py`, and both are published test vectors: the all-zero seed and the address it
  derives to.

## Found

1. **The runtime could not be imported from a clone.** `runtime/agent.py:32` defaulted
   `NANO_PULSE_LIB` to `/opt/swarm/lib` — an install path that exists only on a box the swarm has
   already provisioned — and then did `import journal`. The repository ships that rail at
   `lib/journal.py` and never reached it. `import agent` raised
   `ModuleNotFoundError: No module named 'journal'` before a line of configuration could be read, and
   two of the ten test modules (`test_block_runner`, `test_blocks_from`) failed to import for the
   same reason: **45 tests ran where 57 exist**. The one law that did exercise the entry points,
   `test_entrypoints.py:20`, passed only because it sets `NANO_PULSE_LIB` to this checkout's `lib/`
   by hand, so the broken default was invisible to the suite that was meant to catch exactly this.
   **Fixed** — the default is now the `lib/` beside the runtime. `systemd/swarm-agent@.service:13`
   still sets `NANO_PULSE_LIB=/opt/swarm/lib` explicitly, so a deployed agent is unchanged.

2. **Five tests that had never run, failed once they could.** With the import repaired,
   `test_block_runner` raised `FileNotFoundError: /srv/swarm/a01` five times: `agent.run_tool` passes
   `cwd=str(HOME)`, and the module redirected `agent.JOURNAL_DB` to a temp path — the repository's own
   "point the module's constant, not the env var" rule — but not `agent.HOME`. **Fixed** in the test
   module, same mechanism, restored in `tearDownModule`.

3. **The README's install path does not work.** Two separate breaks, in the first two commands a
   reader runs. Raised separately; see the pull request titled *README: the install path a reader
   follows does not work*.

4. **The pre-push secret gate misses a lowercase seed.** `secret_scan.py:8` matches
   `\b[0-9A-F]{64}\b` with no `re.IGNORECASE`, so a 64-character seed in lowercase hex — what
   `secrets.token_hex(32)` returns, and what `extras/nano_keys.py:101` happily accepts via
   `bytes.fromhex` — is not a finding and is published. Raised separately and **left open for a
   person**, because it changes the gate that stands in front of every push.

## After

`python3 -m unittest discover -s tests -t .` → **57 tests, OK**, from a clone with no environment set.
Before this change the same command on the same clone reported `Ran 45 tests … FAILED (errors=2)`.

## Not verified

- `hub.py` was read but not executed: it imports `websockets`, which is not in the tree and which the
  README's install does not provide (that is finding 3). Its request handling, replay bound and
  per-IP cap are unexercised here and have no laws in the suite.
- `modeld.py`'s provider path was exercised only through `test_modeld_backoff.py`'s fakes. No live
  provider call was made, and none should be from an audit.
- The measured footprint in the README (27.7 MB per turn, 19.7 MB for modeld, 9.6 MB for the hub) was
  not re-measured; it needs the deployed box, not a clone.
