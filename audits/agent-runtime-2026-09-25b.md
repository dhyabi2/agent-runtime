# agent-runtime — audit, 2026-09-25 (second pass)

A clone of `main` at `d073a9a`, Python 3.11. **67 tests, OK** before any change. The 2026-09-24 and
earlier-2026-09-25 notes between them covered `secret_scan.py`, the README's install path, `hub.py`,
`lib/journal.py` and `guard.py`, so this pass took the two things neither had touched: the crypto in
`extras/`, which carries no laws at all, and the integrity claim `receipts.py` makes about itself.

## What was checked

- The full suite before and after the change.
- `extras/nano_keys.py` end to end — key derivation, address encode/decode, and signing — against an
  **independently written verifier** (see below).
- `runtime/receipts.py`: `_hash`, `begin`, `settle`, `verify_chain`, `note_break`, `counts`, and the
  three proof builders, against what the module docstring and the README say the chain guarantees.
- `README.md`'s links and file references. The only external URL is this repository's own clone URL,
  already pinned by `test_the_clone_url_names_the_repository_this_is`. `MEMORY.md` and
  `memory/YYYY-MM-DD.md` are read from the agent's runtime `HOME` (`agent.py:113`), not from the
  repository, so their absence from the tree is correct and not a dead reference.
- A secret sweep of the tree: **clean, 0 findings.**

## Found and fixed

**`receipts.py` claimed more integrity than it has, in three places, and the law that should have
caught it tested only the covered half.**

`row_hash` is computed in `begin`, over `_hash`'s arguments: prev, ts, agent, kind, target, idem,
intent. `settle` writes `proof` and `ok` afterwards, so those two are **outside the hash**. Against
that, the module docstring said *"a receipt cannot be inserted, edited or removed after the fact
without breaking the chain"*, and the README said *"the chain cannot be edited afterwards without
breaking from that row on"*.

Demonstrated on a real chain — a failed push rewritten as a proved one:

```
as recorded : ('{"in_sync": false, "local_sha": "nonexistent", "remote_sha": ""}', 0)
chain       : None
after edit  : ('{"in_sync": true,  "remote_sha": "aaa…", "local_sha": "aaa…"}', 1)
chain       : None          <- the tamper is invisible
counts      : {'push': {'proved': 1, 'failed': 0, 'unsettled': 0}}
```

`ok` is the field that says whether the act worked, so this is precisely the edit the chain exists to
make visible, and `counts` — what the run brief and the Newsletter read — reports the edited value.

The suite read as though it covered this. `test_editing_a_settled_row_breaks_the_chain_from_that_point`
is docstringed *"a record nobody can quietly improve after the fact"*, but the only field it edits is
`target`, which the hash covers. Renamed to `test_editing_a_hashed_field_…`, which is what it proves.

**Not fixed by widening the hash, deliberately.** Bringing the settlement inside `row_hash` means
either re-hashing the row after the act — which changes the hash every later row chains onto — or a
second hash column, which is an on-disk schema change to a published runtime, with a compatibility
path (a NULL column on rows written before it) that a tamperer could simply re-enter. That is a
maintainer's design decision, not an auditor's edit. What this change does is make the documents say
exactly what the code does, and pin the boundary with two laws so the two cannot drift apart again.

## After

`python3 -m unittest discover -s tests -t .` → **69 tests, OK** (67 + 2). The new
`test_both_documents_name_the_columns_the_chain_does_not_cover` derives the settled columns from
`settle`'s own SQL and the covered set from `_hash`'s signature, so it fails against the old prose
with `Lists differ: ['ok', 'proof'] != []` and would fail again the day the settlement is brought
inside the hash — telling whoever does it to correct both documents.

## Read and found sound

- **`extras/nano_keys.py`, the whole module — this is the first time it has been checked here, and
  it holds.** It ships a self-vector (the all-zero seed) which passes, but a self-vector recorded
  from the implementation it tests proves only self-consistency; a signer that is merely
  self-consistent verifies its own wrong signatures happily, which the file's own comments say.
  So it was checked against an **affine-coordinate implementation written from the curve equation**,
  sharing none of `_add`'s extended-coordinate arithmetic:
  - `7·B` compresses identically under both implementations;
  - a signature over a real `state_hash` (account, previous, representative, a 10^29 raw balance,
    link) verifies as `S·B == R + k·A` under the independent verifier;
  - the same signature fails that check against a message differing by one raw.
  Also confirmed by reading: `add-2008-hwcd-3` is transcribed correctly for a = −1 and returns
  (X, Y, Z, T) rather than the intermediates; the clamp is the standard one; `address` pads to the
  5-bit boundary and reverses the blake2b-5 checksum as Nano does; `account_to_pub` round-trips and
  **fails closed** on a bad checksum. Field order in `state_hash` matches the protocol.
- **`verify_chain`'s acknowledged-break handling.** `known` silences only the recorded `seq`, `prev`
  advances to the stored `row_hash` regardless, so detection keeps working for every row after an
  acknowledged break rather than cascading from it.
- **`counts`** sums `n` per group rather than counting groups — the defect its own comment records
  stays fixed.

## Found, not fixed

- **`commit_proof` splits the file list on whitespace** (`receipts.py:151`), so a committed path
  containing a space is recorded as two files in the proof. Cosmetic in this tree, wrong in a proof
  log; `--name-only -z` is the fix. One concern per change.
- **`_mul` is not constant-time** — a plain double-and-add branching on the scalar's bits. It signs
  with a private key, so on a shared host this is a side-channel in principle. It is the standard
  trade for a pure-Python signer with no dependencies, which is the module's stated reason to exist;
  recorded so the trade is on the record, not as something to change quietly.

## Not verified

- **No live provider, network or chain call was made.** `modeld.py`'s provider path is still
  exercised only through `test_modeld_backoff.py`'s fakes, `hub.py` was read rather than served, and
  no block was broadcast — the signature check above is arithmetic against an independent verifier,
  not a node accepting a block.
- **The README's measured footprint** (27.7 MB per turn, 19.7 MB for modeld, 9.6 MB for the hub)
  still needs the deployed box, not a clone.
- The `secret_scan` placeholder-scope change left open by the earlier pass today is still open; this
  audit did not revisit it.
