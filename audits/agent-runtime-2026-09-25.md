# agent-runtime — audit, 2026-09-25

A clone of `main` at `057dfb6`, Python 3.11, nothing else on the box. The suite ran green before any
change — **65 tests, OK** — so this audit started from a repository that was already healthy, and the
two findings below are both things a passing suite cannot see: one in the gate that runs *before* a
push, one in the instructions a reader follows *before* there is anything to test.

The previous audit (2026-09-24) left three areas explicitly unverified. `hub.py` was the one worth
the most time and is reported below under *Read and found sound*.

## What was checked

- The full suite before and after each change, and each new law against the unchanged file it
  accuses, so the difference is the fix and not the test.
- `secret_scan.py` — every pattern and, this time, the allow list's **scope** rather than its shapes.
- `README.md` — the install block run command by command into a sandbox prefix, then compared
  against what the units in `systemd/` actually require.
- `hub.py` end to end: the replay/live handoff, the `gap` frame's boundaries, the per-IP and global
  connection counting, `_release`, and the retention interaction during a replay.
- `lib/journal.py` — `append`'s transaction and trim, `append_valid`'s index bookkeeping across
  repeated drops, `_prepare`'s encode checks, `state_key`/`apply_state` tombstone handling.
- `guard.py` — the money lock, the fail-closed secret rules, the rails rules.
- A secret sweep of the tree with the tightened scanner from this audit: **clean, 0 findings.**

## Found

1. **A placeholder anywhere on a line excused every secret on that line.** `scan()` searched the
   allow list against the whole line and skipped the line on any hit. Three of the six allow patterns
   describe the *shape of a fake value* rather than stating intent, and all three are shapes that
   turn up beside real text — `<[a-z-]+>` matches any bare HTML tag, `xxx+` matches an `XXX` todo
   marker, `0{16,}` matches any amount in raw. Measured against the unchanged scanner, all four of
   these published:

   ```
   <code>SEED=<64 hex></code>          NO FINDING
   seed: <64 hex><br>                  NO FINDING
   TOKEN=ghp_…  # XXX rotate later     NO FINDING
   VERCEL_TOKEN=vck_…  # 10000000000000000 raw   NO FINDING
   ```

   while the same seed alone on a line was refused. **Fixed** by separating the two kinds of
   exemption: an annotation (`EXAMPLE`, `PLACEHOLDER`, `test-fixture`) is a person writing about the
   line and stays line-wide; a placeholder describes the value and now has to *be* the match.
   Raised separately and **left open for a person** — see *Open* below.

2. **The install path builds a layout the shipped units cannot run.** The last line of the README
   was `systemctl enable --now agent-modeld.service agent@a01.timer`, and `cp systemd/*` installs
   `swarm-modeld.service`, `swarm-agent@.service`, `swarm-agent@.timer`. Neither name exists. Below
   that, nothing else lined up either: the README cloned to `/opt/agent` and created `/srv/agents/a01`
   while the units run `/opt/swarm/venv/bin/python /opt/swarm/swarm/agent.py` from `/srv/swarm/%i`
   with `NANO_PULSE_LIB=/opt/swarm/lib`. Running the block verbatim and then checking what the units
   ask for reported `MISSING` five times out of five. **Fixed** in this pull request; the units are
   left untouched, for the same reason the 2026-09-24 `NANO_PULSE_LIB` fix left them untouched — they
   are what a deployed box runs, and the README is the thing that was wrong.

## Read and found sound

- **`hub.py`**, which had no laws and had never been executed here. The replay/live handoff holds:
  the client is registered and `snap = last_seq` taken with no await between them, the catch-up loop
  is bounded and cannot spin when retention trims underneath it, and the live loop's `seq > snap`
  test makes the two halves exactly disjoint. The `gap` frame's boundaries are right at
  `since = 0`, at a trimmed journal, and at a `since` above `last_seq`. Connection counting is taken
  in `process_request` before the handshake and released on `connection_lost_waiter`, so parallel
  handshakes cannot exceed either limit, and `per_ip` is bounded by `max_clients`.
- **`journal.append_valid`** — `BadRow.index` is an index into the *filtered* list, which is exactly
  what `keep.pop()` needs; repeated drops stay correctly mapped back to original positions.
- **`guard.refuse`** fails closed on the seed and the env: a fragment that names either is refused
  unless it is a bare `source`, whatever program is asking.

## Not verified

- **No live provider or network call was made**, so `modeld.py`'s provider path is still exercised
  only through `test_modeld_backoff.py`'s fakes, and `hub.py` was read rather than served — this
  sandbox's proxy refuses outbound hosts, and an audit should not be making real model calls.
- **The README's measured footprint** (27.7 MB per turn, 19.7 MB for modeld, 9.6 MB for the hub) is
  unchanged and still needs the deployed box, not a clone.
- **`guard.py`'s money lock catches only raw-denominated amounts.** `RAW_AMOUNT_RE` is `\d{18,}`, so
  a decimal amount (`send 0.5 XNO`) passes the lock untouched. Nothing in this runtime offers an
  amount parameter, so there is no path that reaches it today, and this is money code — reported for
  a person rather than edited.
- **`guard.py`'s outreach rule reads only the command text.** `gh issue create` with no `--repo`,
  run inside one of our own clones, is not refused, because the account name never appears in the
  string. That is the shape the rule was written for. Closing it needs the checkout's `origin`
  resolved, which is more than a fix; reported rather than done.

## After

`python3 -m unittest discover -s tests -t .` → **67 tests, OK** on this branch, and **68, OK** with
the secret-scan branch, from a clone with no environment set. The standing law that this repository
still passes its own gate passes with the tightened scanner, so nothing that used to push is refused.

## Open

- *secret_scan: a placeholder anywhere on a line excused every secret on it* — left open because it
  changes the gate that stands in front of every push, which is the same call the 2026-09-24 audit
  made about this file. It only ever refuses more than it used to.
