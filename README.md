# agent-runtime

A small runtime for autonomous agents that have to be **cheap, honest and unattended**.

Ten agents run on one 2 GB VPS. A turn is a process, never a daemon. Continuity lives on disk. One
shared daemon holds the provider connection and the whole box's budget, so ten agents cannot race past
one cap. And what an agent *says* it did is not evidence of anything — the runtime performs the
outward act itself and keeps the proof the world returned.

This is the code that actually runs, not a cleaned-up version of it. Diff it against production.

## Browser demo: secret scan security gate

This repository now includes a browser-only live demo game at the site entry page:

- `index.html`
- `assets/css/style.css`
- `assets/js/app.js`

The demo explains, in plain language, the behavior change from:

- **OLD GATE**: can report clean even when files were skipped or scan setup failed.
- **NEW GATE**: fails closed (blocks or reports scan failed) when scanning is incomplete or unavailable.

### Run locally

You can run it with zero dependencies:

- Open `index.html` from your local repository checkout directly in a browser, or
- Serve the repository root as static files, for example:

```bash
cd /path/to/agent-runtime
python3 -m http.server 8000
```

Then open `http://localhost:8000/`.

### GitHub Pages setup

The landing page is repository root `index.html`, so GitHub Pages can publish directly from branch root:

1. Go to **Settings → Pages**
2. Under **Build and deployment**, choose **Deploy from a branch**
3. Select your default branch (for example `main`) and folder **`/(root)`**
4. Save, then open the published site URL shown on the same page

### Customizing demo behavior/text

- Scenario definitions and deterministic OLD/NEW outcomes: `assets/js/app.js` (`SCENARIOS`)
- Narration copy and verdict labels: `assets/js/app.js`
- Layout, colors, responsive behavior: `assets/css/style.css`

## Measured

On a 2 GB / 1 vCPU box, with one agent working:

| | |
|---|---|
| agent turn (peak RSS) | **27.7 MB** |
| model daemon | **19.7 MB** |
| live feed hub | **9.6 MB** |
| whole runtime | **~57 MB** |
| for comparison | a general-purpose agent framework is 300–600 MB for its orchestration layer alone, 1.2–1.8 GB with browser tools |

Ten agents at 27.7 MB each is 277 MB of agent, plus ~30 MB of shared daemons, inside 2 GB with room
to work. That is the whole design goal.

## The four ideas

**1. A turn is a process.** `swarm-agent@.service` is a `oneshot` fired by a timer. There is no long-lived
process whose context can grow, so no compaction, no drift, and a crash costs exactly one turn.
Continuity comes from `MEMORY.md` and `memory/YYYY-MM-DD.md` on disk, read fresh each time and
bounded so a months-old agent still fits in a turn.

**2. One budget for the whole box.** `modeld` owns the provider connection and the daily cap. It
refuses *before* a call, not after, so the cap is a wall rather than a warning. It treats an empty
completion as a failure — a lesson paid for when a runtime accepted one and every turn died quietly.
Its backoff is proportionate: an HTTP 402 is believed on sight because no credit does not fix itself,
while a timeout must happen `FAIL_THRESHOLD` times in a row before one agent's bad luck becomes
everyone's outage.

**3. A shell block is a script.** Everything inside one ```` ```sh ```` fence runs as one script in one
shell, so `cd`, variables, heredocs and loops mean what the model meant by them. The previous version
ran each *line* in its own shell: of 368 tool calls, 103 were `cd` that could never persist, 24 were
`import` lines from a shredded heredoc exiting 127, and 29 were bare variable assignments exiting 2 —
**42% of everything the agent had ever done, wasted on one design choice.**

**4. Receipts, not reports.** `receipts.py` is the part worth stealing. The runtime does the outward
act, captures the proof the world produced — a remote SHA from `git ls-remote`, an on-chain block
hash, an HTTP status and a hash of the body — and appends it to a hash-chained log the agent does not
write. The intent is fsynced *before* the act, so a crash is visible as an unsettled row instead of a
silent repeat or a silent skip, and an idempotency key makes a retry safe. It is cheaper than asking a
second model whether the first one was honest, and where an external fact exists it is also truer.

## Layout

```
runtime/agent.py      the turn: lanes, state from disk, block extraction, the tool loop
runtime/modeld.py     one provider connection, one budget, proportionate backoff
runtime/guard.py      refuses a command before it runs  (domain rules live here)
runtime/receipts.py   hash-chained proof of outward acts  (fully generic)
runtime/secret_scan.py  pre-push gate
lib/journal.py        append-only event log, WAL, bounded retention
hub.py                serves the journal over WebSocket for a live map
systemd/              the units: a timer, a oneshot agent, a daemon
```

**Generic:** `receipts.py`, `modeld.py`, `lib/journal.py`, `hub.py`, the units, and all of `agent.py`
except its default mission text.

**Domain-specific, replace for your project:** `guard.py` carries the rules of *this* swarm — one
allowed payment amount, no posting to a particular social network, no issues on repositories we own.
The structure is what to keep: a single `refuse(command) -> str|None` consulted before anything runs,
failing **closed** on anything naming a credential.

## Using it

```bash
# The units in systemd/ are the ones production runs, verbatim, and they name absolute paths:
# /opt/swarm for the checkout, /srv/swarm/<name> for each agent. The install builds those.
git clone https://github.com/dhyabi2/agent-runtime /opt/swarm

# The one rename publication introduced: this directory is `runtime/` in the repository and
# `swarm/` on a box, which is where the units' ExecStart already points.
mv /opt/swarm/runtime /opt/swarm/swarm

python3 -m venv /opt/swarm/venv
# The agent, modeld, the guard, the journal and the secret scan are stdlib only.
# hub.py is the one exception and is only needed if you serve the live feed:
/opt/swarm/venv/bin/pip install -q websockets

install -d /srv/swarm/a01
cat > /srv/swarm/a01/MISSION.md <<'EOF'
You are {name}. This turn's lane is **{lane}**. Your workspace is {home}.
... your instructions ...
{state}
EOF

cp systemd/* /etc/systemd/system/
systemctl enable --now swarm-modeld.service swarm-agent@a01.timer
```

Configuration is environment only:

| variable | meaning |
|---|---|
| `AGENT_MISSION_FILE` | the mission template (default `$HOME/MISSION.md`) |
| `SWARM_DAILY_USD` | the whole box's daily spend cap |
| `SWARM_FAIL_THRESHOLD` | consecutive failures before an outage is declared |
| `SWARM_SELF_SHARE` | fraction of finished turns spent improving itself |
| `SWARM_MAX_BLOCKS` / `SWARM_MAX_TOOLS` | bounds on one turn |
| `NANO_PULSE_RETAIN` | journal rows kept — the default of 50,000 is **2.4–3.7 days** at 13–16k events/day, which is how a record that mattered got destroyed before anything asked for it |

## What this runtime will not do for you

It will not make an agent honest. It makes dishonesty **detectable**: a claim with no receipt is not
evidence, and no row can be inserted, removed, or have a hashed field edited afterwards without
breaking the chain from that row on. Know where that ends: `proof` and `ok` are written by `settle`
*after* the row is hashed, so the chain does not cover them — what stands behind a settlement is that
its proof names a fact anyone can go and re-check. Three of the
defects listed above were found by measuring the agent's own journal rather than by reading the code,
and one was found only because a law was written to attack the lock rather than describe it — `cat`
on the wallet was refused and `vi` was not.
