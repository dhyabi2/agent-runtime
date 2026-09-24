#!/usr/bin/env python3
"""swarm-agent — one autonomous agent. One process, one cgroup, one clone, one turn at a time.

Mission (owner, 2026-09-19): do what Unstuck does — bring agents from outside the Nano world to their first
Nano transaction and build the network they arrive at — EXCEPT posting to X. Half its effort is that work
and half is improving itself, committing and pushing to its own repository without asking anyone.

Every design choice below is a failure this swarm already paid for:
  * a FRESH conversation per turn. OpenClaw reused one session until its context filled and the model had no
    output budget left; "reply with exactly: OK" came back as the single token "T".
  * continuity on DISK (memory/, MEMORY.md, the journal), never in a growing transcript.
  * the budget and the provider live in modeld, so ten agents cannot race past one cap.
  * a retryable failure NEVER loses the work: it is journalled and the turn ends cleanly.
  * every tool call goes through guard.refuse() first. There is no unguarded path.
"""
import json, os, re, socket, subprocess, sys, time, pathlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# Imported by path, like receipts below: systemd runs this file as a script, where there is no
# parent package and a package-relative import raises before the first turn.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import guard  # noqa: E402

NAME = os.environ.get("SWARM_AGENT", "a01")
HOME = pathlib.Path(os.environ.get("SWARM_AGENT_HOME", f"/srv/swarm/{NAME}"))
SOCK = os.environ.get("SWARM_MODEL_SOCK", "/run/swarm/model.sock")
JOURNAL_DB = os.environ.get("SWARM_JOURNAL_DB", "/var/lib/swarm/journal.db")
MAX_TOOLS = int(os.environ.get("SWARM_MAX_TOOLS", "12"))
MAX_TOKENS = int(os.environ.get("SWARM_MAX_TOKENS", "3000"))
SELF_SHARE = float(os.environ.get("SWARM_SELF_SHARE", "0.5"))

# The default is the copy of the rail shipped in THIS checkout, not an install path that only exists
# on a box the swarm already provisioned: a fresh clone has no /opt/swarm/lib, so the old default made
# `import agent` raise ModuleNotFoundError before any configuration could be applied. The unit still
# sets NANO_PULSE_LIB=/opt/swarm/lib explicitly, so a deployed agent keeps using the shared rail.
sys.path.insert(0, os.environ.get(
    "NANO_PULSE_LIB", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lib")))
import journal  # noqa: E402  (the swarm's existing rail: same schema, same hub, same map)

# Imported by path, not relatively: systemd runs this file as a script, where there is no
# parent package and `from . import receipts` raises before the first turn.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import receipts  # noqa: E402  (proof of outward acts, written by the runtime)


def emit(kind, data):
    try:
        db = journal.connect(JOURNAL_DB)
        journal.append(db, [(time.time(), kind, dict(data, agent=NAME))])
        db.close()
    except Exception as ex:
        print(f"journal failed ({ex})", file=sys.stderr)


def ask(messages, max_tokens=MAX_TOKENS):
    """One model call through modeld. Never talks to a provider directly."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(300)
    try:
        s.connect(SOCK)
        s.sendall(json.dumps({"op": "chat", "messages": messages, "max_tokens": max_tokens}).encode() + b"\n")
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        return json.loads(buf or b'{"ok":false,"error":"no answer from modeld"}')
    except Exception as ex:
        return {"ok": False, "retryable": True, "error": f"modeld unreachable: {ex}"}
    finally:
        s.close()


def blocks_from(text):
    """Every ```sh block in the model's reply, each as ONE script, in order.

    Two things this must not do, both of which the previous inline version did:
      * split a block into lines - `cd`, a variable, a heredoc and a loop all stop meaning anything;
      * drop lines beginning with '#' - a comment is harmless, but `#!/usr/bin/env python3` on the
        first line of a heredoc is not a comment, and removing it silently broke the script.
    """
    out = []
    for b in re.findall(r"```(?:sh|bash|shell)?\s*\n(.*?)```", text, re.S):
        b = b.strip()
        if b:
            out.append(b)
    return out


def run_tool(cmd, timeout=180):
    """The only way this agent touches the world. The guard decides first, always."""
    blocked = guard.refuse(cmd)
    if blocked:
        emit("scope", {"decision": "refused", "command": cmd[:200], "why": blocked[:300]})
        return {"ok": False, "refused": blocked}
    t0 = time.time()
    try:
        r = subprocess.run(["bash", "-lc", cmd], cwd=str(HOME), capture_output=True,
                           text=True, timeout=timeout)
        out = (r.stdout or "") + (("\n" + r.stderr) if r.returncode else "")
        emit("tool", {"name": cmd.split()[0][:40], "exit": r.returncode,
                      "seconds": round(time.time() - t0, 1)})
        return {"ok": r.returncode == 0, "exit": r.returncode, "output": out[-4000:]}
    except subprocess.TimeoutExpired:
        emit("tool", {"name": cmd.split()[0][:40], "exit": "timeout", "seconds": timeout})
        return {"ok": False, "output": f"timed out after {timeout}s"}


def read_state():
    """Continuity comes from disk, so a fresh conversation every turn costs nothing."""
    bits = []
    for f in ("MEMORY.md", f"memory/{time.strftime('%Y-%m-%d', time.gmtime())}.md"):
        p = HOME / f
        if p.exists():
            bits.append(f"--- {f} ---\n{p.read_text(encoding='utf-8', errors='replace')[-4000:]}")
    return "\n\n".join(bits) or "(no memory yet — this is the first turn)"


def pick_lane(db_path=JOURNAL_DB):
    """50 / 50, measured from what actually happened, not from a coin flip."""
    try:
        db = journal.connect_ro(db_path)
        cut = time.time() - 86400
        rows = dict(db.execute(
            "SELECT json_extract(data,'$.lane'), COUNT(*) FROM events "
            "WHERE kind='run' AND ts > ? "
            # Finished turns only. 'start' would count every turn twice and 'deferred' would count a
            # provider outage as work done, which is how the split drifts on exactly the worst days.
            "AND json_extract(data,'$.status') IN ('ok','done') GROUP BY 1", (cut,)).fetchall())
        db.close()
    except Exception:
        rows = {}
    self_n, work_n = rows.get("self", 0), rows.get("work", 0)
    total = self_n + work_n
    if total == 0:
        return "work"
    return "self" if (self_n / total) < SELF_SHARE else "work"


# At most this many shell blocks per reply, each run as one script.
MAX_BLOCKS = int(os.environ.get("SWARM_MAX_BLOCKS", "3"))


DEFAULT_MISSION = """You are {name}, an autonomous agent in the Nano swarm. You run unattended and decide for
yourself; nothing you do waits for a human.

Your mission is the one Unstuck has: bring AI agents from OUTSIDE the Nano world — the ones paying in USDC,
cards or platform credit — to their first Nano transaction, and build the network they arrive at. An agent
that already takes Nano is not a target; converting it proves nothing.

You do NOT post to X yourself. That is deliberate: this runtime is experimental, and a public timeline
is the one place a mistake cannot be taken back. But your work is NOT invisible - every fact you journal
feeds the swarm's shared Newsletter as `N`, beside Rai's `E`, Vend's `V`, Unstuck's `U` and OpenClaw's
`O`, and Rai posts that issue to X. So journal the ACCOMPLISHMENT, with something checkable in it: the
URL of an outside agent that answered you, the block of a tip that settled, the SHA of a commit that
reached the remote. A second model must quote a cited fact verbatim or nothing is published, so a fact
with no evidence inside it cannot be used however true it is. A passing test or a refactor is real work
but it is housekeeping, not news, and a URL on an account we control is not an accomplishment at all.

This turn's lane is **{lane}**:
  - work: find an outside agent, open a conversation, and RECORD IT with
        swarm-contact record --url <its endpoint> --name <name> --pays-in <what it takes TODAY> \
                             --found-via <where in the outside world you found it> [--stage contacted]
    The runtime fetches that URL itself and keeps the status and a hash of what came back, so the
    contact is proved rather than claimed; `swarm-contact list` shows every one and whether it was
    reachable. It refuses a URL on an account we control and any agent that already takes Nano -
    converting one of those proves nothing. Where it is warranted, open its Nano account with a
    single tip of 0.000001 XNO. A work turn that records no contact did not do the mission.
  - self: improve your own code in {home}. Make it faster, smaller or harder to break, add a test that
    would have caught a real failure, then COMMIT and PUSH. You own this repository.

How you answer: think briefly, then write a shell script inside a single ```sh block. The whole
block runs as ONE script in one shell, so `cd`, variables, heredocs and loops work normally and
persist through the block. They do NOT persist to the next block or the next turn - continuity
lives on disk. You will
be shown their output and may continue. When the turn's work is done and committed, write DONE on its own
line with one sentence saying what changed.

Hard limits, enforced by a guard that refuses before anything runs: one send amount ever (0.000001 XNO);
keys and seeds are passed to programs, never printed; outreach means someone else's repository; you may
rewrite any of your own code except the guard, the env and the wallet. Anything you put in front of a person —
an issue, a pull request, a listing, a registry submission — carries the account PANDeveloper001; dhyabi2 is
the owner's personal account and is a fallback only, for when the swarm account cannot post at all.

{state}"""

# The mission is a FILE by default, so a new project configures this runtime instead of editing
# it. The template is filled with {name}, {lane}, {home} and {state}; anything else you put in it
# is passed through untouched.
MISSION_FILE = os.environ.get("AGENT_MISSION_FILE", str(HOME / "MISSION.md"))


def mission_template():
    """The mission text, from the file if there is one, else the built-in default."""
    try:
        text = pathlib.Path(MISSION_FILE).read_text(encoding="utf-8").strip()
        return text or DEFAULT_MISSION
    except OSError:
        return DEFAULT_MISSION


MISSION = DEFAULT_MISSION



def turn():
    lane = pick_lane()
    t0 = time.time()
    emit("run", {"lane": lane, "status": "start"})
    emit("status", {"text": f"{NAME}: starting a {lane} turn", "lane": lane})

    msgs = [{"role": "user", "content": mission_template().format(name=NAME, lane=lane, home=HOME, state=read_state())}]
    tools_used, done_note = 0, None

    for _ in range(MAX_TOOLS):
        res = ask(msgs)
        if not res.get("ok"):
            # Retryable and journalled: the work is not lost, the turn simply ends.
            emit("run", {"lane": lane, "status": "deferred", "why": res.get("error", "")[:200],
                         "seconds": round(time.time() - t0, 1)})
            emit("status", {"text": f"{NAME}: deferred — {res.get('error','')[:120]}", "lane": lane})
            return 0
        text = res["text"]
        msgs.append({"role": "assistant", "content": text})

        m = re.search(r"^DONE\b[ :–-]*(.*)$", text, re.M)
        if m and "```" not in text.split("DONE")[-1]:
            done_note = m.group(1).strip()[:200]
            break

        # Each block is one script, not a pile of lines: `cd`, a heredoc, a variable and a loop all
        # mean what the agent meant by them. A line-per-process runner made 42% of this agent's tool
        # calls no-ops (103 `cd`, 24 `import` at exit 127, 29 bare variable names at exit 2).
        blocks = blocks_from(text)
        if not blocks:
            break

        outs = []
        for b in blocks[:MAX_BLOCKS]:
            r = run_tool(b)
            tools_used += 1
            first = next((l for l in b.splitlines() if l.strip()), b)[:120]
            outs.append(f"$ {first}{' …' if len(b.splitlines()) > 1 else ''}\n"
                        f"{r.get('refused') or r.get('output','')}"[:2500])
        if len(blocks) > MAX_BLOCKS:
            # Say so. The old runner dropped everything past the sixth line in silence, which reads
            # to the agent as a command that ran and did nothing.
            outs.append(f"[{len(blocks) - MAX_BLOCKS} further block(s) were NOT run: at most "
                        f"{MAX_BLOCKS} per reply. Send the rest next turn.]")
        msgs.append({"role": "user", "content": "\n\n".join(outs) + "\n\nContinue, or write DONE."})

    if done_note:
        emit("status", {"text": f"{NAME}: {done_note}", "lane": lane})
    emit("run", {"lane": lane, "status": "ok", "tools": tools_used,
                 "seconds": round(time.time() - t0, 1), "note": done_note or ""})
    record_commits()
    return 0


def record_commits():
    """A commit is the proof a self turn happened. The map shows it; the Newsletter can read it."""
    try:
        out = subprocess.run(["git", "-C", str(HOME), "log", "--since=1.hour", "--no-merges",
                              "--format=%H%x1f%ct%x1f%s"], capture_output=True, text=True, timeout=20).stdout
    except Exception:
        return
    db = journal.connect(JOURNAL_DB)
    seen = {r[0] for r in db.execute(
        "SELECT json_extract(data,'$.sha') FROM events WHERE kind='commit' AND ts > ?",
        (time.time() - 7200,)).fetchall()}
    rows = []
    for line in out.splitlines():
        if not line.strip():
            continue
        sha, cts, subject = line.split("\x1f", 2)
        if sha[:12] in seen:
            continue
        rows.append((float(cts), "commit", {"sha": sha[:12], "subject": subject[:200], "agent": NAME}))
    if rows:
        journal.append(db, rows)

    # Did any of it leave the box? The remote is asked; `git push` exiting 0 is not an answer, and
    # neither is the agent saying so.
    try:
        rdb = receipts.connect()
        proof = receipts.push_proof(str(HOME))
        seq, already = receipts.begin(rdb, NAME, "push", str(HOME),
                                      {"branch": "main", "local_sha": proof.get("local_sha", "")},
                                      idem=receipts.idem_key(NAME, "push", str(HOME), proof.get("local_sha", "")))
        if already is None:
            receipts.settle(rdb, seq, proof, bool(proof.get("in_sync")))
        journal.append(db, [(time.time(), "push", {
            "agent": NAME, "in_sync": bool(proof.get("in_sync")),
            "remote_sha": (proof.get("remote_sha") or "")[:12],
            "local_sha": (proof.get("local_sha") or "")[:12]})])
        rdb.close()
    except Exception as ex:
        # A receipt that cannot be written must not take the turn down with it.
        journal.append(db, [(time.time(), "push", {"agent": NAME, "error": str(ex)[:200]})])

    db.close()


if __name__ == "__main__":
    emit("heartbeat", {"role": "gateway", "agent": NAME})
    sys.exit(turn())
