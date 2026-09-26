#!/usr/bin/env python3
"""Receipts, not reports.

The benchmark (Goal-Autopilot, arXiv 2606.11688) spends a second model call per tick asking whether
the worker's claims are supported. That is expensive and, where an external fact exists, less true
than looking: a git push either created a remote SHA or it did not, and no model's opinion improves
on `git ls-remote`.

So the runtime performs the outward act itself, captures the proof the outside world produced, and
appends it to a hash-chained log the agent does not write. What the agent SAYS it did is no longer
evidence of anything; the chain is.

Three properties, each pinned by a law:
  * an intent is written and fsynced BEFORE the act, so a crash between the act and its record is
    visible as an intent with no receipt, instead of silently repeating or silently skipping;
  * the proof is external - a remote SHA, an on-chain block hash, an HTTP status and body hash - and
    is re-checked against the world, never taken from the agent;
  * every row carries the hash of the row before it, so a receipt cannot be inserted or removed, and
    no field the hash covers can be edited, without breaking the chain from that point on.

WHAT THE CHAIN DOES NOT COVER. `row_hash` is computed in `begin`, from the fields that exist before
the act: prev, ts, agent, kind, target, idem, intent. `proof` and `ok` are written afterwards by
`settle` and are therefore OUTSIDE the hash - editing them breaks nothing, and `counts` will report
the edited value. So the chain proves that an intent was recorded, in this order, and never altered;
it does not by itself prove that the settlement attached to it is the one the world returned. Read
`ok` as evidence only together with the `proof` blob, which names a fact anyone can go and re-check
(a remote SHA, a block hash, a body digest) - that re-checkability, not the hash, is what stands
behind a settlement. `test_the_chain_covers_the_intent_and_not_the_settlement` pins this boundary so
the claim here and the code cannot drift apart again.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import time

DB = os.environ.get("SWARM_RECEIPTS_DB", "/var/lib/swarm/receipts.db")
GENESIS = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS chain_breaks(
  seq        INTEGER PRIMARY KEY,     -- the row whose prev_hash does not match
  noted_at   REAL NOT NULL,
  reason     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS receipts(
  seq        INTEGER PRIMARY KEY AUTOINCREMENT,
  ts         REAL NOT NULL,
  agent      TEXT NOT NULL,
  kind       TEXT NOT NULL,          -- commit | push | contact | tip
  target     TEXT NOT NULL,          -- repo, url or nano address
  idem       TEXT NOT NULL UNIQUE,   -- the same intent twice is the same row, never two acts
  intent     TEXT NOT NULL,          -- written before the act
  proof      TEXT,                   -- written after, from the world; NULL means it did not finish
  ok         INTEGER,
  prev_hash  TEXT NOT NULL,
  row_hash   TEXT NOT NULL
);
"""


def connect(path=None):
    db = sqlite3.connect(path or DB, timeout=10, isolation_level=None)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")      # an intent that is not on disk is not an intent
    db.executescript(SCHEMA)
    return db


def _hash(prev, ts, agent, kind, target, idem, intent):
    blob = json.dumps([prev, round(ts, 3), agent, kind, target, idem, intent],
                      sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


def _tip(db):
    row = db.execute("SELECT row_hash FROM receipts ORDER BY seq DESC LIMIT 1").fetchone()
    return row[0] if row else GENESIS


def idem_key(agent, kind, target, detail=""):
    """The same act, described the same way, is one act. This is what makes a retry safe."""
    return hashlib.sha256(f"{agent}\x00{kind}\x00{target}\x00{detail}".encode()).hexdigest()


def begin(db, agent, kind, target, intent, idem=None):
    """Record what is about to happen. Returns (seq, already_done) - already_done carries the proof."""
    idem = idem or idem_key(agent, kind, target, json.dumps(intent, sort_keys=True))
    prior = db.execute("SELECT seq, proof, ok FROM receipts WHERE idem=?", (idem,)).fetchone()
    if prior:
        # Resume: this exact act already has a row. If it finished, the caller must not do it again.
        return prior[0], ({"proof": json.loads(prior[1]), "ok": bool(prior[2])} if prior[1] else None)
    ts = time.time()
    prev = _tip(db)
    body = json.dumps(intent, sort_keys=True)
    rh = _hash(prev, ts, agent, kind, target, idem, body)
    db.execute("INSERT INTO receipts(ts, agent, kind, target, idem, intent, prev_hash, row_hash) "
               "VALUES (?,?,?,?,?,?,?,?)", (ts, agent, kind, target, idem, body, prev, rh))
    return db.execute("SELECT last_insert_rowid()").fetchone()[0], None


def settle(db, seq, proof, ok):
    """Attach what the world actually returned. An intent left unsettled is a crash, visibly.

    `proof` and `ok` are written after `row_hash` was computed, so they are not covered by the chain
    (see the module docstring). What makes a settlement checkable is the proof blob itself.
    """
    db.execute("UPDATE receipts SET proof=?, ok=? WHERE seq=? AND proof IS NULL",
               (json.dumps(proof, sort_keys=True), 1 if ok else 0, seq))


def verify_chain(db):
    """Recompute every row's hash. Returns the first UNEXPLAINED break, or None.

    A break that has been written down in chain_breaks is skipped - not because it is acceptable,
    but because it is permanent: the only way to make the chain verify again would be to re-hash
    every row after it, which is rewriting the history the chain exists to protect. Acknowledging it
    keeps detection working for everything that comes after. An unrecorded break is still returned.
    """
    known = {seq for (seq,) in db.execute("SELECT seq FROM chain_breaks")}
    prev = GENESIS
    for seq, ts, agent, kind, target, idem, intent, prev_hash, row_hash in db.execute(
            "SELECT seq, ts, agent, kind, target, idem, intent, prev_hash, row_hash FROM receipts ORDER BY seq"):
        if prev_hash != prev or _hash(prev, ts, agent, kind, target, idem, intent) != row_hash:
            if seq not in known:
                return seq
        prev = row_hash
    return None


def note_break(db, seq, reason):
    """Write a break down, with why. Only ever called by a person who has looked at it."""
    db.execute("INSERT OR REPLACE INTO chain_breaks(seq, noted_at, reason) VALUES (?,?,?)",
               (int(seq), time.time(), str(reason)[:500]))


def breaks(db):
    return [{"seq": s, "noted_at": t, "reason": r}
            for s, t, r in db.execute("SELECT seq, noted_at, reason FROM chain_breaks ORDER BY seq")]


# ---------------------------------------------------------------- proofs from the world


def push_proof(repo_dir, remote="origin", branch="main"):
    """The remote's SHA, read from the remote. Not `git push`'s exit code, and not the agent."""
    r = subprocess.run(["git", "ls-remote", remote, f"refs/heads/{branch}"],
                       cwd=repo_dir, capture_output=True, text=True, timeout=60)
    remote_sha = (r.stdout.split() or [""])[0]
    local = subprocess.run(["git", "rev-parse", branch], cwd=repo_dir,
                           capture_output=True, text=True, timeout=30).stdout.strip()
    return {"remote_sha": remote_sha, "local_sha": local, "in_sync": bool(remote_sha) and remote_sha == local}


def commit_proof(repo_dir, sha=None):
    """The commit exists in this repository's history and touched these files."""
    sha = sha or subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo_dir,
                                capture_output=True, text=True, timeout=30).stdout.strip()
    r = subprocess.run(["git", "show", "--stat", "--format=%H%n%an%n%s", sha],
                       cwd=repo_dir, capture_output=True, text=True, timeout=30)
    lines = r.stdout.splitlines()
    # -z, and split on NUL rather than on whitespace. Without it git applies core.quotePath, so a
    # path holding a non-ASCII byte arrives quoted and octal-escaped ("caf\303\251.py"), and a path
    # holding a space arrives as two entries. Either way the proof names files the commit does not
    # contain, which is the one thing a proof log must not do. surrogateescape because a filename is
    # bytes: an undecodable one must round-trip, not raise inside a proof builder.
    files = [f for f in subprocess.run(
        ["git", "show", "--name-only", "--format=", "-z", sha], cwd=repo_dir, capture_output=True,
        text=True, errors="surrogateescape", timeout=30).stdout.split("\0") if f]
    return {"sha": lines[0] if lines else "", "subject": lines[2] if len(lines) > 2 else "",
            "files": files, "exists": r.returncode == 0}


def contact_proof(url, status, body):
    """What the other end answered: its status and a hash of its bytes, so the claim is checkable."""
    return {"url": url, "status": status,
            "body_sha256": hashlib.sha256(body if isinstance(body, bytes) else str(body).encode()).hexdigest(),
            "bytes": len(body) if body is not None else 0}


def counts(db, agent=None, since=None):
    """What actually happened, by kind. Unsettled intents are reported, never quietly dropped."""
    where, args = [], []
    if agent:
        where.append("agent=?")
        args.append(agent)
    if since:
        where.append("ts>?")
        args.append(since)
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    out = {}
    for kind, ok, n in db.execute(
            f"SELECT kind, ok, COUNT(*) FROM receipts{clause} GROUP BY kind, ok", args):
        slot = out.setdefault(kind, {"proved": 0, "failed": 0, "unsettled": 0})
        # by n, not by 1: the query returns one row PER GROUP, and counting groups reported
        # "proved 1, failed 1" for 2 proved and 17 failed - wrong, and plausible enough to believe.
        slot["unsettled" if ok is None else ("proved" if ok else "failed")] += n
    return out
