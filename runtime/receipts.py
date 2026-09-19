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
  * every row carries the hash of the row before it, so a receipt cannot be inserted, edited or
    removed after the fact without breaking the chain from that point on.
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
    """Attach what the world actually returned. An intent left unsettled is a crash, visibly."""
    db.execute("UPDATE receipts SET proof=?, ok=? WHERE seq=? AND proof IS NULL",
               (json.dumps(proof, sort_keys=True), 1 if ok else 0, seq))


def verify_chain(db):
    """Recompute every row's hash. Returns the first seq that does not match, or None."""
    prev = GENESIS
    for seq, ts, agent, kind, target, idem, intent, prev_hash, row_hash in db.execute(
            "SELECT seq, ts, agent, kind, target, idem, intent, prev_hash, row_hash FROM receipts ORDER BY seq"):
        if prev_hash != prev or _hash(prev, ts, agent, kind, target, idem, intent) != row_hash:
            return seq
        prev = row_hash
    return None


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
    files = subprocess.run(["git", "show", "--name-only", "--format=", sha], cwd=repo_dir,
                           capture_output=True, text=True, timeout=30).stdout.split()
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
        slot["unsettled" if ok is None else ("proved" if ok else "failed")] += 1
    return out
