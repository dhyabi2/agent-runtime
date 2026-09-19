"""Append-only SQLite WAL journal shared by the nano-pulse plugin and collector (writers) and the hub (reader).

seq is AUTOINCREMENT so it never repeats, even after retention deletes old rows. epoch is created once
per database file; a client holding a different epoch must replay from the start.

Durability rules:
  - `events` keeps the RETAIN newest rows (history).
  - `state` keeps the latest row per state key (law per repo+id, ledger_state per repo, proposal, funding,
    skill_card, scorecard, source, tests per repo) outside retention, so current state survives trimming.
    A `removed` tombstone deletes the matching keys and is itself kept as state.
  - `receipts` keeps every nano_tx receipt outside retention, so receipt counts never fall as rows age out.
  - ts is stamped at append time (inside the write lock, so it follows seq); source times stay in data.
  - Writers set journal_size_limit and the collector checkpoints with TRUNCATE, so the WAL stays bounded.
  - Readers use read-only connections and never run DDL.
"""
import json
import os
import secrets
import sqlite3
import time
from urllib.parse import quote

DB = os.environ.get("NANO_PULSE_DB", os.path.expanduser("~/.hermes/nano-pulse/journal.db"))
RETAIN = int(os.environ.get("NANO_PULSE_RETAIN", "50000"))
WAL_LIMIT = int(os.environ.get("NANO_PULSE_WAL_LIMIT", str(4 * 1024 * 1024)))

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, kind TEXT NOT NULL, data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS events_kind_ts ON events(kind, ts);
CREATE TABLE IF NOT EXISTS state(key TEXT PRIMARY KEY, seq INTEGER NOT NULL, ts REAL NOT NULL, kind TEXT NOT NULL, data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS state_seq ON state(seq);
CREATE TABLE IF NOT EXISTS receipts(hash TEXT PRIMARY KEY, seq INTEGER NOT NULL, ts REAL NOT NULL, direction TEXT, external INTEGER NOT NULL);
"""


class BadRow(ValueError):
    """A row that cannot be stored (not JSON-serialisable or not encodable as UTF-8)."""

    def __init__(self, index, reason):
        super().__init__(f"row {index}: {reason}")
        self.index = index


def connect(path=None):
    """Writer connection: WAL, bounded WAL file, schema and epoch."""
    path = path or DB
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    db = sqlite3.connect(path, timeout=5, check_same_thread=False, isolation_level=None)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=NORMAL")
    db.execute("PRAGMA busy_timeout=5000")
    db.execute(f"PRAGMA journal_size_limit={int(WAL_LIMIT)}")
    db.executescript(SCHEMA)
    db.execute("INSERT OR IGNORE INTO meta VALUES('epoch', ?)", (secrets.token_hex(4),))
    return db


def ensure(path=None):
    """Create or upgrade the schema once (used by the hub at startup), then close the writer connection."""
    connect(path).close()


def connect_ro(path=None):
    """Reader connection: read-only, no DDL, no epoch insert."""
    path = os.path.abspath(path or DB)
    db = sqlite3.connect(f"file:{quote(path)}?mode=ro", uri=True, timeout=5, check_same_thread=False, isolation_level=None)
    db.execute("PRAGMA busy_timeout=5000")
    return db


def epoch(db):
    return db.execute("SELECT v FROM meta WHERE k='epoch'").fetchone()[0]


def last_seq(db):
    """Newest seq ever assigned (sqlite_sequence survives deletes), 0 for a new journal."""
    row = db.execute("SELECT seq FROM sqlite_sequence WHERE name='events'").fetchone()
    top = db.execute("SELECT coalesce(max(seq), 0) FROM events").fetchone()[0]
    return max(top, row[0] if row else 0)


def min_seq(db):
    """Oldest retained seq; last_seq+1 when the journal holds no rows."""
    low = db.execute("SELECT min(seq) FROM events").fetchone()[0]
    return low if low is not None else last_seq(db) + 1


def last_ts(db, kind):
    return db.execute("SELECT max(ts) FROM events WHERE kind=?", (kind,)).fetchone()[0]


def last_heartbeats(db):
    """{role: newest heartbeat ts}. Heartbeats without a role are reported as 'unknown' and never count as the gateway."""
    rows = db.execute("SELECT coalesce(json_extract(data, '$.role'), 'unknown'), max(ts) FROM events "
                      "WHERE kind='heartbeat' GROUP BY 1").fetchall()
    return {role: ts for role, ts in rows}


def state_key(kind, data):
    """The latest-value key a row updates, or None for pure history rows."""
    if not isinstance(data, dict):
        return None
    g = data.get
    if kind == "law" and g("repo") is not None and g("id") is not None:
        return f"law:{g('repo')}:{g('id')}"
    if kind in ("ledger_state", "scorecard", "tests") and g("repo") is not None:
        return f"{kind}:{g('repo')}"
    if kind == "proposal" and g("id") is not None:
        return f"proposal:{g('id')}"
    if kind == "funding" and g("id") is not None:
        return f"funding:{g('id')}"
    if kind == "access_request" and g("id") is not None:
        return f"access_request:{g('id')}"  # key requests: the newest state of each (no details, no key values)
    if kind == "skill_card" and g("skill"):
        return f"skill_card:{g('skill')}"
    if kind == "source" and g("name"):
        return f"source:{g('name')}"
    if kind == "status" and g("text"):
        return "status:rai"  # what Rai is doing now (rai-status): only the newest matters
    if kind == "removed" and g("what") in ("ledger", "law", "proposal"):
        return f"removed:{g('what')}:{g('repo') or ''}:{g('id') or ''}"
    return None


def _delete_prefix(db, prefix, before_seq):
    db.execute("DELETE FROM state WHERE substr(key, 1, ?) = ? AND seq < ?", (len(prefix), prefix, before_seq))


def apply_state(db, seq, ts, kind, data, text):
    """Update the state table for one row. Newer seq always wins, so replaying old rows is idempotent."""
    key = state_key(kind, data)
    if key is None:
        return
    if kind == "removed":
        what, repo, rid = data.get("what"), data.get("repo") or "", data.get("id") or ""
        if what == "ledger":
            for prefix in (f"ledger_state:{repo}", f"law:{repo}:", f"removed:law:{repo}:"):
                if prefix.endswith(":"):
                    _delete_prefix(db, prefix, seq)
                else:
                    db.execute("DELETE FROM state WHERE key=? AND seq < ?", (prefix, seq))
        elif what == "law":
            db.execute("DELETE FROM state WHERE key=? AND seq < ?", (f"law:{repo}:{rid}", seq))
        elif what == "proposal":
            db.execute("DELETE FROM state WHERE key=? AND seq < ?", (f"proposal:{rid}", seq))
    else:  # the thing exists again: an older tombstone for it no longer applies
        if kind == "law":
            db.execute("DELETE FROM state WHERE key IN (?, ?) AND seq < ?",
                       (f"removed:law:{data.get('repo')}:{data.get('id')}", f"removed:ledger:{data.get('repo')}:", seq))
        elif kind == "ledger_state":
            db.execute("DELETE FROM state WHERE key=? AND seq < ?", (f"removed:ledger:{data.get('repo')}:", seq))
        elif kind == "proposal":
            db.execute("DELETE FROM state WHERE key=? AND seq < ?", (f"removed:proposal::{data.get('id')}", seq))
    db.execute("INSERT INTO state(key, seq, ts, kind, data) VALUES(?,?,?,?,?) "
               "ON CONFLICT(key) DO UPDATE SET seq=excluded.seq, ts=excluded.ts, kind=excluded.kind, data=excluded.data "
               "WHERE excluded.seq > state.seq", (key, seq, ts, kind, text))


def apply_receipt(db, seq, ts, kind, data):
    if kind == "nano_tx" and isinstance(data, dict) and data.get("hash"):
        db.execute("INSERT OR IGNORE INTO receipts(hash, seq, ts, direction, external) VALUES(?,?,?,?,?)",
                   (str(data["hash"]), seq, ts, data.get("direction"), 1 if data.get("external") is True else 0))


def _prepare(rows):
    out = []
    for i, (ts, kind, data) in enumerate(rows):
        try:
            text = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
            text.encode("utf-8")
            str(kind).encode("utf-8")
        except (TypeError, ValueError) as ex:  # UnicodeEncodeError is a ValueError
            raise BadRow(i, f"{type(ex).__name__}: {ex}") from None
        out.append((ts, str(kind), data, text))
    return out


def append(db, rows):
    """rows: iterable of (ts, kind, dict); ts None means now. One transaction; trims events to RETAIN newest rows.
    Raises BadRow (nothing written) when a row cannot be stored. Returns the assigned seqs."""
    prepared = _prepare(list(rows))
    if not prepared:
        return []
    db.execute("BEGIN IMMEDIATE")
    try:
        now = time.time()  # taken inside the write lock, so ts follows seq across writers
        seqs = []
        for ts, kind, data, text in prepared:
            ts = now if ts is None else ts
            seq = db.execute("INSERT INTO events(ts, kind, data) VALUES(?,?,?)", (ts, kind, text)).lastrowid
            apply_state(db, seq, ts, kind, data, text)
            apply_receipt(db, seq, ts, kind, data)
            seqs.append(seq)
        if seqs[-1] > RETAIN:
            db.execute("DELETE FROM events WHERE seq <= ?", (seqs[-1] - RETAIN,))
        db.execute("COMMIT")
        return seqs
    except BaseException:
        db.execute("ROLLBACK")
        raise


def append_valid(db, rows):
    """Like append, but rows that cannot be stored are dropped. Returns (seqs, dropped_indices)."""
    rows, dropped = list(rows), []
    keep = list(range(len(rows)))
    while True:
        try:
            return append(db, [rows[i] for i in keep]), dropped
        except BadRow as ex:
            dropped.append(keep.pop(ex.index))


def checkpoint(db):
    """Checkpoint and truncate the WAL (collector, every run). Returns (busy, wal_frames, checkpointed)."""
    return tuple(db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone())


def read_after(db, after, upto=None, limit=1000):
    """Rows with after < seq <= upto, oldest first, as (seq, ts, kind, data_json)."""
    if upto is None:
        return db.execute("SELECT seq, ts, kind, data FROM events WHERE seq > ? ORDER BY seq LIMIT ?",
                          (after, limit)).fetchall()
    return db.execute("SELECT seq, ts, kind, data FROM events WHERE seq > ? AND seq <= ? ORDER BY seq LIMIT ?",
                      (after, upto, limit)).fetchall()


def read_state(db, after, upto):
    """Current-state rows with after < seq <= upto, oldest first, as (seq, ts, kind, data_json)."""
    return db.execute("SELECT seq, ts, kind, data FROM state WHERE seq > ? AND seq <= ? ORDER BY seq",
                      (after, upto)).fetchall()
