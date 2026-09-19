"""nano-pulse hub: streams the journal over WebSocket and reports progress-based health.

Protocol (read-only for clients):
  connect  wss://<host>/?epoch=<epoch>&since=<seq>
  server → {"type":"hello","epoch","seq","min_seq","replay_max","gap","reset"}
           then current-state rows {"type":"event","seq","ts","kind","data","state":true} (seq ascending, only rows
           newer than `since` and older than the first replayed seq), then {"type":"gap","from","to","min_seq"} once
           when rows between since and the replay window were trimmed or skipped (since=0 included), then events with
           seq in (max(since, min_seq-1, seq-REPLAY_MAX), seq], then live events. A different epoch replays as since=0
           (reset=true).
  GET /healthz → 200 {"ok":true,...} or 503 when the gateway's own heartbeat is older than STALE_S. Heartbeats
           from other processes (role "cli") are reported but never count.
  Any other plain HTTP request → 426.

Replay/live handoff: the client is registered and `snap = last_seq` is taken with no await between them,
so events <= snap come from the database and events > snap arrive through the client's queue.
Fan-out uses put_nowait on a bounded per-client queue; a client that falls behind is closed (1013),
so it can never delay anyone else. Replay cost per connection is bounded by REPLAY_MAX plus the state table.
Connection limits (global and per IP) are counted from process_request, before the handshake completes, and
released when the TCP connection is lost, so parallel handshakes cannot exceed them. SQLite reads run on one
reader thread over a read-only connection, never on the event loop.
"""
import asyncio
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from http import HTTPStatus
from urllib.parse import parse_qs, urlparse

from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosed

sys.path.insert(0, os.environ.get("NANO_PULSE_LIB", os.path.expanduser("~/.hermes/plugins/nano-pulse")))
import journal  # noqa: E402

STALE_S = float(os.environ.get("NANO_PULSE_STALE_S", "120"))
CLIENT_Q = int(os.environ.get("NANO_PULSE_CLIENT_Q", "5000"))
MAX_CLIENTS = int(os.environ.get("NANO_PULSE_MAX_CLIENTS", "200"))
PER_IP = int(os.environ.get("NANO_PULSE_PER_IP", "8"))
REPLAY_MAX = int(os.environ.get("NANO_PULSE_REPLAY_MAX", "5000"))
POLL_S = float(os.environ.get("NANO_PULSE_POLL_S", "0.1"))
TRUST_PROXY = os.environ.get("NANO_PULSE_TRUST_PROXY", "1") == "1"
LOOPBACK = {"127.0.0.1", "::1", "::ffff:127.0.0.1"}


def frame(row, state=False):
    seq, ts, kind, data = row
    tail = ',"state":true' if state else ""
    return f'{{"type":"event","seq":{seq},"ts":{ts},"kind":{json.dumps(kind)},"data":{data}{tail}}}'


def _role(data):
    try:
        role = json.loads(data).get("role")
    except Exception:
        return "unknown"
    return role if isinstance(role, str) and role else "unknown"


class Client:
    __slots__ = ("ws", "q")

    def __init__(self, ws):
        self.ws, self.q = ws, asyncio.Queue(CLIENT_Q)


class Hub:
    def __init__(self, path=None):
        self.path = path or journal.DB
        journal.ensure(self.path)  # schema lives with the writer code; the hub only reads after this
        self.db = journal.connect_ro(self.path)
        self.reader = ThreadPoolExecutor(max_workers=1, thread_name_prefix="nano-pulse-reader")
        self.epoch = journal.epoch(self.db)
        self.last_seq = journal.last_seq(self.db)
        self.heartbeats = journal.last_heartbeats(self.db)
        self.clients: set[Client] = set()
        self.open = 0
        self.per_ip: dict[str, int] = {}
        self.max_clients, self.per_ip_limit, self.replay_max = MAX_CLIENTS, PER_IP, REPLAY_MAX
        self.stats = {"slow_closed": 0, "rejected_busy": 0, "rejected_ip": 0, "rejected_http": 0}
        self.started = time.time()

    async def read(self, fn, *args):
        return await asyncio.get_running_loop().run_in_executor(self.reader, fn, *args)

    @property
    def last_heartbeat(self):
        return self.heartbeats.get("gateway") or 0.0

    def health(self):
        now = time.time()
        gw = self.heartbeats.get("gateway")
        age = now - gw if gw else None
        stale = age is None or age > STALE_S
        return {"ok": not stale, "stale": stale, "heartbeat_age_s": None if age is None else round(age, 1),
                "heartbeat_role": "gateway",
                "roles": {role: round(now - ts, 1) for role, ts in sorted(self.heartbeats.items())},
                "epoch": self.epoch, "seq": self.last_seq, "clients": len(self.clients), "connections": self.open,
                "uptime_s": round(now - self.started), **self.stats}

    def client_ip(self, connection, request):
        try:
            peer = connection.remote_address[0]
        except Exception:
            peer = "?"
        if TRUST_PROXY and peer in LOOPBACK:  # behind Caddy: it sets X-Real-IP / replaces X-Forwarded-For
            real = (request.headers.get("X-Real-IP") or "").strip()
            if real:
                return real
            xff = request.headers.get("X-Forwarded-For") or ""
            if xff.strip():
                return xff.split(",")[-1].strip()
        return peer

    def _release(self, ip):
        self.open = max(0, self.open - 1)
        n = self.per_ip.get(ip, 0) - 1
        if n > 0:
            self.per_ip[ip] = n
        else:
            self.per_ip.pop(ip, None)

    @staticmethod
    def _respond(connection, status, body, content_type="text/plain; charset=utf-8"):
        resp = connection.respond(status, body)
        del resp.headers["Content-Type"]
        resp.headers["Content-Type"] = content_type
        resp.headers["Cache-Control"] = "no-store"
        return resp

    def process_request(self, connection, request):
        if urlparse(request.path).path == "/healthz":
            h = self.health()
            resp = self._respond(connection, HTTPStatus.OK if h["ok"] else HTTPStatus.SERVICE_UNAVAILABLE,
                                 json.dumps(h) + "\n", "application/json")
            resp.headers["Access-Control-Allow-Origin"] = "*"
            return resp
        if "websocket" not in (request.headers.get("Upgrade") or "").lower():
            self.stats["rejected_http"] += 1
            resp = self._respond(connection, HTTPStatus.UPGRADE_REQUIRED, "websocket upgrade required\n")
            resp.headers["Upgrade"] = "websocket"
            return resp
        ip = self.client_ip(connection, request)
        # Counted here, before the handshake, with no await between check and increment.
        if self.open >= self.max_clients:
            self.stats["rejected_busy"] += 1
            return self._respond(connection, HTTPStatus.SERVICE_UNAVAILABLE, "busy\n")
        if self.per_ip.get(ip, 0) >= self.per_ip_limit:
            self.stats["rejected_ip"] += 1
            return self._respond(connection, HTTPStatus.TOO_MANY_REQUESTS, "too many connections from this address\n")
        self.open += 1
        self.per_ip[ip] = self.per_ip.get(ip, 0) + 1
        connection.connection_lost_waiter.add_done_callback(lambda _f, ip=ip: self._release(ip))
        return None

    def _frames(self, after, upto, limit):
        return [(row[0], frame(row)) for row in journal.read_after(self.db, after, upto, limit)]

    def _state_frames(self, after, upto):
        return [frame(row, state=True) for row in journal.read_state(self.db, after, upto)]

    async def poll(self):
        while True:
            try:
                rows = await self.read(journal.read_after, self.db, self.last_seq, None, 1000)
            except Exception as ex:  # a read error must not stop the hub
                print(f"nano-pulse hub: read failed: {ex}", file=sys.stderr)
                await asyncio.sleep(1)
                continue
            for row in rows:
                self.last_seq = row[0]
                if row[2] == "heartbeat":
                    self.heartbeats[_role(row[3])] = row[1]
                msg = (row[0], frame(row))
                for c in list(self.clients):
                    try:
                        c.q.put_nowait(msg)
                    except asyncio.QueueFull:
                        self.clients.discard(c)
                        self.stats["slow_closed"] += 1
                        asyncio.create_task(c.ws.close(1013, "client too slow; reconnect with since"))
            await asyncio.sleep(0 if len(rows) == 1000 else POLL_S)

    async def handler(self, ws):
        qs = parse_qs(urlparse(ws.request.path).query)
        client_epoch = qs.get("epoch", [""])[0]
        try:
            since = max(0, int(qs.get("since", ["0"])[0] or 0))
        except ValueError:
            since = 0
        reset = bool(client_epoch) and client_epoch != self.epoch
        if client_epoch != self.epoch:
            since = 0
        client = Client(ws)
        self.clients.add(client)  # no await between these two lines: the handoff point
        snap = self.last_seq

        def wake(_f):  # a closed connection ends the live loop at once instead of waiting for the next event
            try:
                client.q.put_nowait(None)
            except asyncio.QueueFull:  # the handler is busy sending, and that send fails on the closed connection
                pass

        ws.connection_lost_waiter.add_done_callback(wake)
        try:
            min_seq = await self.read(journal.min_seq, self.db)
            start_after = min(snap, max(since, min_seq - 1, snap - self.replay_max))
            gap = since < start_after
            await ws.send(json.dumps({"type": "hello", "epoch": self.epoch, "seq": snap, "min_seq": min_seq,
                                      "replay_max": self.replay_max, "gap": gap, "reset": reset}))
            for msg in await self.read(self._state_frames, since, start_after):
                await ws.send(msg)
            if gap:
                await ws.send(json.dumps({"type": "gap", "from": since + 1, "to": start_after, "min_seq": min_seq}))
            cursor = start_after
            while cursor < snap:
                batch = await self.read(self._frames, cursor, snap, 500)
                if not batch:
                    break
                for _, msg in batch:
                    await ws.send(msg)
                cursor = batch[-1][0]
            while True:
                item = await client.q.get()
                if item is None:
                    break
                seq, msg = item
                if seq > snap:
                    await ws.send(msg)
        except ConnectionClosed:
            pass
        finally:
            self.clients.discard(client)


async def run(host="127.0.0.1", port=8787, path=None, ready=None):
    hub = Hub(path)
    try:
        async with serve(hub.handler, host, port, process_request=hub.process_request,
                         ping_interval=20, ping_timeout=20, max_size=2 ** 14) as server:
            if ready is not None:
                ready.set_result((hub, server))
            await hub.poll()
    finally:
        hub.reader.shutdown(wait=False, cancel_futures=True)


if __name__ == "__main__":
    asyncio.run(run(os.environ.get("NANO_PULSE_HOST", "127.0.0.1"), int(os.environ.get("NANO_PULSE_PORT", "8787"))))
