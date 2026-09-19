#!/usr/bin/env python3
"""swarm-modeld — one process owns every provider connection for the whole box.

Why a daemon and not a library call per agent:
  * ten agents each holding their own TLS pool is ten times the sockets and ten copies of the client.
  * the daily spend cap is a property of the KEY, not of an agent. Ten agents checking it independently
    raced past it on 2026-09-19 and the fleet burned its budget before anyone noticed.
  * a provider outage should be noticed ONCE and back off ONCE. That day the fleet restarted 3,556 times
    against a provider that was simply out of credits.

It answers on a unix socket, so nothing is exposed to the network. One JSON request per connection.
"""
import asyncio, json, os, time, urllib.request, urllib.error

SOCK = os.environ.get("SWARM_MODEL_SOCK", "/run/swarm/model.sock")
ENV_FILE = os.environ.get("SWARM_ENV", "/etc/swarm/env")
BASE = os.environ.get("SWARM_MODEL_BASE", "https://nano-gpt.com/api/v1")
MODEL = os.environ.get("SWARM_MODEL", "deepseek/deepseek-v4-flash-0731")
DAILY_USD = float(os.environ.get("SWARM_DAILY_USD", "3"))
HEADROOM = float(os.environ.get("SWARM_HEADROOM_USD", "0.25"))
BACKOFF_S = float(os.environ.get("SWARM_OUTAGE_BACKOFF_S", "300"))
TIMEOUT_S = float(os.environ.get("SWARM_MODEL_TIMEOUT_S", "180"))

_state = {"down_until": 0.0, "spend": None, "spend_at": 0.0, "calls": 0, "errors": 0,
          "consecutive": 0}

# How many failures in a row before one agent's bad luck becomes everyone's outage.
FAIL_THRESHOLD = int(os.environ.get("SWARM_FAIL_THRESHOLD", "3"))


def _note_failure(hard):
    """Record a failure and decide whether the provider is actually down.

    hard=True (no credit, HTTP 402) is believed immediately: it will not fix itself.
    Everything else must happen FAIL_THRESHOLD times in a row, and then waits a while
    that grows with the run, so a single slow call never stops ten agents.
    """
    _state["errors"] += 1
    _state["consecutive"] += 1
    if hard:
        _state["down_until"] = time.time() + BACKOFF_S
    elif _state["consecutive"] >= FAIL_THRESHOLD:
        over = _state["consecutive"] - FAIL_THRESHOLD + 1
        _state["down_until"] = time.time() + min(BACKOFF_S, 30.0 * over)


def _key():
    try:
        for line in open(ENV_FILE):
            k, _, v = line.partition("=")
            if k.strip() == "NANOGPT_API_KEY":
                return v.strip().strip('"')
    except OSError:
        pass
    return os.environ.get("NANOGPT_API_KEY", "")


def _spend_today():
    """Spend for the current UTC day, from the provider. Unknown counts as over budget: a loop that
    cannot see its own bill does not get to keep spending (the rule the Hermes loop already proved)."""
    key = _key()
    if not key:
        return None
    req = urllib.request.Request(f"{BASE}/usage", headers={"Authorization": f"Bearer {key}"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            d = json.load(r)
    except Exception:
        return None
    today = time.strftime("%Y-%m-%d", time.gmtime())
    rows = [x for x in (d.get("byDay") or []) if str(x.get("day") or x.get("date") or "").startswith(today)]
    try:
        return sum(float(x.get("netCostUsd") or x.get("costUsd") or 0) for x in rows)
    except Exception:
        return None


def _budget_ok():
    now = time.time()
    if now - _state["spend_at"] > 60:
        _state["spend"] = _spend_today()
        _state["spend_at"] = now
    s = _state["spend"]
    if s is None:
        return False, "spend unknown; treated as over budget"
    if s + HEADROOM >= DAILY_USD:
        return False, f"daily cap: ${s:.4f} of ${DAILY_USD}"
    return True, f"${s:.4f} of ${DAILY_USD}"


def _call(messages, max_tokens, model):
    key = _key()
    body = json.dumps({"model": model or MODEL, "max_tokens": max_tokens, "messages": messages}).encode()
    req = urllib.request.Request(f"{BASE}/chat/completions", data=body, method="POST",
                                 headers={"Authorization": f"Bearer {key}", "content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
        return json.load(r)


async def handle(reader, writer):
    try:
        raw = await asyncio.wait_for(reader.readline(), timeout=30)
        req = json.loads(raw or b"{}")
    except Exception as ex:
        writer.write(json.dumps({"ok": False, "error": f"bad request: {ex}"}).encode() + b"\n")
        await writer.drain(); writer.close(); return

    if req.get("op") == "health":
        ok, why = _budget_ok()
        out = {"ok": True, "budget_ok": ok, "budget": why, "calls": _state["calls"],
               "errors": _state["errors"], "down_until": _state["down_until"],
               "consecutive": _state["consecutive"]}
        writer.write(json.dumps(out).encode() + b"\n"); await writer.drain(); writer.close(); return

    now = time.time()
    if now < _state["down_until"]:
        out = {"ok": False, "retryable": True,
               "error": f"provider backing off for {int(_state['down_until'] - now)}s"}
        writer.write(json.dumps(out).encode() + b"\n"); await writer.drain(); writer.close(); return

    ok, why = _budget_ok()
    if not ok:
        out = {"ok": False, "retryable": True, "error": f"budget: {why}"}
        writer.write(json.dumps(out).encode() + b"\n"); await writer.drain(); writer.close(); return

    try:
        d = await asyncio.get_running_loop().run_in_executor(
            None, _call, req.get("messages") or [], int(req.get("max_tokens") or 2048), req.get("model"))
        ch = (d.get("choices") or [{}])[0]
        text = ((ch.get("message") or {}).get("content")) or ""
        finish = ch.get("finish_reason")
        _state["calls"] += 1
        # An empty completion is a FAILURE, not an answer. OpenClaw treated it as one and every turn died.
        if not text.strip():
            _note_failure(hard=False)
            out = {"ok": False, "retryable": True, "error": f"empty completion (finish_reason={finish})"}
        else:
            _state["consecutive"] = 0      # a success ends the run of failures; that is what makes it a run
            out = {"ok": True, "text": text, "finish_reason": finish, "usage": d.get("usage") or {}}
    except urllib.error.HTTPError as ex:
        code = ex.code
        # 402 is the only one believed on sight: no credit does not clear up by retrying.
        _note_failure(hard=(code == 402))
        out = {"ok": False, "retryable": True, "error": f"HTTP {code}"}
    except Exception as ex:
        # A timeout, a reset connection, a DNS blip. One of these is not an outage.
        _note_failure(hard=False)
        out = {"ok": False, "retryable": True, "error": f"{type(ex).__name__}: {ex}"}

    writer.write(json.dumps(out).encode() + b"\n")
    await writer.drain(); writer.close()


async def main():
    os.makedirs(os.path.dirname(SOCK), exist_ok=True)
    if os.path.exists(SOCK):
        os.unlink(SOCK)
    server = await asyncio.start_unix_server(handle, path=SOCK)
    os.chmod(SOCK, 0o600)
    print(f"swarm-modeld listening on {SOCK} model={MODEL} cap=${DAILY_USD}/day", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
