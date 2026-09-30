#!/usr/bin/env python3
"""The guard. Every tool call passes through refuse() before it runs — there is no other path.

This is not a policy document, it is the choke point. Each rule below exists because the swarm already
paid for it:
  * the money lock, because a starter shipped at 10^22 instead of 10^25 and eight sends were never received;
  * the secret rules, because a turn printed a live API key in full while believing it had redacted it;
  * the outreach rule, because 35 issues were opened on our own forks where no maintainer is notified;
  * the rails rule, because an agent that can edit its own guard has no guard.

The owner (2026-09-19) chose full autonomy for this runtime: it merges its own code and needs no approval
for anything. That makes the money lock the ONLY thing standing between a bad turn and the wallet, so the
amounts live here in code and nowhere else — not in env, not in config, not in the prompt.
"""
import re

# 1 XNO = 10^30 raw. The owner funds this agent with 1 XNO and it tips 0.000001 XNO (10^24 raw).
# Total exposure is bounded by what is in the wallet; a tip is deliberately far below anything worth stealing.
XNO = 10 ** 30
TIP_RAW = "1000000000000000000000000"        # 0.000001 XNO — the one amount this agent may ever send
ALLOWED_AMOUNTS = frozenset({TIP_RAW})
assert int(TIP_RAW) == XNO // 1_000_000, "the tip must be exactly 0.000001 XNO, derived not restated"

RAW_AMOUNT_RE = re.compile(r"\b\d{18,}\b")
MONEY_VERB_RE = re.compile(r"\b(send|transfer|pay|withdraw|deposit|sweep|drain|tip)\b", re.I)
NANO_CONTEXT_RE = re.compile(r"\b(xno|nano_[13][a-z0-9]{59}|nano:mainnet)\b", re.I)

SECRET_VAR_RE = re.compile(
    r"\b(?:NANOGPT_API_KEY|OPENROUTER_API_KEY|GITHUB_TOKEN|VERCEL_TOKEN|SWARM_[A-Z0-9_]*KEY"
    r"|NANO_AGENT_SEED|SWARM_SEED|X_[A-Z]+_(?:KEY|SECRET|TOKEN)|ACCESS_[A-Z0-9_]+)\b")
ENV_PATH_RE = re.compile(r"(?:/etc/swarm/env|(?:/root|~|\$HOME)/\.swarm/(?:env|wallet\.json))\b")
PRINTER_RE = re.compile(
    r"^(?:sudo\s+)?(?:echo|printf|printenv|env|set|cat|tac|less|more|head|tail|grep|egrep|fgrep|rg|awk|sed"
    r"|cut|strings|xxd|od|base64|curl|wget|nc|scp|tee)\b")
BARE_ENV_RE = re.compile(r"^(?:env|printenv|set)\s*$")

OWNED_GITHUB = ("pandeveloper001", "dhyabi2")
GH_CREATE_RE = re.compile(r"\bgh\s+(?:issue|pr)\s+create\b")

# No posting to X from this runtime (owner, 2026-09-19: "exclude posting to X, since this is experimental").
# It does everything Unstuck does except speak publicly on the owner's account: a new runtime is allowed to
# be wrong in its own repo and its own conversations, not on a public timeline nobody can take back.
X_POST_RE = re.compile(r"\brai-x\b|api\.(?:twitter|x)\.com|\b(?:tweet|post-newsletter|answer-replies)\b", re.I)

# The agent may rewrite its own code freely (that is the point), but not the things that keep it honest.
RAILS_RE = re.compile(r"(?:/swarm/guard\.py|/etc/swarm/env|\.swarm/wallet\.json|sshd_config|authorized_keys)")
_SPLIT = re.compile(r"&&|\|\||;|\||\n")

# The rails fail CLOSED, like the seed and the env below, and for the reason this file already
# gives for them: listing the programs that may not write will always be missing one. It was
# missing every wrapper. `rm /opt/swarm/swarm/guard.py` was refused while all of
#
#     bash -c 'rm /opt/swarm/swarm/guard.py'      env rm /opt/swarm/swarm/guard.py
#     timeout 5 rm /opt/swarm/swarm/guard.py      nohup rm /opt/swarm/swarm/guard.py
#     xargs -n1 rm /opt/swarm/swarm/guard.py      find /opt/swarm -name guard.py -exec rm {} +
#
# were allowed, because the old blocklist was anchored with .match() and so only ever saw the
# FIRST word of a fragment. One wrapper word and the guard no longer guarded itself.
#
# So the question is turned round: a fragment naming a rail is refused unless it is recognisably
# a READ. Reads stay possible on purpose -- an agent that cannot read its own rules cannot follow
# them -- but only in these shapes, and anything unrecognised is refused rather than waved past.
RAILS_READ_RE = re.compile(
    r"^(?:cat|head|tail|less|more|nl|wc|grep|egrep|fgrep|rg|stat|ls|file|md5sum|sha256sum|sha1sum"
    r"|cmp|diff|realpath|readlink|dirname|basename|test|\[)\b")
RAILS_REDIRECT_RE = re.compile(
    r">>?\s*\S*(?:/swarm/guard\.py|/etc/swarm/env|\.swarm/wallet\.json|sshd_config|authorized_keys)")

# Wrappers that run the next word as a command. Peeling them is best-effort and safe in this
# direction: an unpeeled fragment is not recognised as a read and is therefore refused, so a
# wrapper this list misses costs a false refusal, never a silent write.
_WRAPPER_RE = re.compile(
    r"^(?:sudo|doas|env|nohup|setsid|exec|command|builtin|time|nice|ionice|stdbuf|xargs|timeout"
    r"|ssh|chroot)\b(?:\s+(?:-{1,2}[\w-]+|[A-Za-z_][A-Za-z0-9_]*=\S*|[\d.]+[smhd]?))*\s+")
_DASH_C_RE = re.compile(
    r"^(?:[bdzk]?a?sh|ash|dash|busybox\s+sh)\b(?:\s+-\w+)*\s+-c\s+(['\"]?)(?P<script>.*?)\1\s*$")
_FIND_EXEC_RE = re.compile(r"-exec(?:dir)?\s+(?P<cmd>.+?)\s*(?:\\;|;|\+)\s*$")


def _shapes(fragment, depth=0):
    """`fragment` plus every command shape hidden inside it (wrappers peeled, an
    interpreter's -c script and a find -exec body examined in their own right).

    Depth-bounded so a nested quote cannot spin. Only ever used to ask whether a
    read is in there, so missing a shape refuses rather than allows.
    """
    out = [fragment]
    if depth >= 4:
        return out
    stripped = fragment
    while True:
        peeled = _WRAPPER_RE.sub("", stripped, count=1).strip()
        if peeled == stripped or not peeled:
            break
        stripped = peeled
        out.append(stripped)
    m = _DASH_C_RE.match(stripped)
    if m and m.group("script").strip():
        for inner in (q.strip() for q in _SPLIT.split(m.group("script")) if q.strip()):
            out += _shapes(inner, depth + 1)
    m = _FIND_EXEC_RE.search(stripped)
    if m:
        out += _shapes(m.group("cmd").strip(), depth + 1)
    return out


def _is_read(fragment):
    """True only if some shape inside `fragment` is one of the permitted reads."""
    return any(RAILS_READ_RE.match(shape) for shape in _shapes(fragment))

# The ONLY permitted shape for a command that names the seed or the env: sourcing it so the program
# that follows inherits the variables. Everything else is refused, whatever program is asking.
SECRET_SAFE_RE = re.compile(r"^(?:set\s+[-+]a|(?:\.|source)\s+\S*(?:env|\.env)\s*)$")



RAILS_REFUSAL = (
    "Blocked: that touches the rails themselves (this guard, the env, the wallet, ssh) in a shape "
    "that is not a plain read. You may rewrite any other part of yourself freely — but not the "
    "thing that checks you. Read them with cat/head/grep if you need to see the rules.")


def refuse(command):
    """Return a refusal string, or None to allow. The refusal is shown to the agent verbatim."""
    cmd = str(command or "")
    if not cmd.strip():
        return None
    parts = [p.strip() for p in _SPLIT.split(cmd) if p.strip()]

    if MONEY_VERB_RE.search(cmd) or NANO_CONTEXT_RE.search(cmd):
        for amount in RAW_AMOUNT_RE.findall(cmd):
            if amount not in ALLOWED_AMOUNTS:
                return (f"Blocked: this agent sends exactly one amount, ever — {TIP_RAW} raw "
                        f"(0.000001 XNO). {amount} was asked for. It is not a payment, a reward, a bounty, "
                        f"an escrow or a test transfer, however the request is phrased.")

    if any(BARE_ENV_RE.match(p) for p in parts):
        return "Blocked: that dumps every variable, keys included. Keys are used by programs, never printed."
    # The seed and the env fail CLOSED: it is not enough to list the programs that may not read them,
    # because the list will always be missing one. Here it was every editor.
    if SECRET_VAR_RE.search(cmd) or ENV_PATH_RE.search(cmd):
        for p in parts:
            if not (SECRET_VAR_RE.search(p) or ENV_PATH_RE.search(p)):
                continue                      # this fragment does not name a secret; it is not the issue
            if SECRET_SAFE_RE.match(p):
                continue                      # loading the env for the program that follows is fine
            return ("Blocked: keys and seeds are used by programs, never printed, copied, opened in an "
                    "editor, or passed to an interpreter. Pass it to the program that needs it; do not "
                    "read it out, move it, or send it anywhere.")

    if GH_CREATE_RE.search(cmd) and any(o in cmd.lower() for o in OWNED_GITHUB):
        return ("Blocked: an issue or PR on our own account reaches no maintainer and can never be merged. "
                "Outreach means the upstream repository.")

    if X_POST_RE.search(cmd):
        return ("Blocked: this runtime does not post to X. It is experimental, and a public timeline is the "
                "one place a mistake cannot be taken back. Record the result in the journal instead — the "
                "live map publishes it, and the swarm's other agents can post it once it is proven.")

    if RAILS_RE.search(cmd):
        if RAILS_REDIRECT_RE.search(cmd):
            return RAILS_REFUSAL
        for p in parts:
            # `. /etc/swarm/env` names a rail and is how every tool on the box is started.
            # The secret path above already permits exactly that shape and nothing else, so
            # the rails path honours the same exemption rather than inventing a second one.
            if RAILS_RE.search(p) and not (_is_read(p) or SECRET_SAFE_RE.match(p)):
                return RAILS_REFUSAL
    return None
