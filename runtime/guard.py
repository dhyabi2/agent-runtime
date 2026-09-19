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
# A write is not six commands. An editor is a write; so is an interpreter, a copy, a link, a patch
# and a redirection. `vi ~/.swarm/wallet.json` was allowed until 2026-09-19 because it was not listed.
RAILS_WRITE_RE = re.compile(
    r"^(?:sudo\s+)?(?:rm|mv|cp|tee|truncate|chmod|chown|chattr|dd|ln|install|rsync|patch|shred|split"
    r"|sed\s+-i|perl\s+-i|vi|vim|nvim|view|nano|pico|emacs|ed|joe|micro|code|gedit|kate"
    r"|python3?|perl|ruby|node|php|busybox|git)\b")
RAILS_REDIRECT_RE = re.compile(
    r">>?\s*\S*(?:/swarm/guard\.py|/etc/swarm/env|\.swarm/wallet\.json|sshd_config|authorized_keys)")

# The ONLY permitted shape for a command that names the seed or the env: sourcing it so the program
# that follows inherits the variables. Everything else is refused, whatever program is asking.
SECRET_SAFE_RE = re.compile(r"^(?:set\s+[-+]a|(?:\.|source)\s+\S*(?:env|\.env)\s*)$")

_SPLIT = re.compile(r"&&|\|\||;|\||\n")


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

    if RAILS_RE.search(cmd) and (RAILS_REDIRECT_RE.search(cmd)
                                 or any(RAILS_WRITE_RE.match(p) for p in parts)):
        return ("Blocked: that edits the rails themselves (this guard, the env, the wallet, ssh). You may "
                "rewrite any other part of yourself freely — but not the thing that checks you.")
    return None
