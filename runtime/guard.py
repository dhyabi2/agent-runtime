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
import posixpath
import re
import shlex

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
# Each rail is a run of whole path components: a word names it when, with the shell's quoting undone,
# its components contain that run. Whole components, so `test_sshd_config.py` and
# `/etc/swarm/environment.example` are not rails; quoting undone, so `"/opt/swarm/swarm/"guard.py`
# and `gu\ard.py` are. sshd_config.d is included by sshd_config, and sshd reads authorized_keys2.
RAIL_PATHS = ("swarm/guard.py", "etc/swarm/env", ".swarm/wallet.json",
              "sshd_config", "sshd_config.d", "authorized_keys", "authorized_keys2")
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
# So the question is turned round: a command naming a rail is refused unless EVERY piece of it is
# recognisably a READ. Reads stay possible on purpose -- an agent that cannot read its own rules
# cannot follow them -- but only in these shapes, and anything unrecognised is refused rather than
# waved past.
#
# Every piece, not only the piece that names the rail: a read word is only a read if nothing earlier
# in the same command changed what that word runs. `cat(){ rm "$1";}; cat <rail>`, `export
# PATH=/evil; cat <rail>` and `env PATH=/evil cat <rail>` all end in a fragment that says `cat`.
#
# Not on the list, deliberately: `rg` (`--pre <cmd>` runs a program per file, and its config file
# can add that flag silently), `less`/`more` (shell escapes and LESSOPEN; a pager is useless to an
# agent without a terminal anyway). grep, head and tail do the same reads and run nothing.
RAILS_READ_WORDS = frozenset((
    "cat", "head", "tail", "nl", "wc", "grep", "egrep", "fgrep", "stat", "ls", "file", "md5sum",
    "sha256sum", "sha1sum", "cmp", "diff", "realpath", "readlink", "dirname", "basename", "test", "["))
# On a rail command the env may be sourced only from the rail itself: SECRET_SAFE_RE below accepts
# any file whose name ends in `env`, and `. /tmp/x/env; cat <rail>` would let that file redefine cat.
_TRUSTED_SETUP_RE = re.compile(r"^(?:set\s+[-+]a|(?:\.|source)\s+/etc/swarm/env)$")

# Wrappers that run the rest of their arguments as a command, each with the ONLY options it may
# carry: (options without a value, options that take a value). Anything else -- an unknown option,
# `sudo -i`/`-s` (a login shell reads profiles), `env -u`, `exec -a` -- leaves the wrapper unpeeled,
# and an unpeeled fragment is not a read, so a miss here costs a false refusal, never a write.
_WRAPPERS = {
    "sudo": ({"-n", "-H", "-E", "-k", "-S", "--non-interactive"}, {"-u", "-g", "--user", "--group"}),
    "doas": ({"-n"}, {"-u"}),
    "env": (set(), set()),
    "nohup": (set(), set()),
    "setsid": (set(), set()),
    "exec": (set(), set()),
    "command": (set(), set()),
    "time": ({"-p"}, set()),
    "nice": (set(), {"-n"}),
    "ionice": ({"-t"}, {"-c", "-n"}),
    "stdbuf": (set(), {"-i", "-o", "-e"}),
    "timeout": ({"--foreground", "--preserve-status", "-v", "--verbose"},
                {"-s", "-k", "--signal", "--kill-after"}),
    "xargs": ({"-r", "-0", "-t", "--no-run-if-empty", "--null"}, {"-n", "-L", "-P"}),
}
# Only these may be set on the way to a read. PATH, BASH_ENV, LD_PRELOAD, RIPGREP_CONFIG_PATH and
# every other variable that decides what a word runs are not on it.
_SAFE_ASSIGN_RE = re.compile(r"^(?:LC_[A-Z]+|LANG|LANGUAGE|TZ|TERM|COLUMNS|LINES|NO_COLOR)=[^=]*$")
_DURATION_RE = re.compile(r"^\d+(?:\.\d+)?[smhd]?$")
_SHELLS = frozenset(("sh", "bash", "dash"))      # zsh reads ~/.zshenv even for -c, so it is not here
_FIND_WRITES = frozenset(("-delete", "-fprint", "-fprint0", "-fprintf", "-fls", "-ok", "-okdir"))
_LOCAL_HOST_RE = re.compile(r"^(?:localhost|127\.|0\.0\.0\.0|::1|\[::1\])", re.I)
# Shapes that run a second command inside what looks like a read: substitution, process
# substitution, and a lone `&` (background-and-continue). `2>&1` and `&>` are redirections.
_HIDDEN_COMMAND_RE = re.compile(r"`|\$\(|[<>]\(|(?<![>&])&(?![>&])")
_FUNCTION_DEF_RE = re.compile(r"\(\s*\)")
_GLOB_RE = re.compile(r"[*?\[\]{}]")


def _split_unquoted(cmd):
    """Split a shell command on ; && || | |& and newline, but not inside quotes or after a backslash.

    `grep -E 'a|b' <rail>` is one command; `find ... -exec cat {} ';'` is one command. None if a
    quote is left open, which bash would refuse to run as written anyway.
    """
    parts, cur, i, q, n = [], [], 0, None, len(cmd)
    while i < n:
        c = cmd[i]
        if q == "'":
            q = None if c == "'" else q
            cur.append(c); i += 1; continue
        if c == "\\" and i + 1 < n:
            cur.append(cmd[i:i + 2]); i += 2; continue
        if q == '"':
            q = None if c == '"' else q
            cur.append(c); i += 1; continue
        if c in "'\"":
            q = c; cur.append(c); i += 1; continue
        if c in ";|\n" or cmd.startswith("&&", i):
            if c == "|" and cur and cur[-1] == ">":          # `>|` is a redirection, not a pipe
                cur.append(c); i += 1; continue
            parts.append("".join(cur)); cur = []
            i += 2 if cmd.startswith(("&&", "||", "|&", ";;"), i) else 1
            continue
        cur.append(c); i += 1
    if q:
        return None
    parts.append("".join(cur))
    return [p.strip() for p in parts if p.strip()]


def _unquoted(fragment):
    """(text bash will expand, text outside every quote). Single-quoted text expands nothing;
    double-quoted text still expands `$`; only text outside all quotes globs."""
    expands, bare, i, q, n = [], [], 0, None, len(fragment)
    while i < n:
        c = fragment[i]
        if q == "'":
            q = None if c == "'" else q
        elif c == "\\" and i + 1 < n:
            i += 1
        elif q == '"':
            q = None if c == '"' else q
            if q:
                expands.append(c)
        elif c in "'\"":
            q = c
        else:
            expands.append(c); bare.append(c)
        i += 1
    return "".join(expands), "".join(bare)


def _peel(argv):
    """Strip permitted wrappers off the front of argv. Returns (argv, peeled_any) or None."""
    peeled = False
    while argv and argv[0] in _WRAPPERS:
        word, (flags, takes_value) = argv[0], _WRAPPERS[argv[0]]
        rest, i = argv[1:], 0
        while i < len(rest) and rest[i].startswith("-") and rest[i] != "-":
            t = rest[i]
            if t == "--":
                i += 1; break
            if t in flags:
                i += 1
            elif t in takes_value:
                i += 2
            elif any(t.startswith(o + "=") for o in takes_value if o.startswith("--")):
                i += 1
            elif any(t.startswith(o) and len(t) > 2 for o in takes_value if len(o) == 2):
                i += 1                                    # attached value: -uroot, -n10, -oL
            else:
                return None
        if word in ("env", "sudo"):
            while i < len(rest) and "=" in rest[i] and not rest[i].startswith("-"):
                if not _SAFE_ASSIGN_RE.match(rest[i]):
                    return None
                i += 1
        if word == "timeout":
            if i >= len(rest) or not _DURATION_RE.match(rest[i]):
                return None
            i += 1
        if i > len(rest):
            return None
        argv, peeled = rest[i:], True
        if word == "xargs":                       # xargs appends stdin to the argv: a plain read only
            return (argv, peeled) if argv and argv[0] in RAILS_READ_WORDS else None
    return argv, peeled


def _script_is_reads(script, depth):
    parts = _split_unquoted(script)
    return bool(parts) and all(_is_read(p, depth + 1) for p in parts)


def _argv_is_read(argv, depth, globby=False):
    got = _peel(argv)
    if not got or not got[0]:
        return False
    argv, peeled = got
    word = argv[0]
    if word in _SHELLS or word == "find" or word == "ssh" or peeled:
        if globby:
            return False                 # a glob next to a wrapper or an exec can expand into a command
    if word in _SHELLS:
        # Only `-c SCRIPT` as the last argument, with no option that loads a profile (-l, -i).
        for k in range(1, len(argv)):
            if re.fullmatch(r"-[eux]*c[eux]*", argv[k]):
                return k == len(argv) - 2 and _script_is_reads(argv[k + 1], depth)
            if not re.fullmatch(r"-[eux]+", argv[k]):
                return False
        return False
    if word == "find":
        i = 1
        while i < len(argv):
            if argv[i] in _FIND_WRITES:
                return False
            if argv[i] in ("-exec", "-execdir"):
                j = i + 1
                while j < len(argv) and argv[j] not in (";", "+"):
                    j += 1
                if j >= len(argv) or not _argv_is_read(argv[i + 1:j], depth + 1):
                    return False
                i = j
            i += 1
        return True
    if word == "ssh":
        # Local options are where ssh runs local commands (-o ProxyCommand=, -F config), so only
        # these few are accepted. The remote command is then held to the same rule as a -c script.
        i = 1
        while i < len(argv) and argv[i].startswith("-"):
            if re.fullmatch(r"-[46Tqntv]+", argv[i]) or re.fullmatch(r"-[pil]\S+", argv[i]):
                i += 1
            elif argv[i] in ("-p", "-i", "-l"):
                i += 2
            else:
                return False
        if i >= len(argv) - 1 or _LOCAL_HOST_RE.match(argv[i].rsplit("@", 1)[-1]):
            return False                 # no remote command, or "remote" is this box
        return _script_is_reads(" ".join(argv[i + 1:]), depth)
    return word in RAILS_READ_WORDS


def _is_read(fragment, depth=0):
    """True only if `fragment`, all the way down, is one of the permitted reads.

    Permitted wrappers (with only their permitted options) are peeled; a shell's -c script, an ssh
    remote command and every find -exec body must themselves be reads; a find must write nothing.
    The answer is about the whole fragment: `rm -- <rail> -exec cat {} +` contains a read-shaped
    piece and is still an rm. Any `$` expansion other than $HOME, a function definition, or a
    substitution makes it not a read. Depth-bounded; anything unrecognised is not a read.
    """
    if depth > 4 or _HIDDEN_COMMAND_RE.search(fragment) or _FUNCTION_DEF_RE.search(fragment):
        return False
    expands, bare = _unquoted(fragment)
    if re.search(r"\$(?!HOME\b|\{HOME\})", expands):
        return False
    try:
        argv = shlex.split(fragment)
    except ValueError:
        return False
    globby = bool(_GLOB_RE.search(re.sub(r"(?:^|\s)(?:\{\}|\[|\])(?=\s|$)", " ", bare)))
    return _argv_is_read(argv, depth, globby)


# Words are cut at whatever cannot be part of a path (`of=`, `f=@`, `host:`, `open(`, `$HOME`),
# after the quoting is undone. Commas are cut later, outside braces, where they are not a brace's.
_WORD_SPLIT_RE = re.compile(r"[\s;&|<>()=`$:@]+")
_ANSI_C_ESCAPE_RE = re.compile(r"\$'[^']*\\")     # $'\x67uard.py' spells a path no regex can read
_REDIRECT_OP_RE = re.compile(r"^[<>&|0-9]*>[<>&|]*$")
# A run of glob components longer than this cannot be one rail, unless `**`s pad it out.
_RAIL_DEPTH = max(r.count("/") for r in RAIL_PATHS) + 1 + 3


def _plain(text):
    """The text with every quote and backslash removed: `"/opt/swarm/"gu\\ard.py` is that path to bash."""
    return re.sub(r"['\"\\]", "", text)


def _brace_expand(word, budget=64):
    """bash's {a,b} expansion. A {x..y} sequence becomes `*`, and more than the budget becomes `**`:
    each is wider than what it replaces, never narrower."""
    first, last = word.find("{"), word.rfind("}")
    if first == -1 or last < first:
        return [word]
    if word.count("{") > 6:
        return [word[:first] + "**" + word[last + 1:]]
    start = first
    while start != -1:
        depth, alts, mark, k = 0, [], start + 1, start
        for k in range(start, len(word)):
            if word[k] == "{":
                depth += 1
            elif word[k] == "}":
                depth -= 1
                if depth == 0:
                    break
            elif word[k] == "," and depth == 1:
                alts.append(word[mark:k]); mark = k + 1
        else:
            return [word]                             # never closed: bash leaves it as written
        pre, body, post = word[:start], word[start + 1:k], word[k + 1:]
        if alts:
            out = []
            for alt in alts + [word[mark:k]]:
                out.extend(_brace_expand(pre + alt + post, budget))
                if len(out) > budget:
                    return _brace_expand(pre + "**" + post, budget)
            return out
        if re.fullmatch(r"-?\w+\.\.-?\w+(?:\.\.-?\d+)?", body):
            return _brace_expand(pre + "*" + post, budget)
        start = word.find("{", start + 1)
    return [word]


def _glob_re(glob):
    """A shell glob as a regex: `*` and `?` stay inside one component, `**` crosses them, and a
    bracket class becomes any one character (wider than the class, never narrower)."""
    out, i = [], 0
    while i < len(glob):
        if glob.startswith("**/", i):
            out.append("(?:.*/)?"); i += 3; continue
        if glob.startswith("**", i):
            out.append(".*"); i += 2; continue
        c = glob[i]
        if c == "*":
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "[" and glob.find("]", i + 2) != -1:
            out.append("[^/]"); i = glob.find("]", i + 2)
        else:
            out.append(re.escape(c))
        i += 1
    return re.compile("".join(out))


def _path_is_rail(path):
    """True if `path`, or any file a glob in it could expand to, contains a rail's components."""
    for p in {path, posixpath.normpath(path)}:
        if not _GLOB_RE.search(p):
            if any(f"/{r}/" in f"/{p}/" for r in RAIL_PATHS):
                return True
            continue
        comps = p.split("/")
        for i in range(len(comps)):
            for j in range(i + 1, min(i + _RAIL_DEPTH, len(comps)) + 1):
                rx = _glob_re("/".join(comps[i:j]))
                if any(rx.fullmatch(r) for r in RAIL_PATHS):
                    return True
    return False


def _names_rail(text):
    """True if any word in `text` is, or could expand to, a rail path. When unsure, it does."""
    if _ANSI_C_ESCAPE_RE.search(text):
        return True
    for word in _WORD_SPLIT_RE.split(_plain(text)):
        for expanded in _brace_expand(word):
            if any(piece and _path_is_rail(piece) for piece in expanded.split(",")):
                return True
    return False


def _writes_to_rail(fragment):
    """True if a redirection in `fragment` targets a rail, however the target is quoted. A fragment
    shlex cannot tokenise counts as one."""
    try:
        lex = shlex.shlex(fragment, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        tokens = list(lex)
    except ValueError:
        return True
    return any(_REDIRECT_OP_RE.match(t) and _names_rail(nxt) for t, nxt in zip(tokens, tokens[1:]))

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
    # Matched with the quoting undone too: `cat "/root/.swarm/"wallet.json` is the same file.
    if any(SECRET_VAR_RE.search(t) or ENV_PATH_RE.search(t) for t in (cmd, _plain(cmd))):
        for p in parts:
            if not any(SECRET_VAR_RE.search(t) or ENV_PATH_RE.search(t) for t in (p, _plain(p))):
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

    if _names_rail(cmd):
        if _writes_to_rail(cmd):
            return RAILS_REFUSAL
        rparts = _split_unquoted(cmd)
        if rparts is None:
            return RAILS_REFUSAL
        # `. /etc/swarm/env && <program>` names a rail and is how every tool on the box is started.
        # The secret path above permits exactly that shape, so a command whose only mention of a
        # rail is that sourcing is not a rail command. Any other mention makes it one, and then
        # EVERY piece of it must be a read: an earlier piece can redefine what a read word runs.
        if any(_names_rail(p) and not SECRET_SAFE_RE.match(p) for p in rparts):
            for p in rparts:
                if not (_TRUSTED_SETUP_RE.match(p) or _is_read(p)):
                    return RAILS_REFUSAL
    return None
