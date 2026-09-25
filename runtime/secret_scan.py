#!/usr/bin/env python3
"""Refuse to publish a secret. The repository is PUBLIC and the agent pushes to it unattended, so this
runs as a pre-push hook: a finding pushes nothing. Owner's standing rule, and the reason it is a hook and
not a guideline is that nobody is watching at 3am."""
import re, subprocess, sys

PATTERNS = [
    # Case-insensitive on purpose. A seed is 32 bytes of hex and nothing fixes its case: the way
    # Python makes one, secrets.token_hex(32), returns it LOWERCASE, and account_from_seed reads
    # either case through bytes.fromhex. An uppercase-only pattern refused half the shapes a real
    # seed arrives in and published the other half.
    ("nano seed/private key", re.compile(r"\b[0-9A-F]{64}\b", re.I)),
    ("nano-gpt key",          re.compile(r"\bsk-nano-[0-9a-f-]{16,}")),
    ("openai-style key",      re.compile(r"\bsk-[A-Za-z0-9_-]{24,}")),
    ("github token",          re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}")),
    ("vercel token",          re.compile(r"\bvck_[A-Za-z0-9]{20,}")),
    ("private key block",     re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("bearer header",         re.compile(r"Authorization:\s*Bearer\s+[A-Za-z0-9._-]{20,}")),
]
# Two kinds of exemption, and the difference between them is the whole of this fix.
#
# An ANNOTATION is something a person writes ABOUT the line — "this value is deliberate, I have read
# it". It says nothing about the value's shape, so a line-level exemption is the only thing it can be,
# and it stays one: `# test-fixture: a PUBLIC key, never a seed` is the convention already in use.
#
# A PLACEHOLDER describes the VALUE — a redacted or invented secret. Applied to the whole line it
# excused every real secret that merely shared a line with it, and these shapes are common enough that
# it was not hypothetical: `xxx+` matches an `XXX` todo marker, `<[a-z-]+>` matches any bare HTML tag
# (`<code>`, `<br>`), and `0{16,}` matches any raw XNO amount. So a placeholder must now BE the match.
ANNOTATION = re.compile(r"(?:EXAMPLE|PLACEHOLDER|test[_-]?fixture)", re.I)
PLACEHOLDER = re.compile(r"(?:<[a-z-]+>|xxx+|0{16,})", re.I)

# Kept, and kept equal to the union of the two, because other rails import this name.
ALLOW = re.compile(f"(?:{ANNOTATION.pattern}|{PLACEHOLDER.pattern})", re.I)


def scan(paths):
    findings = []
    for path in paths:
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if ANNOTATION.search(line):
                continue
            for name, rx in PATTERNS:
                # A finding needs one match that is not itself a placeholder. Every match is weighed,
                # not just the first, so a real key sitting beside a redacted one is still refused.
                if any(not PLACEHOLDER.search(m.group(0)) for m in rx.finditer(line)):
                    findings.append((path, lineno, name))   # never the matched text itself
                    break
    return findings


def tracked():
    out = subprocess.run(["git", "ls-files"], capture_output=True, text=True).stdout
    return [p for p in out.splitlines() if p.strip()]


if __name__ == "__main__":
    hits = scan(sys.argv[1:] or tracked())
    for path, lineno, name in hits:
        print(f"SECRET? {path}:{lineno} looks like a {name}", file=sys.stderr)
    if hits:
        print(f"refusing to push: {len(hits)} finding(s). Nothing was published.", file=sys.stderr)
    sys.exit(1 if hits else 0)
