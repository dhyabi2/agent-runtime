#!/usr/bin/env python3
"""Refuse to publish a secret. The repository is PUBLIC and the agent pushes to it unattended, so this
runs as a pre-push hook: a finding pushes nothing. Owner's standing rule, and the reason it is a hook and
not a guideline is that nobody is watching at 3am."""
import re, subprocess, sys

PATTERNS = [
    ("nano seed/private key", re.compile(r"\b[0-9A-F]{64}\b")),
    ("nano-gpt key",          re.compile(r"\bsk-nano-[0-9a-f-]{16,}")),
    ("openai-style key",      re.compile(r"\bsk-[A-Za-z0-9_-]{24,}")),
    ("github token",          re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}")),
    ("vercel token",          re.compile(r"\bvck_[A-Za-z0-9]{20,}")),
    ("private key block",     re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("bearer header",         re.compile(r"Authorization:\s*Bearer\s+[A-Za-z0-9._-]{20,}")),
]
ALLOW = re.compile(r"(?:EXAMPLE|PLACEHOLDER|<[a-z-]+>|xxx+|0{16,}|test[_-]?fixture)", re.I)


def scan(paths):
    findings = []
    for path in paths:
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if ALLOW.search(line):
                continue
            for name, rx in PATTERNS:
                if rx.search(line):
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
