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
ALLOW = re.compile(r"(?:EXAMPLE|PLACEHOLDER|<[a-z-]+>|xxx+|0{16,}|test[_-]?fixture)", re.I)


class ScanFailed(RuntimeError):
    """The scan could not be performed. Never silently equivalent to 'nothing found'."""


def scan(paths):
    findings = []
    for path in paths:
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                text = f.read()
        except FileNotFoundError:
            # Tracked but absent from the working tree (a deletion not yet committed). There is no
            # content here to publish, so this is not a finding.
            continue
        except OSError as exc:
            # The file is there and could not be read. Reporting clean for it would be the gate
            # lying, so it is refused instead: this hook exists because nobody is watching at 3am.
            findings.append((path, 0, f"unreadable, so unscanned ({type(exc).__name__})"))
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
    r"""Every tracked path, exactly as it is on disk.

    `-z` is not a detail. Without it `git ls-files` applies core.quotePath, so a path holding any
    non-ASCII byte comes back quoted and octal-escaped -- `caf\303\251.py`, quotes included -- which
    open() cannot find. The old code swallowed that as an OSError and the gate reported clean.
    NUL-separated output is never quoted and never escaped.
    """
    r = subprocess.run(["git", "ls-files", "-z"], capture_output=True, text=True)
    if r.returncode != 0:
        # No listing means no scan. Returning [] read as "clean" and let every push through.
        raise ScanFailed(f"git ls-files failed ({r.returncode}): {r.stderr.strip()[:200]}")
    return [p for p in r.stdout.split("\0") if p.strip()]


if __name__ == "__main__":
    try:
        hits = scan(sys.argv[1:] or tracked())
    except ScanFailed as exc:
        print(f"refusing to push: the secret scan could not run ({exc}). Nothing was published.",
              file=sys.stderr)
        sys.exit(2)
    for path, lineno, name in hits:
        print(f"SECRET? {path}:{lineno} looks like a {name}", file=sys.stderr)
    if hits:
        print(f"refusing to push: {len(hits)} finding(s). Nothing was published.", file=sys.stderr)
    sys.exit(1 if hits else 0)
