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


class ScanFailed(RuntimeError):
    """The scan could not be performed. Never silently equivalent to 'nothing found'."""


def scan(paths, unreadable=None):
    """Findings for ``paths``. Every path that could not be read is also appended to ``unreadable``.

    A file this gate cannot open is NOT a file without secrets. It used to be treated as one -- a bare
    `continue` said nothing -- so a path that failed to open dropped out of the scan and the push went
    ahead. Now:

    - present but unreadable (a permission error, a directory): a FINDING, so the push is refused;
    - missing from the working tree (a tracked file deleted but not yet committed): not a finding,
      because there is no working-tree content to read, but still named in ``unreadable`` so the
      caller can say out loud that it was not scanned. It is never silent.

    Callers that pass only paths are unaffected.
    """
    findings = []
    for path in paths:
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                text = f.read()
        except FileNotFoundError:
            if unreadable is not None:
                unreadable.append(path)
            continue
        except OSError as exc:
            # The file is there and could not be read. Reporting clean for it would be the gate
            # lying, so it is refused instead: this hook exists because nobody is watching at 3am.
            if unreadable is not None:
                unreadable.append(path)
            findings.append((path, 0, f"unreadable, so unscanned ({type(exc).__name__})"))
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
    r"""Every tracked path, as bytes on disk rather than as git chooses to display them.

    `-z`, and split on NUL. Without it git applies core.quotePath, which is ON by default: a path
    holding any non-ASCII byte comes back QUOTED and octal-escaped -- `"caf\303\251.py"`, literal
    double quotes included -- which open() cannot find. The old code swallowed that as an OSError and
    the gate reported clean. NUL-separated output is never quoted and never escaped.

    splitlines() was a second route to the same place: it breaks on \v, \f, \x1c-\x1e, \x85, U+2028
    and U+2029, none of which git uses to separate records under -z.

    surrogateescape because a filename is bytes: an undecodable one must round-trip to something
    open() can use, not raise inside the gate. This is the same fix receipts.commit_proof carries.
    """
    r = subprocess.run(["git", "ls-files", "-z"], capture_output=True, text=True,
                       errors="surrogateescape")
    if r.returncode != 0:
        # No listing means no scan. Returning [] read as "clean" and let every push through.
        raise ScanFailed(f"git ls-files failed ({r.returncode}): {r.stderr.strip()[:200]}")
    return [p for p in r.stdout.split("\0") if p.strip()]


if __name__ == "__main__":
    unreadable = []
    try:
        hits = scan(sys.argv[1:] or tracked(), unreadable)
    except ScanFailed as exc:
        print(f"refusing to push: the secret scan could not run ({exc}). Nothing was published.",
              file=sys.stderr)
        sys.exit(2)
    for path, lineno, name in hits:
        print(f"SECRET? {path}:{lineno} looks like a {name}", file=sys.stderr)
    refused = {path for path, _, _ in hits}
    for path in unreadable:
        if path not in refused:
            # Missing from the working tree. Not refused, but never silent either.
            print(f"NOT SCANNED {path}: not in the working tree", file=sys.stderr)
    if hits:
        print(f"refusing to push: {len(hits)} finding(s). Nothing was published.", file=sys.stderr)
    sys.exit(1 if hits else 0)
