# agent-runtime — audit, 2026-09-29

Audited at `be20a58` (head of `main`). Python 3.11.15, stdlib plus `pytest`.

**On a bare checkout the suite is green: 93 passed, 1 skipped, 31 subtests.**
**After following the README's install it is not.** That is the first finding.

## What was checked

- **The README, run rather than read** — the clone URL, the venv, the pip install, the
  `cp systemd/*`, the `systemctl enable`, and `git add -A` afterwards.
- `runtime/guard.py` — every rule in `refuse()`, probed with commands rather than read:
  the money lock, the bare-env rule, the secret/seed path, the outreach rule, the X rule,
  the rails lock.
- `runtime/receipts.py`, `runtime/secret_scan.py`, `lib/journal.py`, `runtime/modeld.py`,
  `runtime/agent.py`, `hub.py` — entry points and the tests that pin them.
- Secret scan of the tree and of every path in history: **nothing found**. The one hit is
  `tests/test_secret_scan.py`'s own fixture token, which is what the scanner is tested
  against, and its copy in an untracked `__pycache__`.

## Found and fixed (this pull request)

**The README's install breaks the repository, twice, from one cause: it makes a
virtualenv inside the checkout and nothing excludes it.** The install block says

    git clone https://github.com/dhyabi2/agent-runtime /opt/swarm
    python3 -m venv /opt/swarm/venv

so `venv/` lands in the clone. Measured, on a fresh clone, running exactly those lines:

1. **`git add -A` stages 1119 paths of the virtualenv.** `.gitignore` carried
   `__pycache__/` and `*.pyc` and nothing else.
2. **The suite goes red, and blames the repository.**
   `tests/test_readme.py::third_party_imports` walked the checkout with `os.walk`,
   excluding only `.git`, `tests` and `audits`, so every module in the venv's
   site-packages was parsed as this repository's code:

       AssertionError: the code imports ['ConfigParser', 'Cython', 'HTMLParser',
       'IPython', ..., 'zope'], which the README never tells anyone to install

   76 modules, none of them imported by anything here. A reader has no way to tell that
   from a real missing dependency — and the two things they do first are follow the README
   and run the tests.

Fixed on both sides. The files are now asked of **git** (`git ls-files '*.py'`), so
anything untracked beside the code is not the code, with the `os.walk` fallback kept for
an installed copy and taught never to descend into a directory holding a `pyvenv.cfg`.
And `.gitignore` gains `venv/` and `.venv/`.

Proved: the venv law fails against the original walker
(`'a_module_this_repository_never_imports' unexpectedly found`), the ignore law fails
against the original `.gitignore` (`git does not ignore 'venv/bin/activate'`). With the
fix, **95 passed, 1 skipped, 31 subtests — with a real virtualenv sitting in the
checkout**, and `git add -A --dry-run` stages 2 paths instead of 1119.

## Found, fix proposed separately — branch `fix/rails-wrapper-bypass`

**The rails lock is defeated by one wrapper word.** `guard.py`'s own docstring says "an
agent that can edit its own guard has no guard", and `RAILS_WRITE_RE` is anchored with
`.match(p)` — so it only sees a write program at the *start* of a fragment. Probed
against the live guard:

    BLOCKED  rm /opt/swarm/swarm/guard.py
    ALLOWED  bash -c 'rm /opt/swarm/swarm/guard.py'
    ALLOWED  env rm /opt/swarm/swarm/guard.py
    ALLOWED  timeout 5 rm /opt/swarm/swarm/guard.py
    ALLOWED  nohup rm /opt/swarm/swarm/guard.py
    ALLOWED  find /opt/swarm -name guard.py -exec rm {} +

The wallet and the env survive this because the **secret** path fails closed — it refuses
any fragment naming them unless the fragment *is* a `source` — which is why
`bash -c 'cat /root/.swarm/wallet.json'` is still blocked. The rails path fails **open**
instead, so `guard.py`, `sshd_config` and `authorized_keys` are protected only for as
long as nobody types a wrapper. It is the lesson the same file already records one
comment higher ("A write is not six commands … Here it was every editor"), applied to
one branch and not the other.

That is a change to a security rail on a live runtime, so it is **not** self-merged.
The separate pull request narrows the gap without removing any read; the sound fix is to
make the rails path fail closed like the secret path, which needs a decision about which
reads stay allowed — an agent that cannot read its own rules cannot follow them — and
that decision is the owner's, not this audit's.

## Not changed

`_SPLIT` does not split on command substitution (`$(…)`, backticks), so a rail named only
inside a substitution is invisible to every rule, not just the rails one. Same class as
the above and the same reason to leave it: it is answered properly by failing closed, not
by another pattern.
