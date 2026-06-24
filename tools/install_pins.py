#!/usr/bin/env python3
"""
install_pins — install the pinned ciris-* wheels with propagation-race retry.

Why this exists
---------------
Every workflow that installs the matrix pins does a plain ``pip install
ciris-foo==X``. When a matrix bump is pushed within minutes of publishing the
wheels, a CI runner can hit a PyPI/Fastly CDN edge that hasn't propagated the
fresh version yet → ``ERROR: No matching distribution found for ciris-foo==X``.
A sibling cell on the *identical* pins, hitting a fresh edge, passes. The tell
is always: one cell red while its siblings on the same pins are green.

This is a transient propagation race, NOT a pin conflict — so the install
should *retry on that specific failure* and otherwise fail fast. A genuine
``ResolutionImpossible`` (two pins that truly can't coexist) must still go red
immediately, with no wasted retry time, so a real regression isn't masked.

What it does
------------
1. Reads the pins from ``matrices/current.yaml`` (``stack`` mapping).
2. Runs ``pip install <pin>...`` (optionally ``--ignore-requires-python`` for
   the Chaquopy bundle path).
3. On failure, classifies the pip output:
   - **propagation race** (no-matching-distribution / can't-find-version for a
     pinned ciris-* package) → wait with backoff and retry.
   - **anything else** (ResolutionImpossible, real conflict, build error,
     network down) → fail immediately, surfacing pip's output.

Usage
-----
    python tools/install_pins.py                      # normal cells
    python tools/install_pins.py --ignore-requires-python   # chaquopy bundle
    python tools/install_pins.py --matrix path/to/current.yaml
    python tools/install_pins.py --attempts 6 --delay 10

Exit status: 0 = installed; 1 = real failure (or retries exhausted).
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
import time

# pip emits these when a version genuinely isn't on the index edge yet. We only
# treat it as a propagation race when it names one of the *pinned* packages.
_PROPAGATION_PATTERNS = (
    re.compile(r"No matching distribution found for\s+(\S+)", re.I),
    re.compile(r"Could not find a version that satisfies the requirement\s+(\S+)", re.I),
)
# If pip reports a true resolver conflict, do NOT retry — that's a real pin bug.
_HARD_CONFLICT = re.compile(
    r"ResolutionImpossible|conflicting dependencies|"
    r"is incompatible|cannot install.*because these package versions have",
    re.I,
)


def load_pins(matrix_path: str) -> dict[str, str]:
    import yaml  # local import so --help works without PyYAML

    stack = yaml.safe_load(open(matrix_path))["stack"]
    # Only the wheels that ship on PyPI (commented-out entries are already
    # stripped by safe_load; values are version strings).
    return {pkg: str(ver) for pkg, ver in stack.items()}


def _is_propagation_race(output: str, pins: dict[str, str]) -> bool:
    if _HARD_CONFLICT.search(output):
        return False
    pinned_names = {p.lower() for p in pins}
    for pat in _PROPAGATION_PATTERNS:
        for m in pat.finditer(output):
            # the matched requirement text starts with the package name
            req = m.group(1).strip().lower()
            name = re.split(r"[=<>!~ ]", req, 1)[0]
            if name in pinned_names:
                return True
    return False


def install(pins: dict[str, str], *, ignore_requires_python: bool,
            attempts: int, delay: float) -> int:
    args = [f"{pkg}=={ver}" for pkg, ver in pins.items()]
    cmd = [sys.executable, "-m", "pip", "install"]
    if ignore_requires_python:
        cmd.append("--ignore-requires-python")
    cmd += args

    flag = " --ignore-requires-python" if ignore_requires_python else ""
    print(f"Installing pinned ciris-* wheels{flag}: {args}", flush=True)

    for attempt in range(1, attempts + 1):
        proc = subprocess.run(cmd, capture_output=True, text=True)
        sys.stdout.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        sys.stdout.flush()
        if proc.returncode == 0:
            if attempt > 1:
                print(f"::notice::pins installed on attempt {attempt}/{attempts} "
                      "(recovered from a PyPI propagation race)", flush=True)
            return 0

        combined = proc.stdout + proc.stderr
        if attempt < attempts and _is_propagation_race(combined, pins):
            wait = delay * attempt  # linear backoff
            print(f"::warning::pinned wheel not yet on this PyPI/CDN edge "
                  f"(propagation race) — attempt {attempt}/{attempts} failed; "
                  f"retrying in {wait:.0f}s", flush=True)
            time.sleep(wait)
            continue

        # Real failure (conflict, build error, or retries exhausted).
        reason = ("retries exhausted (still a propagation race)"
                  if _is_propagation_race(combined, pins)
                  else "non-transient pip failure — NOT retried")
        print(f"::error::pin install failed: {reason}", flush=True)
        return proc.returncode

    return 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="install_pins", description=__doc__)
    p.add_argument("--matrix", default="matrices/current.yaml",
                   help="path to the pin matrix (default: matrices/current.yaml)")
    p.add_argument("--ignore-requires-python", action="store_true",
                   help="bypass the metadata floor (Chaquopy bundle path)")
    p.add_argument("--attempts", type=int, default=6,
                   help="max install attempts on a propagation race (default 6)")
    p.add_argument("--delay", type=float, default=10.0,
                   help="base backoff seconds; grows linearly per attempt (default 10)")
    a = p.parse_args(argv)

    pins = load_pins(a.matrix)
    return install(pins, ignore_requires_python=a.ignore_requires_python,
                   attempts=a.attempts, delay=a.delay)


if __name__ == "__main__":
    raise SystemExit(main())
