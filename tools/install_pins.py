#!/usr/bin/env python3
"""
install_pins — install the coherent set from the matrix, with a retry that
fires only on a PyPI propagation race.

Why this exists
---------------
Every workflow that installs the matrix set does so through here, so the
resolution of "matrix file → pip arguments" has exactly ONE implementation.
It used to have two: this file, plus a copy inlined in
``run-against-wheels.yml``. They drifted the moment the matrix grew a second
channel, and the inline copy would have silently stopped installing the
substrate at all — a green cell testing nothing.

Two channels, because the family ships two ways
-----------------------------------------------
``stack`` members are on PyPI and install as ``name==version``. ``substrate``
members are not, and install as ``git+{repo}@{tag}`` — pip builds those from
source. See ``matrices/current.yaml`` for why each member sits where it does.

The retry
---------
When a matrix bump is pushed within minutes of publishing a wheel, a CI runner
can hit a PyPI/Fastly CDN edge that hasn't propagated the fresh version yet →
``ERROR: No matching distribution found for ciris-foo==X``. A sibling cell on
the *identical* pins, hitting a fresh edge, passes. The tell is always: one
cell red while its siblings on the same pins are green.

That is a transient propagation race, NOT a pin conflict — so the install
retries on that specific failure and otherwise fails fast. A genuine
``ResolutionImpossible`` (two pins that truly can't coexist) must still go red
immediately, with no wasted retry time, so a real regression isn't masked.

A **git-ref member can never be a propagation race**: git refs don't propagate
through a CDN, and a failure there is a real one (bad tag, or a cargo build
that didn't compile). Those fail fast even when the message pattern-matches.

Usage
-----
    python tools/install_pins.py                        # normal cells
    python tools/install_pins.py --ignore-requires-python    # chaquopy bundle
    python tools/install_pins.py --matrix path/to/current.yaml
    python tools/install_pins.py --attempts 6 --delay 10
    python tools/install_pins.py --under-test ciris-edge     # skip the member
                                                            # supplied as an
                                                            # under-test wheel
    python tools/install_pins.py --overrides '{"ciris-persist": "git+…@v4.0-das"}'
    python tools/install_pins.py --print-args           # resolve only, no install

Exit status: 0 = installed; 1 = real failure (or retries exhausted).
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time

# pip emits these when a version genuinely isn't on the index edge yet. We only
# treat it as a propagation race when it names one of the *PyPI-pinned*
# packages — see `_is_propagation_race`.
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


def _norm(name: str) -> str:
    """`ciris_edge` and `ciris-edge` are the same member."""
    return name.replace("-", "_").lower()


def load_matrix(matrix_path: str) -> dict:
    import yaml  # local import so --help works without PyYAML

    return yaml.safe_load(open(matrix_path)) or {}


def load_pins(matrix_path: str) -> dict[str, str]:
    """The PyPI members only: {package: version}.

    Kept as its own function because the propagation-race classifier is scoped
    to exactly these — a git member is never subject to the race.
    """
    stack = load_matrix(matrix_path).get("stack") or {}
    return {pkg: str(ver) for pkg, ver in stack.items()}


_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def load_substrate(matrix_path: str) -> dict[str, str]:
    """The git-tag members: {package: "git+{repo}@{sha}"}.

    Resolved to the SHA, not the tag, on purpose: pip reuses a cached built
    wheel for a VCS requirement only when the ref is immutable. Pinning the tag
    would recompile the substrate in every cell of every run.
    """
    substrate = load_matrix(matrix_path).get("substrate") or {}
    specs: dict[str, str] = {}
    for pkg, entry in substrate.items():
        if isinstance(entry, str):
            # Tolerate a bare spec string, so a hand-edit of the matrix that
            # writes the URL directly still resolves.
            specs[pkg] = entry
            continue
        repo, tag, sha = entry.get("repo"), entry.get("tag"), entry.get("sha")
        if not repo or not tag or not sha:
            raise SystemExit(
                f"matrix substrate member {pkg!r} needs `repo`, `tag` AND `sha` "
                f"(got {entry!r}) — the tag is what a human reads, the sha is "
                f"what gets installed"
            )
        if not _SHA_RE.match(str(sha)):
            raise SystemExit(
                f"matrix substrate member {pkg!r} has sha {sha!r}, which is not "
                f"a full 40-character commit id — an abbreviated or tag-object "
                f"id defeats pip's immutable-ref caching"
            )
        specs[pkg] = f"git+{repo}@{sha}"
    return specs


def verify_refs(matrix_path: str) -> int:
    """Check every substrate `tag` still resolves upstream to its `sha`.

    The matrix records the same commit twice, in two forms. Two strings that
    can disagree is the failure mode this repo keeps filing against other
    people's build systems, so it is checked rather than trusted. Network-only
    and quick — no clone, no build.
    """
    substrate = load_matrix(matrix_path).get("substrate") or {}
    failures = []
    for pkg, entry in substrate.items():
        if not isinstance(entry, dict):
            continue
        repo, tag, sha = entry["repo"], entry["tag"], entry["sha"]
        proc = subprocess.run(
            ["git", "ls-remote", repo, f"refs/tags/{tag}^{{}}", f"refs/tags/{tag}"],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            failures.append(f"{pkg}: git ls-remote {repo} failed: {proc.stderr.strip()}")
            continue
        refs = dict(
            (line.split("\t")[1], line.split("\t")[0])
            for line in proc.stdout.strip().splitlines() if "\t" in line
        )
        # Prefer the dereferenced commit; a lightweight tag has no `^{}` entry.
        resolved = refs.get(f"refs/tags/{tag}^{{}}") or refs.get(f"refs/tags/{tag}")
        if resolved is None:
            failures.append(f"{pkg}: tag {tag} does not exist in {repo}")
        elif resolved != sha:
            failures.append(
                f"{pkg}: tag {tag} resolves to {resolved} but the matrix records "
                f"{sha} — the tag moved, or the sha was hand-edited"
            )
        else:
            print(f"ok  {pkg} {tag} → {sha}", flush=True)
    for f in failures:
        print(f"::error::{f}", flush=True)
    return 1 if failures else 0


def resolve_install_args(
    matrix_path: str,
    *,
    under_test: str | None = None,
    overrides: dict[str, str] | None = None,
) -> tuple[list[str], dict[str, str]]:
    """Build the pip argument list for the whole coherent set.

    Returns `(args, pypi_pins)` — `pypi_pins` is the subset the propagation
    classifier applies to.

    `under_test` names a member supplied separately as a built wheel artifact
    (a consumer repo testing its own build). That member is SKIPPED here so the
    under-test artifact is what ends up installed — installing the pinned
    version alongside it would mean the cell silently tests the pin instead of
    the artifact under test.

    `overrides` maps member name → any pip source spec, and wins over the
    matrix. An override for the under-test member is ignored (the artifact
    wins), and reported as such by the caller.
    """
    overrides = overrides or {}
    pypi = load_pins(matrix_path)
    git = load_substrate(matrix_path)

    args: list[str] = []
    applied_pypi: dict[str, str] = {}
    for pkg, spec in [(p, f"{p}=={v}") for p, v in pypi.items()] + list(git.items()):
        if under_test and _norm(pkg) == _norm(under_test):
            continue
        if pkg in overrides:
            args.append(overrides[pkg])
            continue
        args.append(spec)
        if pkg in pypi:
            applied_pypi[pkg] = pypi[pkg]
    return args, applied_pypi


def _is_propagation_race(output: str, pins: dict[str, str]) -> bool:
    """True only for "a PINNED PyPI version isn't on this index edge yet".

    `pins` must be the PyPI members alone. A git member reaching this function
    would make a bad tag look like a race and burn the full retry budget.
    """
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


def install(args: list[str], pins: dict[str, str], *,
            ignore_requires_python: bool, attempts: int, delay: float) -> int:
    cmd = [sys.executable, "-m", "pip", "install"]
    if ignore_requires_python:
        cmd.append("--ignore-requires-python")
    cmd += args

    flag = " --ignore-requires-python" if ignore_requires_python else ""
    print(f"Installing the coherent set{flag}: {args}", flush=True)

    for attempt in range(1, attempts + 1):
        proc = subprocess.run(cmd, capture_output=True, text=True)
        sys.stdout.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        sys.stdout.flush()
        if proc.returncode == 0:
            if attempt > 1:
                print(f"::notice::set installed on attempt {attempt}/{attempts} "
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

        # Real failure (conflict, build error, bad git tag, or retries exhausted).
        reason = ("retries exhausted (still a propagation race)"
                  if _is_propagation_race(combined, pins)
                  else "non-transient pip failure — NOT retried")
        print(f"::error::set install failed: {reason}", flush=True)
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
    p.add_argument("--under-test", default=None, metavar="PKG",
                   help="member supplied separately as a wheel artifact — skip it")
    p.add_argument("--overrides", default=None, metavar="JSON",
                   help="JSON object mapping member name → pip source spec")
    p.add_argument("--print-args", action="store_true",
                   help="print the resolved pip arguments and exit without installing")
    p.add_argument("--verify-refs", action="store_true",
                   help="check each substrate tag still resolves to its recorded "
                        "sha upstream, then exit (network only, no install)")
    a = p.parse_args(argv)

    if a.verify_refs:
        return verify_refs(a.matrix)

    try:
        overrides = json.loads(a.overrides or "{}")
    except json.JSONDecodeError as e:
        return _fail(f"--overrides is not valid JSON: {e}")
    if not isinstance(overrides, dict):
        return _fail(f"--overrides must decode to a JSON object, "
                     f"got {type(overrides).__name__}")

    args, pins = resolve_install_args(
        a.matrix, under_test=a.under_test, overrides=overrides)

    if overrides:
        applied = {k: v for k, v in overrides.items()
                   if not (a.under_test and _norm(k) == _norm(a.under_test))}
        ignored = set(overrides) - set(applied)
        print(f"overrides applied: {applied}", flush=True)
        if ignored:
            print(f"overrides ignored (under-test artifact wins): {sorted(ignored)}",
                  flush=True)

    if a.print_args:
        print("\n".join(args))
        return 0

    return install(args, pins, ignore_requires_python=a.ignore_requires_python,
                   attempts=a.attempts, delay=a.delay)


def _fail(msg: str) -> int:
    print(f"::error::{msg}", flush=True)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
