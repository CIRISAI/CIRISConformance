#!/usr/bin/env python3
"""
vendor_constitution — re-vendor ``reference/CIRIS_Constitution/`` from one
CIRISConstitution commit, in one step.

Why this exists
---------------
The vendored Constitution is a snapshot the tests cite by section number, and
``matrices/current.yaml``'s ``constitution.commit`` names the cut the snapshot
was taken from. Both have drifted apart before (the copy sat at rc4 while the
matrix named rc2), because the copy was made by hand. This script is the one
way to take the snapshot: it reads every file from the named commit with
``git show <commit>:<path>`` (it never checks out or modifies the source
checkout), writes them under ``reference/CIRIS_Constitution/``, and prints the
commit so the matrix and ``reference/README.md`` can name the same one.

The file set is the one PRs #15/#17/#101 vendored: ``constitution/*.md``, the
root ``CHANGELOG.md`` and ``README.md``, and ``manifests/WIRE_VOCABULARY.md``.

Usage
-----
    python tools/vendor_constitution.py --source ../CIRISConstitution --commit v1.0-rc17
    python tools/vendor_constitution.py --source ../CIRISConstitution --commit 892a68b --check

``--check`` writes nothing and exits 1 if the vendored tree differs from the
commit (a drift gate). ``--skip PATH`` leaves one vendored file as it is (used
when another open branch owns that file's update).
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEST = REPO_ROOT / "reference" / "CIRIS_Constitution"

# source path in CIRISConstitution -> vendored file name
FIXED = {
    "CHANGELOG.md": "CHANGELOG.md",
    "README.md": "README.md",
    "manifests/WIRE_VOCABULARY.md": "WIRE_VOCABULARY.md",
}


def git(source: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(source), *args], check=True,
                          capture_output=True, text=True).stdout


def file_set(source: Path, commit: str) -> dict[str, str]:
    names = git(source, "ls-tree", "--name-only", commit, "constitution/").split()
    files = {n: Path(n).name for n in names if n.endswith(".md")}
    files.update(FIXED)
    return files


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--source", required=True, type=Path,
                    help="a CIRISConstitution clone (read only)")
    ap.add_argument("--commit", required=True, help="tag or commit to vendor")
    ap.add_argument("--check", action="store_true", help="report drift, write nothing")
    ap.add_argument("--skip", action="append", default=[],
                    help="vendored file name to leave untouched (repeatable)")
    a = ap.parse_args()

    full = git(a.source, "rev-parse", f"{a.commit}^{{commit}}").strip()
    drift = []
    for src, name in sorted(file_set(a.source, full).items()):
        if name in a.skip:
            continue
        data = subprocess.run(["git", "-C", str(a.source), "show", f"{full}:{src}"],
                              check=True, capture_output=True).stdout
        out = DEST / name
        if out.exists() and out.read_bytes() == data:
            continue
        drift.append(name)
        if not a.check:
            out.write_bytes(data)
    print(f"constitution commit {full[:7]} ({full}); "
          f"{'drifted' if a.check else 'updated'}: {', '.join(drift) or 'none'}")
    return 1 if (a.check and drift) else 0


if __name__ == "__main__":
    sys.exit(main())
