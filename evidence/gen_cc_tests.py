#!/usr/bin/env python3
"""Generate ``evidence/cc_tests.tsv`` — the CIRIS Conformance evidence registry.

Companion to **CIRISConstitution#17** (the CC 1.0-rc2 evidence-tag registry) and
**CIRISConformance#59**. CIRISConformance owns the ``test:`` tier: this file
publishes a machine-readable map from Constitution normative claims to the
conformance tests / freeze-gate vectors that establish them, which the
Constitution's ``check_claims.py`` resolves against (pinned by CIRISConformance
commit).

Two inputs, two responsibilities:

  1. ``evidence/claim_map.tsv`` (hand-maintained, EDITORIAL) — the CC-claim <->
     test association. This cannot be auto-derived: which normative clause a test
     establishes is a judgement call. Columns:
         cc_decimal_id \t cc_claim_id \t conformance_test_id(s) \t freeze_gate_vector(s)

  2. the LIVE suite (auto-derived, NEVER hand-edited) — the ``status`` column.
     ``gen_cc_tests.py`` runs the mapped tests and reads each node's real pytest
     outcome (see ``evidence/_status_plugin.py``), so the map can never silently
     drift from the suite. A parallel effort flips xfails -> green as the floor
     bumps; because status is derived, those flips land here for free.

Output: ``evidence/cc_tests.tsv`` (sorted, deterministic, idempotent). CI
regenerates it and fails on ``git diff``.

Run it with the CC-floor venv (see ``evidence/README.md``)::

    /path/to/floor-venv/bin/python evidence/gen_cc_tests.py

Exit code is non-zero if the map references a missing test, or if a mapped test
neither passes nor cleanly xfails on the floor (a genuine regression or an
under-provisioned host) — the registry must never encode an ambiguous status.
"""
from __future__ import annotations

import importlib.metadata as importlib_metadata
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

EVIDENCE_DIR = Path(__file__).resolve().parent
REPO_ROOT = EVIDENCE_DIR.parent
CLAIM_MAP = EVIDENCE_DIR / "claim_map.tsv"
OUT_TSV = EVIDENCE_DIR / "cc_tests.tsv"

COLUMNS = [
    "cc_decimal_id",
    "cc_claim_id",
    "conformance_test_id(s)",
    "freeze_gate_vector(s)",
    "status",
]

# The ciris-* distributions whose versions pin the floor the registry is derived
# against; recorded in the TSV header so a floor bump is visible in the diff.
#
# ciris-server joined the set when persist and edge left PyPI: it is the
# integrator whose Cargo.toml states what cohabits, and the suite drives its
# surfaces directly. A floor that named the substrate but not the integrator
# would not identify the code the statuses were actually recorded against.
#
# Versions come from installed metadata, so a git-tag member reports its
# package version (32.3.0), not the tag it was installed from (v32.3.0).
FLOOR_DISTS = ("ciris-server", "ciris-persist", "ciris-verify", "ciris-edge")


class ClaimRow:
    __slots__ = ("decimal", "claim_id", "test_ids", "freeze", "status")

    def __init__(self, decimal, claim_id, test_ids, freeze):
        self.decimal = decimal
        self.claim_id = claim_id
        self.test_ids = test_ids
        self.freeze = freeze or "-"
        self.status = None


def load_claim_map():
    """Parse evidence/claim_map.tsv into ClaimRow objects (editorial mapping)."""
    if not CLAIM_MAP.exists():
        sys.exit(f"error: {CLAIM_MAP} not found")
    rows = []
    for raw in CLAIM_MAP.read_text(encoding="utf-8").splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        parts = raw.split("\t")
        if parts[0].strip() == "cc_decimal_id":  # header
            continue
        parts = (parts + ["", "", "", ""])[:4]
        decimal, claim_id, tests, freeze = (p.strip() for p in parts)
        test_ids = [t.strip() for t in tests.split(",") if t.strip()]
        if not decimal or not claim_id or not test_ids:
            sys.exit(f"error: malformed claim_map row: {raw!r}")
        rows.append(ClaimRow(decimal, claim_id, test_ids, freeze))
    if not rows:
        sys.exit("error: claim_map.tsv has no claim rows")
    return rows


def collect_status(selectors):
    """Run the mapped tests once; return the plugin's captured status dict."""
    fd, out_path = tempfile.mkstemp(suffix=".json", prefix="evidence-status-")
    os.close(fd)
    env = dict(os.environ)
    env["EVIDENCE_STATUS_OUT"] = out_path
    env["PYTHONPATH"] = os.pathsep.join(
        [str(EVIDENCE_DIR), env.get("PYTHONPATH", "")]
    ).strip(os.pathsep)
    # Backend-independent substrate primitives; sqlite keeps the run deterministic
    # (postgres has the unrelated init_edge_runtime crash, CIRISPersist#354).
    env.setdefault("CIRIS_CONFORMANCE_DATABASE_URL", "sqlite::memory:")
    cmd = [
        sys.executable, "-m", "pytest",
        "-p", "no:cacheprovider",
        "-o", "addopts=",              # drop the repo's -ra/--strict-*; we drive selection
        "-p", "_status_plugin",        # evidence/_status_plugin.py (on PYTHONPATH)
        "--tb=no", "-q", "-p", "no:randomly",
        *selectors,
    ]
    subprocess.run(cmd, cwd=str(REPO_ROOT), env=env, check=False)
    try:
        data = json.loads(Path(out_path).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        sys.exit(
            "error: the status plugin produced no report — the pytest subprocess "
            "likely died before session finish (native crash?). Re-run the mapped "
            "tests directly to diagnose."
        )
    finally:
        Path(out_path).unlink(missing_ok=True)
    return data


def match_nodes(selector, node_status):
    """Nodes established by a selector (exact, ::-child of a file, or [param] of a func)."""
    hits = {}
    for nid, st in node_status.items():
        if nid == selector or nid.startswith(selector + "::") or nid.startswith(selector + "["):
            hits[nid] = st
    return hits


def derive_row_status(row, node_status):
    statuses = set()
    for selector in row.test_ids:
        hits = match_nodes(selector, node_status)
        if not hits:
            sys.exit(
                f"error: claim {row.claim_id} references '{selector}' which the suite "
                "did not run — a stale test id (rename?) or a wrong path in claim_map.tsv"
            )
        statuses.update(hits.values())
    if statuses == {"green"}:
        return "green"
    if statuses == {"xfail"}:
        return "xfail"
    # Mixed green+xfail: the claim is only partially established. Report the weaker
    # status (xfail) and warn — the fix is to split the row to claim granularity.
    sys.stderr.write(
        f"warning: claim {row.claim_id} mixes green and xfail across its tests "
        f"({sorted(statuses)}); reporting 'xfail'. Consider splitting the row.\n"
    )
    return "xfail"


def floor_pins():
    pins = {}
    for dist in FLOOR_DISTS:
        try:
            pins[dist] = importlib_metadata.version(dist)
        except importlib_metadata.PackageNotFoundError:
            sys.exit(
                f"error: {dist} is not installed — run the generator inside the CC "
                "floor venv (see evidence/README.md)"
            )
    return pins


def version_key(decimal):
    parts = []
    for p in decimal.split("."):
        try:
            parts.append((0, int(p)))
        except ValueError:
            parts.append((1, p))  # non-numeric segments sort after numerics
    return tuple(parts)


def render(rows, pins):
    lines = [
        "# CIRIS Conformance evidence registry — the `test:` tier of the CC evidence tags.",
        "# Companion to CIRISConstitution#17; tracked in CIRISConformance#59.",
        "# AUTO-GENERATED by evidence/gen_cc_tests.py from evidence/claim_map.tsv — DO NOT EDIT BY HAND.",
        "# `status` is derived from the live conformance suite on the CC floor: "
        + ", ".join(f"{k}=={v}" for k, v in pins.items()) + ".",
        "# Consumers (e.g. the Constitution's check_claims.py) MUST skip '#'-prefixed lines; "
        "the next line is the header.",
        "\t".join(COLUMNS),
    ]
    for row in rows:
        lines.append(
            "\t".join([
                row.decimal,
                row.claim_id,
                ",".join(row.test_ids),
                row.freeze,
                row.status,
            ])
        )
    return "\n".join(lines) + "\n"


def main():
    rows = load_claim_map()
    pins = floor_pins()

    selectors = sorted({sel for row in rows for sel in row.test_ids})
    data = collect_status(selectors)
    node_status = data.get("node_status", {})
    node_reason = data.get("node_reason", {})
    errors = data.get("errors", [])

    if errors:
        # Only pure environment gates land here (a missing wheel / native lib). The
        # registry has no basis for a status, so provision the host and re-run.
        sys.stderr.write("error: mapped tests skipped for an environment reason:\n")
        for nid, reason in errors:
            sys.stderr.write(f"  - {nid}: {reason}\n")
        sys.exit(
            "the registry cannot be built while a mapped test is environment-skipped; "
            "provision the floor host (e.g. libtss2 for the scope-privacy native lib) "
            "and re-run."
        )

    for row in rows:
        row.status = derive_row_status(row, node_status)

    rows.sort(key=lambda r: (version_key(r.decimal), r.claim_id))
    OUT_TSV.write_text(render(rows, pins), encoding="utf-8")

    n_green = sum(r.status == "green" for r in rows)
    n_xfail = sum(r.status == "xfail" for r in rows)
    sys.stderr.write(
        f"wrote {OUT_TSV.relative_to(REPO_ROOT)}: {len(rows)} claims "
        f"({n_green} green, {n_xfail} xfail) against "
        + ", ".join(f"{k}=={v}" for k, v in pins.items()) + "\n"
    )

    # Visibility: call out the two transitional categories the floor-bump effort owns.
    stale = sorted(n for n, r in node_reason.items() if r == "xpass-strict")
    broken = sorted(
        (n, r) for n, r in node_reason.items()
        if r.startswith("genuine-failure") or r in ("setup-error", "teardown-error")
    )
    if stale:
        sys.stderr.write(
            "note: GREEN only because a strict-xfail marker is now stale (the floor "
            "shipped the surface / the gate went live — remove the markers):\n"
        )
        for nid in stale:
            sys.stderr.write(f"  - {nid}\n")
    if broken:
        sys.stderr.write(
            "note: XFAIL because the test does not pass on this floor (a gate pending "
            "rework, not an explicit marker — auto-flips to green when it lands):\n"
        )
        for nid, reason in broken:
            sys.stderr.write(f"  - {nid}: {reason}\n")


if __name__ == "__main__":
    main()
