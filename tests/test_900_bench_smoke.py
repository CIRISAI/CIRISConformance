"""
Bit-rot gate for the cross-wheel benchmark tier.

Mirrors the substrate sisters' "compile benches `--no-run`" per-PR gate:
the benchmark suite (`benchmarks/bench_substrate.py`) is NOT a pass/fail
performance gate (shared runners are too noisy — it publishes numbers via
`bench.yml`), but it must keep running. This runs it in `--quick` mode in a
fresh subprocess and asserts it still produces a well-formed report against
the real wheels, so a wheel-surface change that breaks the harness fails a
normal PR instead of silently rotting until the next `bench.yml` run.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
BENCH = REPO_ROOT / "benchmarks" / "bench_substrate.py"

# The cross-wheel measurements the report must always carry.
_REQUIRED_RESULTS = {
    "ed25519_sign",
    "hybrid_verify",
    "canonicalize",
    "put_blob_signing_composite",
    "cohab_init_edge_runtime",
}


@pytest.mark.cohabitation
@pytest.mark.requires_persist
@pytest.mark.requires_edge
def test_bench_suite_runs_and_reports(tmp_path):
    """`bench_substrate.py --quick` runs against the real wheels and reports numbers."""
    out = tmp_path / "bench.json"
    proc = subprocess.run(
        [sys.executable, str(BENCH), "--quick", "--json", str(out)],
        capture_output=True, text=True, timeout=180,
    )
    assert proc.returncode == 0, f"bench exited {proc.returncode}\nSTDERR:\n{proc.stderr}"
    report = json.loads(out.read_text())

    assert report["schema"] == "ciris-conformance/bench/1", report.get("schema")
    assert _REQUIRED_RESULTS <= set(report["results"]), set(report["results"])
    # Every measured op produced a positive p50 latency.
    for name in _REQUIRED_RESULTS:
        r = report["results"][name]
        assert r.get("p50_ns", 0) > 0, (name, r)
    # The report cites the sister-repo reference numbers (build-on-top, not re-measure).
    assert "hybrid_sign" in report["reference"], report["reference"]
