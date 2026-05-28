"""
Pairwise import conformance: any two CIRIS wheels coexist in one
Python process without crashing on import.

This is the first test class to catch true cross-module problems —
import-order regressions, duplicate symbol panics, version-skew
ImportErrors. A failure here is upstream of every cohabitation test;
fix it before debugging anything more elaborate.

Tests are parametrized over `(first, second)` pairs and over which
order they import — `ciris_persist` then `ciris_edge` is a different
PyO3 initialization sequence than `ciris_edge` then `ciris_persist`
and either can be the failing one.
"""

from __future__ import annotations

import itertools

import pytest

from conftest import ALL_WHEELS


def _import_pair_script(first: str, second: str) -> str:
    """A Python script that imports two modules in order and prints JSON."""
    return f"""
        import json, sys
        try:
            import {first}
        except ImportError as exc:
            print(json.dumps({{"stage": "first", "module": {first!r}, "error": str(exc)}}))
            sys.exit(2)
        try:
            import {second}
        except ImportError as exc:
            print(json.dumps({{"stage": "second", "module": {second!r}, "error": str(exc)}}))
            sys.exit(3)
        print(json.dumps({{
            "stage": "ok",
            "first": {first!r},
            "second": {second!r},
            "first_attrs_count": len(dir({first})),
            "second_attrs_count": len(dir({second})),
        }}))
    """


# Build the full ordered-pair list. `(a, a)` is excluded — that's the
# solo-import case already covered.
_PAIRS = [
    (a, b) for a, b in itertools.product(ALL_WHEELS, ALL_WHEELS) if a != b
]


@pytest.mark.cohabitation
@pytest.mark.parametrize("first,second", _PAIRS, ids=lambda p: p.replace("ciris_", ""))
def test_ordered_pair_imports_cleanly(
    python_subprocess, installed, first: str, second: str
):
    """Two wheels, two import orders, must both succeed."""
    if first not in installed or second not in installed:
        pytest.skip(f"missing wheel(s): {first}/{second} need both installed")

    result = python_subprocess(_import_pair_script(first, second), expect_ok=False)
    if not result.ok:
        # Surface the structured failure: which stage failed, which module.
        try:
            detail = result.parsed_stdout()
        except Exception:
            detail = {"raw_stdout": result.stdout, "raw_stderr": result.stderr}
        pytest.fail(
            f"Pairwise import {first} → {second} failed "
            f"(exit {result.returncode}): {detail}"
        )

    payload = result.parsed_stdout()
    assert payload["stage"] == "ok"
    assert payload["first_attrs_count"] > 0
    assert payload["second_attrs_count"] > 0
