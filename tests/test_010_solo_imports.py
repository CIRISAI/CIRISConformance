"""
Solo-import conformance: each CIRIS wheel imports cleanly when it is
the ONLY ciris-* module loaded in the interpreter.

These tests catch wheel-packaging bugs (missing shared library, wrong
manylinux tag, missing libpython link) before they compound with
cross-module issues. If a wheel fails to import alone, no cohabitation
test against it has a chance of passing.

Each test runs in a fresh subprocess so the import state of one test
does not pollute the next.
"""

from __future__ import annotations

import pytest


@pytest.mark.requires_persist
def test_ciris_persist_imports_alone(python_subprocess):
    result = python_subprocess(
        """
        import ciris_persist
        import json
        print(json.dumps({
            "module": "ciris_persist",
            "version": getattr(ciris_persist, "__version__", None),
            "attrs": sorted(a for a in dir(ciris_persist) if not a.startswith("_"))[:20],
        }))
        """,
        expect_ok=True,
    )
    payload = result.parsed_stdout()
    assert payload["module"] == "ciris_persist"
    assert "Engine" in payload["attrs"], (
        "ciris_persist must export `Engine` (the cohabitation handshake type). "
        f"Got attrs: {payload['attrs']}"
    )


@pytest.mark.requires_edge
def test_ciris_edge_imports_alone(python_subprocess):
    result = python_subprocess(
        """
        import ciris_edge
        import json
        print(json.dumps({
            "module": "ciris_edge",
            "version": getattr(ciris_edge, "__version__", None),
            "attrs": sorted(a for a in dir(ciris_edge) if not a.startswith("_"))[:20],
        }))
        """,
        expect_ok=True,
    )
    payload = result.parsed_stdout()
    assert payload["module"] == "ciris_edge"


@pytest.mark.requires_edge
def test_ciris_edge_exposes_init_edge_runtime(python_subprocess):
    """The cohabitation entry point must be importable from the top-level module."""
    result = python_subprocess(
        """
        from ciris_edge.ciris_edge import init_edge_runtime
        import json
        print(json.dumps({"found": init_edge_runtime is not None}))
        """,
        expect_ok=True,
    )
    assert result.parsed_stdout() == {"found": True}


@pytest.mark.requires_verify
def test_ciris_verify_imports_alone(python_subprocess):
    """
    `ciris_verify` is the Python wheel that wraps the Rust crates
    `ciris-keyring` and `ciris-crypto`. The two Rust crates have no
    standalone Python wheels — they ride inside this one.
    """
    result = python_subprocess(
        """
        import ciris_verify
        import json
        print(json.dumps({
            "module": "ciris_verify",
            "version": getattr(ciris_verify, "__version__", None),
            "ok": True,
        }))
        """,
        expect_ok=True,
    )
    assert result.parsed_stdout()["ok"] is True
