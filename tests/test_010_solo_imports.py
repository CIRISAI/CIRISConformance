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


# ─── Lens surface, now ABSORBED into the ciris-server wheel ────────────
# CIRISServer owns lens-core: the standalone `ciris_lens_core` wheel is
# retired and its Python surface is re-exported INSIDE `ciris_server` via the
# same `ffi::pyo3::register()`. So the lens drop-in contract is now asserted
# against `ciris_server` (the proof that the absorption is a real drop-in:
# `from ciris_server import LensClient`). `requires_lens` maps to ciris_server.


@pytest.mark.requires_lens
def test_lens_surface_imports_in_ciris_server(python_subprocess):
    """
    The lens science layer — capacity-score + Coherence-Ratchet detectors +
    cohort manifold conformity — now ships INSIDE `ciris_server` (CIRISServer
    absorbed lens-core). Solo import must succeed and expose the deployed-lens
    drop-in contract; the downstream cohabitation tests depend on this.
    """
    result = python_subprocess(
        """
        import ciris_server
        import json
        print(json.dumps({
            "module": "ciris_server",
            "version": getattr(ciris_server, "__version__", None),
            "attrs": sorted(a for a in dir(ciris_server) if not a.startswith("_")),
        }))
        """,
        expect_ok=True,
    )
    payload = result.parsed_stdout()
    assert payload["module"] == "ciris_server"
    # The deployed-lens drop-in surface is preserved through the absorption
    # (CIRISServer re-exports lens-core's register() verbatim).
    for fn in ("process_trace_batch", "scrub_trace", "scrub_traces_batch", "ner_is_configured"):
        assert fn in payload["attrs"], (
            f"ciris_server must expose `{fn}` (lens drop-in contract, absorbed "
            f"from lens-core). Got attrs: {payload['attrs']}"
        )
    # The headline drop-in the agent swaps to: `from ciris_server import LensClient`.
    assert "LensClient" in payload["attrs"], (
        f"ciris_server must re-export `LensClient` (the lens-core drop-in). "
        f"Got attrs: {payload['attrs']}"
    )


@pytest.mark.requires_lens
def test_ciris_server_exposes_install_relay(python_subprocess):
    """
    The cohabitation bootstrap entry point, absorbed into ciris-server. A
    cohabiting agent registers the lens handler on the shared `Arc<Edge>` via
    `ciris_server.install_relay(edge)`. This asserts the symbol is importable;
    test_030 asserts it actually binds + registers a handler.
    """
    result = python_subprocess(
        """
        import ciris_server
        import json
        print(json.dumps({
            "found": "install_relay" in dir(ciris_server),
        }))
        """,
        expect_ok=True,
    )
    assert result.parsed_stdout() == {"found": True}, (
        "ciris_server.install_relay is the cohabitation bootstrap entry "
        "(absorbed from lens-core); missing it breaks Python cohabitation agents."
    )


@pytest.mark.requires_lens
def test_ciris_server_exposes_projection_version(python_subprocess):
    """
    `PROJECTION_VERSION` is the lens module-level smoke-test attribute, now
    surfaced through ciris-server — proves the cdylib loaded and the absorbed
    lens PyO3 surface is reachable. `crc-vN` shape.
    """
    result = python_subprocess(
        """
        import ciris_server
        import json
        print(json.dumps({
            "version": ciris_server.PROJECTION_VERSION,
        }))
        """,
        expect_ok=True,
    )
    payload = result.parsed_stdout()
    assert isinstance(payload["version"], str)
    assert payload["version"].startswith("crc-v"), (
        f"PROJECTION_VERSION must be `crc-vN` shape; got `{payload['version']}`"
    )
