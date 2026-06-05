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


@pytest.mark.requires_lens
def test_ciris_lens_core_imports_alone(python_subprocess):
    """
    `ciris_lens_core` is the science layer — capacity-score +
    Coherence-Ratchet detectors + cohort manifold conformity. Solo
    import must succeed; the cohabitation tests downstream depend on
    this passing first.
    """
    result = python_subprocess(
        """
        import ciris_lens_core
        import json
        print(json.dumps({
            "module": "ciris_lens_core",
            "version": getattr(ciris_lens_core, "__version__", None),
            "attrs": sorted(a for a in dir(ciris_lens_core) if not a.startswith("_"))[:20],
        }))
        """,
        expect_ok=True,
    )
    payload = result.parsed_stdout()
    assert payload["module"] == "ciris_lens_core"
    # The v0.1.1 deployed-lens drop-in surface must still be reachable
    # in v0.2.0+ (semver pre-1.0 preserves the 4-function contract).
    for fn in ("process_trace_batch", "scrub_trace", "scrub_traces_batch", "ner_is_configured"):
        assert fn in payload["attrs"], (
            f"ciris_lens_core must expose `{fn}` (deployed-lens drop-in "
            f"contract; preserved across v0.1.1 → v0.2.0). Got attrs: {payload['attrs']}"
        )


@pytest.mark.requires_lens
def test_ciris_lens_core_exposes_install_relay(python_subprocess):
    """
    The v0.2.0 cohabitation bootstrap entry point. Every cohabitation
    agent in production after v1.0 calls `ciris_lens_core.install_relay
    (edge)` to register the lens handler on the shared `Arc<Edge>`.
    This test asserts the symbol is importable — the cohabitation
    cross-wheel test (test_030_cohabitation_init) asserts it actually
    binds and registers a handler.
    """
    result = python_subprocess(
        """
        import ciris_lens_core
        import json
        print(json.dumps({
            "found": "install_relay" in dir(ciris_lens_core),
        }))
        """,
        expect_ok=True,
    )
    assert result.parsed_stdout() == {"found": True}, (
        "ciris_lens_core.install_relay is the v0.2.0+ cohabitation "
        "bootstrap entry; missing it breaks every Python cohabitation "
        "agent."
    )


@pytest.mark.requires_lens
def test_ciris_lens_core_exposes_projection_version(python_subprocess):
    """
    `PROJECTION_VERSION` is the module-level smoke-test attribute —
    proves the cdylib loaded, the rlib's compiled, the PyO3 surface
    is reachable. Currently `"crc-v1"`; bumps to `"crc-v2"` post-
    RATCHET calibration (CIRISLensCore#3).
    """
    result = python_subprocess(
        """
        import ciris_lens_core
        import json
        print(json.dumps({
            "version": ciris_lens_core.PROJECTION_VERSION,
        }))
        """,
        expect_ok=True,
    )
    payload = result.parsed_stdout()
    assert isinstance(payload["version"], str)
    assert payload["version"].startswith("crc-v"), (
        f"PROJECTION_VERSION must be `crc-vN` shape; got `{payload['version']}`"
    )
