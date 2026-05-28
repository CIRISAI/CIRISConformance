"""
Cohabitation init handshake conformance.

The load-bearing scenario this harness exists for:

    1. Python process starts
    2. `import ciris_persist` — `ciris_persist.abi3.so` loads + registers `Engine`
    3. `import ciris_edge` — `ciris_edge.abi3.so` loads
    4. `engine = ciris_persist.Engine("sqlite::memory:", "test-key")`
    5. `edge = ciris_edge.init_edge_runtime(engine, "/tmp/identity.rid", ...)`

Step 5 is the cohabitation handshake. It fails in v0.9.1 with:

    TypeError: argument 'engine': 'Engine' object is not an instance of 'Engine'

Root cause: PyO3 PyClass registration is per-extension-module. Each
.so file embeds its OWN PyTypeInfo for `PyEngine`; Python's type-id
check rejects the cross-module instance.

These tests are marked `xfail(strict=True)` against the current
matrix. When CIRISPersist#109 + the matching edge fix ship, the
xfails flip to xpass, the marker is removed, and the harness
turns this into a strict regression gate.

See:
- https://github.com/CIRISAI/CIRISPersist/issues/109 — the persist-side fix
- https://github.com/CIRISAI/CIRISEdge/issues/22 — the edge-side consumer impact
"""

from __future__ import annotations

import pytest


_INIT_HANDSHAKE_SCRIPT = """
    import json, sys, tempfile, os
    try:
        import ciris_persist
        from ciris_edge.ciris_edge import init_edge_runtime
    except ImportError as exc:
        print(json.dumps({"stage": "import", "error": str(exc)}))
        sys.exit(2)

    try:
        engine = ciris_persist.Engine("sqlite::memory:", "test-key")
    except Exception as exc:
        print(json.dumps({"stage": "engine_construct", "error": str(exc), "type": type(exc).__name__}))
        sys.exit(3)

    # Identity file path. The init constructor expects a file; it doesn't
    # need to be a real Reticulum identity for the type-handshake to
    # succeed (the failure we're testing fires BEFORE identity loading).
    fd, identity_path = tempfile.mkstemp(suffix=".rid")
    try:
        os.write(fd, b"\\x00" * 64)  # placeholder identity bytes
        os.close(fd)

        try:
            edge = init_edge_runtime(engine, identity_path)
        except TypeError as exc:
            # This is the persist#109 signature — surface it explicitly.
            print(json.dumps({
                "stage": "init_handshake",
                "error": str(exc),
                "type": "TypeError",
                "is_persist_109": "'Engine' object is not an instance of 'Engine'" in str(exc),
            }))
            sys.exit(4)
        except Exception as exc:
            print(json.dumps({
                "stage": "init_handshake",
                "error": str(exc),
                "type": type(exc).__name__,
            }))
            sys.exit(5)

        print(json.dumps({
            "stage": "ok",
            "edge_has_signer_key_id": hasattr(edge, "signer_key_id"),
            "edge_version": edge.crate_version() if hasattr(edge, "crate_version") else None,
        }))
    finally:
        try: os.unlink(identity_path)
        except OSError: pass
"""


@pytest.mark.cohabitation
@pytest.mark.requires_persist
@pytest.mark.requires_edge
@pytest.mark.xfail(
    strict=True,
    reason=(
        "persist#109 — PyO3 cross-crate PyClass identity. "
        "Remove this xfail when persist#109 ships + edge consumes the fix."
    ),
)
def test_init_edge_runtime_succeeds(python_subprocess):
    """The actual cohabitation init handshake completes successfully."""
    result = python_subprocess(_INIT_HANDSHAKE_SCRIPT, expect_ok=False)
    assert result.ok, (
        f"init_edge_runtime cohabitation handshake failed "
        f"(exit {result.returncode}):\n"
        f"STDOUT: {result.stdout}\n"
        f"STDERR: {result.stderr}"
    )
    payload = result.parsed_stdout()
    assert payload["stage"] == "ok"


@pytest.mark.cohabitation
@pytest.mark.requires_persist
@pytest.mark.requires_edge
def test_init_handshake_fails_with_persist_109_signature(python_subprocess):
    """
    The current matrix MUST surface the persist#109 failure with the
    exact diagnostic signature. If this test fails BUT
    `test_init_edge_runtime_succeeds` xpasses, the bug was silently
    fixed without a coordinated release — surface that.

    If this test fails AND `test_init_edge_runtime_succeeds` still
    xfails with a DIFFERENT signature, persist#109 mutated into a
    different bug — also worth flagging.

    Remove this test when persist#109 closes.
    """
    result = python_subprocess(_INIT_HANDSHAKE_SCRIPT, expect_ok=False)
    if result.ok:
        pytest.skip("init_handshake unexpectedly succeeded — persist#109 may be fixed")

    # The script exited non-zero. Confirm it's the persist#109 signature.
    try:
        payload = result.parsed_stdout()
    except Exception:
        pytest.fail(
            f"init_handshake failed but didn't produce parseable JSON:\n"
            f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}"
        )

    assert payload.get("stage") == "init_handshake", (
        f"Expected failure at init_handshake stage, got {payload.get('stage')!r}: {payload}"
    )
    assert payload.get("is_persist_109") is True, (
        f"Expected persist#109 signature, got different failure: {payload}"
    )
