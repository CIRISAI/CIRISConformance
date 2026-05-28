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

from conftest import get_database_url


def _init_handshake_script(database_url: str) -> str:
    """Build the cohabitation-init scenario as a self-contained Python script.

    The database URL is interpolated as a Python string literal so the
    test runs against whatever backend the harness's environment selects
    (sqlite::memory: by default; postgres://... when CI flips the env).
    """
    # `db_url_repr` produces a valid Python string literal we can drop
    # straight into the script body. Avoids tangled f-string brace
    # escaping for the rest of the script.
    db_url_repr = repr(database_url)
    return (
        "import json, sys, tempfile, os\n"
        "try:\n"
        "    import ciris_persist\n"
        "    from ciris_edge.ciris_edge import init_edge_runtime\n"
        "except ImportError as exc:\n"
        "    print(json.dumps({'stage': 'import', 'error': str(exc)}))\n"
        "    sys.exit(2)\n"
        "\n"
        "try:\n"
        f"    engine = ciris_persist.Engine({db_url_repr}, 'test-key')\n"
        "except Exception as exc:\n"
        "    print(json.dumps({\n"
        "        'stage': 'engine_construct',\n"
        "        'error': str(exc),\n"
        "        'type': type(exc).__name__,\n"
        f"        'database_url': {db_url_repr},\n"
        "    }))\n"
        "    sys.exit(3)\n"
        "\n"
        "# Identity file path. The init constructor expects a file; it doesn't\n"
        "# need to be a real Reticulum identity for the type-handshake to\n"
        "# succeed (the failure we're testing fires BEFORE identity loading).\n"
        "fd, identity_path = tempfile.mkstemp(suffix='.rid')\n"
        "try:\n"
        "    os.write(fd, b'\\x00' * 64)\n"
        "    os.close(fd)\n"
        "    try:\n"
        "        edge = init_edge_runtime(engine, identity_path)\n"
        "    except TypeError as exc:\n"
        "        print(json.dumps({\n"
        "            'stage': 'init_handshake',\n"
        "            'error': str(exc),\n"
        "            'type': 'TypeError',\n"
        "            'is_persist_109': \"'Engine' object is not an instance of 'Engine'\" in str(exc),\n"
        "        }))\n"
        "        sys.exit(4)\n"
        "    except Exception as exc:\n"
        "        print(json.dumps({\n"
        "            'stage': 'init_handshake',\n"
        "            'error': str(exc),\n"
        "            'type': type(exc).__name__,\n"
        "        }))\n"
        "        sys.exit(5)\n"
        "    print(json.dumps({\n"
        "        'stage': 'ok',\n"
        "        'edge_has_signer_key_id': hasattr(edge, 'signer_key_id'),\n"
        "        'edge_version': edge.crate_version() if hasattr(edge, 'crate_version') else None,\n"
        "    }))\n"
        "finally:\n"
        "    try: os.unlink(identity_path)\n"
        "    except OSError: pass\n"
    )


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
    result = python_subprocess(_init_handshake_script(get_database_url()), expect_ok=False)
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
    result = python_subprocess(_init_handshake_script(get_database_url()), expect_ok=False)
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
