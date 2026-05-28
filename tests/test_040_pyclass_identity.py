"""
Cross-module PyClass identity invariants.

These tests probe the deeper property the persist#109 bug violates:
**a PyClass type registered in module A should be the same type that
module B sees when B uses A as a dependency** — but PyO3 v0.28+
violates this when both modules statically link the dependency.

The tests in this file run independently of any specific init
handshake — they directly inspect Python type-identity properties of
shared PyClasses across imports. If these tests fail, every
cohabitation flow involving those types will also fail; fix here
first.
"""

from __future__ import annotations

import pytest


@pytest.mark.cohabitation
@pytest.mark.requires_persist
def test_persist_engine_constructable_from_module(python_subprocess):
    """
    Sanity baseline: `ciris_persist.Engine` is the constructor surface.
    A failure here means persist's wheel is broken regardless of
    cohabitation.
    """
    result = python_subprocess(
        """
        import ciris_persist, json
        engine = ciris_persist.Engine("sqlite::memory:", "test-key")
        print(json.dumps({
            "type_module": type(engine).__module__,
            "type_qualname": type(engine).__qualname__,
        }))
        """,
        expect_ok=True,
    )
    payload = result.parsed_stdout()
    assert payload["type_module"].startswith("ciris_persist"), payload
    assert payload["type_qualname"] == "Engine", payload


@pytest.mark.cohabitation
@pytest.mark.requires_persist
@pytest.mark.requires_edge
@pytest.mark.xfail(
    strict=True,
    reason=(
        "persist#109 — when edge statically links ciris-persist, the "
        "PyTypeInfo for Engine in ciris_edge.abi3.so is DIFFERENT from "
        "the one in ciris_persist.abi3.so. Same Rust struct, different "
        "Python types. Remove this xfail when persist#109 ships the "
        "cross-module identity fix."
    ),
)
def test_persist_engine_type_identity_across_imports(python_subprocess):
    """
    The Engine type object visible after `import ciris_persist` MUST
    be the same Python type the `ciris_edge.init_edge_runtime`
    pymethod expects as its `engine` argument. PyO3's per-module
    PyClass registration breaks this invariant for statically-linked
    cross-crate deps.
    """
    result = python_subprocess(
        """
        import ciris_persist, ciris_edge, json
        from ciris_edge.ciris_edge import init_edge_runtime

        engine_type = ciris_persist.Engine
        # Probe what init_edge_runtime annotates the engine arg as.
        # PyO3 attaches type hints to the signature; we surface what
        # the harness can about the expected type.
        sig = getattr(init_edge_runtime, "__text_signature__", None)

        # Construct an Engine instance and ask Python whether it's an
        # instance of `ciris_persist.Engine`. Trivially True under
        # normal circumstances.
        engine = engine_type("sqlite::memory:", "test-key")
        is_instance_via_module = isinstance(engine, ciris_persist.Engine)

        # The bug: even though `engine` was constructed from
        # `ciris_persist.Engine`, the init_edge_runtime pymethod's
        # internal PyRef<PyEngine> downcast may reject it because
        # ciris_edge's compiled-in PyTypeInfo for PyEngine is a
        # DIFFERENT pointer than ciris_persist's. We can't directly
        # observe edge's internal PyTypeInfo from Python, but we can
        # invoke init_edge_runtime and see whether it accepts the
        # instance — that's the integration check we delegate to
        # test_030_cohabitation_init.

        print(json.dumps({
            "is_instance_via_module": is_instance_via_module,
            "engine_type_id": id(engine_type),
            "init_signature": sig,
        }))
        """,
        expect_ok=True,
    )
    payload = result.parsed_stdout()
    assert payload["is_instance_via_module"], (
        "Sanity: an Engine constructed from ciris_persist.Engine should "
        "be isinstance of ciris_persist.Engine. If this fails, persist's "
        "wheel itself is corrupt — not a cross-module identity issue."
    )
    # The actual cross-module identity check is delegated to
    # test_030_cohabitation_init.py::test_init_edge_runtime_succeeds —
    # we mark this test xfail in lockstep so when persist#109 ships,
    # both flip at once and we know the fix is end-to-end.


@pytest.mark.cohabitation
@pytest.mark.requires_persist
def test_engine_type_stable_across_repeated_import(python_subprocess):
    """
    Within a single Python process, `import ciris_persist` followed by
    a second `import ciris_persist` MUST yield the same Engine type
    object. (Python's import caching guarantees this; this test
    catches the day someone accidentally invokes
    `importlib.reload(ciris_persist)` and breaks the singleton.)
    """
    result = python_subprocess(
        """
        import ciris_persist, json
        first_type = ciris_persist.Engine
        import ciris_persist  # second import is a cache hit
        second_type = ciris_persist.Engine
        print(json.dumps({
            "same_type": first_type is second_type,
            "first_id": id(first_type),
            "second_id": id(second_type),
        }))
        """,
        expect_ok=True,
    )
    payload = result.parsed_stdout()
    assert payload["same_type"] is True, payload
