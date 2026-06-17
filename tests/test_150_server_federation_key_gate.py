"""
test_150 — the v8.8.0 federation-key admission surface, through `ciris_server`.

CIRISPersist v8.8.0 (CIRISRegistry#234, CEG 1.0-RC28/RC29 §5.6.8.15) split the
federation-key registration surface in two:

  * `register_self_federation_key(identity_type, identity_ref, ...)` — the
    self-registration convenience helper (the old `register_federation_key`,
    renamed; signature unchanged → returns the key_id).
  * `register_federation_key(signed_key_record_json)` — the NEW single canonical
    §5.6.8.15 admission gate (fail-secure hybrid-verify of a caller-assembled,
    already-hybrid-signed SignedKeyRecord, THEN put_public_key).

Because CIRISServer absorbed lens-core and re-exports the persist PyO3 surface
inside the one `ciris_server` wheel (the one-wheel drop-in: `ciris_server.Engine`
IS `ciris_persist.Engine`), the out-of-group peering CIRISServer + CIRISStatus
implement (consent:replication, §5.6.8.15) reaches this gate THROUGH the
ciris_server drop-in. This test proves the drop-in carries BOTH halves of the
v8.8.0 surface — surface conformance only (no engine construction), mirroring
test_010's subprocess-introspection pattern so it stays cohabitation-safe.
"""

import pytest


@pytest.mark.requires_lens
def test_ciris_server_exposes_v8_8_0_federation_key_surface(python_subprocess):
    """`ciris_server` must re-export `Engine` carrying both the renamed
    self-registration helper AND the new §5.6.8.15 admission gate — the proof
    the fabric-node drop-in is behaviour-correct for the v8.8.0 peering surface.
    """
    result = python_subprocess(
        """
        import ciris_server
        import json
        engine_cls = getattr(ciris_server, "Engine", None)
        methods = sorted(m for m in dir(engine_cls) if not m.startswith("_")) if engine_cls else []
        print(json.dumps({
            "module": "ciris_server",
            "has_engine": engine_cls is not None,
            "engine_methods": methods,
        }))
        """,
        expect_ok=True,
    )
    payload = result.parsed_stdout()
    assert payload["has_engine"], (
        "ciris_server must re-export `Engine` (the one-wheel persist re-export — "
        "`ciris_server.Engine` is `ciris_persist.Engine`). The §5.6.8.15 "
        "consent:replication peering reaches the admission gate through it."
    )
    methods = payload["engine_methods"]
    # The renamed self-registration helper (old register_federation_key).
    assert "register_self_federation_key" in methods, (
        "ciris_server.Engine must expose `register_self_federation_key` "
        f"(v8.8.0 self-helper rename). Got: {methods}"
    )
    # The NEW canonical §5.6.8.15 admission gate.
    assert "register_federation_key" in methods, (
        "ciris_server.Engine must expose the new §5.6.8.15 admission gate "
        f"`register_federation_key(signed_key_record_json)` (v8.8.0). Got: {methods}"
    )
    # The symmetric deregister (revocation teeth a withdrawn grant relies on).
    assert "deregister_federation_key" in methods, (
        "ciris_server.Engine must expose `deregister_federation_key` "
        f"(v8.8.0 §5.6.8.15 revocation teeth). Got: {methods}"
    )
