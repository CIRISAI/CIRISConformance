"""
Fabric tier — trust × capacity intake gate (FEDERATION_SCALING_MODEL §1.1).

The scaling model's load-bearing replication rule is the **intake gate**: a node
only holds bytes from a source it trusts. "Carry the internet on commodity
hardware" depends on each node refusing low-trust inbound at the door, so the
trust short-circuit at edge's `dispatch_inbound` (CIRISEdge#48 / #208) is the
mechanical form of that rule.

This drives the REAL edge dispatch path end-to-end (no mock, no hand-rolled
wire bytes) and pins the gate:

1. **Baseline** — a well-formed, verified inbound envelope is `received`.
2. **Refusal** — with a trust resolver scoring the sender *below* the configured
   threshold, the same envelope is dropped: `trust_short_circuited`.
3. **Admit-all** — dropping the threshold to 0.0 (bootstrap-permissive) admits
   the same low-scored sender again: `received`.

Drivable as of **edge 7.0.10** (CIRISEdge#211): `build_signed_inbound_envelope`
mints the exact byte-shape `dispatch_inbound_bytes` expects, so the harness
never reverse-engineers the wire format. The envelope is Ed25519-only, so the
edge runtime is built with `hybrid_policy="ed25519_fallback"` (the helper's
documented pairing) and the sender is an Ed25519-only — i.e. hybrid-pending —
federation key. The trust gate runs *after* verify, so a passing envelope is the
precondition; this test proves the whole chain.
"""

from __future__ import annotations

import pytest

from conftest import (
    get_database_url,
    run_python_script,
    xfail_if_pg_edge_runtime_crash,
)

pytestmark = pytest.mark.fabric

_INTAKE_BODY = r"""
import json, sys, os, tempfile, secrets, base64
try:
    import ciris_persist as cp
    from ciris_edge.ciris_edge import init_edge_runtime
except ImportError as exc:
    print(json.dumps({"_error": "import", "detail": str(exc)})); sys.exit(2)

# The sender's raw Ed25519 seed — the same bytes the engine's local key uses,
# so register_self_federation_key registers the pubkey the helper signs with.
_sender_seed = secrets.token_bytes(32)
_d = tempfile.mkdtemp()
_seed = os.path.join(_d, "s"); open(_seed, "wb").write(_sender_seed)
_idp = os.path.join(_d, "t.id"); open(_idp, "wb").write(b"\x00" * 64)
cp.reset_engine()
k = "node-" + secrets.token_hex(8)
# Ed25519-ONLY engine → register_self yields a hybrid-pending key the
# ed25519_fallback verify policy accepts (the helper emits no PQC half).
engine = cp.Engine(DB_URL, k, local_key_id=k, local_key_path=_seed)
kid = engine.register_self_federation_key("agent", "intake-ref", None, None, None)

edge = init_edge_runtime(engine, _idp, listen_addr="127.0.0.1:0",
                         hybrid_policy="ed25519_fallback")

if not hasattr(edge, "build_signed_inbound_envelope"):
    print(json.dumps({"_error": "absent"})); sys.exit(2)

dest = edge.signer_key_id()

def dispatch():
    # edge 8 (CIRISConformance#53): the inline-text wire variant was ripped;
    # the intake gate runs after verify regardless of body type, so drive a
    # valid opaque wire variant. `OpaqueEvent` body is {"kind", "payload"}
    # (payload = base64 opaque bytes).
    env = edge.build_signed_inbound_envelope(
        kid, _sender_seed, dest, "OpaqueEvent",
        json.dumps({"kind": 7, "payload": base64.b64encode(b"intake").decode()}))
    # dispatch_inbound_bytes returns a dict {"outcome": ...} directly.
    return edge.dispatch_inbound_bytes(env, "http").get("outcome")

report = {}

# (1) Baseline — no gate configured: a verified envelope is received.
report["baseline"] = dispatch()

# (2) Refusal — score the sender 0.2, set the threshold to 0.5 → short-circuit.
edge.install_trust_resolver(lambda key_id, depth: 0.2)
edge.set_trust_threshold(0.5)
report["low_trust"] = dispatch()

# (3) Admit-all — threshold 0.0 readmits the same low-scored sender.
edge.set_trust_threshold(0.0)
report["admit_all"] = dispatch()

report["stage"] = "done"
print(json.dumps(report)); sys.stdout.flush()
sys.exit(0)
"""


def _intake_script(database_url: str) -> str:
    return f"DB_URL = {database_url!r}\n" + _INTAKE_BODY


@pytest.fixture(scope="module")
def intake_gate():
    result = run_python_script(_intake_script(get_database_url()))
    xfail_if_pg_edge_runtime_crash(result)  # CIRISPersist#354 (postgres native abort)
    payload = result.parsed_stdout()
    if payload.get("_error") == "absent":
        pytest.fail("edge.build_signed_inbound_envelope is missing — the intake-gate "
                    "test needs CIRISEdge#211 (edge >= 7.0.10)")
    assert payload.get("stage") == "done", payload
    return payload


@pytest.mark.cohabitation
@pytest.mark.requires_persist
@pytest.mark.requires_edge
def test_verified_inbound_is_received(intake_gate):
    """§1.1 baseline: a well-formed, verified inbound envelope reaches dispatch."""
    assert intake_gate["baseline"] == "received", intake_gate


@pytest.mark.cohabitation
@pytest.mark.requires_persist
@pytest.mark.requires_edge
def test_low_trust_source_is_short_circuited(intake_gate):
    """§1.1: a sender scored below the threshold is refused at the intake gate."""
    assert intake_gate["low_trust"] == "trust_short_circuited", (
        f"a sender scored 0.2 under threshold 0.5 was not refused: {intake_gate}"
    )


@pytest.mark.cohabitation
@pytest.mark.requires_persist
@pytest.mark.requires_edge
def test_threshold_zero_readmits(intake_gate):
    """§1.1: dropping the threshold to 0.0 (admit-all) readmits the same source."""
    assert intake_gate["admit_all"] == "received", intake_gate
