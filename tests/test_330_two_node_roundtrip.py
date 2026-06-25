"""
Fabric tier — real two-node transport round-trip (Conformance#4).

The single-process loopback in `test_050` can't deliver to self (no self-route).
The property that actually matters is **delivery between two nodes over a live
transport**: node A sends an inline-text envelope to node B, and B's registered
handler receives it. This is the headline of the cross-transport conformance
matrix (Conformance#4) and the foundation the per-MessageType × per-transport
round-trips build on.

The `two_node_transport` fixture brings up two real edge **processes** (B
listening on a fixed TCP port with `enable_transport=True`, A bootstrapping to
it), exchanges their transport identities, and drives `send_inline_text(A→B)`.

Status: `xfail` on **CIRISEdge#214** — cold 2-node delivery requires each side to
*root* the other's peer mapping (key_id → reticulum dest-hash + transport
ed25519 pubkey). Per edge's own loopback test (`tests/reticulum_loopback.rs`),
v7.0.0 explicit-hash discovery is **out-of-band**, and edge primes the pair with
the Rust-only `inject_rooted_peer_for_test`; the published wheel has no Python
equivalent yet. The fixture already calls `edge.prime_peer(...)` when present, so
this flips to a real green gate the moment CIRISEdge#214 ships that surface — no
test change needed. The fixture infra (two processes, identity exchange, delivery
polling) runs for real today.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.fabric


@pytest.mark.cohabitation
@pytest.mark.requires_persist
@pytest.mark.requires_edge
@pytest.mark.xfail(
    reason="CIRISEdge#217 — edge 7.0.11 shipped prime_peer (#214 closed), but on "
    "a bootstrapping node the prime_peer/send link-establishment path aborts the "
    "process with an uncatchable 'no reactor running' Tokio panic, so real A→B "
    "delivery can't complete. The fixture exchanges identities + calls prime_peer; "
    "this flips green when #217 fixes the runtime-context bug. (The abort is "
    "contained in the node SUBPROCESS — it can't crash the pytest run.)",
    strict=False,
)
def test_two_node_inline_text_round_trip(two_node_transport):
    """A→B inline-text crosses a live transport and reaches B's handler."""
    assert two_node_transport.get("delivered") is True, (
        f"A could not deliver to B: send_outcome={two_node_transport.get('send_outcome')!r} "
        f"prime_peer_available={two_node_transport.get('prime_peer_available')} "
        f"(CIRISEdge#214)"
    )
    assert two_node_transport.get("b_received") is True, (
        f"send reported success but B's handler never fired: {two_node_transport.get('b_detail')}"
    )
