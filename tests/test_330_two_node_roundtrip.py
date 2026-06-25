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
    reason="CIRISEdge#214 — cold 2-node delivery needs a Python peer-rooting "
    "surface (prime_peer). v7.0.0 explicit-hash discovery is out-of-band; edge's "
    "own loopback test roots the pair via the Rust-only inject_rooted_peer_for_test, "
    "which isn't on the published wheel. The fixture calls edge.prime_peer(...) when "
    "present — this flips green when #214 ships it.",
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
