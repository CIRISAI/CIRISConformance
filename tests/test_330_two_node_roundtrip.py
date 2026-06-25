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

Status: `xfail` on **CIRISEdge#220**. The story so far:

- #214 shipped `prime_peer` (the Python surface to root a peer's key_id →
  reticulum dest-hash + transport ed25519 pubkey, mirroring edge's Rust-only
  `inject_rooted_peer_for_test`).
- #217 fixed the abort: on edge ≤7.0.11 the `prime_peer`/send path crashed the
  bootstrapping node with an uncatchable "no reactor running" Tokio panic. As of
  **edge 7.0.12** that is gone — the fixture runs clean, `prime_peer` succeeds
  (`knows_peer=True`), and the A↔B TCP interface establishes (ESTAB both ways).
- #220 is the remaining gap: real A→B `send_inline_text` still times out at the
  transport layer (`transport timeout after 30s`, B never receives) even with
  both nodes primed and the interface up — the rooted-resolver mapping doesn't
  yield a live Reticulum Link over a real (non in-process-loopback) interface
  (`peer_reachability` stays empty, the dest's `last_seen_at` stays None).

The fixture (two processes, identity exchange, `prime_peer` on both, delivery
polling) runs for real today and flips to a green gate the moment cross-process
delivery completes — no test change needed.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.fabric


@pytest.mark.cohabitation
@pytest.mark.requires_persist
@pytest.mark.requires_edge
@pytest.mark.xfail(
    reason="CIRISEdge#220 — on edge 7.0.12 the #217 abort is fixed (the fixture "
    "runs clean, prime_peer succeeds with knows_peer=True, the A↔B TCP interface "
    "establishes ESTAB both ways), but real A→B send_inline_text still times out at "
    "the transport layer ('transport timeout after 30s', B never receives): the "
    "rooted-resolver mapping doesn't yield a live Reticulum Link over a real "
    "(non-loopback) interface (peer_reachability stays empty, dest last_seen_at "
    "None). Flips green when #220 lands cross-process delivery.",
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
