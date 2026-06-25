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
- #220 is the remaining gap, and edge **7.1.0** changed its *shape* without
  closing it. The 30s transport timeout is gone — `send_inline_text` now returns
  immediately and A reports `delivered=true` (`send_outcome="sent"`) — but the
  message resolves to a **self-scope** publish (`PublishOutcome` `scope:
  {kind: self}`, `holder_count: 0`, the documented §3.2 default) and is never
  transported to the primed peer: B's handler never fires (`b_received=false`),
  `peer_reachability` stays empty, and the dest's `last_seen_at` stays None. So
  the wire-level cross-process delivery still doesn't happen — and the new mode
  is more dangerous, since the send now *falsely reports success*.

This test asserts BOTH `delivered` AND `b_received`, so the silent non-delivery
is still caught. It is `xfail(strict=True)`: it stays XFAIL while `b_received`
is false, and the moment a wheel actually lands cross-process delivery it will
XPASS-strict — failing CI loudly to force the flip to a real green gate (the
signal the edge team asked for on #220). The fixture (two processes, identity
exchange, `prime_peer` on both, delivery polling) runs for real today.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.fabric


@pytest.mark.cohabitation
@pytest.mark.requires_persist
@pytest.mark.requires_edge
@pytest.mark.xfail(
    reason="CIRISEdge#220 — on edge 7.1.0 the abort (#217) and the 30s transport "
    "timeout are both gone, but real cross-process delivery still doesn't happen: "
    "send_inline_text returns 'sent' (A reports delivered=true) yet resolves to a "
    "self-scope publish (PublishOutcome scope:self, holder_count:0) and never "
    "transports to the primed peer — B's handler never fires (b_received=false), "
    "peer_reachability stays {} and the dest last_seen_at stays None. strict=True: "
    "stays XFAIL while b_received is false, XPASS-strict (fails CI) the moment a "
    "wheel lands cross-process delivery — the tripwire the edge team asked for.",
    strict=True,
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
