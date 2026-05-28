"""
Full federation send/receive round-trip conformance.

After CIRISPersist#109 ships + CIRISEdge v0.9.2 consumes the fix, this
file holds the actual end-to-end coexistence proof: persist + edge in
one process, edge sends an inline-text message, edge receives it back
via the loopback transport, the message body survives the round-trip
unmodified.

Until #109 ships these tests skip (the init handshake fails before
send/receive can be exercised). Once #109 is in, remove the
`pytest.skip` guard and the harness becomes a strict regression gate
on the whole federation flow.

Planned test cases:

- `test_inline_text_loopback_round_trip` — agent sends to its own
  key_id; the registered handler observes the body.
- `test_durable_inline_text_acks` — durable send; receiver-side ACK
  flips `DurableHandle.is_acknowledged()` to True within timeout.
- `test_content_fetch_round_trip` — request bytes by SHA, receiver
  returns ContentBody, SHA integrity verifies on receipt.
- `test_subscription_handle_lifecycle_under_cohabitation` — the v0.9.0
  Tier 2 subscription primitive works when persist and edge are
  loaded as separate wheels (not just statically linked).

Each will live as its own self-contained subprocess script that:
1. Imports both wheels
2. Builds an Engine + Edge via init_edge_runtime
3. Configures the loopback transport
4. Exercises the scenario
5. Asserts outcomes via JSON to stdout
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.skip(reason="Pending CIRISPersist#109 + CIRISEdge v0.9.2 cohabitation fix")


def test_inline_text_loopback_round_trip(python_subprocess):
    """Send `send_inline_text` to self; registered handler observes the body."""
    pytest.fail("Not implemented yet — see file docblock")


def test_durable_inline_text_acks(python_subprocess):
    """Durable send to self; ACK lands within timeout."""
    pytest.fail("Not implemented yet — see file docblock")


def test_content_fetch_round_trip(python_subprocess):
    """Request bytes by SHA; ContentBody returned; integrity verifies."""
    pytest.fail("Not implemented yet — see file docblock")
