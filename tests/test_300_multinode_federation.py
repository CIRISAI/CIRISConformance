"""
Fabric tier — multi-node federation (shared-substrate).

The first scenarios that genuinely need more than one node. Using the
`federation` fixture (N PyO3-isolated node subprocesses sharing one
substrate — the shared SQLite federation directory + blob store), these
exercise the §9 identity-aware-storage thesis and the replication
discipline at *federation* scope, which the single-node suite structurally
cannot reach:

- **Multi-holder discovery** (§9.1): when two nodes hold the same content,
  `list_holders` returns BOTH — the federation-wide "whose bytes?" answer.
  (Single-node, `list_holders` sees only the one local holder; the
  cross-node case is what the property is actually for.)
- **Per-actor eviction is local, not federation-wide** (§9.5): a node
  evicting *its own* holdings does not delete a peer's copy — eviction
  authority is per-operator, and the content survives at other holders.
- **Federation directory visibility** (§10.1): a node sees a peer's
  `holds_bytes` attestation + blob through the shared substrate.

This fixture is the foundation the still-pending multi-node scenarios build
on (cross-transport #4, trust-depth admission, the F-AV enforcement half of
#8) — see `docs/FABRIC_CONFORMANCE.md`.
"""

from __future__ import annotations

import json

import pytest

pytestmark = pytest.mark.fabric


@pytest.mark.requires_persist
def test_federation_directory_cross_node_visibility(federation):
    """§10.1: a node sees a peer's blob + holder attestation via the shared substrate."""
    a = federation(
        r'''
body = b"federation-visibility-content"
sha = hashlib.sha256(body).hexdigest()
engine.put_blob_signing(sha, base64.b64encode(body).decode(), None, None,
                        kid, "2026-05-28T13:45:09.000Z", str(uuid.uuid4()))
report["kid"] = kid; report["sha"] = sha
''',
        identity_ref="node-A",
    )
    b = federation(
        r'''
report["sees_blob"] = engine.has_blob_json(SHA)
holders = json.loads(engine.list_attestations_for(KID_A))['items']
report["sees_holder_attestation"] = any(
    h.get("attestation_type", "").startswith("holds_bytes:sha256:") for h in holders)
''',
        identity_ref="node-B", SHA=a["sha"], KID_A=a["kid"],
    )
    assert b["sees_blob"] is True, b
    assert b["sees_holder_attestation"] is True, b


@pytest.mark.requires_persist
def test_multi_holder_federation_discovery(federation):
    """§9.1: two nodes holding the same content → list_holders returns BOTH."""
    a = federation(
        r'''
body = b"multi-holder-content"
sha = hashlib.sha256(body).hexdigest()
engine.put_blob_signing(sha, base64.b64encode(body).decode(), None, None,
                        kid, "2026-05-28T13:45:09.000Z", str(uuid.uuid4()))
report["kid"] = kid; report["sha"] = sha; report["b64"] = base64.b64encode(body).decode()
''',
        identity_ref="holder-A",
    )
    b = federation(
        r'''
# node B independently holds the SAME content, then asks the federation.
engine.put_blob_signing(SHA, B64, None, None, kid, "2026-05-28T13:45:09.000Z", str(uuid.uuid4()))
report["kid"] = kid
report["holders"] = engine.list_holders_json(SHA)
''',
        identity_ref="holder-B", SHA=a["sha"], B64=a["b64"],
    )
    holders = json.loads(b["holders"])
    assert a["kid"] in holders, (a["kid"], holders)
    assert b["kid"] in holders, (b["kid"], holders)
    assert len(holders) >= 2, holders


@pytest.mark.requires_persist
def test_per_actor_eviction_is_local_not_federation_wide(federation):
    """§9.5: a node evicting its own holdings does not withdraw a peer's holder attestation."""
    a = federation(
        r'''
body = b"survives-peer-eviction"
sha = hashlib.sha256(body).hexdigest()
engine.put_blob_signing(sha, base64.b64encode(body).decode(), None, None,
                        kid, "2026-05-28T13:45:09.000Z", str(uuid.uuid4()))
report["kid"] = kid; report["sha"] = sha; report["b64"] = base64.b64encode(body).decode()
''',
        identity_ref="holder-A",
    )
    # Node B also holds it, then evicts ITS OWN holdings.
    b = federation(
        r'''
engine.put_blob_signing(SHA, B64, None, None, kid, "2026-05-28T13:45:09.000Z", str(uuid.uuid4()))
report["held_before"] = engine.has_blob_json(SHA)
rep = json.loads(engine.evict_actor_json(kid, "2026-05-28T14:00:00.000Z"))
report["evicted_own"] = rep["blobs_evicted"]
''',
        identity_ref="holder-B", SHA=a["sha"], B64=a["b64"],
    )
    # Node C observes the federation directory: A's holder attestation is
    # still active (B's per-operator eviction only withdrew B's own).
    c = federation(
        r'''
atts = json.loads(engine.list_attestations_for(KID_A))['items']
report["a_holds_bytes"] = sum(1 for x in atts if x.get("attestation_type","").startswith("holds_bytes:sha256:"))
report["a_withdraws"] = sum(1 for x in atts if x.get("attestation_type","") == "withdraws")
''',
        identity_ref="observer-C", KID_A=a["kid"],
    )
    assert b["held_before"] is True, b
    assert b["evicted_own"] >= 1, b
    # A's holder attestation survives B's eviction; B's withdraws are B's own.
    assert c["a_holds_bytes"] >= 1, c
    assert c["a_withdraws"] == 0, c
