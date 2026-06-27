"""
Fabric tier — CC 0.5.1 §4.4.3.2.8 affiliations cohort add / revoke / active-read lifecycle.

An affiliation (`cohort_scope: affiliations`) shares the community machinery
(CC 4.4.3.2.8): membership is the load-bearing authorization surface that gates
read access to affiliation-scoped content under the CommunityDek, with
**forward-secrecy on removal** (a removed key MUST stop appearing as an active
member the instant the removal takes effect, re-wrapping the DEK — CC 4.4.3.2.1).
The membership lifecycle is therefore identical in shape to the family/community
roster lifecycle (test_260), just keyed on the `affiliations` cohort
discriminator: an `add` shows the key in the active roster and is idempotent on
re-add; an immediate `revoke` drops it; a future-dated revoke leaves it active
until its `effective_at`.

This drives the REAL persist cohort lifecycle surfaces (`cohort_add_member`,
`cohort_revoke_member`, `cohort_active_members_json`) over the shared substrate —
member nodes are genuine registered federation keys, the founder is owner-bound
(`user`) and steward-bound into a real community so only the cohort-scope is under
test.

**Status on persist 11.0.0: xfail(strict=True).** The cohort admission enum is
`self | family | community`; the `affiliations` discriminator is rejected at the
boundary (`unknown cohort "affiliations"`), so an affiliations roster cannot be
created at all and the lifecycle is not Python-drivable. The strict-xfail flips to
a hard gate the instant persist admits the token (see test_262 for the
admission-boundary gate this lifecycle depends on).
"""

from __future__ import annotations

import json

import pytest

pytestmark = pytest.mark.fabric

_NOW = "2026-06-25T00:00:00.000Z"
_FUTURE = "2099-01-01T00:00:00.000Z"

# The founder node creates a real (community-backed) affiliation it owns, then
# drives the full add/revoke lifecycle ON THE `affiliations` COHORT. Every
# substrate call is wrapped so the test asserts on the actual admission decision
# rather than crashing the node before it can report.
_FOUNDER_BODY = r"""
founder = kid  # owner-bound via IDENTITY_TYPE="user"

engine.put_community_json(json.dumps({
    "community_key_id": founder, "community_name": "conformance-affil-life",
    "members": [{"key_id": founder, "joined_at": NOW, "role": "founder"}],
    "founded_at": NOW, "consensus_protocol": "founder_only", "persist_row_hash": "",
}))

def roster():
    return sorted(m["key_id"] for m in
                  json.loads(engine.cohort_active_members_json("affiliations", founder)))

def step(label, fn):
    try:
        report[label] = {"ok": True, "result": fn()}
    except Exception as exc:  # noqa: BLE001 — capture the substrate's decision
        report[label] = {"ok": False, "error": str(exc)}

# add — genuine add then idempotent re-add on the affiliations cohort
step("add_alice", lambda: engine.cohort_add_member(
    "affiliations", founder, json.dumps({"key_id": ALICE, "joined_at": NOW})))
step("after_add", roster)
step("readd_alice", lambda: engine.cohort_add_member(
    "affiliations", founder, json.dumps({"key_id": ALICE, "joined_at": NOW})))

# add bob, then immediate-revoke bob → forward secrecy drops him now
step("add_bob", lambda: engine.cohort_add_member(
    "affiliations", founder, json.dumps({"key_id": BOB, "joined_at": NOW})))
step("revoke_bob", lambda: engine.cohort_revoke_member(
    "affiliations", founder, BOB, json.dumps({"effective_at": NOW, "reason": "removed"})))
step("after_revoke_bob", roster)

# future-dated revoke of alice → she stays active until 2099
step("future_revoke_alice", lambda: engine.cohort_revoke_member(
    "affiliations", founder, ALICE, json.dumps({"effective_at": FUTURE})))
step("after_future_revoke_alice", roster)

report["stage"] = "done"
"""


@pytest.fixture(scope="module")
def affiliation_lifecycle(federation_module):
    """Register two member nodes, then run the owner-bound founder lifecycle node."""
    node = federation_module
    alice = node("report['kid'] = kid", identity_ref="alice")["kid"]
    bob = node("report['kid'] = kid", identity_ref="bob")["kid"]
    payload = node(
        _FOUNDER_BODY,
        identity_ref="founder",
        IDENTITY_TYPE="user",
        ALICE=alice, BOB=bob, NOW=_NOW, FUTURE=_FUTURE,
    )
    payload["alice"] = alice
    payload["bob"] = bob
    return payload


@pytest.mark.requires_persist
@pytest.mark.xfail(
    strict=True,
    reason=(
        "persist 11.0.0 cohort admission enum is self|family|community; the "
        '`affiliations` discriminator is rejected (unknown cohort "affiliations"), '
        "so an affiliations roster cannot be created and CC 4.4.3.2.8 membership "
        "is not Python-drivable. See test_262 for the admission-boundary gate. Filed: CIRISPersist#308."
    ),
)
def test_affiliation_add_is_observable_and_idempotent(affiliation_lifecycle):
    """CC 4.4.3.2.8: adding a member to an affiliations roster is observable + idempotent."""
    r = affiliation_lifecycle
    assert r["stage"] == "done", r
    assert r["add_alice"]["ok"] is True and r["add_alice"]["result"] is True, r
    assert r["after_add"]["ok"] is True, r
    assert len(r["after_add"]["result"]) == 1, (
        f"the added member is not on the active affiliations roster: {r}")
    # idempotent re-add is a no-op (False)
    assert r["readd_alice"]["ok"] is True and r["readd_alice"]["result"] is False, r


@pytest.mark.requires_persist
@pytest.mark.xfail(
    strict=True,
    reason=(
        "persist 11.0.0 does not admit the `affiliations` cohort discriminator "
        '(unknown cohort "affiliations"); the forward-secrecy revoke lifecycle of '
        "CC 4.4.3.2.8 cannot be driven until the token is exposed (see test_262). Filed: CIRISPersist#308."
    ),
)
def test_affiliation_revoke_honors_effective_at(affiliation_lifecycle):
    """CC 4.4.3.2.1 forward secrecy: immediate revoke drops now; future-dated stays active."""
    r = affiliation_lifecycle
    assert r["stage"] == "done", r
    # bob was added then immediately revoked → forward secrecy drops him now.
    assert r["add_bob"]["ok"] is True and r["add_bob"]["result"] is True, r
    assert r["revoke_bob"]["ok"] is True, r
    assert r["after_revoke_bob"]["ok"] is True, r
    assert r["bob"] not in r["after_revoke_bob"]["result"], (
        f"an immediately-revoked affiliations member is still active: {r}")
    # alice future-revoked (2099) → still active now (effective_at honored).
    assert r["after_future_revoke_alice"]["ok"] is True, r
    assert r["after_future_revoke_alice"]["result"] == r["after_revoke_bob"]["result"], (
        "a future-dated affiliations revocation dropped the member early — the "
        f"active read must honor effective_at: {r}")
