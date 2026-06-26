"""
Fabric tier — family cohort member add / remove lifecycle (CC 3.3.4 / CC 4.4.3.4 (legacy CEG cut G1)).

A CIRIS family is a roster of identity keys whose membership gates read access to
family-scoped content (the CC 4.4.3.4.4 caller-admission walk resolves `family_key_ids`
through the *active* membership reads). Membership is therefore a load-bearing
authorization surface: a key that has been removed MUST stop appearing as an
active member the instant the removal takes effect, and a future-dated removal
MUST NOT drop the member early.

This drives the REAL persist cohort surfaces end-to-end over a shared substrate
(each member is its own federation node registering its own
`register_self_federation_key`, so every roster entry is a genuine
`federation_keys` row — the membership-revocation table FK-references it):

- **add** — `cohort_add_member` returns `True` on a genuine add and is
  idempotent (`False`) on a re-add; the new key shows in
  `active_family_members_json`.
- **remove** — `cohort_revoke_member` with `effective_at <= now` drops the key
  from the active roster (the append-only revocation composes against the
  intact JSONB roster); a **future-dated** `effective_at` leaves the member
  active until it arrives.
- **swap** — `cohort_swap_member` atomically revokes one key and adds another.
- **reverse read** — `list_families_for_member_active_json` reflects the active
  membership from the member's side (removed members resolve to no family).

The family is created with `put_family_json` (a flat `Family`; `persist_row_hash`
is backend-computed) — no out-of-band builder needed (see CIRISPersist#289). The
community analogue is blocked on CIRISPersist#290 (`put_community_json` is not
exposed), so this module covers the family cohort only.
"""

from __future__ import annotations

import json

import pytest

pytestmark = pytest.mark.fabric

_NOW = "2026-06-25T00:00:00.000Z"
_FUTURE = "2099-01-01T00:00:00.000Z"

# The founder node: creates the family (itself as family_key_id) with alice+bob,
# then drives the full add/revoke/swap lifecycle and reports each roster state.
# alice/bob/carol/dave kids are injected as context from prior member nodes.
_FOUNDER_BODY = r"""
fam = {
    "family_key_id": kid, "family_name": "conformance-fam",
    "members": [{"key_id": ALICE, "joined_at": NOW},
                {"key_id": BOB, "joined_at": NOW}],
    "founded_at": NOW, "consensus_protocol": "majority",
    "consensus_protocol_entrenched": False, "persist_row_hash": "",
}
engine.put_family_json(json.dumps(fam))

def roster():
    return sorted(m["key_id"] for m in
                  json.loads(engine.active_family_members_json(kid)))

report["family_key_id"] = kid
report["initial"] = roster()

# add — genuine add then idempotent re-add
report["add_carol"] = engine.cohort_add_member(
    "family", kid, json.dumps({"key_id": CAROL, "joined_at": NOW}))
report["after_add"] = roster()
report["readd_carol"] = engine.cohort_add_member(
    "family", kid, json.dumps({"key_id": CAROL, "joined_at": NOW}))

# remove — immediate revoke drops bob
engine.cohort_revoke_member(
    "family", kid, BOB, json.dumps({"effective_at": NOW, "reason": "removed"}))
report["after_revoke_bob"] = roster()

# remove — future-dated revoke leaves carol active until 2099
engine.cohort_revoke_member(
    "family", kid, CAROL, json.dumps({"effective_at": FUTURE}))
report["after_future_revoke_carol"] = roster()

# swap — atomically revoke alice, add dave
report["swap_alice_dave"] = engine.cohort_swap_member(
    "family", kid, ALICE, json.dumps({"key_id": DAVE, "joined_at": NOW}),
    json.dumps({"effective_at": NOW, "reason": "swap"}))
report["after_swap"] = roster()

# reverse read — dave is now an active member; bob (revoked) is not.
report["families_for_dave"] = [
    f["family_key_id"]
    for f in json.loads(engine.list_families_for_member_active_json(DAVE))]
report["families_for_bob"] = [
    f["family_key_id"]
    for f in json.loads(engine.list_families_for_member_active_json(BOB))]
report["stage"] = "done"
"""


@pytest.fixture(scope="module")
def cohort_lifecycle(federation_module):
    """Register four member nodes, then run the founder lifecycle node."""
    node = federation_module
    alice = node("report['kid'] = kid", identity_ref="alice")["kid"]
    bob = node("report['kid'] = kid", identity_ref="bob")["kid"]
    carol = node("report['kid'] = kid", identity_ref="carol")["kid"]
    dave = node("report['kid'] = kid", identity_ref="dave")["kid"]
    return node(
        _FOUNDER_BODY,
        identity_ref="founder",
        ALICE=alice, BOB=bob, CAROL=carol, DAVE=dave,
        NOW=_NOW, FUTURE=_FUTURE,
    )


@pytest.mark.requires_persist
def test_add_member_is_observable_and_idempotent(cohort_lifecycle):
    """`cohort_add_member` adds a real key and is idempotent on re-add."""
    r = cohort_lifecycle
    assert r["stage"] == "done", r
    assert r["add_carol"] is True, r
    assert r["readd_carol"] is False, ("re-adding an existing member must be an "
                                       f"idempotent no-op (False): {r}")
    # carol appears in the active roster only after the add.
    assert set(r["after_add"]) - set(r["initial"]) and len(r["after_add"]) == 3, r


@pytest.mark.requires_persist
def test_immediate_revoke_drops_member_from_active_roster(cohort_lifecycle):
    """`cohort_revoke_member` with effective_at<=now removes the key immediately."""
    r = cohort_lifecycle
    before = set(r["after_add"])
    after = set(r["after_revoke_bob"])
    dropped = before - after
    assert len(after) == len(before) - 1, r
    assert len(dropped) == 1, ("exactly one member (bob) must leave the active "
                               f"roster on an immediate revoke: {r}")


@pytest.mark.requires_persist
def test_future_dated_revoke_keeps_member_active(cohort_lifecycle):
    """A future-dated `effective_at` must NOT drop the member early (CC #249 G1)."""
    r = cohort_lifecycle
    # carol was future-revoked (2099) — the active roster is unchanged.
    assert r["after_future_revoke_carol"] == r["after_revoke_bob"], (
        "a future-dated revocation dropped the member before its effective_at — "
        f"the active read must honor effective_at: {r}"
    )


@pytest.mark.requires_persist
def test_swap_member_is_atomic_revoke_and_add(cohort_lifecycle):
    """`cohort_swap_member` removes the outgoing key and adds the incoming one."""
    r = cohort_lifecycle
    assert r["swap_alice_dave"] is True, r
    before = set(r["after_future_revoke_carol"])
    after = set(r["after_swap"])
    assert before - after, "swap did not remove the outgoing member: %r" % (r,)
    assert after - before, "swap did not add the incoming member: %r" % (r,)
    assert len(after) == len(before), r


@pytest.mark.requires_persist
def test_member_side_read_reflects_active_membership(cohort_lifecycle):
    """`list_families_for_member_active_json` mirrors the roster from the member side."""
    r = cohort_lifecycle
    assert r["family_key_id"] in r["families_for_dave"], (
        "a freshly-added member does not see the family from their side: %r" % (r,))
    assert r["families_for_bob"] == [], (
        "a revoked member still resolves to an active family membership — the "
        f"CC 4.4.3.4.4 caller-admission read would over-grant: {r}")
