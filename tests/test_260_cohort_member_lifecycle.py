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
# persist v52.0.0 (CIRISPersist#955): nobody joins without their own signed
# acceptance, and a founding record admits only the members who signed it. So
# the family is founded with its founder alone (role `founder`, `founder_only` —
# this module is about the add/revoke/swap lifecycle, not quorum; test_264 owns
# quorum), and alice + bob join by proposal → acceptance → widening. Members are
# minted in this script so each can sign its own acceptance (conftest preamble).
_members = {name: mint_member(name) for name in ("alice", "bob", "carol", "dave")}
ALICE, BOB, CAROL, DAVE = (_members[n]["kid"] for n in ("alice", "bob", "carol", "dave"))
fam = {
    "family_key_id": kid, "family_name": "conformance-fam",
    "members": [{"key_id": kid, "joined_at": NOW, "role": "founder"}],
    "founded_at": NOW, "consensus_protocol": "founder_only",
    "consensus_protocol_entrenched": False, "persist_row_hash": "",
}
engine.put_family_json(json.dumps(fam))
for name in ("alice", "bob"):
    consent_to_join("family", kid, _members[name])
    _m = roster_member(_members[name]["kid"], NOW)
    engine.cohort_add_member("family", kid, json.dumps(_m), admit_spec("family", kid, _m))
# carol and dave accept up front, so the unsigned add below is refused for want
# of AUTHORITY, not for want of consent.
consent_to_join("family", kid, _members["carol"])
consent_to_join("family", kid, _members["dave"])

def roster():
    return sorted(m["key_id"] for m in
                  json.loads(engine.active_family_members_json(kid)))

report["family_key_id"] = kid
report["initial"] = roster()

# UNSIGNED add — REJECTED (persist v31.0.0, CIRISPersist#654). Roster growth
# used to be reachable from PyO3 with no authority check at all, and the roster
# is both numerator and denominator of the family quorum, so a free seat changes
# who can charter a trust root. An empty AdmitSpec decodes fine and then fails
# closed at admission: an absent signer/signature never verifies.
_carol = roster_member(CAROL, NOW)
try:
    engine.cohort_add_member("family", kid, json.dumps(_carol), "{}")
    report["unsigned_add"] = {"rejected": False}
except Exception as exc:  # noqa: BLE001 — the substrate's decision is the result
    report["unsigned_add"] = {"rejected": True, "error": str(exc)}
report["after_unsigned_add"] = roster()

# add — genuine add then idempotent re-add
report["add_carol"] = engine.cohort_add_member(
    "family", kid, json.dumps(_carol), admit_spec("family", kid, _carol))
report["after_add"] = roster()
# The idempotent re-add, both forms. A SIGNED exact retry returns False (the
# fold sees carol active; no row is written). The UNSIGNED exact retry is the
# documented no-op on the community plane since persist v51.2.0
# (CIRISPersist#936) but is still refused on the FAMILY plane v49 added
# (CIRISPersist#990) — recorded, and asserted as a strict xfail.
report["readd_carol"] = engine.cohort_add_member(
    "family", kid, json.dumps(_carol), admit_spec("family", kid, _carol))
try:
    report["readd_carol_unsigned"] = engine.cohort_add_member(
        "family", kid, json.dumps(_carol), "{}")
except Exception as exc:  # noqa: BLE001 — the substrate's decision is the result
    report["readd_carol_unsigned"] = str(exc)

# remove — immediate revoke drops bob
engine.cohort_revoke_member(
    "family", kid, BOB,
    revoke_spec("family", kid, BOB, NOW, reason="removed"))
report["after_revoke_bob"] = roster()

# remove — future-dated revoke leaves carol active until 2099
engine.cohort_revoke_member(
    "family", kid, CAROL, revoke_spec("family", kid, CAROL, FUTURE))
report["after_future_revoke_carol"] = roster()

# swap — atomically revoke alice, add dave. swap_member is revoke-then-add and
# the revocation leaves `members[]` intact, so the admission preimage is the
# roster as it stands now plus dave.
_dave = roster_member(DAVE, NOW)
report["swap_alice_dave"] = engine.cohort_swap_member(
    "family", kid, ALICE, json.dumps(_dave),
    revoke_spec("family", kid, ALICE, NOW, reason="swap"),
    admit_spec("family", kid, _dave))
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
    """Run the founder lifecycle node; it mints its four members itself so each
    can sign its own membership acceptance (CIRISPersist#955)."""
    node = federation_module
    return node(
        _FOUNDER_BODY,
        identity_ref="founder",
        IDENTITY_TYPE="user",
        NOW=_NOW, FUTURE=_FUTURE,
    )


@pytest.mark.requires_persist
def test_unsigned_roster_growth_is_rejected(cohort_lifecycle):
    """An addition carrying no authority signature must fail closed.

    CIRISPersist#654 (persist v31.0.0). Until that cut `cohort_add_member` was
    reachable from PyO3 with no authority check at all, so a caller could grow
    a family roster nobody had signed — and `family_quorum_over` counts that
    roster as both numerator and denominator, so a free seat changes who can
    charter a trust root and what threshold they must clear. This is the gate
    that closed it; it fails closed on an empty `AdmitSpec` because an absent
    signer and signature can never verify.
    """
    r = cohort_lifecycle
    assert r["stage"] == "done", r
    assert r["unsigned_add"]["rejected"] is True, (
        "an unsigned roster addition was ADMITTED — the CIRISPersist#654 "
        f"authorship gate is not holding: {r['unsigned_add']}")
    # And it left no trace: the roster is untouched by the refused add.
    assert r["after_unsigned_add"] == r["initial"], (
        "the refused add still mutated the roster — the gate must run BEFORE "
        f"any DB work: {r}")


@pytest.mark.requires_persist
def test_add_member_is_observable_and_idempotent(cohort_lifecycle):
    """`cohort_add_member` adds a real key and is idempotent on re-add."""
    r = cohort_lifecycle
    assert r["stage"] == "done", r
    assert r["add_carol"] is True, r
    assert r["readd_carol"] is False, ("re-adding an existing member must be an "
                                       f"idempotent no-op (False): {r}")
    # carol appears in the active roster only after the add.
    assert set(r["after_add"]) - set(r["initial"]) and len(r["after_add"]) == len(r["initial"]) + 1, r


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


@pytest.mark.requires_persist
@pytest.mark.xfail(strict=True, reason=
    "CIRISPersist#990: on the family widening plane (persist v49+) an exact UNSIGNED re-add of "
    "an already-active member is refused federation_federation_tier_unverified — #936 fixed the "
    "community arm in v51.2.0, not the family twin. Turns red when the family arm matches.")
def test_unsigned_exact_readd_is_a_noop(cohort_lifecycle):
    """CC #249 G1 idempotency, the authority-free half: re-adding an already-active
    family member with NO authority signature is a no-op (`False`), not a refusal —
    as it is on the community plane since persist v51.2.0."""
    assert cohort_lifecycle["readd_carol_unsigned"] is False, cohort_lifecycle["readd_carol_unsigned"]
