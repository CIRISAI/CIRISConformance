"""
Fabric tier — CC 0.6 §4.4.3.2.8 affiliations cohort add / revoke / active-read lifecycle.

An affiliation (`cohort_scope: affiliations`) shares the community machinery
(CC §4.4.3.2.8): membership is the load-bearing authorization surface that gates
read access to affiliation-scoped content under the CommunityDek, with
**forward-secrecy on removal** (a removed key MUST stop appearing as an active
member the instant the removal takes effect, re-wrapping the DEK — CC §4.4.3.2.2).

Because affiliations ride the **community** revocation table (not the family one),
the removal semantics are the community's, not the family's:

- **add** — `cohort_add_member("affiliations", ...)` returns `True` on a genuine
  add and is idempotent (`False`) on a re-add; the new key shows in
  `cohort_active_members_json("affiliations", ...)`.
- **revoke** — `cohort_revoke_member` with `effective_at <= now` drops the key
  from the active roster *immediately*.
- **forward-secrecy is immediate-only** — unlike a `family` revoke (test_260),
  a **future-dated** community/affiliations revoke is **REJECTED at the
  boundary**: `community membership revocation effective_at … is future-dated;
  community removal is immediate for forward-secrecy (SecReview F4)`. The
  CommunityDek epoch bumps at write time, so a scheduled-future removal that
  left the DEK un-rotated would be a forward-secrecy hole; the substrate
  fail-closes it. This gate asserts that rejection as the real, enforced
  invariant (it is NOT an xfail — it is the affiliations tier behaving
  correctly and *differently* from family).

This drives the REAL persist cohort lifecycle surfaces (`cohort_add_member`,
`cohort_revoke_member`, `cohort_active_members_json`) over the shared substrate —
member nodes are genuine registered federation keys, the founder is owner-bound
(`user`) and steward-bound into a real community so only the cohort-scope is
under test.
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
step("after_add_bob", roster)
step("revoke_bob", lambda: engine.cohort_revoke_member(
    "affiliations", founder, BOB, json.dumps({"effective_at": NOW, "reason": "removed"})))
step("after_revoke_bob", roster)

# future-dated revoke of alice → REJECTED: community/affiliations removal is
# immediate-only for forward secrecy (SecReview F4). The boundary fail-closes;
# alice stays active because the revoke never landed.
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
def test_affiliation_add_is_observable_and_idempotent(affiliation_lifecycle):
    """CC §4.4.3.2.8: adding a member to an affiliations roster is observable + idempotent."""
    r = affiliation_lifecycle
    assert r["stage"] == "done", r
    assert r["add_alice"]["ok"] is True and r["add_alice"]["result"] is True, r
    assert r["after_add"]["ok"] is True, r
    assert r["alice"] in r["after_add"]["result"], (
        f"the added member is not on the active affiliations roster: {r}")
    # idempotent re-add is a no-op (False)
    assert r["readd_alice"]["ok"] is True and r["readd_alice"]["result"] is False, r


@pytest.mark.requires_persist
def test_affiliation_immediate_revoke_drops_member(affiliation_lifecycle):
    """CC §4.4.3.2.2 forward secrecy: an immediate revoke drops the member now."""
    r = affiliation_lifecycle
    assert r["stage"] == "done", r
    assert r["add_bob"]["ok"] is True and r["add_bob"]["result"] is True, r
    assert r["bob"] in r["after_add_bob"]["result"], r
    assert r["revoke_bob"]["ok"] is True, r
    assert r["bob"] not in r["after_revoke_bob"]["result"], (
        f"an immediately-revoked affiliations member is still active: {r}")


@pytest.mark.requires_persist
def test_affiliation_future_dated_revoke_is_rejected(affiliation_lifecycle):
    """CC §4.4.3.2.2 / SecReview F4: future-dated community/affiliations revoke is rejected.

    Distinct from the `family` cohort (test_260, which honors a future
    `effective_at`): an affiliation rides the community revocation table, whose
    DEK epoch bumps at write time, so a future-dated removal would leave the DEK
    un-rotated — a forward-secrecy hole. The substrate fail-closes the call.
    """
    r = affiliation_lifecycle
    assert r["stage"] == "done", r
    fr = r["future_revoke_alice"]
    assert fr["ok"] is False, (
        "a future-dated affiliations revoke must be REJECTED (community removal "
        f"is immediate for forward secrecy), but it was accepted: {r}")
    # The PyO3 boundary surfaces only the error *kind* token (the descriptive
    # "future-dated … immediate for forward-secrecy (SecReview F4)" detail lives
    # on the Rust Error and is dropped by federation_err_to_py), so we assert on
    # the invalid-argument rejection kind — the immediate-only invariant
    # rejecting the future date.
    assert fr["error"] == "federation_invalid_argument", (
        "the future-dated revoke was rejected for an unexpected reason — expected "
        f"the invalid-argument (immediate-removal) gate: {fr}")
    # Because the revoke never landed, alice is still an active member.
    assert r["after_future_revoke_alice"]["ok"] is True, r
    assert r["alice"] in r["after_future_revoke_alice"]["result"], (
        f"a rejected future-dated revoke wrongly dropped the member: {r}")
