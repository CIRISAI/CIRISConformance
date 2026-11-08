"""
Fabric tier — CC 0.6 §4.4.3.2.8 `affiliations` is the fourth admitted cohort scope.

CC §4.4.3.2.8 adds `affiliations` as a NEW `cohort_scope` value alongside
`self`/`family`/`community`: an affiliation gathers by *necessity* (the
institution/office a role requires) rather than *interest*, but it **shares the
CommunityDek crypto tier** (CC §4.4.3.2.1) and all the community machinery (DEK
cascade, forward-secrecy on removal, `consensus_protocol` admission). The
load-bearing, enforced behaviour is therefore two-fold:

1. the substrate must **admit `affiliations` as a cohort scope** at all — the
   generic cohort admission boundary (`cohort_add_member` /
   `cohort_active_members_json` / `cohort_groups_of_json`, all keyed by a
   `cohort` discriminator string) must recognize `"affiliations"` the same way
   it recognizes `"community"`; and
2. it must **resolve `affiliations` to the CommunityDek crypto tier** (CC table
   §4.4.3.2.1) — i.e. `cohort_scope_crypto_tier("affiliations") == "community_dek"`,
   the per-community DEK cascade, NOT the Commons/infrastructure plaintext
   exception.

Shipped in persist 11.5.0 (CIRISPersist#308): `affiliations` is now admitted,
backed by the shared community row, and resolves to `community_dek`. This gate
drives the REAL persist cohort-admission boundary + the crypto-tier resolver
over the shared substrate (a fully owner-bound `user` founder, mirroring
test_270, so the only thing under test is the scope-token admission, not an
unrelated steward gate):

- Control: `cohort_add_member("community", ...)` is admitted and resolves to
  `community_dek`.
- Under test: `cohort_add_member("affiliations", ...)` is admitted symmetrically,
  the read surfaces accept the `"affiliations"` discriminator, AND the tier
  resolver returns `community_dek` (NOT the `commons` plaintext exception, and
  distinct from the `self`/`family` `invisible_encrypted` tier).
"""

from __future__ import annotations

import json

import pytest

pytestmark = pytest.mark.fabric

_NOW = "2026-06-25T00:00:00.000Z"

# An owner-bound (`user`) founder creates a real group record of cohort COHORT (so
# any membership steward gate is satisfied) and drives the cohort-admission
# boundary under that scope. It also probes the crypto-tier resolver for every
# scope so the test asserts on the substrate's actual tier-resolution decision
# (CC §4.4.3.2.1 table).
#
# persist v54.0.0 (CIRISPersist#1034; CC 4.4.3.2.8): an affiliation and a
# community are DIFFERENT records. The record declares its cohort in
# `policy_blob.cohort_scope` (absent ⇒ community), immutably, and a door that
# addresses it under the other cohort is refused
# `federation_affiliation_cohort_mismatch`. So the control (`community`) and the
# scope under test (`affiliations`) each get their own founder and record; one
# record probed under both scopes would be the mismatch, not the admission.
#
# persist v61.0.0 (CIRISPersist#1123; CC 4.4.3.2 / CC 4.5.13): `founder_only` is
# refused for a community above the family (`founder_only_above_family`), so the
# one-founder community is founded under `majority`; an affiliation keeps
# `founder_only` (CC 4.4.3.2: admissible for an affiliation under the one-voice
# countersign rule).
_FOUNDER_BODY = r"""
founder = kid  # owner-bound via IDENTITY_TYPE="user" in the preamble
_record = {
    "community_key_id": founder, "community_name": "conformance-" + COHORT,
    "members": [{"key_id": founder, "joined_at": NOW, "role": "founder"}],
    "founded_at": NOW, "persist_row_hash": "",
    "consensus_protocol": "founder_only" if COHORT == "affiliations" else "majority",
}
if COHORT == "affiliations":
    _record["policy_blob"] = {"cohort_scope": "affiliations"}
engine.put_community_json(json.dumps(_record))

def probe(label, fn):
    try:
        report[label] = {"admitted": True, "result": fn()}
    except Exception as exc:  # noqa: BLE001 — record the substrate's decision verbatim
        report[label] = {"admitted": False, "error": str(exc)}

# The add is an idempotent re-add of the founder, who is already on the roster.
# persist short-circuits that to False BEFORE the CIRISPersist#654 authorship
# gate ("already on the roster — no-op, nothing to authorize"), so the empty
# AdmitSpec is the honest argument: there is no grown record to sign over, and
# fabricating one would assert a preimage persist never computes. What is under
# test here is the cohort-SCOPE discriminator, not the authority gate — that is
# test_260's subject.
_founder_member = roster_member(founder, NOW, role="founder")
probe(COHORT + "_add", lambda: engine.cohort_add_member(
    COHORT, founder, json.dumps(_founder_member), "{}"))
probe(COHORT + "_active_read",
      lambda: engine.cohort_active_members_json(COHORT, founder))
probe(COHORT + "_groups_read",
      lambda: engine.cohort_groups_of_json(COHORT, founder))

# CC §4.4.3.2.1 crypto-tier resolution for every cohort scope.
for scope in ("self", "family", "community", "affiliations", "commons"):
    probe("tier_" + scope, (lambda s: lambda: engine.cohort_scope_crypto_tier(s))(scope))

report["stage"] = "done"
"""


@pytest.fixture(scope="module")
def affiliation_scope(federation_module):
    """Run one owner-bound founder per cohort; merge their probe reports."""
    node = federation_module
    community = node(_FOUNDER_BODY, identity_ref="founder-community", IDENTITY_TYPE="user",
                     NOW=_NOW, COHORT="community")
    affiliation = node(_FOUNDER_BODY, identity_ref="founder-affiliations", IDENTITY_TYPE="user",
                       NOW=_NOW, COHORT="affiliations")
    assert community["stage"] == "done" and affiliation["stage"] == "done", (community, affiliation)
    return {**community, **{k: v for k, v in affiliation.items() if k.startswith("affiliations_")}}


@pytest.mark.requires_persist
def test_community_scope_is_admitted_control(affiliation_scope):
    """Control: the existing `community` cohort scope is admitted (sanity anchor)."""
    r = affiliation_scope
    assert r["stage"] == "done", r
    assert r["community_add"]["admitted"] is True, (
        "the known-good `community` cohort scope was rejected — the test's "
        f"admission baseline is broken, not affiliations: {r}")


@pytest.mark.requires_persist
def test_affiliations_is_an_admitted_cohort_scope(affiliation_scope):
    """CC §4.4.3.2.8: `affiliations` MUST be an admitted cohort scope like `community`."""
    r = affiliation_scope
    add = r["affiliations_add"]
    assert add["admitted"] is True, (
        "`affiliations` is not admitted as a cohort scope — the CC §4.4.3.2.8 "
        f"fourth-tier admission is unenforced on this wheel: {add}")
    # The read surfaces must accept the discriminator too (a scope you can write
    # but cannot read back is not a usable cohort tier).
    assert r["affiliations_active_read"]["admitted"] is True, r
    assert r["affiliations_groups_read"]["admitted"] is True, r
    # The admitted-and-readable affiliations roster actually contains the founder
    # the add wrote (not just an empty, vacuously-accepting surface).
    roster = json.loads(r["affiliations_active_read"]["result"])
    assert any(m.get("key_id") for m in roster), (
        f"affiliations roster read back empty after a successful add: {r}")


@pytest.mark.requires_persist
def test_affiliations_resolves_to_the_community_dek_tier(affiliation_scope):
    """CC §4.4.3.2.1 table: `affiliations` shares the CommunityDek crypto tier."""
    r = affiliation_scope
    for scope in ("community", "affiliations"):
        t = r["tier_" + scope]
        assert t["admitted"] is True, f"crypto-tier resolver rejected {scope!r}: {t}"
    assert r["tier_affiliations"]["result"] == "community_dek", (
        "`affiliations` must resolve to the CommunityDek tier (the per-community "
        f"DEK cascade), the same tier as `community`: {r}")
    # ...and it is NOT the Commons plaintext exception, nor the self/family
    # structural-invisibility tier — the affiliation's DEK is its sole
    # confidentiality boundary (CC §4.4.3.2.1).
    assert r["tier_affiliations"]["result"] == r["tier_community"]["result"], r
    assert r["tier_affiliations"]["result"] != r["tier_commons"]["result"], r
    assert r["tier_affiliations"]["result"] != r["tier_self"]["result"], r
