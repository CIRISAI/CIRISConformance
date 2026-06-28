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

# An owner-bound (`user`) founder creates a real community (so any membership
# steward gate is satisfied) and then drives the cohort-admission boundary for
# BOTH the known-good `community` scope and the scope under test, `affiliations`.
# It also probes the crypto-tier resolver for every scope so the test asserts on
# the substrate's actual tier-resolution decision (CC §4.4.3.2.1 table).
_FOUNDER_BODY = r"""
founder = kid  # owner-bound via IDENTITY_TYPE="user" in the preamble

# A real community exists and the founder is steward-bound into it — this isolates
# the test to the cohort-SCOPE admission, not an incidental membership gate.
engine.put_community_json(json.dumps({
    "community_key_id": founder, "community_name": "conformance-affil",
    "members": [{"key_id": founder, "joined_at": NOW, "role": "founder"}],
    "founded_at": NOW, "consensus_protocol": "founder_only", "persist_row_hash": "",
}))

def probe(label, fn):
    try:
        report[label] = {"admitted": True, "result": fn()}
    except Exception as exc:  # noqa: BLE001 — record the substrate's decision verbatim
        report[label] = {"admitted": False, "error": str(exc)}

# Control: `community` is an admitted scope (idempotent re-add of the founder).
probe("community_add", lambda: engine.cohort_add_member(
    "community", founder, json.dumps({"key_id": founder, "joined_at": NOW})))

# Under test: `affiliations` must be admitted symmetrically.
probe("affiliations_add", lambda: engine.cohort_add_member(
    "affiliations", founder, json.dumps({"key_id": founder, "joined_at": NOW})))
probe("affiliations_active_read",
      lambda: engine.cohort_active_members_json("affiliations", founder))
probe("affiliations_groups_read",
      lambda: engine.cohort_groups_of_json("affiliations", founder))

# CC §4.4.3.2.1 crypto-tier resolution for every cohort scope.
for scope in ("self", "family", "community", "affiliations", "commons"):
    probe("tier_" + scope, (lambda s: lambda: engine.cohort_scope_crypto_tier(s))(scope))

report["stage"] = "done"
"""


@pytest.fixture(scope="module")
def affiliation_scope(federation_module):
    """Run an owner-bound founder node that probes the affiliations cohort scope."""
    node = federation_module
    return node(_FOUNDER_BODY, identity_ref="founder", IDENTITY_TYPE="user", NOW=_NOW)


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
