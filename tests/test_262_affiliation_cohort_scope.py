"""
Fabric tier — CC 0.5.1 §4.4.3.2.8 `affiliations` is the fourth admitted cohort scope.

CC 0.5.1 adds `affiliations` as a NEW `cohort_scope` value alongside
`self`/`family`/`community` (CC 4.4.3.2.8): an affiliation gathers by *necessity*
(the institution/office a role requires) rather than *interest*, but it **shares
the CommunityDek crypto tier** (CC 4.4.3.2.1) and all the community machinery
(DEK cascade, forward-secrecy on removal, `consensus_protocol` admission). The
load-bearing, enforced behaviour is therefore the very first one: the substrate
must **admit `affiliations` as a cohort scope** at all — the generic cohort
admission boundary (`cohort_add_member` / `cohort_active_members_json` /
`cohort_groups_of_json`, all keyed by a `cohort` discriminator string) must
recognize `"affiliations"` the same way it recognizes `"community"`, and (CC
4.4.3.2.1, table) resolve it to the Community/CommunityDek tier rather than the
Commons/infrastructure plaintext exception.

This gate drives the REAL persist cohort-admission boundary over the shared
substrate (a fully owner-bound `user` founder, mirroring test_270, so the only
thing being tested is the scope-token admission, not an unrelated steward gate):

- An admitted scope: `cohort_add_member("community", ...)` is accepted.
- The scope under test: `cohort_add_member("affiliations", ...)` MUST be admitted
  symmetrically — and the read surfaces (`cohort_active_members_json`,
  `cohort_groups_of_json`) must accept the `"affiliations"` discriminator.

**Status on persist 11.0.0: xfail(strict=True).** The cohort admission enum is
hard-coded to `self | family | community`; every `affiliations` operation is
rejected at the boundary with
`ValueError: unknown cohort "affiliations" (expected one of: self | family | community)`.
There is also no `crypto_tier(...)` resolver exposed on the Python wheel, so the
affiliations→CommunityDek tier resolution (CC 4.4.3.2.1) cannot be probed at all.
This matches the Constitution's own changelog ("Address `affiliations` … remains
deferred to a later candidate round", §4.4 deferrals). The strict-xfail is the
real signal that the surface is not yet exposed; it flips to a hard gate the
instant persist admits the token.
"""

from __future__ import annotations

import json

import pytest

pytestmark = pytest.mark.fabric

_NOW = "2026-06-25T00:00:00.000Z"

# An owner-bound (`user`) founder creates a real community (so any membership
# steward gate is satisfied) and then drives the cohort-admission boundary for
# BOTH the known-good `community` scope and the scope under test, `affiliations`.
# Each probe records either the admitted result or the raised error string, so
# the test asserts on the substrate's actual admission decision.
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

# Is the affiliations→CommunityDek tier resolution (CC 4.4.3.2.1) even probeable?
report["has_crypto_tier_resolver"] = hasattr(engine, "crypto_tier")

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
@pytest.mark.xfail(
    strict=True,
    reason=(
        "persist 11.0.0 cohort admission enum is hard-coded to "
        "self|family|community; `affiliations` is rejected at the boundary with "
        'ValueError: unknown cohort "affiliations". CC 0.5.1 §4.4.3.2.8 makes it '
        "the fourth cohort_scope tier (shares CommunityDek) — not yet exposed on "
        "the Python wheel (Constitution §4.4 changelog: affiliations deferred). Filed: CIRISPersist#308."
    ),
)
def test_affiliations_is_an_admitted_cohort_scope(affiliation_scope):
    """CC 4.4.3.2.8: `affiliations` MUST be an admitted cohort scope like `community`."""
    r = affiliation_scope
    add = r["affiliations_add"]
    assert add["admitted"] is True, (
        "`affiliations` is not admitted as a cohort scope — the CC 4.4.3.2.8 "
        f"fourth-tier admission is unenforced on this wheel: {add}")
    # The read surfaces must accept the discriminator too (a scope you can write
    # but cannot read back is not a usable cohort tier).
    assert r["affiliations_active_read"]["admitted"] is True, r
    assert r["affiliations_groups_read"]["admitted"] is True, r
