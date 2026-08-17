"""
Fabric tier — CC 3.4.9 co-stewardship (`CLM-co-stewarded`): a node may be stewarded
by MORE THAN ONE steward.

CC 3.4.9 (part_3_the_namespace.md §3.4.9) and the CC 3.2 minor-stewardship clause
pin **M-of-N co-stewardship as a verified DAG over `delegates_to`**: a node/agent
target MAY carry live steward-bindings from *multiple distinct* stewards, and the
target "is never orphaned while ≥1 live adult steward remains." This is the
multi-parent steward DAG — **explicitly distinct from the CC 3.2 single-OWNER
rule** (test_551_single_owner.py), where the `delegation_purpose: owner_binding`
sub-relation is single-valued and a second distinct-owner binding is REJECTED at
bind time. A plain `steward_bind` carries NO owner-binding purpose, so it stays
multi-parent: co-stewardship and single-owner coexist on the same substrate.

What is REAL on the floor (persist 15.1.0), driven end-to-end here:

- **Two distinct stewards, both admitted.** Two distinct adult `user` identities
  each `steward_bind` the SAME node/agent and **both bindings are admitted** — the
  multi-parent co-stewardship DAG.
- **Cardinality 2 resolver.** `steward_bindings_of_json(node)` resolves to BOTH
  stewards (cardinality 2), and each steward's `nodes_stewarded_by_json` includes
  the node — the DAG is real in both directions.
- **Never orphaned while ≥1 remains.** Revoking one steward's binding leaves the
  node still steward-bound by the other (`is_steward_bound_json` stays `true`) —
  the §3.4.9 fail-secure "never orphaned while ≥1 live steward remains" guarantee.

The contrast anchor: this is the invariant the CC 3.2 single-owner gate must NOT
break — steward-binding is multi-parent; only the `owner_binding` PURPOSE is
single-valued (asserted in test_551). Node/agent steward-binding is governed by
the older gate (unaffected by the CC 3.2 user-target rule).

Real surface: `Engine.steward_bind(node_key, infra_scopes, delegation_purpose=None)`,
`Engine.steward_bindings_of_json(node_key)`, `Engine.nodes_stewarded_by_json(
steward_key)`, `Engine.is_steward_bound_json(node_key)`, `Engine.revoke_delegation`.
"""

from __future__ import annotations

import pytest

from conftest import get_database_url, run_python_script

pytestmark = pytest.mark.fabric

# A single SHARED substrate (on-disk sqlite file, or the injected postgres URL) so
# every reconstructed engine sees the same federation_keys / bindings. Only one
# Engine may be live at a time; each identity is reconstructed on the shared
# substrate when it must be the live signer (stable kid across reconstructions).
_BODY = r"""
import json, sys, os, tempfile, secrets

def report(obj):
    print(json.dumps(obj)); sys.stdout.flush(); os._exit(0)

try:
    import ciris_persist as cp
except ImportError as exc:
    report({"_error": "import", "detail": str(exc)})

if INJECTED_URL.startswith("postgres"):
    DB_URL = INJECTED_URL
else:
    _dbf = os.path.join(tempfile.mkdtemp(), "f.db"); open(_dbf, "a").close()
    DB_URL = "sqlite:///" + _dbf


class Ident:
    def __init__(self, prefix, itype, ref):
        d = tempfile.mkdtemp()
        self.s = os.path.join(d, "s"); open(self.s, "wb").write(secrets.token_bytes(32))
        self.p = os.path.join(d, "p"); open(self.p, "wb").write(secrets.token_bytes(32))
        self.k = prefix + "-" + secrets.token_hex(8)
        self.kid = self.engine().register_self_federation_key(itype, ref, None, None, None)

    def engine(self):
        cp.reset_engine()
        return cp.Engine(DB_URL, self.k, local_key_id=self.k, local_key_path=self.s,
                         local_pqc_key_id=self.k + "-pqc", local_pqc_key_path=self.p)


for surface in ("steward_bind", "steward_bindings_of_json", "nodes_stewarded_by_json",
                "is_steward_bound_json", "revoke_delegation", "emit_attestation"):
    if not hasattr(Ident("probe", "agent", "probe").engine(), surface):
        report({"_error": "absent", "surface": surface})

W = Ident("witness", "witness", "age-witness")   # graduates the stewards to adult (#368 path)
S1 = Ident("steward1", "user", "adult-s1")       # first adult steward
S2 = Ident("steward2", "user", "adult-s2")       # a distinct second adult steward
N = Ident("node", "agent", "co-stewarded-node")  # the co-stewarded node

r = {"S1": S1.kid, "S2": S2.kid, "N": N.kid}


def _attempt(label, fn):
    try:
        r[label] = {"outcome": "admitted", "id": str(fn())}
    except Exception as exc:
        r[label] = {"outcome": "rejected", "token": str(exc)[:200]}


def _attest_adult(subject_kid):
    return W.engine().emit_attestation(json.dumps({
        "attestation_type": "age_assurance:provider:adult:v1",
        "attestation_envelope": {}, "attested_key_id": subject_kid}))


# Both stewards are proven adults (steward MUST be an adult identity).
_attempt("attest_S1_adult", lambda: _attest_adult(S1.kid))
_attempt("attest_S2_adult", lambda: _attest_adult(S2.kid))

# ── Two distinct stewards both bind the same node — both admitted (co-stewardship) ──
# steward_bind returns the binding attestation id (used below to revoke exactly one).
_attempt("bind_S1", lambda: S1.engine().steward_bind(N.kid, ["infra:transport"]))
_attempt("bind_S2", lambda: S2.engine().steward_bind(N.kid, ["infra:transport"]))

# ── Cardinality-2 resolver: the node's bindings name BOTH stewards ──
e = N.engine()
r["bindings_of_N"] = json.loads(e.steward_bindings_of_json(N.kid))
r["N_in_stewarded_by_S1"] = N.kid in json.loads(S1.engine().nodes_stewarded_by_json(S1.kid))
r["N_in_stewarded_by_S2"] = N.kid in json.loads(S2.engine().nodes_stewarded_by_json(S2.kid))

# ── Never orphaned while ≥1 remains: revoke S1's binding, N still steward-bound by S2 ──
# revoke_delegation(target_attestation_id, delegate_key_id): the binding id + node.
_bind_S1_id = r["bind_S1"].get("id")
_attempt("revoke_S1", lambda: S1.engine().revoke_delegation(_bind_S1_id, N.kid))
e = N.engine()
r["is_bound_after_revoke"] = e.is_steward_bound_json(N.kid)
r["bindings_after_revoke"] = json.loads(e.steward_bindings_of_json(N.kid))

r["stage"] = "done"
report(r)
"""


@pytest.fixture(scope="module")
def costeward():
    script = f"INJECTED_URL = {get_database_url()!r}\n" + _BODY
    payload = run_python_script(script).parsed_stdout()
    if payload.get("_error") == "absent":
        pytest.fail(f"persist steward surface missing: {payload.get('surface')}")
    if payload.get("_error"):
        pytest.fail(f"probe failed: {payload}")
    assert payload.get("stage") == "done", payload
    return payload


@pytest.mark.requires_persist
def test_two_distinct_stewards_both_admitted(costeward):
    """CC 3.4.9: two distinct stewards both binding the same node are BOTH admitted.

    The multi-parent co-stewardship DAG — distinct from the CC 3.2 single-OWNER
    rule (test_551), where a second distinct `owner_binding` is rejected. A plain
    `steward_bind` carries no owner-binding purpose, so both distinct stewards are
    admitted onto the one node.
    """
    r = costeward
    assert r["bind_S1"]["outcome"] == "admitted", (
        f"first steward's steward_bind was refused: {r['bind_S1']}")
    assert r["bind_S2"]["outcome"] == "admitted", (
        f"a SECOND distinct steward's steward_bind was refused — co-stewardship "
        f"(multi-parent steward DAG) is not admitted: {r['bind_S2']}")


@pytest.mark.requires_persist
@pytest.mark.xfail(strict=True, reason=
    "CIRISConformance#87: `age_assurance:`/`capacity_assurance:` now also require `infra:attest_assurance` CONFERRED from a trust root this node trusts (persist v32.3.0). The harness has no trust-root ceremony, so the witness emit is refused with federation_reserved_prefix_emitter_mismatch.")
def test_steward_bindings_resolve_to_both_stewards(costeward):
    """CC 3.4.9: the node's steward-bindings resolve to BOTH stewards (cardinality 2).

    `steward_bindings_of_json(node)` names both stewards, and each steward's
    `nodes_stewarded_by_json` includes the node — the co-stewardship DAG is real in
    both directions.
    """
    r = costeward
    bindings = r["bindings_of_N"]
    assert r["S1"] in bindings and r["S2"] in bindings, (
        f"the node's steward_bindings_of must name both co-stewards: {bindings}")
    assert len(set(bindings)) == 2, (
        f"co-stewardship must resolve to cardinality 2 (contrast the single-owner "
        f"cardinality-1 resolver): {bindings}")
    assert r["N_in_stewarded_by_S1"], "node absent from S1's nodes_stewarded_by"
    assert r["N_in_stewarded_by_S2"], "node absent from S2's nodes_stewarded_by"


@pytest.mark.requires_persist
@pytest.mark.xfail(strict=True, reason=
    "CIRISConformance#87: `age_assurance:`/`capacity_assurance:` now also require `infra:attest_assurance` CONFERRED from a trust root this node trusts (persist v32.3.0). The harness has no trust-root ceremony, so the witness emit is refused with federation_reserved_prefix_emitter_mismatch.")
def test_node_never_orphaned_while_one_steward_remains(costeward):
    """CC 3.4.9: revoking one steward's binding leaves the node still steward-bound.

    Fail-secure "never orphaned while ≥1 live steward remains": after S1's binding
    is revoked, `is_steward_bound_json(node)` stays `true` and the remaining
    binding names S2.
    """
    r = costeward
    assert r["revoke_S1"]["outcome"] == "admitted", (
        f"revoking the first steward's binding failed: {r['revoke_S1']}")
    assert r["is_bound_after_revoke"] == "true", (
        f"node dropped to steward-less after ONE of two stewards was revoked — the "
        f"never-orphaned-while-≥1-remains guarantee is broken: {r}")
    assert r["S2"] in r["bindings_after_revoke"], (
        f"the surviving steward S2 is absent from the node's bindings after S1 "
        f"revocation: {r['bindings_after_revoke']}")
