"""
Fabric tier — CC 3.4.7.3 Clause D cardinality / CC 3.2 single-owner
(`CLM-common-human`): a node's custody set is the occurrence half plus ONE
custody claim, and a second distinct custody claim is refused at bind time.

THE STANDARD MOVED UNDER THIS FILE. Through CC 1.0-rc2 it drove "co-stewardship":
two distinct adult stewards both `steward_bind` the same node, both admitted, the
node never orphaned while one remains. CC 1.0-rc4 (CC 3.4.7.3, amended with
CIRISPersist v38.6.0) withdrew that reading as "too broad": `stewards_of` is the
CUSTODY set, never the conferral set; for a key that can accept for itself (an
agent) the delegation half counts only where the envelope declares custody
(CIRISConstitution#87 — conferral is not stewardship); and the cardinality is the
`identity_occurrence` half plus **one** custody claim, "a second distinct claim
being refused at bind time (single-owner admission; a same-owner refresh is
idempotent)". "A design assuming N co-equal stewards of one agent is assuming a
shape the substrate will not admit."

What is REAL on the floor (persist v40.0.0), driven end-to-end here:

- **Custody is the owner-binding edge.** `steward_bind(node, infra_scopes,
  delegation_purpose="responsible_for")` writes the versioned
  `ownership:responsible_party:node:v1` owner-binding; the first from a proven
  adult is ADMITTED and `steward_bindings_of(node)` resolves that steward.
- **A second DISTINCT custody claim is REFUSED at bind time** with
  `federation_node_already_owned` — the CC 3.2 single-owner admission.
- **A same-owner refresh is idempotent** — the same steward re-binding is admitted
  and the custody set still names exactly one.
- **A conferral is not custody.** The second adult's plain `steward_bind` (no
  purpose) is ADMITTED — it is a consensual capability grant, not refused as a
  stewardship act — and does NOT enter `steward_bindings_of`; `nodes_stewarded_by`
  is the exact inverse.
- **Withdrawing the one custody claim empties the custody set** (fail-secure): the
  surviving conferral keeps nothing. (The PREDICATE `is_steward_bound` still reads
  true on this floor with a surviving conferral — CIRISPersist#811, asserted as
  xfail in test_361, not here.)

Real surface: `Engine.steward_bind(node_key, infra_scopes, delegation_purpose=None)`,
`Engine.steward_bindings_of_json(node_key)`, `Engine.nodes_stewarded_by_json(
steward_key)`, `Engine.revoke_delegation(binding_id, node_key)`. Both stewards are
graduated to adult through the #368 witness-attests-subject path, under a
conferred `infra:attest_assurance` (CIRISConformance#87 ceremony, see conftest).
"""

from __future__ import annotations

import pytest

from conftest import TRUST_ROOT_CEREMONY_SRC, get_database_url, run_python_script

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
        self.itype = itype
        self.kid = self.engine().register_self_federation_key(itype, ref, None, None, None)

    def engine(self):
        cp.reset_engine()
        eng = cp.Engine(DB_URL, self.k, local_key_id=self.k, local_key_path=self.s,
                        local_pqc_key_id=self.k + "-pqc", local_pqc_key_path=self.p)
        # persist v40: a fresh Engine has no node identity until it registers;
        # the conferral gates resolve "does THIS NODE trust the root", so bind
        # it on every reconstruction (see conftest.TRUST_ROOT_CEREMONY_SRC).
        if getattr(self, "kid", None):
            _bind_node_identity(eng, self.itype)
        return eng


for surface in ("steward_bind", "steward_bindings_of_json", "nodes_stewarded_by_json",
                "is_steward_bound_json", "revoke_delegation", "emit_attestation"):
    if not hasattr(Ident("probe", "agent", "probe").engine(), surface):
        report({"_error": "absent", "surface": surface})

W = Ident("witness", "witness", "age-witness")   # graduates the stewards to adult (#368 path)
S1 = Ident("steward1", "user", "adult-s1")       # first adult steward
S2 = Ident("steward2", "user", "adult-s2")       # a distinct second adult steward
N = Ident("node", "agent", "co-stewarded-node")  # the co-stewarded node

# CIRISConformance#87 — stand up a trust root and confer the witness-reserved
# capability from it (persist v30.2.0+): holding `witness` is necessary, never
# sufficient. Drives the real three-row ceremony (see conftest).
ROOT = Ident("root", "agent", "trust-root")
_TRUST_ROOT_CEREMONY = confer_from_trust_root(ROOT, W, "infra:attest_assurance")

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

# CC 3.2 / CIRISConstitution#87: custody is the OWNER-BINDING edge; persist's
# engine path for it is delegation_purpose="responsible_for". No purpose = a
# capability conferral, which is never custody.
CUSTODY = "responsible_for"

# ── The first custody claim admits; a second DISTINCT one is refused at bind time ──
_attempt("bind_S1", lambda: S1.engine().steward_bind(N.kid, ["infra:transport"], CUSTODY))
_attempt("bind_S2", lambda: S2.engine().steward_bind(N.kid, ["infra:transport"], CUSTODY))
# A same-owner refresh is idempotent (not a second claim).
_attempt("refresh_S1", lambda: S1.engine().steward_bind(N.kid, ["infra:transport"], CUSTODY))
# A conferral from the second adult is admitted — and is not custody.
_attempt("confer_S2", lambda: S2.engine().steward_bind(N.kid, ["infra:transport"]))

# ── Cardinality-ONE resolver: the custody set names S1 alone ──
e = N.engine()
r["bindings_of_N"] = json.loads(e.steward_bindings_of_json(N.kid))
r["is_bound_N"] = e.is_steward_bound_json(N.kid)
r["N_in_stewarded_by_S1"] = N.kid in json.loads(S1.engine().nodes_stewarded_by_json(S1.kid))
r["N_in_stewarded_by_S2"] = N.kid in json.loads(S2.engine().nodes_stewarded_by_json(S2.kid))

# ── Fail-secure: withdraw the one custody claim; the surviving conferral keeps nothing ──
_bind_S1_id = r["bind_S1"].get("id")
_attempt("revoke_S1", lambda: S1.engine().revoke_delegation(_bind_S1_id, N.kid))
e = N.engine()
r["bindings_after_revoke"] = json.loads(e.steward_bindings_of_json(N.kid))
r["is_bound_after_revoke"] = e.is_steward_bound_json(N.kid)   # CIRISPersist#811 — recorded, asserted in test_361
r["N_in_stewarded_by_S1_after"] = N.kid in json.loads(S1.engine().nodes_stewarded_by_json(S1.kid))

r["stage"] = "done"
report(r)
"""


@pytest.fixture(scope="module")
def costeward():
    script = f"INJECTED_URL = {get_database_url()!r}\n" + TRUST_ROOT_CEREMONY_SRC + _BODY
    payload = run_python_script(script).parsed_stdout()
    if payload.get("_error") == "absent":
        pytest.fail(f"persist steward surface missing: {payload.get('surface')}")
    if payload.get("_error"):
        pytest.fail(f"probe failed: {payload}")
    assert payload.get("stage") == "done", payload
    return payload


@pytest.mark.requires_persist
def test_first_custody_binding_admits_and_resolves(costeward):
    """CC 3.2: the first owner-binding from a proven adult onto a node is admitted and
    `steward_bindings_of` resolves exactly that steward; `nodes_stewarded_by` is
    the inverse."""
    r = costeward
    assert r["bind_S1"]["outcome"] == "admitted", (
        f"first steward's owner-binding was refused: {r['bind_S1']}")
    assert r["bindings_of_N"] == [r["S1"]], (
        f"the custody set must name S1 alone: {r['bindings_of_N']}")
    assert r["is_bound_N"] == "true", r
    assert r["N_in_stewarded_by_S1"], "node absent from S1's nodes_stewarded_by"


@pytest.mark.requires_persist
def test_second_distinct_custody_claim_is_refused(costeward):
    """CC 3.4.7.3 Clause D cardinality / CC 3.2 single-owner: a second DISTINCT
    custody claim on the same node is refused at bind time, while a same-owner
    refresh is idempotent.

    `federation_node_already_owned` on S2's owner-binding; S1's re-binding admits.
    This is the RC4 withdrawal of the rc2 co-stewardship reading: "a design
    assuming N co-equal stewards of one agent is assuming a shape the substrate
    will not admit."
    """
    r = costeward
    assert r["bind_S2"]["outcome"] == "rejected", (
        f"a SECOND distinct owner-binding was ADMITTED — the single-owner admission "
        f"(CC 3.2 / CC 3.4.7.3 Clause D cardinality) is not enforced: {r['bind_S2']}")
    assert "node_already_owned" in r["bind_S2"]["token"], (
        f"unexpected refusal token for the second owner: {r['bind_S2']}")
    assert r["refresh_S1"]["outcome"] == "admitted", (
        f"a same-owner refresh was refused as if it were a second claim: {r['refresh_S1']}")
    assert r["bindings_of_N"] == [r["S1"]], (
        f"the custody set is not exactly one after the refresh: {r['bindings_of_N']}")


@pytest.mark.requires_persist
def test_conferral_is_not_custody(costeward):
    """CC 3.2 (CIRISConstitution#87): the second adult's plain `steward_bind` is a
    capability conferral — admitted, never refused as a stewardship act — and it
    does not enter the custody set on either reader."""
    r = costeward
    assert r["confer_S2"]["outcome"] == "admitted", (
        f"a conferral onto the node was refused as if it were custody: {r['confer_S2']}")
    assert r["S2"] not in r["bindings_of_N"], (
        f"the conferring steward entered the custody set: {r['bindings_of_N']}")
    assert not r["N_in_stewarded_by_S2"], "a conferral shows in S2's nodes_stewarded_by"


@pytest.mark.requires_persist
def test_withdrawing_the_one_custody_claim_empties_the_custody_set(costeward):
    """CC 3.2 fail-secure: withdrawing the single custody claim leaves the custody set
    empty — the surviving conferral keeps nothing.

    `revoke_delegation(binding_id, node)` admits; `steward_bindings_of(node)` is
    empty and S1's `nodes_stewarded_by` no longer names the node. (Whether
    `is_steward_bound` agrees is CIRISPersist#811, asserted in test_361.)
    """
    r = costeward
    assert r["revoke_S1"]["outcome"] == "admitted", (
        f"revoking the steward's own binding was refused: {r['revoke_S1']}")
    assert r["bindings_after_revoke"] == [], (
        f"custody withdrawn but the custody set still names a steward: "
        f"{r['bindings_after_revoke']}")
    assert not r["N_in_stewarded_by_S1_after"], "node still in S1's nodes_stewarded_by after revocation"
