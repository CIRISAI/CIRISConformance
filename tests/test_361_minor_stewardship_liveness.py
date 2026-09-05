"""
Fabric tier — CC 3.2 minor-stewardship liveness (the no-slavery fail-secure).

CC 3.2 (part_3_the_namespace.md, "Minor-stewardship rule"): an under-18 `user`
identity MUST have a **live steward-binding** — a non-superseded, non-withdrawn
`delegates_to(adult-user → minor-user)` — from an over-18 `user` at all times.
"No minor `user` identity operates without a live adult steward." A minor whose
binding goes non-live (superseded-without-replacement or **withdrawn**) is
**steward-less and MUST NOT operate** until re-stewarded — fail-secure, identical
in posture to a steward-less `node`/`agent`.

The lifecycle rides existing structural composers (no new primitive): the binding
is a `delegates_to` (here via `steward_bind` / `grant_delegation`); revocation is
a `withdraws` (here via `revoke_delegation` by the original granter).

What is REAL on the floor (persist 13.2.0), asserted as live gates — the
proven-adult → proven-minor model (CIRISPersist#367, shipped at persist 13.0):

- **node/agent fail-secure (control)** — a steward-bound agent resolves
  `is_steward_bound` true; after the adult granter `revoke_delegation`s the
  binding, `is_steward_bound` flips to **false** and `steward_bindings_of` empties.
- **the minor-guardianship binding IS creatable** — once the guardian S is a
  proven adult and the ward M is a proven minor (graduated via the #368
  witness-attests-subject path), the adult→minor `steward_bind` is ADMITTED and
  resolves `is_steward_bound(M)` true. (On persist 12.5.0 this was forbidden
  wholesale; that block was a stale precondition, not a spec gap.)
- **the minor-specific fail-secure IS observable** — after the adult granter
  withdraws the live adult→minor binding (`revoke_delegation`), `is_steward_bound`
  on the minor flips to **false** and `steward_bindings_of` empties: the
  steward-less minor "MUST NOT operate" posture, machine-checked on the `user`
  target exactly as on a node/agent. Was `xfail(strict)` on persist 12.5.0 (the
  binding could not be created to withdraw); now a real green gate.
"""

from __future__ import annotations

import pytest

from conftest import (
    TRUST_ROOT_CEREMONY_SRC,
    get_database_url,
    run_python_script,
)

pytestmark = pytest.mark.fabric

_BODY = r"""
import json, sys, os, tempfile, secrets
try:
    import ciris_persist as cp
except ImportError as exc:
    print(json.dumps({"_error": "import", "detail": str(exc)})); sys.exit(2)

# Shared substrate so every reconstructed engine sees the same keys/attestations
# (the witness's age attestations about the subjects must be visible to the
# guardian's engine). The harness injects INJECTED_URL to honor the chosen backend
# (full sqlite+postgres parity): postgres is shared across subprocesses; the sqlite
# default needs an ON-DISK file (`:memory:` gives each Engine a private DB).
if INJECTED_URL.startswith("postgres"):
    DB_URL = INJECTED_URL
else:
    _dbf = os.path.join(tempfile.mkdtemp(), "f.db"); open(_dbf, "a").close()
    DB_URL = "sqlite:///" + _dbf


# Only one Engine is live at a time (`reset_engine` closes the prior); each
# identity carries stable alias + key paths and is reconstructed to sign. The kid
# is stable across reconstructions (same alias + seed → same derived key_id).
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


for surface in ("steward_bind", "revoke_delegation", "is_steward_bound_json",
                "steward_bindings_of_json", "emit_attestation", "age_band_json"):
    probe = Ident("probe", "agent", "probe")
    if not hasattr(probe.engine(), surface):
        print(json.dumps({"_error": "absent", "surface": surface})); sys.exit(2)

W = Ident("witness", "witness", "age-witness")   # attests subjects' age bands (#368)
S = Ident("steward", "user", "adult-steward")    # the adult-user guardian (signer)
M = Ident("minor", "user", "minor-ward")         # the proven-minor user ward
N = Ident("node", "agent", "node-ref")           # node/agent control
N2 = Ident("node2", "agent", "node-ref-2")       # node with a surviving conferral (CIRISPersist#811)
S2 = Ident("steward2", "user", "adult-steward-2")  # a second adult user — confers, never stewards

# CIRISConformance#87 — stand up a trust root and confer the witness-reserved
# capability from it (persist v30.2.0+): holding `witness` is necessary, never
# sufficient. Drives the real three-row ceremony (see conftest).
ROOT = Ident("root", "agent", "trust-root")
_TRUST_ROOT_CEREMONY = confer_from_trust_root(ROOT, W, "infra:attest_assurance")

report = {"S": S.kid, "S2": S2.kid, "M": M.kid, "N": N.kid, "N2": N2.kid}

# ── #368 witness-attests-subject: graduate the ages FIRST ──
# The witness emits age_assurance:provider:* attestations naming each subject's
# attested_key_id: S → adult, M → minor. This is the precondition the CC 3.2
# admit rule requires — a proven-adult guardian binding a proven-minor ward.
def _attest(subject_kid, atype):
    return W.engine().emit_attestation(json.dumps({
        "attestation_type": atype, "attestation_envelope": {},
        "attested_key_id": subject_kid}))

_attest(S.kid, "age_assurance:provider:adult:v1")
_attest(S2.kid, "age_assurance:provider:adult:v1")
_attest(M.kid, "age_assurance:provider:16_17:v1")

# CIRISConstitution#87 / CC 3.2: stewardship is the OWNER-BINDING edge; persist's
# engine path for it is `delegation_purpose="responsible_for"`. A steward_bind with
# no purpose is a capability conferral and neither enters nor leaves custody.
CUSTODY = "responsible_for"
e = W.engine()
report["band_S"] = e.age_band_json(S.kid)
report["band_M"] = e.age_band_json(M.kid)

# ── Minor: create the live adult→minor guardianship binding ──
# Proven-adult S → proven-minor M is ADMITTED (CIRISPersist#367, persist 13.0).
try:
    appt_m = S.engine().steward_bind(M.kid, ["infra:transport"], CUSTODY)
    report["minor_bind"] = {"outcome": "admitted", "id": appt_m}
except Exception as exc:
    appt_m = None
    report["minor_bind"] = {"outcome": "rejected", "token": str(exc)[:200]}

# Confirm the minor is steward-bound while the binding is live.
if appt_m is not None:
    e = S.engine()
    report["minor_bound_is_steward_bound"] = e.is_steward_bound_json(M.kid)
    report["minor_bound_bindings_of"] = json.loads(e.steward_bindings_of_json(M.kid))

    # ── Withdraw the binding: the steward-less-minor fail-secure transition ──
    S.engine().revoke_delegation(appt_m, M.kid)
    e = S.engine()
    report["minor_revoked_is_steward_bound"] = e.is_steward_bound_json(M.kid)
    report["minor_revoked_bindings_of"] = json.loads(e.steward_bindings_of_json(M.kid))

# ── Control: node/agent fail-secure — bind then withdraw ──
appt_n = S.engine().steward_bind(N.kid, ["infra:transport"], CUSTODY)
e = S.engine()
report["node_bound_is_steward_bound"] = e.is_steward_bound_json(N.kid)
report["node_bound_bindings_of"] = json.loads(e.steward_bindings_of_json(N.kid))

S.engine().revoke_delegation(appt_n, N.kid)
e = S.engine()
report["node_revoked_is_steward_bound"] = e.is_steward_bound_json(N.kid)
report["node_revoked_bindings_of"] = json.loads(e.steward_bindings_of_json(N.kid))

# ── Fail-secure with a SURVIVING conferral (CIRISPersist#811) ──
# Custody from S plus a plain conferral from S2; withdraw the custody. The fold
# empties (a conferral is not custody); the predicate MUST agree — CC 3.2 rc4
# pairs them on the same owner-binding predicate, and persist documents
# `is_steward_bound(k) ⟺ !steward_bindings_of(k).is_empty()`.
appt_n2 = S.engine().steward_bind(N2.kid, ["infra:transport"], CUSTODY)
report["n2_conferral"] = S2.engine().steward_bind(N2.kid, ["infra:transport"])
e = S.engine()
report["n2_bound_bindings_of"] = json.loads(e.steward_bindings_of_json(N2.kid))
S.engine().revoke_delegation(appt_n2, N2.kid)
e = S.engine()
report["n2_revoked_is_steward_bound"] = e.is_steward_bound_json(N2.kid)
report["n2_revoked_bindings_of"] = json.loads(e.steward_bindings_of_json(N2.kid))

report["stage"] = "done"
print(json.dumps(report)); sys.stdout.flush(); os._exit(0)
"""


@pytest.fixture(scope="module")
def liveness():
    script = f"INJECTED_URL = {get_database_url()!r}\n" + TRUST_ROOT_CEREMONY_SRC + _BODY
    result = run_python_script(script)
    payload = result.parsed_stdout()
    if payload.get("_error") == "absent":
        pytest.fail(f"persist steward surface missing: {payload.get('surface')}")
    assert payload.get("stage") == "done", payload
    return payload


# ── Control: node/agent steward-binding fail-secure IS real (the posture CC 3.2
#    says a steward-less minor must share) ──
@pytest.mark.requires_persist
def test_node_binding_revocation_fails_secure(liveness):
    """A steward-bound node, once its binding is withdrawn, is steward-less again."""
    r = liveness
    assert r["node_bound_is_steward_bound"] == "true", r
    assert r["S"] in r["node_bound_bindings_of"], r
    assert r["node_revoked_is_steward_bound"] == "false", (
        f"a node's binding was withdrawn yet is_steward_bound still resolves true "
        f"— the node/agent fail-secure path is broken: {r}")
    assert r["node_revoked_bindings_of"] == [], (
        f"a withdrawn node binding still lists a steward: {r}")


# ── The minor-guardianship binding IS creatable (proven-adult → proven-minor) ──
@pytest.mark.requires_persist
def test_minor_guardianship_binding_is_admitted(liveness):
    """On persist 13.2.0 a proven-adult → proven-minor steward_bind is ADMITTED.

    Once the guardian S is a proven adult and the ward M is a proven minor
    (graduated via the #368 witness-attests-subject path), the CC 3.2
    minor-guardianship `delegates_to(adult-user → minor-user)` is admitted and
    resolves `is_steward_bound(M)` true — the live binding whose withdrawal the
    fail-secure test below observes. (Was forbidden wholesale on persist 12.5.0.)
    """
    r = liveness
    assert r["band_S"] == '"adult"', f"guardian S did not graduate to adult: {r['band_S']}"
    assert r["band_M"] == '"minor"', f"ward M did not graduate to minor: {r['band_M']}"
    assert r["minor_bind"]["outcome"] == "admitted", (
        f"a proven-adult → proven-minor steward_bind was refused — the CC 3.2 "
        f"conditional minor-guardianship admit is not enforced: {r['minor_bind']}")
    assert r["minor_bound_is_steward_bound"] == "true", (
        f"the admitted adult→minor binding does not resolve is_steward_bound: {r}")
    assert r["S"] in r["minor_bound_bindings_of"], (
        f"adult guardian absent from the minor's steward_bindings_of: {r}")


# ── CC 3.2 minor fail-secure — the steward-less-minor transition IS observable ──
@pytest.mark.requires_persist
def test_steward_less_minor_fails_secure(liveness):
    """CC 3.2: a minor whose adult steward is withdrawn MUST be steward-less.

    Probed real on persist 13.2.0: with a live proven-adult → proven-minor binding
    in place (`is_steward_bound(M) == true`), the adult granter withdraws it via
    `revoke_delegation`. `is_steward_bound(M)` then flips to **false** and
    `steward_bindings_of(M)` empties — the steward-less-minor fail-secure posture
    ("a minor MUST NOT operate without a live adult steward"), machine-checked on
    the `user` target exactly as on the node/agent control. Was `xfail(strict)` on
    persist 12.5.0 (the adult→minor binding could not be created to withdraw); now
    a real green gate (CIRISPersist#367, shipped at persist 13.0).
    """
    r = liveness
    assert r["minor_revoked_is_steward_bound"] == "false", (
        f"a minor's adult steward-binding was withdrawn yet is_steward_bound still "
        f"resolves true — the steward-less-minor fail-secure transition is broken: {r}")
    assert r["minor_revoked_bindings_of"] == [], (
        f"a withdrawn minor binding still lists a steward: {r}")


@pytest.mark.requires_persist
def test_conferral_does_not_keep_a_node_steward_bound_fold(liveness):
    """CC 3.2 (CIRISConstitution#87): a capability conferral is not custody, so the
    custody FOLD ignores it — before and after the owner-binding is withdrawn.

    N2 carries custody from S and a plain conferral from S2. `steward_bindings_of`
    names S alone while the custody is live, and is empty once it is withdrawn:
    the conferring user never enters the custody set.
    """
    r = liveness
    assert r["n2_bound_bindings_of"] == [r["S"]], (
        f"the conferring user S2 entered the custody set: {r['n2_bound_bindings_of']}")
    assert r["n2_revoked_bindings_of"] == [], (
        f"custody withdrawn but the fold still names a steward: {r['n2_revoked_bindings_of']}")


@pytest.mark.requires_persist
@pytest.mark.xfail(strict=True, reason=
    "CIRISPersist#811: `is_steward_bound` still counts a plain conferral after the sole "
    "owner-binding is revoked — the predicate did not narrow with the fold (CC 3.2 rc4 pairs "
    "them; persist documents the biconditional). Turns red the moment the predicate is narrowed.")
def test_conferral_does_not_keep_a_node_steward_bound_predicate(liveness):
    """CC 3.2 (CIRISConstitution#87): the PREDICATE agrees with the fold — a node whose
    only custody edge is withdrawn is steward-less, whatever conferrals survive.

    Same N2 as the fold test: after S's owner-binding is revoked, with S2's
    conferral still live, `is_steward_bound(N2)` MUST read false. On persist
    v40.0.0 it reads true (CIRISPersist#811) while the fold is already empty — a
    steward-less state the substrate can create but not describe.
    """
    r = liveness
    assert r["n2_revoked_bindings_of"] == [], r
    assert r["n2_revoked_is_steward_bound"] == "false", (
        f"the node reads steward-bound on the strength of a conferral alone after its "
        f"custody was withdrawn: is_steward_bound={r['n2_revoked_is_steward_bound']} "
        f"bindings_of={r['n2_revoked_bindings_of']}")
