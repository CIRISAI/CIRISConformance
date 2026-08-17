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

from conftest import (get_database_url, run_python_script,
                      xfail_if_unconferred_assurance_scope)

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
        self.kid = self.engine().register_self_federation_key(itype, ref, None, None, None)

    def engine(self):
        cp.reset_engine()
        return cp.Engine(DB_URL, self.k, local_key_id=self.k, local_key_path=self.s,
                         local_pqc_key_id=self.k + "-pqc", local_pqc_key_path=self.p)


for surface in ("steward_bind", "revoke_delegation", "is_steward_bound_json",
                "steward_bindings_of_json", "emit_attestation", "age_band_json"):
    probe = Ident("probe", "agent", "probe")
    if not hasattr(probe.engine(), surface):
        print(json.dumps({"_error": "absent", "surface": surface})); sys.exit(2)

W = Ident("witness", "witness", "age-witness")   # attests subjects' age bands (#368)
S = Ident("steward", "user", "adult-steward")    # the adult-user guardian (signer)
M = Ident("minor", "user", "minor-ward")         # the proven-minor user ward
N = Ident("node", "agent", "node-ref")           # node/agent control

report = {"S": S.kid, "M": M.kid, "N": N.kid}

# ── #368 witness-attests-subject: graduate the ages FIRST ──
# The witness emits age_assurance:provider:* attestations naming each subject's
# attested_key_id: S → adult, M → minor. This is the precondition the CC 3.2
# admit rule requires — a proven-adult guardian binding a proven-minor ward.
def _attest(subject_kid, atype):
    return W.engine().emit_attestation(json.dumps({
        "attestation_type": atype, "attestation_envelope": {},
        "attested_key_id": subject_kid}))

_attest(S.kid, "age_assurance:provider:adult:v1")
_attest(M.kid, "age_assurance:provider:16_17:v1")
e = W.engine()
report["band_S"] = e.age_band_json(S.kid)
report["band_M"] = e.age_band_json(M.kid)

# ── Minor: create the live adult→minor guardianship binding ──
# Proven-adult S → proven-minor M is ADMITTED (CIRISPersist#367, persist 13.0).
try:
    appt_m = S.engine().steward_bind(M.kid, ["infra:transport"])
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
appt_n = S.engine().steward_bind(N.kid, ["infra:transport"])
e = S.engine()
report["node_bound_is_steward_bound"] = e.is_steward_bound_json(N.kid)
report["node_bound_bindings_of"] = json.loads(e.steward_bindings_of_json(N.kid))

S.engine().revoke_delegation(appt_n, N.kid)
e = S.engine()
report["node_revoked_is_steward_bound"] = e.is_steward_bound_json(N.kid)
report["node_revoked_bindings_of"] = json.loads(e.steward_bindings_of_json(N.kid))

report["stage"] = "done"
print(json.dumps(report)); sys.stdout.flush(); os._exit(0)
"""


@pytest.fixture(scope="module")
def liveness():
    script = f"INJECTED_URL = {get_database_url()!r}\n" + _BODY
    result = run_python_script(script)
    # The scenario attests an age band, which is a witness-reserved prefix.
    # Since persist v32.3.0 that also requires a CONFERRED
    # `infra:attest_assurance` capability, which the harness cannot yet mint —
    # the node dies before printing its report, so this must be caught here
    # rather than by an xfail marker on each test (CIRISConformance#87).
    xfail_if_unconferred_assurance_scope(result)
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
