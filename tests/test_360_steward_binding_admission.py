"""
Fabric tier — CC 3.2 user-target steward-binding admission rule.

CC 3.2 (part_3_the_namespace.md, "User-target admission rule") closes the gap
left by the node/agent steward-binding gate: a `delegates_to(S → T)` whose
**target `T` resolves to a `user`-role identity** is otherwise unguarded —
"stewarding a person" is admissible. The rule narrows the admissible set to
exactly minor-guardianship:

    admit_user_steward_binding(delegates_to S -> T):
      require  age_band(T) == minor   (< 18)      # ward is a minor
      require  user in S.identity_type            # steward is a user identity
      require  age_band(S) == adult   (>= 18)     # steward is an adult
      require  S == delegates_to.attesting_key_id # steward signed it
      otherwise REJECT

A user-target binding whose target `T` is an **adult** — or whose age is
**unverified** (presumption of sovereignty: no proven-minor band ⇒ treat as a
self-sovereign adult) — is **rejected** (the un-stewardable case, CC 3.2 /
CC 1.15.6). A binding where the steward `S` is a minor, or where the signer is
not the steward, is likewise rejected. `node`/`agent`-target admission is
governed by the older steward-binding gate and is NOT affected by this rule.

What is REAL on the floor (persist 13.2.0), the proven-adult → proven-minor
model — probed end-to-end here:

- **the conditional minor-guardianship admit ships** (CIRISPersist#367, closed;
  landed at persist 13.0). Once the ages are ESTABLISHED via the #368
  witness-attests-subject path — a `witness` identity emits an
  `age_assurance:provider:*` attestation naming the subject's `attested_key_id`,
  graduating `age_band(S)==adult` and `age_band(T)==minor` — a `grant_delegation`
  / `steward_bind` from the proven-adult steward `S` onto the proven-minor ward
  `T` is **ADMITTED**. This is the CC 3.2 positive path, now a real green gate
  (was `xfail(strict)` on persist 12.5.0, when only the wholesale user-target
  forbid was exposed).
- **the un-stewardable rejection is enforced** — a binding onto a **proven-adult**
  user (`age_band==adult`) OR an **unverified-age** user (`age_band==unknown`,
  presumption of sovereignty) rejects with
  `federation_user_target_steward_binding_forbidden`. The earlier test drove this
  WRONG: it bound onto a target of unverified age and read the forbid as a
  "wholesale" block; in fact the forbid is exactly the presumption-of-sovereignty
  refusal — the admit fires only for a proven-adult → proven-minor binding.
- **node/agent control** — a node/agent steward-binding is admitted and resolves
  `is_steward_bound` true (unchanged, governed by the older gate).
"""

from __future__ import annotations

import pytest

from conftest import get_database_url, run_python_script

pytestmark = pytest.mark.fabric

# A shared-substrate scenario: register a witness, an adult-user steward, a minor
# user ward, a self-sovereign adult user, an unverified-age user, and an agent
# node — all over one sqlite file. The witness graduates the ages via the #368
# witness-attests-subject path (age_assurance:provider:* naming attested_key_id),
# then the steward attempts each binding and we report the outcome token + bands.
_BODY = r"""
import json, sys, os, tempfile, secrets
try:
    import ciris_persist as cp
except ImportError as exc:
    print(json.dumps({"_error": "import", "detail": str(exc)})); sys.exit(2)

# A single SHARED substrate so every reconstructed engine sees the same
# federation_keys / attestations — cross-engine key visibility is the whole point
# (the witness's attestation about a subject must be visible to the steward's
# engine when it evaluates the binding). The harness injects INJECTED_URL to honor
# the chosen backend: postgres is already shared across subprocesses; for the
# sqlite default we need an ON-DISK file (`sqlite::memory:` gives each Engine its
# own private DB). Full sqlite+postgres parity (the user's hard requirement).
if INJECTED_URL.startswith("postgres"):
    DB_URL = INJECTED_URL
else:
    _dbf = os.path.join(tempfile.mkdtemp(), "f.db"); open(_dbf, "a").close()
    DB_URL = "sqlite:///" + _dbf


# Only one Engine may be live at a time (`reset_engine` closes the prior one), so
# each identity carries its stable alias + key paths and is RECONSTRUCTED on the
# shared substrate whenever it must be the live signer. The kid is stable across
# reconstructions (same alias + same Ed25519 seed → same derived key_id).
class Ident:
    def __init__(self, prefix, itype, ref):
        d = tempfile.mkdtemp()
        self.s = os.path.join(d, "s"); open(self.s, "wb").write(secrets.token_bytes(32))
        self.p = os.path.join(d, "p"); open(self.p, "wb").write(secrets.token_bytes(32))
        self.k = prefix + "-" + secrets.token_hex(8)
        self.itype, self.ref = itype, ref
        self.kid = self.engine().register_self_federation_key(itype, ref, None, None, None)

    def engine(self):
        cp.reset_engine()
        return cp.Engine(DB_URL, self.k, local_key_id=self.k, local_key_path=self.s,
                         local_pqc_key_id=self.k + "-pqc", local_pqc_key_path=self.p)


for surface in ("steward_bind", "grant_delegation", "is_steward_bound_json",
                "steward_bindings_of_json", "emit_attestation", "age_band_json"):
    probe = Ident("probe", "agent", "probe")
    if not hasattr(probe.engine(), surface):
        print(json.dumps({"_error": "absent", "surface": surface})); sys.exit(2)

W = Ident("witness", "witness", "age-witness")   # attests subjects' age bands (#368)
S = Ident("steward", "user", "adult-steward")    # the adult-user steward (signer)
T = Ident("minor", "user", "minor-ward")         # the proven-minor ward (user)
A = Ident("adult", "user", "adult-other")        # a self-sovereign adult user
U = Ident("unver", "user", "unverified-user")    # a user of unverified age
N = Ident("node", "agent", "node-ref")           # a node/agent (the control)

report = {"S": S.kid, "T": T.kid, "A": A.kid, "U": U.kid, "N": N.kid}


def _attempt(label, fn):
    try:
        report[label] = {"outcome": "admitted", "id": fn()}
    except Exception as exc:
        report[label] = {"outcome": "rejected", "token": str(exc)[:200]}


# ── #368 witness-attests-subject: establish the ages FIRST ──
# The witness emits an age_assurance:provider:* attestation naming each subject's
# attested_key_id, graduating S → adult and T → minor. A is proven adult (also
# un-stewardable); U is left unattested (age_band unknown → presumed sovereign).
def _attest(subject_kid, atype):
    return W.engine().emit_attestation(json.dumps({
        "attestation_type": atype, "attestation_envelope": {},
        "attested_key_id": subject_kid}))

_attempt("attest_S", lambda: _attest(S.kid, "age_assurance:provider:adult:v1"))
_attempt("attest_T", lambda: _attest(T.kid, "age_assurance:provider:16_17:v1"))
_attempt("attest_A", lambda: _attest(A.kid, "age_assurance:provider:adult:v1"))

# Record the resulting age bands (coarse + fine) — the admit rule keys off these.
e = W.engine()
for lbl, kid in (("S", S.kid), ("T", T.kid), ("A", A.kid), ("U", U.kid)):
    report["band_" + lbl] = e.age_band_json(kid)
    report["fine_" + lbl] = e.age_band_fine_json(kid)

# ── CC 3.2 user-target admission attempts, signed by the adult steward S ──
# S (proven adult) → T (proven minor): the legal minor-guardianship case → ADMIT.
_attempt("minor_target_grant", lambda: S.engine().grant_delegation(T.kid, ["steward"], False))
_attempt("minor_target_bind", lambda: S.engine().steward_bind(T.kid, ["infra:transport"]))
# S (proven adult) → A (proven adult): un-stewardable → REJECT.
_attempt("adult_target_grant", lambda: S.engine().grant_delegation(A.kid, ["steward"], False))
_attempt("adult_target_steward_bind", lambda: S.engine().steward_bind(A.kid, ["infra:transport"]))
# S (proven adult) → U (unverified age): presumption of sovereignty → REJECT.
_attempt("unver_target_steward_bind", lambda: S.engine().steward_bind(U.kid, ["infra:transport"]))

# Confirm the admitted minor binding actually resolves as a live steward-binding.
e = S.engine()
report["minor_is_steward_bound"] = e.is_steward_bound_json(T.kid)
report["minor_bindings_of"] = json.loads(e.steward_bindings_of_json(T.kid))

# ── Control: node/agent steward-binding IS real and enforced ──
_attempt("node_bind", lambda: S.engine().steward_bind(N.kid, ["infra:transport"]))
e = S.engine()
report["node_is_steward_bound"] = e.is_steward_bound_json(N.kid)
report["node_bindings_of"] = json.loads(e.steward_bindings_of_json(N.kid))

report["stage"] = "done"
print(json.dumps(report)); sys.stdout.flush(); os._exit(0)
"""


@pytest.fixture(scope="module")
def admission():
    # Honor the chosen backend: under postgres the injected URL is the shared
    # substrate; under the sqlite default the body mints an on-disk file (the
    # cross-engine key visibility this scenario needs is impossible over the
    # conftest `:memory:` default, where each Engine gets a private database).
    script = f"INJECTED_URL = {get_database_url()!r}\n" + _BODY
    payload = run_python_script(script).parsed_stdout()
    if payload.get("_error") == "absent":
        pytest.fail(f"persist steward surface missing: {payload.get('surface')}")
    assert payload.get("stage") == "done", payload
    return payload


# ── Control: the node/agent steward-binding gate IS real (CC 3.2 unchanged) ──
@pytest.mark.requires_persist
@pytest.mark.xfail(strict=True, reason=
    "CIRISConformance#87: `age_assurance:`/`capacity_assurance:` now also require `infra:attest_assurance` CONFERRED from a trust root this node trusts (persist v32.3.0). The harness has no trust-root ceremony, so the witness emit is refused with federation_reserved_prefix_emitter_mismatch.")
def test_node_steward_binding_is_admitted_and_resolves(admission):
    """A node/agent steward-binding is admitted and resolves `is_steward_bound` true."""
    r = admission
    assert r["node_bind"]["outcome"] == "admitted", (
        f"node steward_bind was refused: {r['node_bind']}")
    assert r["node_is_steward_bound"] == "true", (
        f"steward-bound node not recognized by is_steward_bound: {r}")
    assert r["S"] in r["node_bindings_of"], (
        f"adult steward absent from the node's steward_bindings_of: {r}")


# ── Age graduation via the #368 witness-attests-subject path IS the precondition ──
@pytest.mark.requires_persist
@pytest.mark.xfail(strict=True, reason=
    "CIRISConformance#87: `age_assurance:`/`capacity_assurance:` now also require `infra:attest_assurance` CONFERRED from a trust root this node trusts (persist v32.3.0). The harness has no trust-root ceremony, so the witness emit is refused with federation_reserved_prefix_emitter_mismatch.")
def test_witness_attestation_graduates_age_bands(admission):
    """The witness's age_assurance attestations graduate S → adult and T → minor.

    Probed real on persist 13.2.0: a `witness` identity's
    `age_assurance:provider:*` attestation naming a subject's `attested_key_id`
    (the #368 path) resolves that subject's `age_band`. S graduates to `adult`,
    T to `minor` (fine band `16_17`); an unattested user U stays `unknown`. These
    bands are the exact inputs the CC 3.2 admit rule keys off.
    """
    r = admission
    assert r["attest_S"]["outcome"] == "admitted", r["attest_S"]
    assert r["attest_T"]["outcome"] == "admitted", r["attest_T"]
    assert r["band_S"] == '"adult"', f"steward S did not graduate to adult: {r['band_S']}"
    assert r["band_T"] == '"minor"', f"ward T did not graduate to minor: {r['band_T']}"
    assert r["fine_T"] == '"16_17"', f"ward T fine band unexpected: {r['fine_T']}"
    assert r["band_U"] == '"unknown"', (
        f"unattested user U should have unknown age band: {r['band_U']}")


# ── CC 3.2 user-target admission rule — the un-stewardable rejections ──
@pytest.mark.requires_persist
@pytest.mark.xfail(strict=True, reason=
    "CIRISConformance#87: `age_assurance:`/`capacity_assurance:` now also require `infra:attest_assurance` CONFERRED from a trust root this node trusts (persist v32.3.0). The harness has no trust-root ceremony, so the witness emit is refused with federation_reserved_prefix_emitter_mismatch.")
def test_adult_target_user_binding_is_rejected(admission):
    """CC 3.2: a user-target steward-binding onto a PROVEN adult MUST be rejected.

    Probed real on persist 13.2.0: `grant_delegation` targeting a user whose
    `age_band==adult` is rejected with
    `federation_user_target_steward_binding_forbidden` — the un-stewardable-adult
    guarantee (presumption of sovereignty). The admit fires ONLY for a
    proven-minor target, never an adult one.
    """
    r = admission
    assert r["adult_target_grant"]["outcome"] == "rejected", (
        f"a delegates_to targeting a proven-adult user was admitted — the CC 3.2 "
        f"un-stewardable guarantee is not enforced: {r['adult_target_grant']}")
    assert "user_target_steward_binding_forbidden" in r["adult_target_grant"]["token"], (
        f"unexpected rejection token for an adult user-target delegation: "
        f"{r['adult_target_grant']}")


@pytest.mark.requires_persist
@pytest.mark.xfail(strict=True, reason=
    "CIRISConformance#87: `age_assurance:`/`capacity_assurance:` now also require `infra:attest_assurance` CONFERRED from a trust root this node trusts (persist v32.3.0). The harness has no trust-root ceremony, so the witness emit is refused with federation_reserved_prefix_emitter_mismatch.")
def test_adult_target_steward_bind_is_rejected(admission):
    """CC 3.2: `steward_bind` onto a PROVEN adult user MUST be rejected.

    Probed real on persist 13.2.0: `steward_bind` onto a user whose
    `age_band==adult` is rejected with
    `federation_user_target_steward_binding_forbidden`.
    """
    r = admission
    assert r["adult_target_steward_bind"]["outcome"] == "rejected", (
        f"steward_bind onto a proven-adult user was admitted: "
        f"{r['adult_target_steward_bind']}")
    assert "user_target_steward_binding_forbidden" in r["adult_target_steward_bind"]["token"], (
        f"unexpected rejection token for an adult user-target steward_bind: "
        f"{r['adult_target_steward_bind']}")


@pytest.mark.requires_persist
@pytest.mark.xfail(strict=True, reason=
    "CIRISConformance#87: `age_assurance:`/`capacity_assurance:` now also require `infra:attest_assurance` CONFERRED from a trust root this node trusts (persist v32.3.0). The harness has no trust-root ceremony, so the witness emit is refused with federation_reserved_prefix_emitter_mismatch.")
def test_unverified_age_target_is_rejected(admission):
    """CC 3.2: `steward_bind` onto a user of UNVERIFIED age MUST be rejected.

    Presumption of sovereignty (probed real on persist 13.2.0): a user with no
    proven-minor band (`age_band==unknown`) is treated as a self-sovereign adult,
    so binding onto it rejects with
    `federation_user_target_steward_binding_forbidden` — identical posture to a
    proven-adult target. This is the leg the earlier (12.5.0) test drove WRONG:
    it bound onto an unverified target and misread this sovereignty forbid as a
    "wholesale" block of ALL user-target bindings.
    """
    r = admission
    assert r["unver_target_steward_bind"]["outcome"] == "rejected", (
        f"steward_bind onto an unverified-age user was admitted — presumption of "
        f"sovereignty is not enforced: {r['unver_target_steward_bind']}")
    assert "user_target_steward_binding_forbidden" in r["unver_target_steward_bind"]["token"], (
        f"unexpected rejection token for an unverified-age user-target steward_bind: "
        f"{r['unver_target_steward_bind']}")


# ── CC 3.2 user-target admission rule — the POSITIVE minor-guardianship admit ──
@pytest.mark.requires_persist
@pytest.mark.xfail(strict=True, reason=
    "CIRISConformance#87: `age_assurance:`/`capacity_assurance:` now also require `infra:attest_assurance` CONFERRED from a trust root this node trusts (persist v32.3.0). The harness has no trust-root ceremony, so the witness emit is refused with federation_reserved_prefix_emitter_mismatch.")
def test_minor_target_user_binding_is_admitted_only_because_minor(admission):
    """CC 3.2: a user-target binding is ADMITTED iff the target is a proven minor.

    Probed real on persist 13.2.0 (CIRISPersist#367, shipped at persist 13.0):
    once S is a proven adult and T is a proven minor (graduated via the #368
    witness-attests-subject path), a `grant_delegation` / `steward_bind` from the
    adult steward S onto the minor ward T is ADMITTED — the conditional
    minor-guardianship admit. The admit is CONDITIONED on the minor band: the same
    binding onto a proven-adult or unverified-age target is refused (the sibling
    rejection tests). Was `xfail(strict)` on persist 12.5.0 (only the wholesale
    forbid was exposed then); now a real green gate.
    """
    r = admission
    assert r["minor_target_grant"]["outcome"] == "admitted", (
        f"the §3.2 conditional minor-guardianship grant_delegation was refused — a "
        f"proven-adult → proven-minor binding must be admitted: {r['minor_target_grant']}")
    assert r["minor_target_bind"]["outcome"] == "admitted", (
        f"the §3.2 conditional minor-guardianship steward_bind was refused: "
        f"{r['minor_target_bind']}")
    # And the admitted binding resolves as a live steward-binding on the minor.
    assert r["minor_is_steward_bound"] == "true", (
        f"the admitted adult→minor binding does not resolve is_steward_bound: {r}")
    assert r["S"] in r["minor_bindings_of"], (
        f"adult steward absent from the minor's steward_bindings_of: {r}")
