"""
Fabric tier — CC 3.4.12 the adult-incapacity capacity gate (`CLM-adult-incapacity`).

CC 3.4.12 (part_3_the_namespace.md §3.4.12,
"`adult-incapacity-stewardship` — Adult stewardship under incapacity") carves the
single admissible aperture in the CC 3.2 "an adult is sovereign and un-stewardable"
wall: an adult who has suffered an **attested loss of decisional capacity** MAY
become a steward-target. The load-bearing safeguard is the **capacity-assurance
ladder** — the sibling of the CC 3.4.11 age-assurance ladder, with the **same
witness-reservation discipline**, but **multiplied per decision-domain** because
capacity (unlike age) is a per-domain, time-varying vector:

    capacity_assurance:{level}:{domain}:{band}:v1
        band ∈ { capacitated, incapacitated }        # per-domain, per-decision-class
        e.g. capacity_assurance:panel:financial:incapacitated:v1

Three normative properties of the gate — all REAL on the floor (persist 15.1.0),
driven end-to-end here through `Engine.capacity_state_json(key_id, domain)`:

- **Per-domain graduation + presumption of capacity.** A `witness` identity's
  `capacity_assurance:*:{domain}:incapacitated` attestation naming a subject's
  `attested_key_id` graduates `capacity_state_json(subject, domain)`
  `"unknown" → "incapacitated"`. A domain with NO attestation stays `"unknown"`
  (§3.4.12 rule 1: "Absence resolves to CAPACITY, not protection" — the
  presumption of capacity; no row on a domain means the adult holds that domain).
  The untouched-domain control is what makes the per-domain vector real, not a
  scalar.
- **`capacity_assurance:` is witness-RESERVED.** The subject MUST NOT emit it —
  a subject self-emitting its own incapacity is rejected
  `federation_capacity_self_emission_rejected` (§3.4.12: "No one can self-mint an
  adult's incapacity"). A non-witness `agent` key is rejected at the reserved-
  prefix admission gate `federation_reserved_prefix_emitter_mismatch`.

**What is NOT asserted here — a SEPARATE persist gap.** The CC 3.4.12 admission
*aperture* itself — a `steward_bind` onto the incapacitated adult being ADMITTED
(the third admissible case of `admit_user_steward_binding`, rooted in prior-will /
due-process / emergency-necessity) — is **not wired on the floor**: `steward_bind`
onto a proven-incapacitated adult is still rejected
`federation_user_target_steward_binding_forbidden` regardless of
`delegation_purpose` (probed on persist 15.1.0). That aperture is a distinct
CIRISPersist gap and is NOT asserted by this test; this file drives only the
capacity **gate** (the ladder), which is genuinely green.

Real surface: `Engine.capacity_state_json(key_id, domain)` (the per-domain reader),
`Engine.emit_attestation` (witness→subject), `Engine.emit_attestation_self`
(self-emission — must reject the reserved prefix).
"""

from __future__ import annotations

import pytest

from conftest import TRUST_ROOT_CEREMONY_SRC, get_database_url, run_python_script

pytestmark = pytest.mark.fabric

# One shared substrate (an on-disk sqlite file, or the injected postgres URL) so a
# witness's attestation about a subject is visible to any reconstructed engine —
# cross-engine key visibility is the whole point. Only one Engine may be live at a
# time (reset_engine closes the prior one), so each identity is RECONSTRUCTED on
# the shared substrate whenever it must be the live signer; its kid is stable
# across reconstructions (same alias + same Ed25519 seed → same derived key_id).
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


for surface in ("capacity_state_json", "emit_attestation", "emit_attestation_self",
                "register_self_federation_key"):
    if not hasattr(Ident("probe", "agent", "probe").engine(), surface):
        report({"_error": "absent", "surface": surface})

W = Ident("witness", "witness", "cap-witness")     # the qualified assessor (witness-reserved)
Sub = Ident("subj", "user", "adult-subject")       # the adult whose capacity is assessed
Ag = Ident("agentx", "agent", "agent-emitter")     # a non-witness key (must be refused the prefix)

# CIRISConformance#87 — stand up a trust root and confer the witness-reserved
# capability from it (persist v30.2.0+): holding `witness` is necessary, never
# sufficient. Drives the real three-row ceremony (see conftest).
ROOT = Ident("root", "agent", "trust-root")
_TRUST_ROOT_CEREMONY = confer_from_trust_root(ROOT, W, "infra:attest_assurance")

r = {}


def _attempt(label, fn):
    try:
        r[label] = {"outcome": "admitted", "id": str(fn())}
    except Exception as exc:
        r[label] = {"outcome": "rejected", "token": str(exc)[:200]}


def _witness_attest(who, subject_kid, atype):
    return who.engine().emit_attestation(json.dumps({
        "attestation_type": atype, "attestation_envelope": {},
        "attested_key_id": subject_kid}))


# Establish the subject as a proven adult first (the aperture is adult-only).
_attempt("attest_adult", lambda: _witness_attest(W, Sub.kid, "age_assurance:provider:adult:v1"))

# ── Presumption of capacity: every domain is "unknown" before any attestation ──
r["financial_pre"] = W.engine().capacity_state_json(Sub.kid, "financial")

# ── Per-domain graduation: witness attests financial incapacity (+ reversible-excl) ──
_attempt("attest_incap_financial", lambda: _witness_attest(
    W, Sub.kid, "capacity_assurance:panel:financial:incapacitated:v1"))
_attempt("attest_reversible_excluded", lambda: _witness_attest(
    W, Sub.kid, "capacity_assurance:reversible_excluded:financial"))

e = W.engine()
r["financial_post"] = e.capacity_state_json(Sub.kid, "financial")
r["medical_untouched"] = e.capacity_state_json(Sub.kid, "medical")   # presumption control

# ── Witness-reservation: the SUBJECT must not self-mint its own incapacity ──
_attempt("self_emit_incapacity", lambda: Sub.engine().emit_attestation_self(json.dumps({
    "attestation_type": "capacity_assurance:panel:financial:incapacitated:v1",
    "attestation_envelope": {}, "attested_key_id": Sub.kid})))

# ── Witness-reservation: a non-witness AGENT key is refused the reserved prefix ──
_attempt("agent_emit_incapacity", lambda: _witness_attest(
    Ag, Sub.kid, "capacity_assurance:panel:financial:incapacitated:v1"))

r["stage"] = "done"
report(r)
"""


@pytest.fixture(scope="module")
def gate():
    script = f"INJECTED_URL = {get_database_url()!r}\n" + TRUST_ROOT_CEREMONY_SRC + _BODY
    payload = run_python_script(script).parsed_stdout()
    if payload.get("_error") == "absent":
        pytest.fail(f"persist capacity surface missing: {payload.get('surface')}")
    if payload.get("_error"):
        pytest.fail(f"probe failed: {payload}")
    assert payload.get("stage") == "done", payload
    return payload


@pytest.mark.requires_persist
def test_capacity_graduates_per_domain_and_presumes_capacity(gate):
    """CC 3.4.12: a witness's per-domain incapacity attestation graduates
    `capacity_state_json`; an untouched domain stays `"unknown"` (presumption of
    capacity).

    The witness's `capacity_assurance:panel:financial:incapacitated:v1` (with its
    `reversible_excluded` companion) resolves the subject's `financial` domain
    `"unknown" → "incapacitated"`, while an untouched `medical` domain stays
    `"unknown"` — §3.4.12 rule 1 ("absence resolves to CAPACITY, not protection").
    The untouched-domain control proves capacity is a per-domain vector, not a
    scalar.
    """
    r = gate
    assert r["attest_incap_financial"]["outcome"] == "admitted", r["attest_incap_financial"]
    assert r["financial_pre"] == '"unknown"', (
        f"financial domain should presume capacity before any attestation: {r['financial_pre']}")
    assert r["financial_post"] == '"incapacitated"', (
        f"witness incapacity attestation did not graduate the financial domain: "
        f"{r['financial_post']}")
    assert r["medical_untouched"] == '"unknown"', (
        f"an UNATTESTED domain must presume capacity (per-domain vector): "
        f"{r['medical_untouched']}")


@pytest.mark.requires_persist
def test_subject_cannot_self_mint_incapacity(gate):
    """CC 3.4.12: the subject MUST NOT emit its own incapacity — no one self-mints
    an adult's incapacity.

    A subject `emit_attestation_self` of `capacity_assurance:*:incapacitated` is
    rejected `federation_capacity_self_emission_rejected` — the witness-reservation
    self-emission wall (the sibling of CC 3.4.5's capacity-score self-emission
    rejection).
    """
    r = gate
    assert r["self_emit_incapacity"]["outcome"] == "rejected", (
        f"the subject self-minted its own incapacity — the §3.4.12 self-emission "
        f"wall is not enforced: {r['self_emit_incapacity']}")
    assert "capacity_self_emission_rejected" in r["self_emit_incapacity"]["token"], (
        f"unexpected rejection token for subject self-minted incapacity: "
        f"{r['self_emit_incapacity']}")


@pytest.mark.requires_persist
def test_non_witness_agent_refused_capacity_prefix(gate):
    """CC 3.4.12: `capacity_assurance:` is witness-RESERVED — a non-witness emitter
    is refused at admission.

    An `agent` key emitting `capacity_assurance:*:incapacitated` about a subject is
    rejected `federation_reserved_prefix_emitter_mismatch` — only a registered
    qualified assessor (`witness` identity) may attest capacity.
    """
    r = gate
    assert r["agent_emit_incapacity"]["outcome"] == "rejected", (
        f"a non-witness agent emitted a capacity_assurance attestation — the "
        f"reserved-prefix witness gate is not enforced: {r['agent_emit_incapacity']}")
    assert "reserved_prefix_emitter_mismatch" in r["agent_emit_incapacity"]["token"], (
        f"unexpected rejection token for an agent-emitted capacity attestation: "
        f"{r['agent_emit_incapacity']}")
