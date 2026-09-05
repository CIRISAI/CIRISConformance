"""
Fabric tier — CC 3.4.11 age-assurance: witness-reserved vs subject self-declared.

Age-assurance is **two** dimension families, not one, and the split is
load-bearing (part_3_the_namespace.md §3.4.11):

- **`age_assurance:`** — witness-RESERVED. The provider/government rung. As of
  persist 13.0.1 (CIRISPersist#368, the cross-subject witness graduation that
  shipped for CC 1.0-rc2) this rung is **attest-about-subject only**: it is
  emitted by a `witness`-role engine ABOUT a DIFFERENT subject's key
  (`attested_key_id`), and the SUBJECT's band graduates. Two gates guard it:
    * **self-emission is rejected for EVERYONE** — attester == attested on
      `age_assurance:*` raises `federation_age_assurance_self_emission_rejected`,
      whether the emitter is an agent OR a witness. A witness can no longer
      self-mint its own adulthood (that was the pre-13 model); nobody can. `self`
      is unfalsifiable, so the assurance rung must name a distinct subject.
    * **the emitter must be a witness** — a non-witness emitting `age_assurance:*`
      (even about another subject) raises
      `federation_reserved_prefix_emitter_mismatch`. A `roles=["witness"]` list on
      an `agent` identity_type does NOT satisfy the emitter rule; the
      discriminator is `federation_keys.identity_type` itself.
- **`age_self_declared:`** — NON-reserved, subject-signed. The onboarding "state
  your age range" rung. Admitted iff the signer acts for the subject. It carries
  **only** a `{band}` — never a `{level}` token — because its level is `self` by
  construction.

The self rungs are driven through the REAL persist `emit_attestation_self` (the
build-sign-admit one-call surface, self-binding to the emitter's key). The
witness-reserved rung is driven through `emit_attestation` with an
`attested_key_id` naming the SUBJECT (the cross-subject surface).

**Probed against persist 13.0.1 (venv /tmp/nf17):**

- `age_assurance:*` **self**-emission is REJECTED for both an agent-type key and a
  witness-type key with `federation_age_assurance_self_emission_rejected` (both the
  short `:level:band` form and the fully qualified `:level:band:vN` form). This is
  the persist 12.5 → 13.0.1 flip: a witness self-emitting `age_assurance:*` was
  accepted on 12.5 and is now rejected — the rung is attest-about-subject only.
- A **non-witness** emitting `age_assurance:*` ABOUT a subject (via
  `emit_attestation` + `attested_key_id`) is refused with
  `federation_reserved_prefix_emitter_mismatch` — the reservation gate. A
  `roles=["witness"]` agent key is refused the same way.
- A **witness**-type key emitting `age_assurance:*` ABOUT a subject IS admitted —
  the positive half of the reservation. This is the real cross-subject
  graduation surface; without it the refusals above could be a blanket "nobody may
  emit age_assurance:*" rather than a genuine witness reservation.
- A key registered `identity_type="agent"` is ACCEPTED on
  `age_self_declared:band:adult` (non-reserved, subject-signed), and REFUSED on
  `age_self_declared:level:adult` with `federation_dimension_rejected` (the self
  rung carries a `{band}`, never a `{level}` — CIRISPersist#307).

Lower-priority / undrivable here: the read-union band resolution (witness outranks
self) lives in test_351; the protective content gate and the
`moderation:age_assurance_misdeclaration` routing are consumer/adjudication
behaviors, not admission surfaces — not gated in this file.
"""

from __future__ import annotations

import pytest

from conftest import TRUST_ROOT_CEREMONY_SRC, get_database_url, run_python_script

pytestmark = pytest.mark.fabric

_ADMIT_BODY = r"""
import json, sys, os, tempfile, secrets
try:
    import ciris_persist as cp
except ImportError as exc:
    print(json.dumps({"_error": "import", "detail": str(exc)})); sys.exit(2)

# Shared on-disk substrate so the witness and its cross-subject target live in
# the same federation_keys table. postgres is shared across subprocesses; the
# sqlite default needs an ON-DISK file (`:memory:` gives each Engine a private
# DB, so a cross-subject subject would be invisible to the witness engine).
if DB_URL.startswith("postgres"):
    _URL = DB_URL
else:
    _dbf = os.path.join(tempfile.mkdtemp(), "f.db"); open(_dbf, "a").close()
    _URL = "sqlite:///" + _dbf


class Ident:
    # Stable alias + key paths; reconstructed to sign. Only one Engine is live at
    # a time (reset_engine closes the prior). The kid is stable across
    # reconstructions (same alias + seed → same derived key_id).
    def __init__(self, prefix, itype, ref, roles=None):
        d = tempfile.mkdtemp()
        self.s = os.path.join(d, "s"); open(self.s, "wb").write(secrets.token_bytes(32))
        self.p = os.path.join(d, "p"); open(self.p, "wb").write(secrets.token_bytes(32))
        self.k = prefix + "-" + secrets.token_hex(8)
        self.itype = itype
        self.reg_error = None
        try:
            self.kid = self.engine().register_self_federation_key(itype, ref, None, None, roles)
        except Exception as exc:
            self.kid = None
            self.reg_error = str(exc)[:80]

    def engine(self):
        cp.reset_engine()
        eng = cp.Engine(_URL, self.k, local_key_id=self.k, local_key_path=self.s,
                        local_pqc_key_id=self.k + "-pqc", local_pqc_key_path=self.p)
        # persist v40: a fresh Engine has no node identity until it registers;
        # the conferral gates resolve "does THIS NODE trust the root", so bind
        # it on every reconstruction (see conftest.TRUST_ROOT_CEREMONY_SRC).
        if getattr(self, "kid", None):
            _bind_node_identity(eng, self.itype)
        return eng


# Sanity: both admission surfaces must exist.
_probe = Ident("probe", "agent", "probe")
for _surface in ("emit_attestation_self", "emit_attestation"):
    if not hasattr(_probe.engine(), _surface):
        print(json.dumps({"_error": "absent", "surface": _surface})); sys.exit(2)


def emit_self(ident, atype):
    # Self-bound emit over the emitter's OWN key → "accepted" or reject token.
    try:
        ident.engine().emit_attestation_self(json.dumps(
            {"attestation_type": atype, "attestation_envelope": {}}))
        return "accepted"
    except Exception as exc:
        return str(exc)[:80]


def emit_about(ident, atype, subject_kid):
    # Cross-subject emit: this key attests `atype` ABOUT subject_kid.
    try:
        ident.engine().emit_attestation(json.dumps(
            {"attestation_type": atype, "attestation_envelope": {},
             "attested_key_id": subject_kid}))
        return "accepted"
    except Exception as exc:
        return str(exc)[:80]


report = {}

# ── A registered AGENT-type key (a subject) ──────────────────────────────
agent = Ident("agent", "agent", "age-agent")

# Sanity baseline: a plain scores attestation self-emitted from an agent key is
# admitted — else the rejection assertions below would pass for the wrong reason.
report["baseline_scores"] = emit_self(agent, "scores:quality:test")

# CC 3.4.11 (persist 13) — age_assurance:* is attest-about-subject ONLY. A
# SELF-emission (attester == attested) is rejected regardless of role. Both the
# short `:level:band` form and the fully qualified `:level:band:vN` form.
report["agent_self_age_assurance_level"] = emit_self(agent, "age_assurance:level:adult")
report["agent_self_age_assurance_provider"] = emit_self(agent, "age_assurance:provider:adult:v1")

# CC 3.4.11 — age_self_declared:* is NON-reserved, subject-signed. The subject's
# own occurrence may self-emit its self-declared band → admitted.
report["agent_self_declared_band"] = emit_self(agent, "age_self_declared:band:adult")

# CC 3.4.11 / CIRISPersist#307 — the self rung carries a {band}, NEVER a {level}.
report["agent_self_declared_level"] = emit_self(agent, "age_self_declared:level:adult")

# ── The cross-subject SUBJECT the witness will attest about ───────────────
subject = Ident("subj", "agent", "age-subject")
report["subject_kid"] = subject.kid

# A non-witness (agent) emitting the reserved prefix ABOUT another subject is
# refused: the emitter rule is witness ∈ identity_type. This is the reservation
# gate — even the cross-subject surface will not admit a non-witness emitter.
report["agent_xsubject_age_assurance"] = emit_about(
    agent, "age_assurance:provider:adult:v1", subject.kid)

# A roles=["witness"] list on an agent identity_type does NOT satisfy the
# emitter rule — the discriminator is identity_type itself, not a roles list.
agent_roles = Ident("agentr", "agent", "age-agent-roles", roles=["witness"])
report["agent_roles_xsubject_age_assurance"] = emit_about(
    agent_roles, "age_assurance:provider:adult:v1", subject.kid)

# ── A registered WITNESS-type key (a provider/government verifier) ────────
witness = Ident("witn", "witness", "age-witness")

# CIRISConformance#87 — stand up a trust root and confer the witness-reserved
# capability from it (persist v30.2.0+): holding `witness` is necessary, never
# sufficient. Drives the real three-row ceremony (see conftest).
ROOT = Ident("root", "agent", "trust-root")
_TRUST_ROOT_CEREMONY = confer_from_trust_root(ROOT, witness, "infra:attest_assurance")
report["witness_register"] = "ok" if witness.reg_error is None else "REGFAIL:" + witness.reg_error

# The witness cannot SELF-emit age_assurance:* either — self is unfalsifiable, so
# even a witness's own adulthood is rejected (the persist 12.5 → 13 flip).
report["witness_self_age_assurance_provider"] = emit_self(witness, "age_assurance:provider:adult:v1")
report["witness_self_age_assurance_level"] = emit_self(witness, "age_assurance:level:adult")

# The positive reservation gate: a witness emitting age_assurance:* ABOUT a
# subject IS admitted — the real cross-subject graduation surface.
report["witness_xsubject_age_assurance"] = emit_about(
    witness, "age_assurance:provider:adult:v1", subject.kid)

report["stage"] = "done"
print(json.dumps(report)); sys.stdout.flush()
os._exit(0)
"""


def _admit_script(database_url: str) -> str:
    return f"DB_URL = {database_url!r}\n" + TRUST_ROOT_CEREMONY_SRC + _ADMIT_BODY


@pytest.fixture(scope="module")
def admission():
    result = run_python_script(_admit_script(get_database_url()))
    payload = result.parsed_stdout()
    if payload.get("_error") == "absent":
        pytest.fail(f"persist admission surface is missing: {payload.get('surface')} "
                    "— the attestation admission surfaces are not on the wheel")
    if payload.get("_error") == "import":
        pytest.fail(f"ciris_persist import failed: {payload.get('detail')}")
    assert payload.get("stage") == "done", payload
    # Guard: the surface must accept a legitimate attestation, else the
    # rejection assertions below would pass for the wrong reason.
    assert payload["baseline_scores"] == "accepted", payload
    return payload


@pytest.mark.requires_persist
def test_agent_refused_on_age_assurance_prefix(admission):
    """CC 3.4.11 (persist 13): a subject cannot self-mint OR cross-attest on the reserved age_assurance:* prefix.

    Two refusals guard the witness-reserved prefix for a non-witness (agent) key:

    - **self-emission** (attester == attested) is rejected with
      `federation_age_assurance_self_emission_rejected` — the persist-13
      attest-about-subject model: `self` is unfalsifiable, so nobody self-mints
      an age assurance. Both the short `age_assurance:level:adult` and the
      fully-qualified `age_assurance:provider:adult:v1` are refused.
    - **cross-subject emission** by a non-witness (even ABOUT a distinct subject)
      is refused with `federation_reserved_prefix_emitter_mismatch` — the emitter
      rule `witness ∈ identity_type`. A `roles=["witness"]` agent key is refused
      the same way; the gate keys off identity_type, not a roles list.
    """
    # Self-emission is rejected for the agent (attest-about-subject only).
    assert admission["agent_self_age_assurance_level"] != "accepted", (
        f"agent self-minted age_assurance:level:* (CC 3.4.11): "
        f"{admission['agent_self_age_assurance_level']}")
    assert "federation_age_assurance_self_emission_rejected" in admission["agent_self_age_assurance_level"], (
        admission["agent_self_age_assurance_level"])

    assert admission["agent_self_age_assurance_provider"] != "accepted", (
        f"agent self-minted age_assurance:provider:* (CC 3.4.11): "
        f"{admission['agent_self_age_assurance_provider']}")
    assert "federation_age_assurance_self_emission_rejected" in admission["agent_self_age_assurance_provider"], (
        admission["agent_self_age_assurance_provider"])

    # Cross-subject emission by a non-witness is refused with the reserved-prefix
    # emitter mismatch — the reservation is real, not a blanket "nobody emits".
    assert admission["agent_xsubject_age_assurance"] != "accepted", (
        f"a non-witness agent emitted age_assurance:* ABOUT a subject (CC 3.4.11): "
        f"{admission['agent_xsubject_age_assurance']}")
    assert "federation_reserved_prefix_emitter_mismatch" in admission["agent_xsubject_age_assurance"], (
        admission["agent_xsubject_age_assurance"])

    # A roles=["witness"] list on an agent identity_type does NOT satisfy the
    # emitter rule — the discriminator is identity_type, not a roles list.
    assert admission["agent_roles_xsubject_age_assurance"] != "accepted", (
        f"a roles=['witness'] agent key minted age_assurance:* — the gate keys "
        f"off identity_type, not roles: {admission['agent_roles_xsubject_age_assurance']}")
    assert "federation_reserved_prefix_emitter_mismatch" in admission["agent_roles_xsubject_age_assurance"], (
        admission["agent_roles_xsubject_age_assurance"])


@pytest.mark.requires_persist
def test_agent_admitted_on_age_self_declared_band(admission):
    """CC 3.4.11: a subject's age_self_declared:band:* is non-reserved and admitted.

    `age_self_declared:` is NON-reserved, subject-signed — the onboarding "state
    your age range" rung. The subject's own occurrence may self-emit its
    self-declared band, so `age_self_declared:band:adult` from the subject's agent
    key is admitted (persist 13.0.1).
    """
    assert admission["agent_self_declared_band"] == "accepted", (
        f"a subject's own age_self_declared:band:* was refused (CC 3.4.11): "
        f"{admission['agent_self_declared_band']}")


@pytest.mark.requires_persist
def test_witness_key_admitted_on_age_assurance(admission):
    """CC 3.4.11 (persist 13) reservation is symmetric: witness self-emit REFUSED, witness cross-attest ADMITTED.

    On persist 13.0.1 a witness may no longer self-mint its own adulthood — a
    witness SELF-emitting `age_assurance:*` (attester == attested) is refused with
    `federation_age_assurance_self_emission_rejected`, exactly like any other key
    (this is the persist 12.5 → 13.0.1 flip; it was accepted on 12.5). The
    witness's ADMITTED path is the cross-subject one: emitting `age_assurance:*`
    ABOUT a DISTINCT subject via `emit_attestation` + `attested_key_id` is
    accepted. This is the real positive half of the reservation gate — without it,
    the refusals in `test_agent_refused_on_age_assurance_prefix` could be a blanket
    "nobody may emit age_assurance:*" rather than a genuine witness reservation.
    """
    assert admission["witness_register"] == "ok", (
        f"could not register a witness-type federation key: {admission['witness_register']}")

    # A witness cannot self-mint its own age assurance (self is unfalsifiable).
    assert admission["witness_self_age_assurance_provider"] != "accepted", (
        f"a witness SELF-minted age_assurance:provider:* — persist 13 rejects "
        f"self-emission for everyone (CC 3.4.11): "
        f"{admission['witness_self_age_assurance_provider']}")
    assert "federation_age_assurance_self_emission_rejected" in admission["witness_self_age_assurance_provider"], (
        admission["witness_self_age_assurance_provider"])
    assert "federation_age_assurance_self_emission_rejected" in admission["witness_self_age_assurance_level"], (
        admission["witness_self_age_assurance_level"])

    # The witness IS admitted attesting age_assurance:* ABOUT a distinct subject —
    # the positive reservation gate on the cross-subject surface.
    assert admission["subject_kid"], (
        f"the cross-subject target key did not register: {admission['subject_kid']}")
    assert admission["witness_xsubject_age_assurance"] == "accepted", (
        f"a witness-rung key was refused emitting age_assurance:provider:* ABOUT a "
        f"subject — the reservation is not symmetric (CC 3.4.11): "
        f"{admission['witness_xsubject_age_assurance']}")


@pytest.mark.requires_persist
def test_age_self_declared_rejects_level_token(admission):
    """CC 3.4.11: a {level} token on the self prefix is refused (self level is `self` by construction).

    The self-declared rung carries a `{band}`, NEVER a `{level}` — its level is
    `self` by construction (§3.4.11). Probed against persist 13.0.1:
    `age_self_declared:level:adult` is REFUSED at admission with
    `federation_dimension_rejected` (shipped in CIRISPersist#307).
    """
    assert admission["agent_self_declared_level"] != "accepted", (
        f"age_self_declared:level:* was admitted — the self rung must carry a "
        f"{{band}}, not a {{level}} (CC 3.4.11): "
        f"{admission['agent_self_declared_level']}")
    assert "federation_dimension_rejected" in admission["agent_self_declared_level"], (
        f"expected federation_dimension_rejected on a {{level}} token on the "
        f"self-declared prefix (CC 3.4.11 / CIRISPersist#307): "
        f"{admission['agent_self_declared_level']}")
