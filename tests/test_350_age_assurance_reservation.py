"""
Fabric tier — CC 3.4.11 age-assurance: witness-reserved vs subject self-declared.

Age-assurance is **two** dimension families, not one, and the split is
load-bearing (part_3_the_namespace.md §3.4.11):

- **`age_assurance:`** — witness-RESERVED. The provider/government rung. Emitter
  rule (CC 3.4.7.1 set membership): `witness ∈ attesting_key.identity_type`. A
  subject MUST NOT emit on it; per the CC 3.4 three-actor rule a CCS MUST reject
  a non-witness emitter at admission. So a subject cannot self-mint a
  provider/government adulthood.
- **`age_self_declared:`** — NON-reserved, subject-signed. The onboarding
  "state your age range" rung. Admitted iff the signer acts for the subject. It
  carries **only** a `{band}` — never a `{level}` token — because its level is
  `self` by construction.

These are driven through the REAL persist `emit_attestation_self` (the
build-sign-admit one-call surface), mirroring test_240's emit-admission style.

**Probed against persist 11.0.0 (venv /tmp/nf11):**

- A registered **agent**-type key is REFUSED on `age_assurance:*` (both
  `age_assurance:level:adult` and the fully-qualified
  `age_assurance:provider:adult:v1`) with `federation_reserved_prefix_emitter_mismatch`
  — the same reserved-prefix admission gate as CC 3.4.10's witness-emitter family.
- That agent key is ACCEPTED on `age_self_declared:band:adult` (non-reserved,
  subject-signed).
- A key registered with `identity_type="witness"` IS admitted on `age_assurance:*`
  — the positive gate is REAL here (see `test_witness_key_admitted_on_age_assurance`).
  Registering with `identity_type="agent"` + a `roles=["witness"]` list does NOT
  satisfy the emitter rule (still refused); the discriminator is the
  `federation_keys.identity_type` itself.

**Optional rule NOT yet enforced (xfail strict):** a `{level}` token on the
self-declared prefix (`age_self_declared:level:adult`) SHOULD be refused — the
self rung carries a `{band}`, never a `{level}` (§3.4.11). persist 11.0.0 admits
it. Marked xfail(strict) so it flips to a real gate the moment the substrate
enforces it.

Lower-priority / undrivable here: the read-union (witness outranks self), the
protective content gate, and the `moderation:age_assurance_misdeclaration`
routing are consumer/adjudication behaviors, not `emit_attestation_self`
admission surfaces — not gated in this file.
"""

from __future__ import annotations

import pytest

from conftest import get_database_url, run_python_script

pytestmark = pytest.mark.fabric

_ADMIT_BODY = r"""
import json, sys, os, tempfile, secrets
try:
    import ciris_persist as cp
except ImportError as exc:
    print(json.dumps({"_error": "import", "detail": str(exc)})); sys.exit(2)

def fresh_engine():
    _d = tempfile.mkdtemp()
    _s = os.path.join(_d, "s"); open(_s, "wb").write(secrets.token_bytes(32))
    _p = os.path.join(_d, "p"); open(_p, "wb").write(secrets.token_bytes(32))
    cp.reset_engine()
    k = "node-" + secrets.token_hex(8)
    return cp.Engine(DB_URL, k, local_key_id=k, local_key_path=_s,
                     local_pqc_key_id=k + "-pqc", local_pqc_key_path=_p)

# Sanity: the admission surface must exist.
_probe = fresh_engine()
if not hasattr(_probe, "emit_attestation_self"):
    print(json.dumps({"_error": "absent"})); sys.exit(2)

def emit(engine, inp):
    # Return "accepted" or the rejection token.
    try:
        engine.emit_attestation_self(json.dumps(inp))
        return "accepted"
    except Exception as exc:
        return str(exc)[:80]

report = {}

# ── A registered AGENT-type key (a subject) ──────────────────────────────
agent = fresh_engine()
agent.register_self_federation_key("agent", "age-agent", None, None, None)

# Sanity baseline: a plain scores attestation from an agent key is admitted —
# else the rejection assertions below would pass for the wrong reason.
report["baseline_scores"] = emit(
    agent, {"attestation_type": "scores:quality:test",
            "attestation_envelope": {"n": "x"}, "weight": 0.5})

# CC 3.4.11 — age_assurance:* is witness-RESERVED. A subject (agent) MUST be
# refused at admission. Both the short `:level:band` form and the fully
# qualified `:level:band:vN` form.
report["agent_age_assurance_level"] = emit(
    agent, {"attestation_type": "age_assurance:level:adult",
            "attestation_envelope": {}})
report["agent_age_assurance_provider"] = emit(
    agent, {"attestation_type": "age_assurance:provider:adult:v1",
            "attestation_envelope": {}})

# CC 3.4.11 — age_self_declared:* is NON-reserved, subject-signed. The subject's
# own occurrence may emit its self-declared band → admitted.
report["agent_age_self_declared_band"] = emit(
    agent, {"attestation_type": "age_self_declared:band:adult",
            "attestation_envelope": {}})

# Optional CC 3.4.11 rule: the self rung carries a {band}, NEVER a {level}.
# A {level} token on the self prefix SHOULD be refused. persist 11.0.0 admits
# it (xfail strict below).
report["agent_age_self_declared_level"] = emit(
    agent, {"attestation_type": "age_self_declared:level:adult",
            "attestation_envelope": {}})

# A roles=["witness"] list on an agent identity_type does NOT satisfy the
# emitter rule — the discriminator is identity_type itself, not a roles list.
agent_roles = fresh_engine()
agent_roles.register_self_federation_key("agent", "age-agent-roles", None, None, ["witness"])
report["agent_roles_witness_age_assurance"] = emit(
    agent_roles, {"attestation_type": "age_assurance:provider:adult:v1",
                  "attestation_envelope": {}})

# ── A registered WITNESS-type key (a provider/government verifier) ────────
# The positive gate: witness ∈ identity_type → admitted on age_assurance:*.
witness = fresh_engine()
report["witness_register"] = "ok"
try:
    witness.register_self_federation_key("witness", "age-witness", None, None, None)
except Exception as exc:
    report["witness_register"] = "REGFAIL:" + str(exc)[:80]
report["witness_age_assurance_provider"] = emit(
    witness, {"attestation_type": "age_assurance:provider:adult:v1",
              "attestation_envelope": {}})
report["witness_age_assurance_level"] = emit(
    witness, {"attestation_type": "age_assurance:level:adult",
              "attestation_envelope": {}})

report["stage"] = "done"
print(json.dumps(report)); sys.stdout.flush()
sys.exit(0)
"""


def _admit_script(database_url: str) -> str:
    return f"DB_URL = {database_url!r}\n" + _ADMIT_BODY


@pytest.fixture(scope="module")
def admission():
    result = run_python_script(_admit_script(get_database_url()))
    payload = result.parsed_stdout()
    if payload.get("_error") == "absent":
        pytest.fail("persist.emit_attestation_self is missing — the attestation "
                    "admission surface is not on the wheel")
    assert payload.get("stage") == "done", payload
    # Guard: the surface must accept a legitimate attestation, else the
    # rejection assertions below would pass for the wrong reason.
    assert payload["baseline_scores"] == "accepted", payload
    return payload


@pytest.mark.requires_persist
def test_agent_refused_on_age_assurance_prefix(admission):
    """CC 3.4.11: a subject (agent key) cannot emit on the witness-reserved age_assurance:* prefix.

    `age_assurance:` is witness-RESERVED — the emitter rule is
    `witness ∈ attesting_key.identity_type`. An agent-type key is not a witness,
    so the CCS MUST refuse it at admission. Probed against persist 11.0.0: both
    the short `age_assurance:level:adult` and the fully-qualified
    `age_assurance:provider:adult:v1` are refused with
    `federation_reserved_prefix_emitter_mismatch`.
    """
    assert admission["agent_age_assurance_level"] != "accepted", (
        f"agent self-minted age_assurance:* (CC 3.4.11): "
        f"{admission['agent_age_assurance_level']}")
    assert "reserved_prefix_emitter_mismatch" in admission["agent_age_assurance_level"], (
        admission["agent_age_assurance_level"])

    assert admission["agent_age_assurance_provider"] != "accepted", (
        f"agent self-minted age_assurance:provider:* (CC 3.4.11): "
        f"{admission['agent_age_assurance_provider']}")
    assert "reserved_prefix_emitter_mismatch" in admission["agent_age_assurance_provider"], (
        admission["agent_age_assurance_provider"])

    # A roles=["witness"] list on an agent identity_type does NOT satisfy the
    # emitter rule — the discriminator is identity_type, not a roles list.
    assert admission["agent_roles_witness_age_assurance"] != "accepted", (
        f"a roles=['witness'] agent key minted age_assurance:* — the gate keys "
        f"off identity_type, not roles: {admission['agent_roles_witness_age_assurance']}")


@pytest.mark.requires_persist
def test_agent_admitted_on_age_self_declared_band(admission):
    """CC 3.4.11: a subject's age_self_declared:band:* is non-reserved and admitted.

    `age_self_declared:` is NON-reserved, subject-signed — the onboarding "state
    your age range" rung. The subject's own occurrence may emit its self-declared
    band, so `age_self_declared:band:adult` from the subject's agent key is
    admitted (persist 11.0.0).
    """
    assert admission["agent_age_self_declared_band"] == "accepted", (
        f"a subject's own age_self_declared:band:* was refused (CC 3.4.11): "
        f"{admission['agent_age_self_declared_band']}")


@pytest.mark.requires_persist
def test_witness_key_admitted_on_age_assurance(admission):
    """CC 3.4.11 positive gate: a witness-rung key IS admitted on age_assurance:*.

    The reservation is symmetric — refuse the non-witness, ADMIT the witness. A
    key registered via `register_self_federation_key("witness", ...)` carries
    `witness ∈ identity_type`, satisfying the emitter rule. Probed against persist
    11.0.0: such a key is admitted on both `age_assurance:provider:adult:v1` and
    `age_assurance:level:adult`. This is the real positive half of the
    reserved-prefix gate; without it, the refusal above could be a blanket
    "nobody may emit age_assurance:*" rather than a genuine reservation.
    """
    assert admission["witness_register"] == "ok", (
        f"could not register a witness-type federation key: {admission['witness_register']}")
    assert admission["witness_age_assurance_provider"] == "accepted", (
        f"a witness-rung key was refused on age_assurance:provider:* — the "
        f"reservation is not symmetric (CC 3.4.11): "
        f"{admission['witness_age_assurance_provider']}")
    assert admission["witness_age_assurance_level"] == "accepted", (
        f"a witness-rung key was refused on age_assurance:level:* (CC 3.4.11): "
        f"{admission['witness_age_assurance_level']}")


@pytest.mark.requires_persist
def test_age_self_declared_rejects_level_token(admission):
    """CC 3.4.11: a {level} token on the self prefix is refused (self level is `self` by construction).

    The self-declared rung carries a `{band}`, NEVER a `{level}` — its level is
    `self` by construction (§3.4.11). Probed against persist 11.5.0:
    `age_self_declared:level:adult` is now REFUSED at admission with
    `federation_dimension_rejected`. This shipped in CIRISPersist#307, so what was
    an xfail(strict) on persist 11.0.0 is now a real green gate.
    """
    assert admission["agent_age_self_declared_level"] != "accepted", (
        f"age_self_declared:level:* was admitted — the self rung must carry a "
        f"{{band}}, not a {{level}} (CC 3.4.11): "
        f"{admission['agent_age_self_declared_level']}")
    assert "federation_dimension_rejected" in admission["agent_age_self_declared_level"], (
        f"expected federation_dimension_rejected on a {{level}} token on the "
        f"self-declared prefix (CC 3.4.11 / CIRISPersist#307): "
        f"{admission['agent_age_self_declared_level']}")
