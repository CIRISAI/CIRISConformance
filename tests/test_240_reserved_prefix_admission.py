"""
Fabric tier — namespace admission gates (CC 3.4 reserved prefixes + 2.3 scope).

The CIRIS Constitution reserves parts of the dimension namespace to specific
identity types, and the substrate is named as the enforcer at admission
(part_3_the_namespace.md):

- **CC 3.4.1 — `accord:*`**: "Reserved — only `identity_type=accord_holder` may
  emit. The one constitutional asymmetry."
- **CC 3.4.5 — `capacity:*`**: "Critical enforcement: `capacity:*` rejects
  self-emission. The agent's own capacity score is never fed back into the
  agent's own context."
- **CC 3.4.3 — `system:*`**: reserved to substrate-self-report
  (`substrate_persist` / `substrate_edge`).

These gate the federation's epistemic integrity: an agent must not be able to
mint constitutional-authority (`accord:*`), substrate-truth (`system:*`), or
self-flattering capacity (`capacity:*`) attestations.

All three are driven through the REAL persist `emit_attestation_self` (the
build-sign-admit one-call surface) by a registered **agent**-type key — none of
the reserved authorizations apply, so each MUST be refused. **Real gate as of
persist 10.4.0** (the reserved-prefix half of **CIRISPersist#288** closed): the
substrate now enforces the prefix↔identity_type rules and refuses each with a
distinct typed reason. (Through persist 10.2.2 all three were wrongly accepted.)
The residual open part of #288 — `subject_key_ids[]` elements MUST be lowercase
hex (CC 2.6.3) but an uppercase-hex entry is still admitted — remains
`xfail(strict=True)` and flips the moment persist applies the §0.6 hex rule on
the emit path.

The scope gate that IS enforced — a `cohort_scope: family` attestation missing
its required `family_id` is refused (`federation_write_scope_refused`, CC 2.3.1)
— is asserted as a real green gate here.
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

_d = tempfile.mkdtemp()
_s = os.path.join(_d, "s"); open(_s, "wb").write(secrets.token_bytes(32))
_p = os.path.join(_d, "p"); open(_p, "wb").write(secrets.token_bytes(32))
cp.reset_engine()
k = "node-" + secrets.token_hex(8)
engine = cp.Engine(DB_URL, k, local_key_id=k, local_key_path=_s,
                   local_pqc_key_id=k + "-pqc", local_pqc_key_path=_p)

if not hasattr(engine, "emit_attestation_self"):
    print(json.dumps({"_error": "absent"})); sys.exit(2)

# A registered AGENT-type key — none of the reserved-prefix authorizations
# (accord_holder / substrate_*) apply to it.
kid = engine.register_self_federation_key("agent", "admit-ref", None, None, None)

def emit(inp):
    # Return "accepted" or the rejection token.
    try:
        engine.emit_attestation_self(json.dumps(inp))
        return "accepted"
    except Exception as exc:
        return str(exc)[:80]

report = {}
# Sanity: a plain scores attestation from an agent key is fine.
report["baseline_scores"] = emit(
    {"attestation_type": "scores:quality:test", "attestation_envelope": {"n": "x"}, "weight": 0.5})

# CC 3.4.1 — accord:* reserved to accord_holder.
report["accord_prefix"] = emit(
    {"attestation_type": "accord:invoke:notify:test", "attestation_envelope": {}})

# CC 3.4.5 — capacity:* must reject self-emission (attester == attested).
report["capacity_self"] = emit(
    {"attestation_type": "capacity:composite", "attested_key_id": kid,
     "attestation_envelope": {}})

# CC 3.4.3 — system:* reserved to substrate self-report.
report["system_prefix"] = emit(
    {"attestation_type": "system:audit_chain:hash_continuity", "attestation_envelope": {}})

# CC 2.6.3 — subject_key_ids[] elements MUST be lowercase hex. An uppercase
# 64-char hex entry must be refused (same hex rule already enforced on the
# canonical hash fields, but not on the emit path's subject_key_ids).
_UPPER = "FF7C5632DAE6EF3AE7F6283BD35268BC7910332414AA8A1C35A1645CA0295F61"
report["subject_key_ids_upper_hex"] = emit(
    {"attestation_type": "scores:x", "subject_key_ids": [_UPPER],
     "attestation_envelope": {}})

# CC 2.3 / scope authority — a non-member node cannot write to a family/community
# cohort scope at all (federation_write_scope_refused), regardless of the id
# field. (This is membership-authority enforcement, NOT the CC 2.3.1
# conditional-field gate — both family-no-id and family-with-id are refused
# identically because a standalone key holds no family roster membership.)
report["family_scope_refused"] = emit(
    {"attestation_type": "scores:x", "cohort_scope": "family",
     "family_id": "fam-key", "attestation_envelope": {}})

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
def test_non_member_cannot_write_family_scope(admission):
    """CC 2.3: a non-member node cannot emit into a family cohort scope.

    `emit_attestation_self` from a standalone agent key is refused
    (`federation_write_scope_refused`) for a `cohort_scope: family` write — the
    key holds no family-roster membership, so it has no authority to write into
    that scope. (Self-scope writes succeed — see the module fixture's baseline.)
    """
    assert admission["family_scope_refused"] != "accepted", (
        "a non-member key wrote into a family cohort scope — the scope-authority "
        "gate is not enforced"
    )
    assert "scope_refused" in admission["family_scope_refused"], admission["family_scope_refused"]


@pytest.mark.requires_persist
def test_reserved_prefixes_refused_from_agent_key(admission):
    """CC 3.4.1/3.4.3/3.4.5: an agent key cannot mint accord:* / system:* / capacity:*-self.

    Real gate as of **persist 10.4.0** (the reserved-prefix half of
    CIRISPersist#288 closed): `emit_attestation_self` now enforces the CC 3.4
    prefix↔identity_type admission rules, so an agent-type key is refused on each
    reserved prefix with a distinct typed reason —
    `federation_accord_dimension_requires_accord_holder` (CC 3.4.1),
    `federation_capacity_self_emission_rejected` (CC 3.4.5), and
    `federation_reserved_prefix_emitter_mismatch` (CC 3.4.3). (Through persist
    10.2.2 all three were wrongly accepted; the subject_key_ids lowercase-hex
    rule remains open — see the test below.)
    """
    assert admission["accord_prefix"] != "accepted", (
        f"agent key minted accord:* (CC 3.4.1): {admission['accord_prefix']}")
    assert admission["capacity_self"] != "accepted", (
        f"agent key self-emitted capacity:* (CC 3.4.5): {admission['capacity_self']}")
    assert admission["system_prefix"] != "accepted", (
        f"agent key minted system:* (CC 3.4.3): {admission['system_prefix']}")


@pytest.mark.requires_persist
@pytest.mark.xfail(
    strict=True,
    reason="CIRISPersist#288 (residual) — persist 10.4.0 closed the reserved-prefix "
    "half (accord:*/capacity:*-self/system:* are now refused — see the test above), "
    "but subject_key_ids[] elements MUST be lowercase hex (CC 2.6.3) and "
    "emit_attestation_self still admits an uppercase-hex entry. The §0.6 hex rule is "
    "enforced on the canonical hash fields but not on the emit path's subject_key_ids. "
    "Flips to a real gate when persist applies it there.",
)
def test_subject_key_ids_must_be_lowercase_hex(admission):
    """CC 2.6.3: an uppercase-hex subject_key_ids entry is refused at admission."""
    assert admission["subject_key_ids_upper_hex"] != "accepted", (
        f"uppercase-hex subject_key_ids admitted (CC 2.6.3): "
        f"{admission['subject_key_ids_upper_hex']}")
