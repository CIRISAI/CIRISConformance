"""
Fabric tier — CC 4.5.13 infohazard consent gate (CC 0.5.1).

§4.5.13 ("Infohazard consent gate — no passive exposure"): when a live-majority
vote favors removal/moderation but the content is *retained* (flagged, not
hard-removed), it is auto-hidden behind an active interstitial — *"I consent to
view this material reported as a potential infohazard."* Clicking it **publishes
a [CC 3.3.1] `consent:*` attestation** (`consent:state:granted` + a
`consent:scope:view` qualifier, viewer-side, attributable within scope) — so
passive exposure is impossible: every viewing is an affirmative, signed act by a
named identity. It **rides the existing `consent:*` family + a [CC 3.3.12]
`content_class:{class}` flag** (`content_class:infohazard` / `content_class:
reported`); no new wire shape — the CC 4.5.5 `content_class` gate composed with
the CC 3.3.1 consent primitive.

Probed against persist 11.0.0 via the REAL `emit_attestation_self` admission
surface (the same build-sign-admit one-call path test_240 drives):

1. **The affirmative-consent primitive is admitted.** `consent:state:granted`
   and `consent:scope:view` (and the combined viewer-side declaration carrying
   the `content_class` in its envelope) emit cleanly from a registered agent
   key — the signed act the interstitial publishes is a real, admittable wire
   shape (CC 3.3.1).

2. **The `content_class:*` flag is a substrate-gated reserved prefix.** An agent
   (or any non-substrate identity — user / community / moderator) is REFUSED at
   `content_class:infohazard` / `content_class:reported`
   (`federation_reserved_prefix_emitter_mismatch`): the producer-declared
   content-class flag is a substrate-truth prefix (CC 3.4-style reservation, the
   same shape as `system:*`), not an agent-mintable label. So a viewer cannot
   self-clear a flag by minting its own `content_class`, and the flag the consent
   gate composes over is admission-controlled.

The undrivable piece — the consent gate's *enforcement* (the interstitial /
"viewing flagged content REQUIRES a prior `consent:state:granted` +
`consent:scope:view`") — is a consumer / LensCore filter-policy decision, NOT a
persist byte-gate: persist exposes no view/reveal/gate-decision surface that
refuses a read absent consent. That enforcement is xfail(strict) at the bottom.
"""

from __future__ import annotations

import pytest

from conftest import get_database_url, run_python_script

pytestmark = pytest.mark.fabric

_CONSENT_BODY = r"""
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

# A registered AGENT-type key — a community member / viewer, not the substrate.
kid = engine.register_self_federation_key("agent", "viewer-ref", None, None, None)

def emit(inp):
    try:
        engine.emit_attestation_self(json.dumps(inp))
        return "accepted"
    except Exception as exc:
        return str(exc)[:90]

report = {}
# Sanity baseline — a plain scores attestation from an agent key is admitted, so
# a rejection below is the gate, not a broken emit path.
report["baseline_scores"] = emit(
    {"attestation_type": "scores:quality:test", "attestation_envelope": {"n": "x"}, "weight": 0.5})

# (1) The affirmative-consent-to-view primitive — the signed act the interstitial
#     publishes (CC 3.3.1 + CC 4.5.13). Each limb, and the combined viewer-side
#     declaration carrying the content_class it consents to view.
report["consent_state_granted"] = emit(
    {"attestation_type": "consent:state:granted", "attestation_envelope": {}})
report["consent_scope_view"] = emit(
    {"attestation_type": "consent:scope:view", "attestation_envelope": {}})
report["consent_view_infohazard"] = emit(
    {"attestation_type": "consent:state:granted",
     "attestation_envelope": {"scope": "view", "content_class": "infohazard"}})

# (2) The content_class:* flag the gate composes over is a substrate-reserved
#     prefix — an agent/viewer key cannot mint it (CC 3.3.12 / CC 3.4-style).
report["content_class_infohazard_from_agent"] = emit(
    {"attestation_type": "content_class:infohazard", "attestation_envelope": {}})
report["content_class_reported_from_agent"] = emit(
    {"attestation_type": "content_class:reported", "attestation_envelope": {}})

report["stage"] = "done"
print(json.dumps(report)); sys.stdout.flush()
sys.exit(0)
"""


def _consent_script(database_url: str) -> str:
    return f"DB_URL = {database_url!r}\n" + _CONSENT_BODY


@pytest.fixture(scope="module")
def consent():
    payload = run_python_script(_consent_script(get_database_url())).parsed_stdout()
    if payload.get("_error") == "absent":
        pytest.fail("persist.emit_attestation_self is missing — the attestation "
                    "admission surface is not on the wheel")
    assert payload.get("stage") == "done", payload
    # Guard: the surface must accept a legitimate attestation, else the assertions
    # below would pass / fail for the wrong reason.
    assert payload["baseline_scores"] == "accepted", payload
    return payload


@pytest.mark.requires_persist
def test_consent_to_view_attestation_is_admitted(consent):
    """CC 4.5.13 / CC 3.3.1: the affirmative consent-to-view signed act is admittable.

    `consent:state:granted` + `consent:scope:view` (and the combined viewer-side
    declaration carrying the `content_class` it consents to view) emit cleanly —
    the wire shape the interstitial publishes is real, so every viewing CAN be an
    affirmative, signed, attributable act (no new wire shape needed).
    """
    assert consent["consent_state_granted"] == "accepted", (
        f"consent:state:granted refused — the consent-to-view primitive is not "
        f"admittable: {consent['consent_state_granted']}")
    assert consent["consent_scope_view"] == "accepted", (
        f"consent:scope:view refused: {consent['consent_scope_view']}")
    assert consent["consent_view_infohazard"] == "accepted", (
        f"combined consent-to-view-infohazard declaration refused: "
        f"{consent['consent_view_infohazard']}")


@pytest.mark.requires_persist
def test_content_class_flag_is_substrate_reserved(consent):
    """CC 3.3.12 / CC 4.5.13: an agent/viewer cannot mint the `content_class:*` flag.

    The producer-declared content-class flag the consent gate composes over is a
    substrate-reserved prefix — a registered agent key is refused at
    `content_class:infohazard` / `content_class:reported`
    (`federation_reserved_prefix_emitter_mismatch`). A viewer therefore cannot
    self-declare (or self-clear) the flag; it is admission-controlled, like the
    other reserved substrate-truth prefixes.
    """
    for field in ("content_class_infohazard_from_agent",
                  "content_class_reported_from_agent"):
        outcome = consent[field]
        assert outcome != "accepted", (
            f"an agent key minted a {field} content_class flag — the CC 3.3.12 "
            f"content_class reservation is not enforced: {outcome}")
        assert "reserved_prefix" in outcome or "mismatch" in outcome, (
            f"{field} refused with an unexpected reason: {outcome}")


@pytest.mark.requires_persist
@pytest.mark.xfail(strict=True, reason=(
    "CC 4.5.13 consent-gate ENFORCEMENT (viewing flagged content REQUIRES a "
    "prior consent:state:granted + consent:scope:view) is not byte-gated on "
    "persist 11.0.0. The substrate admits the consent primitive (gated green "
    "above) and reserves the content_class flag (gated green above), but exposes "
    "no view/reveal/gate-decision read surface that REFUSES access to a flagged "
    "(content_class:infohazard / reported) item absent a matching consent emit — "
    "the interstitial gate is a consumer / LensCore filter-policy decision (CC "
    "4.4), not a persist write/read gate. File upstream if a substrate-level "
    "consent-gated read surface is ever desired; otherwise this enforcement "
    "lives in the consumer tier and is out of persist's scope. Tracked: CIRISPersist#238."))
def test_viewing_flagged_content_requires_consent_enforced():
    """CC 4.5.13: a flagged item cannot be read absent a prior consent-to-view.

    Probes for a substrate read/reveal gate that refuses access to a
    `content_class:infohazard`/`reported` item unless the reader has emitted
    `consent:state:granted` + `consent:scope:view`. No such surface exists on
    persist 11.0.0 (enforcement is consumer/LensCore policy) — strict-xfail.
    """
    import os
    import secrets
    import tempfile

    import ciris_persist as cp

    cp.reset_engine()
    d = tempfile.mkdtemp()
    s = os.path.join(d, "s")
    open(s, "wb").write(secrets.token_bytes(32))
    p = os.path.join(d, "p")
    open(p, "wb").write(secrets.token_bytes(32))
    k = "node-" + secrets.token_hex(8)
    engine = cp.Engine("sqlite::memory:", k, local_key_id=k, local_key_path=s,
                       local_pqc_key_id=k + "-pqc", local_pqc_key_path=p)
    # A drivable consent-gate enforcement surface would expose a consent-gated
    # read/reveal. Assert one exists — fails (xfail) until it does.
    gate_surfaces = [m for m in dir(engine)
                     if ("view" in m.lower() or "reveal" in m.lower()
                         or "gate_decision" in m.lower() or "interstit" in m.lower())
                     and "consent" in m.lower()]
    assert gate_surfaces, (
        "no consent-gated read/reveal surface on the engine — the CC 4.5.13 "
        "interstitial enforcement is consumer-tier, not a persist byte-gate")
