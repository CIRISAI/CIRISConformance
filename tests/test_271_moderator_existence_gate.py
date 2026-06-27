"""
Fabric tier — CC 4.5.4 / 4.5.5 named-moderator EXISTENCE gate (CC 0.5.1).

CC 0.5.1 adds a substrate **existence** invariant on top of the CC 4.5.5
moderation-authority model that `tests/test_270_moderation_authority.py`
already gates: a `community` ([CC 3.2]) operates / federates at moderated
capability **only while a live `moderate`-duty holder is resolvable** over it
(§4.5.4 rule 1). The enforcement layer is named explicitly (§4.5.4, the
"Enforcement layer — substrate, at admission *and* on every federation step"
paragraph): the substrate MUST evaluate `is_named_moderator(·, C, moderate)`
**(i) at admission** — `C` federates only if a live `moderate`-holder resolves —
and **(ii) on every federation apply step** — re-checked at apply time so a
community that *loses* its moderator cannot continue at moderated capability;
on loss it MUST fail-secure (rule 3) and NOT federate at moderated capability.

The present-moderator model is UNCHANGED: a present moderator still acts by a
single signature (`add_moderator` / `is_named_moderator` / `remove_moderator`
— gated by test_270). The "reverse" in §4.5.13 reverse-quorum applies only to
the moderator-*absence* fallback vote (time/governance), which is NOT a persist
byte-gate — see the xfail at the bottom.

What the substrate exposes (probed against persist 11.0.0) is the **resolution
primitive** the §4.5.4 gate is defined to consume:

- `is_named_moderator_json(K, C, duty)` — fail-closed `"true"`/`"false"`.
- `moderators_of_json(C, duty)` — the FULL named-moderator set (authority roots
  ∪ duty-scoped delegates).
- `duty_holders_for_community_json(C, duty)` — the steward-bound authority roots.

This module gates the **existence** behaviour those primitives express, built on
test_270's appoint/remove flow over the `federation_module` fixture:

1. **Moderator EXISTS** — an owner-bound (steward-bound, `identity_type=user`)
   founder resolves as its community's moderator zero-hop: `moderators_of` /
   `duty_holders_for_community` are non-empty and the authority can `file_moderation`
   (operates at moderated capability). This is the admission-positive case.

2. **Loss → absence resolves to empty** — after appointing a delegate moderator
   and then `remove_moderator`-ing it, the delegate no longer resolves
   (`is_named_moderator` → `"false"`) and drops out of `moderators_of`. The
   resolution primitive correctly reports the loss the §4.5.4 apply-step gate
   would key on.

3. **Admission fail-secure — a stewardless community is REFUSED.** A real
   admission-side enforcement gate: `put_community_json` REFUSES a community
   whose founder member is not steward-bound
   (`federation_unstewarded_community_member`) — so a community lacking a
   steward-bound authority (hence lacking a resolvable zero-hop moderator)
   cannot be brought into existence at all. This is the §3.2-mirrored
   admission gate the §4.5.4 existence invariant builds on.

4. **The absence STATE is resolvable** — an empty-roster community IS admitted
   but resolves an empty moderator / duty-holder set (`moderators_of == []`):
   the substrate-resolvable shape the §4.5.4 apply-step gate keys on. (That the
   empty-roster community is admitted-and-kept rather than refused on the apply
   step is exactly the missing enforcement captured by the xfail below.)

The undrivable piece — the §4.5.4 *enforcement-layer gate itself* (an
admission/federation-apply step that REFUSES a moderator-less community at the
write boundary, distinct from the `is_named_moderator` primitive it consumes) —
is xfail(strict) at the bottom with the precise surface that is missing.
"""

from __future__ import annotations

import json

import pytest

pytestmark = pytest.mark.fabric

_NOW = "2026-06-25T00:00:00.000Z"
_SHA = "a" * 64  # 32-byte lowercase-hex content hash


# ── EXISTS: an owner-bound founder + an appointed-then-removed delegate ──────
# Mirrors test_270's founder authority node (IDENTITY_TYPE="user" ⇒ steward-bound),
# but asserts the §4.5.4 EXISTENCE surface rather than the authority lifecycle.
_FOUNDER_BODY = r"""
founder = kid  # owner-bound (steward-bound) via IDENTITY_TYPE="user" injection
engine.put_community_json(json.dumps({
    "community_key_id": founder, "community_name": "exists-comm",
    "members": [{"key_id": founder, "joined_at": NOW, "role": "founder"}],
    "founded_at": NOW, "consensus_protocol": "founder_only", "persist_row_hash": "",
}))

# (1) A live moderate-holder resolves over C — C may operate at moderated capability.
report["moderators_present"] = json.loads(engine.moderators_of_json(founder, "moderate"))
report["duty_holders_present"] = json.loads(
    engine.duty_holders_for_community_json(founder, "moderate"))
report["founder_is_named"] = engine.is_named_moderator_json(founder, founder, "moderate")
try:
    engine.file_moderation(SHA, founder, "moderate", "spam")
    report["moderated_action_with_holder"] = "admitted"
except Exception as exc:
    report["moderated_action_with_holder"] = str(exc)[:80]

# (2) Appoint a delegate moderator, then remove it — the loss the apply-step gate keys on.
appt = engine.add_moderator(founder, MOD_KID, "moderate")
report["delegate_named_after_appoint"] = engine.is_named_moderator_json(
    MOD_KID, founder, "moderate")
report["moderators_after_appoint"] = json.loads(
    engine.moderators_of_json(founder, "moderate"))

engine.remove_moderator(founder, appt, MOD_KID, "moderate")
report["delegate_named_after_remove"] = engine.is_named_moderator_json(
    MOD_KID, founder, "moderate")
report["moderators_after_remove"] = json.loads(
    engine.moderators_of_json(founder, "moderate"))

report["founder"] = founder
report["stage"] = "done"
"""


# ── ABSENCE: stewardless community is refused at admission; empty-roster ─────
# An AGENT founder (NOT steward-bound) is refused at put_community_json (the §3.2-
# mirrored admission fail-secure). An empty-roster community is admitted but
# resolves NO moderator — the substrate-resolvable shape of the absence state.
_ABSENT_BODY = r"""
# This node registered identity_type="agent" (NOT steward-bound).
founder = kid
try:
    engine.put_community_json(json.dumps({
        "community_key_id": founder, "community_name": "moderatorless-comm",
        "members": [{"key_id": founder, "joined_at": NOW, "role": "founder"}],
        "founded_at": NOW, "consensus_protocol": "founder_only", "persist_row_hash": "",
    }))
    report["stewardless_community_admit"] = "admitted"
except Exception as exc:
    report["stewardless_community_admit"] = str(exc)[:80]

# An EMPTY-roster community: admitted, but resolves no moderator (absence state).
try:
    engine.put_community_json(json.dumps({
        "community_key_id": founder, "community_name": "empty-comm",
        "members": [], "founded_at": NOW,
        "consensus_protocol": "founder_only", "persist_row_hash": "",
    }))
    report["empty_community_admit"] = "admitted"
    report["empty_moderators"] = json.loads(engine.moderators_of_json(founder, "moderate"))
    report["empty_duty_holders"] = json.loads(
        engine.duty_holders_for_community_json(founder, "moderate"))
except Exception as exc:
    report["empty_community_admit"] = str(exc)[:80]

report["founder"] = founder
report["stage"] = "done"
"""


@pytest.fixture(scope="module")
def existence(federation_module):
    """Run the owner-bound founder existence/loss node and the absence node."""
    node = federation_module
    mod_kid = node("report['kid'] = kid", identity_ref="delegate")["kid"]
    present = node(_FOUNDER_BODY, identity_ref="founder", IDENTITY_TYPE="user",
                   MOD_KID=mod_kid, NOW=_NOW, SHA=_SHA)
    present["mod_kid"] = mod_kid
    absent = node(_ABSENT_BODY, identity_ref="agent_founder", NOW=_NOW)
    return {"present": present, "absent": absent}


# ── EXISTS-side gates (real green on persist 11.0.0) ─────────────────────────
@pytest.mark.requires_persist
def test_live_moderator_resolves_for_moderated_capability(existence):
    """CC 4.5.4 (i): a community with a live `moderate`-holder resolves one, and may act.

    The owner-bound founder is its community's moderator zero-hop — it populates
    `moderators_of` / `duty_holders_for_community` (the resolution the §4.5.4
    admission gate consumes) and is admitted at `file_moderation` (operating at
    moderated capability).
    """
    p = existence["present"]
    assert p["stage"] == "done", p
    assert p["founder_is_named"] == "true", (
        f"owner-bound founder not recognized as its community's moderator: {p}")
    assert p["founder"] in p["moderators_present"], (
        f"no live moderate-holder resolves over the community: {p}")
    assert p["founder"] in p["duty_holders_present"], (
        f"the steward-bound authority root is absent from duty_holders: {p}")
    assert p["moderated_action_with_holder"] == "admitted", (
        f"community with a live moderator was refused at moderated action: {p}")


@pytest.mark.requires_persist
def test_moderator_loss_resolves_to_absence(existence):
    """CC 4.5.4 (ii): after `remove_moderator`, the delegate no longer resolves.

    The apply-step gate is defined to re-check `is_named_moderator` at apply time;
    this asserts the primitive reports the loss — the removed delegate flips
    `is_named_moderator` to `"false"` and drops out of `moderators_of`, while the
    owner-bound authority root (still present) remains.
    """
    p = existence["present"]
    assert p["delegate_named_after_appoint"] == "true", (
        f"appointed delegate did not resolve as a named moderator: {p}")
    assert p["mod_kid"] in p["moderators_after_appoint"], p
    assert p["delegate_named_after_remove"] == "false", (
        f"removed delegate still resolves as a named moderator — the loss the "
        f"§4.5.4 apply-step gate keys on is not reflected: {p}")
    assert p["mod_kid"] not in p["moderators_after_remove"], (
        f"removed delegate still listed in moderators_of: {p}")


@pytest.mark.requires_persist
def test_stewardless_community_refused_at_admission(existence):
    """CC 4.5.4 / CC 3.2: a community with no steward-bound authority is refused at admission.

    A real admission-side fail-secure gate: `put_community_json` REFUSES a
    community whose founder member is not steward-bound
    (`federation_unstewarded_community_member`), so a community lacking a
    steward-bound authority (hence lacking a resolvable zero-hop moderator)
    cannot be brought into existence — the §3.2-mirrored admission gate the
    §4.5.4 existence invariant builds on.
    """
    a = existence["absent"]
    assert a["stage"] == "done", a
    assert a["stewardless_community_admit"] != "admitted", (
        f"a stewardless (hence moderator-less) community was admitted: {a}")
    assert "unstewarded" in a["stewardless_community_admit"], (
        f"stewardless community refused with an unexpected reason: {a}")


@pytest.mark.requires_persist
def test_empty_roster_community_resolves_no_moderator(existence):
    """CC 4.5.4 rule 3: an empty-roster community resolves NO moderator (absence state).

    The substrate-resolvable shape of the fail-secure absence state: a community
    with no members resolves an EMPTY moderator / duty-holder set (no live
    moderate-holder ⇒ MUST NOT operate at moderated capability). That this state
    is *admitted and kept* rather than refused on the apply step is the missing
    enforcement captured by the strict-xfail below.
    """
    a = existence["absent"]
    assert a["empty_community_admit"] == "admitted", (
        f"empty-roster community unexpectedly refused: {a}")
    assert a["empty_moderators"] == [], (
        f"an empty-roster community resolved a non-empty moderator set: {a}")
    assert a["empty_duty_holders"] == [], (
        f"an empty-roster community resolved non-empty duty-holders: {a}")


# ── Undrivable: the §4.5.4 enforcement-layer gate + §4.5.13 reverse-quorum ───
@pytest.mark.requires_persist
@pytest.mark.xfail(strict=True, reason=(
    "CC 4.5.4 federation-APPLY-step gate + CC 4.5.13 reverse-quorum vote are not "
    "byte-gated on persist 11.0.0. The admission HALF of §4.5.4 is partly real "
    "(put_community_json refuses a stewardless founder — gated green above), but "
    "the APPLY-step half is not: the substrate exposes only the RESOLUTION "
    "primitive (is_named_moderator_json / moderators_of_json / "
    "duty_holders_for_community_json), NOT the gate that CONSUMES it on every "
    "federation step — there is no admission::named_moderator_holders / "
    "'federate at moderated capability' refusal call, and a community can reach "
    "the empty-moderator absence state (empty roster — gated green above) "
    "admitted-and-kept with no apply-step re-check that fails it secure. The "
    "§4.5.13 48h no-moderator recovery / 24h candidacy / live-majority fallback "
    "vote is time/governance, with no candidacy/tally/window surface. File "
    "upstream (CIRISPersist) for a drivable moderator-existence federation-apply "
    "gate before flipping this to a real green gate. Tracked: CIRISPersist#238."))
def test_moderator_existence_federation_apply_gate_enforced():
    """CC 4.5.4: a federation apply step over a moderator-less community is REFUSED.

    Probes for a substrate enforcement surface (distinct from the resolution
    primitive): an admission / federation-apply call that fails-secure on a
    community with no resolvable `moderate`-holder. None is exposed on persist
    11.0.0 — strict-xfail until one ships.
    """
    import os
    import secrets
    import tempfile

    import ciris_persist as cp  # noqa: F401 (imported inside the xfail body)

    cp.reset_engine()
    d = tempfile.mkdtemp()
    s = os.path.join(d, "s")
    open(s, "wb").write(secrets.token_bytes(32))
    p = os.path.join(d, "p")
    open(p, "wb").write(secrets.token_bytes(32))
    k = "node-" + secrets.token_hex(8)
    engine = cp.Engine("sqlite::memory:", k, local_key_id=k, local_key_path=s,
                       local_pqc_key_id=k + "-pqc", local_pqc_key_path=p)
    # A drivable enforcement gate would expose a method refusing a moderator-less
    # community at admission / apply time. Assert it exists — fails (xfail) until it does.
    gate_surfaces = [m for m in dir(engine)
                     if "moderator" in m.lower()
                     and ("admit" in m.lower() or "apply" in m.lower()
                          or "federate" in m.lower() or "existence" in m.lower())]
    assert gate_surfaces, (
        "no moderator-existence admission/federation-apply enforcement surface on "
        "the engine — only the resolution primitive is exposed")
