"""
Fabric tier — CC 4.5.5 moderation-authority gates (CC 4.5.4 moderation duty).

CIRIS moderation is a *delegated duty*: only a key that is a recognized
`moderate` duty-holder over a target may file a moderation report against it.
The substrate enforces this at the emit boundary so an arbitrary key cannot mint
moderation `scores` (which feed community trust + takedown decisions). The
authority model (`src/federation/admission.rs`):

- `file_moderation(content_sha256, community_id, duty, allegation_type)` is
  admitted IFF the engine's signer reaches the target as a `moderate`
  duty-holder — otherwise `federation_delegated_scope_unauthorized`.
- `add_moderator(community_id, moderator_key_id, duty)` emits an **owner-bound**
  scoped `delegates_to` appointment edge (returns its `attestation_id`).
- `is_named_moderator(k, community_id, duty)` walks from the community's
  authority set (members with `role:"founder"`, each gated by `is_owner_bound`)
  down the scoped-delegation chain to `k`. The authority root itself is a
  moderator zero-hop.

This drives the full lifecycle against the REAL persist surfaces:

**Negative gate** (single engine): a registered agent key holding no moderation
duty is refused at `file_moderation` (`federation_delegated_scope_unauthorized`),
and `add_moderator` still mints a well-formed owner-bound appointment edge.

**Positive lifecycle** (multi-node, real gate as of **persist 10.4.0** —
CIRISPersist#290 shipped `put_community_json`): a founder (owner-bound via
`identity_type=user`) creates a community and is recognized as its moderator
zero-hop, so it can `file_moderation` against its own community; appointing a
separate registered key as a `moderate` delegate makes `is_named_moderator`
resolve true and lists it under `moderators_of`; and `remove_moderator`
(`withdraws` the appointment edge) revokes that recognition. Through persist
10.2.2 this was `xfail` — `put_community_json` was unexposed, so no community
authority root could be created and `is_named_moderator` never resolved true.
"""

from __future__ import annotations

import pytest

from conftest import get_database_url, run_python_script

pytestmark = pytest.mark.fabric

_NOW = "2026-06-25T00:00:00.000Z"
_SHA = "a" * 64  # 32-byte lowercase-hex content hash

# ── Negative gate: a single agent engine with no moderation duty ──────────
_NEG_BODY = r"""
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

for surface in ("file_moderation", "add_moderator", "is_named_moderator_json",
                "put_community_json"):
    if not hasattr(engine, surface):
        print(json.dumps({"_error": "absent", "surface": surface})); sys.exit(2)

kid = engine.register_self_federation_key("agent", "mod-ref", None, None, None)
report = {}

# A non-member, non-authority key cannot file a moderation report (CC 4.5.4).
try:
    engine.file_moderation("a" * 64, kid, "moderate", "spam")
    report["non_moderator_file"] = "accepted"
except Exception as exc:
    report["non_moderator_file"] = str(exc)[:80]

# add_moderator still mints a well-formed owner-bound appointment edge.
try:
    report["appointment_id"] = engine.add_moderator(kid, kid, "moderate")
except Exception as exc:
    report["appointment_id"] = {"_error": str(exc)[:120]}

report["stage"] = "done"
print(json.dumps(report)); sys.stdout.flush()
sys.exit(0)
"""


def _neg_script(database_url: str) -> str:
    return f"DB_URL = {database_url!r}\n" + _NEG_BODY


@pytest.fixture(scope="module")
def moderation():
    payload = run_python_script(_neg_script(get_database_url())).parsed_stdout()
    if payload.get("_error") == "absent":
        pytest.fail(f"persist moderation surface missing: {payload.get('surface')}")
    assert payload.get("stage") == "done", payload
    return payload


# ── Positive lifecycle: a real community authority + an appointed delegate ──
# The founder node creates a community it founds (owner-bound via the `user`
# identity_type), files as the zero-hop authority, then appoints/removes a
# separately-registered moderator key. MOD_KID comes from a prior member node.
_FOUNDER_BODY = r"""
# This node registered as identity_type=user (owner-bound) via the preamble's
# IDENTITY_TYPE injection, so `kid` is the founder's owner-bound federation id.
founder = kid
engine.put_community_json(json.dumps({
    "community_key_id": founder, "community_name": "conformance-comm",
    "members": [{"key_id": founder, "joined_at": NOW, "role": "founder"}],
    "founded_at": NOW, "consensus_protocol": "founder_only", "persist_row_hash": "",
}))
report["founder"] = founder

# The community authority is a moderator of its own community, zero-hop.
report["founder_is_named"] = engine.is_named_moderator_json(founder, founder, "moderate")
try:
    engine.file_moderation(SHA, founder, "moderate", "spam")
    report["founder_can_file"] = "admitted"
except Exception as exc:
    report["founder_can_file"] = str(exc)[:80]

# Appoint a separate registered key as a moderate delegate → recognized.
appt = engine.add_moderator(founder, MOD_KID, "moderate")
report["appointed_is_named"] = engine.is_named_moderator_json(MOD_KID, founder, "moderate")
report["moderators_of"] = json.loads(engine.moderators_of_json(founder, "moderate"))

# Remove the appointment → recognition is revoked.
engine.remove_moderator(founder, appt, MOD_KID, "moderate")
report["after_remove_is_named"] = engine.is_named_moderator_json(MOD_KID, founder, "moderate")
report["stage"] = "done"
"""


@pytest.fixture(scope="module")
def moderation_authority(federation_module):
    """Register a moderator member node, then run the founder authority node."""
    node = federation_module
    mod_kid = node("report['kid'] = kid", identity_ref="moderator")["kid"]
    payload = node(_FOUNDER_BODY, identity_ref="founder", IDENTITY_TYPE="user",
                   MOD_KID=mod_kid, NOW=_NOW, SHA=_SHA)
    payload["mod_kid"] = mod_kid
    return payload


# ── Negative-gate tests ──────────────────────────────────────────────────
def _is_uuid(value) -> bool:
    return isinstance(value, str) and len(value) == 36 and value.count("-") == 4


@pytest.mark.requires_persist
def test_non_moderator_cannot_file_moderation(moderation):
    """CC 4.5.4: a key with no `moderate` duty is refused at `file_moderation`."""
    outcome = moderation["non_moderator_file"]
    assert outcome != "accepted", (
        "a key holding no moderation duty filed a moderation report — the "
        "delegated-duty admission gate is not enforced"
    )
    assert "delegated_scope_unauthorized" in outcome, outcome


@pytest.mark.requires_persist
def test_add_moderator_emits_appointment_edge(moderation):
    """`add_moderator` mints an owner-bound scoped-delegation appointment edge."""
    aid = moderation["appointment_id"]
    assert _is_uuid(aid), (
        f"add_moderator did not return a well-formed appointment attestation_id: {aid}"
    )


# ── Positive-lifecycle tests (real gate as of persist 10.4.0 / #290) ──────
@pytest.mark.requires_persist
def test_community_authority_can_file_moderation(moderation_authority):
    """CC 4.5.4: the owner-bound community authority is a moderator zero-hop and may file."""
    r = moderation_authority
    assert r["stage"] == "done", r
    assert r["founder_is_named"] == "true", (
        f"the community's owner-bound founder is not recognized as its moderator: {r}")
    assert r["founder_can_file"] == "admitted", (
        f"the community authority was refused at file_moderation: {r}")


@pytest.mark.requires_persist
def test_appointed_moderator_is_recognized(moderation_authority):
    """CC 4.5.5: an appointed delegate resolves as a named moderator of the community.

    Real gate as of **persist 10.4.0** (CIRISPersist#290 shipped
    `put_community_json`): the founder appoints a separately-registered key as a
    `moderate` delegate, the CC 4.5.5 walk reaches it from the owner-bound authority
    root, so `is_named_moderator` resolves true and `moderators_of` lists it.
    """
    r = moderation_authority
    assert r["appointed_is_named"] == "true", (
        f"appointed moderator not recognized by is_named_moderator: {r}")
    assert r["mod_kid"] in r["moderators_of"], (
        f"appointed moderator absent from moderators_of: {r}")


@pytest.mark.requires_persist
def test_moderator_removal_revokes_recognition(moderation_authority):
    """`remove_moderator` (`withdraws` the appointment) revokes the duty recognition."""
    r = moderation_authority
    assert r["after_remove_is_named"] == "false", (
        f"is_named_moderator still resolves true after remove_moderator — the "
        f"withdraws did not revoke the appointment: {r}")
