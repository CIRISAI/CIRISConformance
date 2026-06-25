"""
Substrate tier — §11.10 moderation-authority gates (CC 4.5.4 moderation duty).

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
  down the scoped-delegation chain to `k`.

**Real gates here:**

1. A key with no moderation duty is refused at `file_moderation`
   (`federation_delegated_scope_unauthorized`) — the core CC 4.5.4 gate.
2. `add_moderator` produces a well-formed appointment attestation_id (the
   delegated-duty *emit* surface works).

**xfail (CIRISPersist#290):** the positive resolution — appoint a moderator and
have `is_named_moderator` recognize them — is undrivable from Python because the
§11.10 walk roots at a *community* authority set and `put_community_json` is not
exposed on the wheel (only `put_family_json` is). With no way to create a
community, the authority set is always empty, so `is_named_moderator` can never
resolve true. Flips to a real gate the moment #290 ships `put_community_json`.
"""

from __future__ import annotations

import pytest

from conftest import get_database_url, run_python_script

pytestmark = pytest.mark.substrate

_BODY = r"""
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

for surface in ("file_moderation", "add_moderator", "is_named_moderator_json"):
    if not hasattr(engine, surface):
        print(json.dumps({"_error": "absent", "surface": surface})); sys.exit(2)

# A plain agent key — registered, but holding no moderation duty over anything.
kid = engine.register_self_federation_key("agent", "mod-ref", None, None, None)
content_sha = "a" * 64  # 32-byte lowercase-hex content hash

report = {}

# Gate 1 — a non-moderator cannot file a moderation report (CC 4.5.4).
try:
    engine.file_moderation(content_sha, kid, "moderate", "spam")
    report["non_moderator_file"] = "accepted"
except Exception as exc:
    report["non_moderator_file"] = str(exc)[:80]

# Gate 2 — add_moderator emits a well-formed appointment edge.
try:
    aid = engine.add_moderator(kid, kid, "moderate")
    report["appointment_id"] = aid
except Exception as exc:
    report["appointment_id"] = {"_error": str(exc)[:120]}

# Positive resolution (blocked on CIRISPersist#290 — no put_community_json, so
# no community authority root exists for the §11.10 walk to start from).
try:
    report["is_named_moderator"] = engine.is_named_moderator_json(
        kid, kid, "moderate")
except Exception as exc:
    report["is_named_moderator"] = {"_error": str(exc)[:120]}

report["stage"] = "done"
print(json.dumps(report)); sys.stdout.flush()
sys.exit(0)
"""


def _script(database_url: str) -> str:
    return f"DB_URL = {database_url!r}\n" + _BODY


@pytest.fixture(scope="module")
def moderation():
    result = run_python_script(_script(get_database_url()))
    payload = result.parsed_stdout()
    if payload.get("_error") == "absent":
        pytest.fail(f"persist moderation surface missing: {payload.get('surface')}")
    assert payload.get("stage") == "done", payload
    return payload


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


@pytest.mark.requires_persist
@pytest.mark.xfail(
    strict=True,
    reason="CIRISPersist#290 — the §11.10 moderation walk roots at a COMMUNITY "
    "authority set, but the wheel exposes no put_community_json (only "
    "put_family_json), so no community — and thus no owner-bound authority root — "
    "can be created from Python. is_named_moderator therefore can never resolve "
    "true for an appointed moderator. Flips to a real gate when #290 exposes "
    "put_community_json.",
)
def test_appointed_moderator_is_recognized(moderation):
    """§11.10: an appointed moderator resolves as a named moderator of the community."""
    assert moderation["is_named_moderator"] == "true", (
        f"appointed moderator not recognized by is_named_moderator: "
        f"{moderation['is_named_moderator']}"
    )
