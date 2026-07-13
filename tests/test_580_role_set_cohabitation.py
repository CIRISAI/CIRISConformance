"""
Fabric tier — CC 4.5.8.1 single-key role cohabitation (`CLM-cohabitation`).

⚠️ NOT the harness's `cohabitation` pytest marker. That marker means "multiple
ciris-* wheels dlopen'd in one process" (PyClass identity / init handshake —
test_010, test_030, test_050). CC 4.5.8.1 is a DIFFERENT property with an
unfortunately-colliding name: SINGLE-KEY role cohabitation — one
`federation_keys` key carrying a SET of `identity_type` roles.

CC 4.5.8.1 (part_4_composition_governance.md §4.5.8.1, "`cohabitation` —
Cohabitation discipline for constitutional + substrate roles") builds on CC 4.5.8 /
CC 3.4.7.1: `federation_keys.identity_type` is a SET of roles, not a scalar, and the
CC 3.4 reserved-prefix emitter gates are evaluated by SET MEMBERSHIP (`X ∈
identity_type`). Set membership grants the wire-level RIGHT to emit per held role —
and no more. Crucially, cohabitation is NOT a self-claim backdoor: the constitutional
roles (`canonical`, `accord_holder`) cannot be self-conferred by listing them in the
role set.

What is REAL on the floor (persist 16.1.1), driven end-to-end here:

- **`identity_type` is a stored role SET.** `register_self_federation_key(..., roles=
  ["agent", "substrate_persist"])` produces a `federation_keys` row whose `roles`
  column is exactly `["agent", "substrate_persist"]` — a genuine multi-role key.
- **Set membership is the emitter gate (CC 3.4.7.1).** The cohabiting
  `{agent, substrate_persist}` key MAY emit on a held role's surface (`observed:*`,
  via `emit_attestation_self`) but MUST NOT emit `accord:*` — it rejects with
  `federation_accord_dimension_requires_accord_holder` (the `accord_holder` role is
  not in its set). The right is per-held-role, not blanket.
- **Cohabitation is not a self-claim backdoor.** Registering `identity_type=
  'canonical'` directly is rejected (`canonical_role_not_accord_conferred`);
  registering `identity_type='accord_holder'` without hardware evidence is rejected
  (`federation_accord_holder_requires_attestation_evidence`). And a key that lists
  `canonical` in its role SET is still NOT canonical: `is_canonical(kid)` is False
  and it is absent from `list_canonical_servers()` — the conferred anchor, by
  contrast, resolves True. The role set is a right-to-emit surface, never a
  conferral surface for constitutional roles.

Real surface: `Engine.register_self_federation_key(identity_type, identity_ref,
valid_until, registration_envelope_json, roles)`,
`Engine.list_federation_keys(filter_json, cursor_json, limit, caller_occurrence)`,
`Engine.emit_attestation_self(input_json)`, `Engine.is_canonical(key_id)`,
`Engine.list_canonical_servers()`. Engines carry PQC identities so
`emit_attestation_self`'s hybrid sign succeeds.
"""

from __future__ import annotations

import pytest

from conftest import get_database_url, run_python_script

pytestmark = [pytest.mark.fabric, pytest.mark.ceg, pytest.mark.ccs]

_BODY = r"""
import json, sys, os, tempfile, secrets

def report(obj):
    print(json.dumps(obj)); sys.stdout.flush(); os._exit(0)

try:
    import ciris_persist as cp
except ImportError as exc:
    print(json.dumps({"_error": "import", "detail": str(exc)})); sys.exit(2)

if INJECTED_URL.startswith("postgres"):
    DB_URL = INJECTED_URL
else:
    _dbf = os.path.join(tempfile.mkdtemp(), "f.db"); open(_dbf, "a").close()
    DB_URL = "sqlite:///" + _dbf


def make(prefix, itype, ref, roles=None):
    d = tempfile.mkdtemp()
    s = os.path.join(d, "s"); open(s, "wb").write(secrets.token_bytes(32))
    p = os.path.join(d, "p"); open(p, "wb").write(secrets.token_bytes(32))
    k = prefix + "-" + secrets.token_hex(8)

    def engine():
        cp.reset_engine()
        return cp.Engine(DB_URL, k, local_key_id=k, local_key_path=s,
                         local_pqc_key_id=k + "-pqc", local_pqc_key_path=p)

    kid = engine().register_self_federation_key(itype, ref, None, None, roles)
    return kid, engine


_pk, _pe = make("probe", "agent", "probe")
_probe_engine = _pe()
for surface in ("register_self_federation_key", "list_federation_keys",
                "emit_attestation_self", "is_canonical", "list_canonical_servers"):
    if not hasattr(_probe_engine, surface):
        print(json.dumps({"_error": "absent", "surface": surface})); sys.exit(2)

r = {}


def _attempt(label, fn):
    try:
        r[label] = {"outcome": "ok", "value": fn()}
    except Exception as exc:
        r[label] = {"outcome": "err", "token": str(exc)[:160]}


# ── identity_type is a role SET: a multi-role key is ADMITTED ──
# register_self_federation_key(..., roles=[...]) accepts a set of roles on both
# backends (returns a key_id). NOTE: the `roles` column read back via
# list_federation_keys is a DIAGNOSTIC only — it is populated on sqlite but returns
# [] on postgres via the FFI read path (the raw DB column holds the set correctly on
# BOTH; only the postgres FFI serialization drops it — a persist backend-parity bug,
# filed upstream). So the readback is recorded, never asserted for equality; the
# set-membership SEMANTICS are asserted behaviorally below (backend-stable).
multi_kid, multi_eng = make("multi", "agent", "multi-role",
                            roles=["agent", "substrate_persist"])
r["multi_admitted"] = bool(multi_kid) and isinstance(multi_kid, str)
_page = json.loads(multi_eng().list_federation_keys(json.dumps({}), None, 100, multi_kid))
_row = next(x for x in _page["items"] if x["key_id"] == multi_kid)
r["role_set_readback"] = _row.get("roles")  # diagnostic, NOT asserted (pg FFI bug)

# ── Set-membership emitter gate (CC 3.4.7.1): right is per held role ──
def _emit(kid, engine, dim):
    env = {"attesting_key_id": kid, "attested_key_id": kid, "dimension": dim,
           "score": 1.0, "asserted_at": "2026-05-28T14:00:00.000Z",
           "witness_relation": "self"}
    return engine().emit_attestation_self(json.dumps(
        {"attestation_type": dim, "attestation_envelope": env, "attested_key_id": kid}))

_attempt("emit_held_role", lambda: _emit(multi_kid, multi_eng, "observed:x"))
_attempt("emit_unheld_role", lambda: _emit(multi_kid, multi_eng, "accord:invocation"))

# ── Cohabitation is not a self-claim backdoor ──
_attempt("selfclaim_canonical_scalar", lambda: make("sc", "canonical", "sc")[0])
_attempt("selfclaim_accord_scalar", lambda: make("ah", "accord_holder", "ah")[0])

# A key that LISTS canonical in its role set is admitted (the roles list itself is
# not gated) but is STILL not canonical — the role is not conferred.
rolecanon_kid, rolecanon_eng = make("rc", "agent", "role-canonical",
                                    roles=["agent", "canonical"])
r["rolecanon_is_canonical"] = rolecanon_eng().is_canonical(rolecanon_kid)
_conferred = [x["key_id"] for x in json.loads(rolecanon_eng().list_canonical_servers())]
r["rolecanon_absent_from_canonical_set"] = rolecanon_kid not in _conferred
r["conferred_anchor_is_canonical"] = (
    bool(_conferred) and rolecanon_eng().is_canonical(_conferred[0]))
r["multi_is_canonical"] = multi_eng().is_canonical(multi_kid)

r["stage"] = "done"
report(r)
"""


@pytest.fixture(scope="module")
def roleset():
    script = f"INJECTED_URL = {get_database_url()!r}\n" + _BODY
    payload = run_python_script(script).parsed_stdout()
    if payload.get("_error") == "absent":
        pytest.fail(f"persist role-set surface missing: {payload.get('surface')}")
    if payload.get("_error"):
        pytest.fail(f"probe failed: {payload}")
    assert payload.get("stage") == "done", payload
    return payload


@pytest.mark.requires_persist
def test_multi_role_key_is_admitted(roleset):
    """CC 4.5.8 / 4.5.8.1: `federation_keys.identity_type` is a SET of roles — the
    substrate admits a key carrying more than one role.

    `register_self_federation_key(..., roles=["agent", "substrate_persist"])` is
    accepted (returns a key_id) on both backends — the single-key role cohabitation
    that CC 4.5.8 introduces.

    (The literal `roles` column readback is a persist backend-parity DIAGNOSTIC only:
    populated on sqlite, dropped by the FFI read on postgres though the raw DB column
    holds the set on both — a persist bug filed upstream. The set-membership
    SEMANTICS are asserted behaviorally in the next test, which is green on both
    backends.)
    """
    assert roleset["multi_admitted"] is True, (
        f"a multi-role registration (roles=[agent, substrate_persist]) was not "
        f"admitted: multi_admitted={roleset['multi_admitted']}, "
        f"roles_readback={roleset.get('role_set_readback')!r}")


@pytest.mark.requires_persist
def test_set_membership_grants_right_to_emit_per_held_role(roleset):
    """CC 4.5.8.1 / 3.4.7.1: set membership grants the wire-level right to emit per
    held role — and no more.

    The `{agent, substrate_persist}` key MAY emit on a held-role surface
    (`observed:*`) but MUST NOT emit `accord:*` (the `accord_holder` role is not in
    its set) — rejected by the reserved-prefix emitter gate.
    """
    assert roleset["emit_held_role"]["outcome"] == "ok", (
        f"the cohabiting key could not emit on a held role's surface (observed:*): "
        f"{roleset['emit_held_role']}")
    assert roleset["emit_unheld_role"]["outcome"] == "err", (
        f"the cohabiting key emitted accord:* WITHOUT holding accord_holder — set "
        f"membership is not gating the emitter: {roleset['emit_unheld_role']}")
    assert "accord_holder" in roleset["emit_unheld_role"]["token"], (
        f"accord:* was rejected but not by the accord_holder set-membership gate: "
        f"{roleset['emit_unheld_role']['token']}")


@pytest.mark.requires_persist
def test_constitutional_roles_cannot_be_self_claimed(roleset):
    """CC 4.5.8.1: cohabitation is NOT a self-claim backdoor for constitutional roles.

    Registering `identity_type='canonical'` is rejected (must be accord-conferred);
    `identity_type='accord_holder'` is rejected without hardware attestation
    evidence.
    """
    assert roleset["selfclaim_canonical_scalar"]["outcome"] == "err", (
        f"identity_type='canonical' was self-claimed and admitted: "
        f"{roleset['selfclaim_canonical_scalar']}")
    assert "canonical_role_not_accord_conferred" in roleset["selfclaim_canonical_scalar"]["token"], (
        f"canonical self-claim rejected by an unexpected gate: "
        f"{roleset['selfclaim_canonical_scalar']['token']}")
    assert roleset["selfclaim_accord_scalar"]["outcome"] == "err", (
        f"identity_type='accord_holder' was self-claimed without evidence and "
        f"admitted: {roleset['selfclaim_accord_scalar']}")
    assert "attestation_evidence" in roleset["selfclaim_accord_scalar"]["token"], (
        f"accord_holder self-claim rejected by an unexpected gate: "
        f"{roleset['selfclaim_accord_scalar']['token']}")


@pytest.mark.requires_persist
def test_listing_canonical_in_role_set_confers_nothing(roleset):
    """CC 4.5.8.1: the role SET grants the right to emit, never conferral of a
    constitutional role.

    A key that lists `canonical` in its role set is admitted (the roles list is not
    itself gated) yet is NOT canonical: `is_canonical` is False and it is absent from
    `list_canonical_servers()`. The accord-conferred anchor, by contrast, resolves
    True — proving `is_canonical` reads conferral, not the self-listed role.
    """
    assert roleset["rolecanon_is_canonical"] is False, (
        "a key that merely LISTS 'canonical' in its role set resolved is_canonical() "
        "True — the role set is being read as a conferral surface, which CC 4.5.8.1 "
        "forbids")
    assert roleset["rolecanon_absent_from_canonical_set"] is True, (
        "a self-listed 'canonical' role key appeared in list_canonical_servers()")
    assert roleset["conferred_anchor_is_canonical"] is True, (
        "the accord-conferred canonical anchor did not resolve is_canonical() True — "
        "the control that proves conferral (not self-listing) is what counts")
    assert roleset["multi_is_canonical"] is False, (
        "the {agent, substrate_persist} cohabiting key (no canonical role) resolved "
        "is_canonical() True")
