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

What is REAL on the floor (persist 17.5.2), driven end-to-end here:

- **`identity_type` is a stored role SET.** `register_self_federation_key(..., roles=
  ["agent", "substrate_persist"])` produces a `federation_keys` row whose `roles`
  column reads back verbatim as `["agent", "substrate_persist"]` on BOTH backends — a
  genuine multi-role key.
- **Set membership is the emitter gate (CC 3.4.7.1).** The cohabiting
  `{agent, substrate_persist}` key MAY emit on a held role's surface (`observed:*`,
  via `emit_attestation_self`) but MUST NOT emit `accord:*` — it rejects with
  `federation_accord_dimension_requires_accord_holder` (the `accord_holder` role is
  not in its set). The right is per-held-role, not blanket.
- **Cohabitation is not a self-claim backdoor — closed on BOTH admission paths.** A
  constitutional role is rejected whether it arrives as the scalar `identity_type` or
  as a member of `roles=[...]`: `canonical` → `canonical_role_not_accord_conferred`,
  `accord_holder` (without hardware evidence) →
  `federation_accord_holder_requires_attestation_evidence`. Behind that gate, the
  conferral control still holds: `is_canonical` resolves the accord-conferred anchor
  True and a cohabiting key False. The role set is a right-to-emit surface, never a
  conferral surface for constitutional roles.

**Two flag days flipped here (both filed by this harness, both shipped in persist
17.x) — this test asserts the POST-fix behavior and fails closed if either regresses:**

- **CIRISPersist#441** — the `roles=[...]` set path used to BYPASS the accord-conferral
  gate the scalar path enforced. Through 16.1.1 the self-claim was ADMITTED and the
  backdoor was closed only downstream (a self-listed role conferred nothing because
  `is_canonical` reads conferral) — it held by the ACCIDENT that `roles` was
  decorative, and would have become a live escalation the moment any gate started
  evaluating the set as CC 3.4.7.1 says it should. Now rejected at admission.
- **CIRISPersist#442** — `list_federation_keys` used to drop the `roles` array to `[]`
  on postgres while sqlite returned it populated (the raw DB column held the set on
  both; an FFI serialization-only parity bug). The readback is now a real cross-backend
  assertion rather than a recorded diagnostic.

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
# register_self_federation_key(..., roles=[...]) accepts a set of BENIGN roles and
# the set reads back verbatim on BOTH backends (CIRISPersist#442 shipped in 17.x —
# the postgres FFI read path used to drop the array to []; it no longer does, so the
# readback is a real assertion here rather than a diagnostic).
multi_kid, multi_eng = make("multi", "agent", "multi-role",
                            roles=["agent", "substrate_persist"])
r["multi_admitted"] = bool(multi_kid) and isinstance(multi_kid, str)
_page = json.loads(multi_eng().list_federation_keys(json.dumps({}), None, 100, multi_kid))
_row = next(x for x in _page["items"] if x["key_id"] == multi_kid)
r["role_set_readback"] = _row.get("roles")

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

# THE FLAG DAY (CIRISPersist#441, shipped in persist 17.x): listing a constitutional
# role in the role SET is now REJECTED AT ADMISSION, identically to the scalar path.
# Through persist 16.1.1 this registration was ADMITTED and the backdoor was closed
# only downstream (`is_canonical` reads conferral, so the self-listed role conferred
# nothing) — i.e. it held by the ACCIDENT that `roles` was decorative. The gate now
# closes it BY CONSTRUCTION, which is what this harness filed #441 to get.
_attempt("selfclaim_canonical_roleset",
         lambda: make("rc", "agent", "role-canonical", roles=["agent", "canonical"])[0])
_attempt("selfclaim_accord_roleset",
         lambda: make("ah2", "agent", "role-accord", roles=["agent", "accord_holder"])[0])

# The conferral control: the accord-conferred anchor still resolves is_canonical True,
# and the benign cohabiting key does not.
_conferred = [x["key_id"] for x in json.loads(multi_eng().list_canonical_servers())]
r["conferred_anchor_is_canonical"] = (
    bool(_conferred) and multi_eng().is_canonical(_conferred[0]))
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
    accepted (returns a key_id) and the set reads back VERBATIM on both backends.

    The readback is a real assertion as of persist 17.x: CIRISPersist#442 (filed by
    this harness) fixed the FFI read path, which used to drop the array to `[]` on
    postgres while sqlite returned it populated — the raw DB column always held the
    set on both, so it was a serialization-only parity bug. Asserting it here pins
    the parity closed.
    """
    assert roleset["multi_admitted"] is True, (
        f"a multi-role registration (roles=[agent, substrate_persist]) was not "
        f"admitted: multi_admitted={roleset['multi_admitted']}")
    assert roleset["role_set_readback"] == ["agent", "substrate_persist"], (
        f"the role SET did not read back verbatim — identity_type is not being stored "
        f"as a set (or the CIRISPersist#442 postgres FFI read-path regression is back): "
        f"{roleset['role_set_readback']!r}")


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
def test_constitutional_role_in_the_role_SET_is_rejected_at_admission(roleset):
    """CC 4.5.8.1: the role SET is not a self-claim backdoor — THE FLAG DAY.

    Listing a constitutional role (`canonical` / `accord_holder`) in `roles=[...]` is
    REJECTED at admission on persist ≥17.x, with the SAME tokens the scalar
    `identity_type` path raises. The two admission paths no longer disagree about
    which roles a key may self-assert.

    This flipped with CIRISPersist#441, which this harness filed. Through persist
    16.1.1 the set path was UNGATED: the registration was admitted and the backdoor
    was closed only downstream (`is_canonical` reads conferral, so a self-listed role
    conferred nothing). That held by the ACCIDENT that `roles` was decorative — the
    moment any gate started evaluating the set (which CC 3.4.7.1 says gates SHOULD do,
    by `X ∈ identity_type`), it would have become a live escalation. It is now closed
    by construction.
    """
    for label, token in (("selfclaim_canonical_roleset", "canonical_role_not_accord_conferred"),
                         ("selfclaim_accord_roleset", "attestation_evidence")):
        got = roleset[label]
        assert got["outcome"] == "err", (
            f"a constitutional role was self-claimed via the roles=[...] SET path and "
            f"ADMITTED — the CC 4.5.8.1 self-claim backdoor is open (CIRISPersist#441 "
            f"regressed): {label}={got}")
        assert token in got["token"], (
            f"{label} was rejected, but not by the conferral gate the scalar path "
            f"uses — the two admission paths disagree: {got['token']}")


@pytest.mark.requires_persist
def test_is_canonical_reads_conferral_not_self_listing(roleset):
    """CC 4.5.8.1: `is_canonical` resolves ACCORD CONFERRAL, never a self-listed role.

    The defense-in-depth control behind the admission gate above: the accord-conferred
    anchor resolves True, while the benign `{agent, substrate_persist}` cohabiting key
    — which holds no canonical role — resolves False.
    """
    assert roleset["conferred_anchor_is_canonical"] is True, (
        "the accord-conferred canonical anchor did not resolve is_canonical() True — "
        "the control that proves conferral (not self-listing) is what counts")
    assert roleset["multi_is_canonical"] is False, (
        "the {agent, substrate_persist} cohabiting key (no canonical role) resolved "
        "is_canonical() True")
