"""
Fabric tier — CC 5.3.2.4.1 local-tier eligibility (`CLM-authority-local`).

CC 5.3.2.4.1 (part_5_transport_substrate.md §5.3.2.4.1, "`authority-local` —
Local-tier eligibility — the discriminator is *revocation authority*, not
subject-set emptiness") pins the exact discriminator for what may rest local-tier:

    A write is local-tier-eligible iff the producer holds SOLE revocation authority
    over it. The discriminator is *revocation authority*, NOT an empty
    `subject_key_ids`.

The single carve-out: a Contribution where a subject OTHER than the producer holds
revocation authority (a subject-emitted `consent:state:revoked`) MUST go signed /
promote per the CC 5.3.2.2 24-hour obligation — it MUST NOT rest local.

This test isolates the discriminator with the case that distinguishes "revocation
authority" from "subject-set emptiness": a producer-authority write that NAMES a
subject. If the discriminator were subject-set emptiness, that row would be
ineligible; because the discriminator is revocation authority, it rests local-eligible.

What is REAL on the floor (persist v40.0.0), driven end-to-end here:

- **The tier gate: local-tier is `cohort_scope=self` only.** `attestation_insert_local`
  REJECTS `cohort_scope` ∈ {family, community, federation} with
  `federation_invalid_argument` — nothing crosses toward federation-visible via the
  local-write path.
- **Producer-authority rows rest local-eligible — INCLUDING one that names a
  subject.** A producer's own `observed:x` (no subject) AND a producer's
  `observed:about` that NAMES a subject in `subject_key_ids` are BOTH admitted local
  and are NOT flagged by the promotion-overdue detector. This is the load-bearing
  observation: the named-subject row proves the discriminator is authority, not
  subject-set emptiness.
- **A subject-authority row is flagged not-local-eligible.** A `consent:state:revoked`
  where the subject (not the producer) holds revocation authority is flagged overdue
  by `list_consent_revocation_promotion_overdue_json(sla_seconds=0)` — the carve-out
  that must NOT rest local.
- **Entering the mesh resolves it.** After `enter_mesh` (persist v39.0.0 — the
  local→federation flip over the same bytes that replaced the node-re-signing
  `attestation_promote`), the subject-authority row is no longer flagged; it is
  then widened to `federation` by an actor-signed `supersedes` so the revocation
  is visible, per CC 5.3.2.2.

NOT ASSERTED (verified unenforced on the floor): the §5.3.2.4.1 tier-specific
addition "`witness_relation` MUST be `self` for any local-tier write" — the string
`witness_relation` does not appear in the persist binary at all; it survives only as
a free-form envelope member, so there is no gate to assert. That is a distinct
CIRISPersist gap, out of scope here.

Real surface: `Engine.attestation_insert_local(input_json)`,
`Engine.describe_crossing(id, scope, cohort_target, basis_json)`,
`Engine.enter_mesh(id, ci_json)`, `Engine.widen_audience(prior_id, ci_json, strip)`,
`Engine.list_consent_revocation_promotion_overdue_json(sla_seconds)`. Engines carry
PQC identities so the crossing's hybrid sign succeeds.
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


class Ident:
    def __init__(self, prefix, itype, ref):
        d = tempfile.mkdtemp()
        self.s = os.path.join(d, "s"); open(self.s, "wb").write(secrets.token_bytes(32))
        self.p = os.path.join(d, "p"); open(self.p, "wb").write(secrets.token_bytes(32))
        self.k = prefix + "-" + secrets.token_hex(8)
        self.kid = self.engine().register_self_federation_key(itype, ref, None, None, None)

    def engine(self):
        cp.reset_engine()
        return cp.Engine(DB_URL, self.k, local_key_id=self.k, local_key_path=self.s,
                         local_pqc_key_id=self.k + "-pqc", local_pqc_key_path=self.p)


for surface in ("attestation_insert_local", "describe_crossing", "enter_mesh",
                "widen_audience", "list_consent_revocation_promotion_overdue_json"):
    if not hasattr(Ident("probe", "agent", "probe").engine(), surface):
        print(json.dumps({"_error": "absent", "surface": surface})); sys.exit(2)

A = Ident("author", "agent", "author")           # the producer
SUB = Ident("subj", "user", "revoking-subject")  # a subject who can hold authority

r = {"A": A.kid, "SUB": SUB.kid}


def _attempt(label, fn):
    try:
        r[label] = {"outcome": "ok", "value": fn()}
    except Exception as exc:
        r[label] = {"outcome": "err", "token": str(exc)[:160]}


# persist v39.0.0: a crossing is described (nine CC 4.5.1.1 axes derived from the
# row by `describe_crossing`), then entered / widened; the basis is producer
# authority — the actor publishes its own claim.
_BASIS = json.dumps({"kind": "producer_authority"})


def _enter(engine, aid):
    return engine.enter_mesh(aid, engine.describe_crossing(aid, "self", None, _BASIS))


def _widen(engine, aid, audience="federation"):
    return engine.widen_audience(aid, engine.describe_crossing(aid, audience, None, _BASIS), [])


def _local(dim, subject_key_ids=None, cohort_scope="self"):
    env = {"attesting_key_id": A.kid, "attested_key_id": A.kid, "dimension": dim,
           "score": 1.0, "asserted_at": "2026-05-28T14:00:00.000Z",
           "witness_relation": "self", "cohort_scope": cohort_scope}
    inp = {"attesting_key_id": A.kid, "attestation_type": dim, "attested_key_id": A.kid,
           "dimension": dim, "witness_relation": "self", "cohort_scope": cohort_scope,
           "attestation_envelope": dict(env)}
    if subject_key_ids:
        env["subject_key_ids"] = subject_key_ids
        inp["subject_key_ids"] = subject_key_ids
        inp["attestation_envelope"]["subject_key_ids"] = subject_key_ids
    return A.engine().attestation_insert_local(json.dumps(inp))


# ── The tier gate: local-tier is cohort_scope=self ONLY ──
for cs in ("family", "community", "federation"):
    _attempt("scope_" + cs, lambda cs=cs: _local("observed:x", cohort_scope=cs))

# ── Producer-authority rows (local-eligible), one of which NAMES a subject ──
_attempt("producer_no_subject", lambda: _local("observed:x"))
_attempt("producer_named_subject", lambda: _local("observed:about", [SUB.kid]))
# ── Subject-authority row: the carve-out that must NOT rest local ──
_attempt("subject_authority", lambda: _local("consent:state:revoked", [SUB.kid]))


def _overdue_ids():
    raw = A.engine().list_consent_revocation_promotion_overdue_json(0)
    rows = json.loads(raw) if isinstance(raw, str) else raw
    return [x["attestation_id"] for x in rows]


_attempt("overdue_ids", _overdue_ids)
_sa = r["subject_authority"].get("value")
_pn = r["producer_no_subject"].get("value")
_pns = r["producer_named_subject"].get("value")
_ids = r["overdue_ids"].get("value") or []
r["subject_flagged"] = _sa in _ids
r["producer_no_subject_local_ok"] = _pn not in _ids
r["producer_named_subject_local_ok"] = _pns not in _ids

# ── Entering the mesh resolves the not-local-eligible flag ──
_attempt("enter_subject", lambda: _enter(A.engine(), _sa))
_attempt("widen_subject", lambda: _widen(A.engine(), _sa))
_attempt("overdue_after", _overdue_ids)
_ids_after = r["overdue_after"].get("value") or []
r["cleared_after_promote"] = _sa not in _ids_after

r["stage"] = "done"
report(r)
"""


@pytest.fixture(scope="module")
def tier():
    script = f"INJECTED_URL = {get_database_url()!r}\n" + _BODY
    payload = run_python_script(script).parsed_stdout()
    if payload.get("_error") == "absent":
        pytest.fail(f"persist local-tier surface missing: {payload.get('surface')}")
    if payload.get("_error"):
        pytest.fail(f"probe failed: {payload}")
    assert payload.get("stage") == "done", payload
    return payload


@pytest.mark.requires_persist
@pytest.mark.parametrize("scope", ["family", "community", "federation"])
def test_local_tier_admits_only_self_scope(tier, scope):
    """CC 5.3.2.4.1 / §5.3.2.4.3: the local-write path admits only `cohort_scope=self`
    — nothing crosses toward federation-visible unsigned.

    `attestation_insert_local` rejects family / community / federation cohort scopes
    with `federation_invalid_argument`.
    """
    res = tier["scope_" + scope]
    assert res["outcome"] == "err", (
        f"local-tier write admitted cohort_scope={scope!r} — only 'self' may rest "
        f"local: {res}")
    assert "federation_invalid_argument" in res["token"], (
        f"cohort_scope={scope!r} rejected but with an unexpected token: {res['token']}")


@pytest.mark.requires_persist
def test_discriminator_is_authority_not_subject_emptiness(tier):
    """CC 5.3.2.4.1: the discriminator is REVOCATION AUTHORITY, not subject-set
    emptiness.

    BOTH producer-authority rows rest local-eligible (are NOT flagged overdue) —
    crucially including `observed:about`, which NAMES a subject in `subject_key_ids`.
    If the discriminator were subject-set emptiness, the named-subject row would be
    ineligible; because it is revocation authority, it rests local.
    """
    assert tier["producer_no_subject"]["outcome"] == "ok", (
        f"producer's own no-subject write was not admitted local: "
        f"{tier['producer_no_subject']}")
    assert tier["producer_named_subject"]["outcome"] == "ok", (
        f"producer's named-subject write was not admitted local: "
        f"{tier['producer_named_subject']}")
    assert tier["producer_no_subject_local_ok"] is True, (
        "a producer-authority row (no subject) was flagged not-local-eligible")
    assert tier["producer_named_subject_local_ok"] is True, (
        "a producer-authority row that NAMES a subject was flagged "
        "not-local-eligible — the discriminator is being read as subject-set "
        "emptiness, which CC 5.3.2.4.1 explicitly rejects")


@pytest.mark.requires_persist
def test_subject_authority_revocation_is_not_local_eligible(tier):
    """CC 5.3.2.4.1 carve-out: a Contribution where a subject other than the producer
    holds revocation authority is NOT local-tier-eligible.

    The subject-side `consent:state:revoked` is flagged by the promotion-overdue
    detector at sla_seconds=0 — the "must not rest local" state.
    """
    assert tier["subject_authority"]["outcome"] == "ok", (
        f"could not write the subject-authority revocation: {tier['subject_authority']}")
    assert tier["subject_flagged"] is True, (
        "the subject-authority revocation was NOT flagged not-local-eligible — the "
        "CC 5.3.2.4.1 carve-out (subject holds revocation authority) is unobserved")


@pytest.mark.requires_persist
def test_promotion_clears_not_local_eligible(tier):
    """CC 5.3.2.4.1 / §5.3.2.4.2: entering the mesh is the conformant resolution —
    the subject-authority row, once crossed local→federation over the same bytes,
    is no longer flagged; the actor-signed widening then makes it visible.
    """
    assert tier["enter_subject"]["outcome"] == "ok" and tier["enter_subject"]["value"].get("outcome") == "crossed", (
        f"entering the mesh with the subject-authority revocation did not report "
        f"`crossed`: {tier['enter_subject']}")
    assert tier["widen_subject"]["outcome"] == "ok" and tier["widen_subject"]["value"].get("outcome") == "crossed", (
        f"widening the subject-authority revocation to `federation` did not report "
        f"`crossed`: {tier['widen_subject']}")
    assert tier["cleared_after_promote"] is True, (
        "the subject-authority revocation was still flagged not-local-eligible after "
        "it entered the mesh — the crossing does not resolve the carve-out")
