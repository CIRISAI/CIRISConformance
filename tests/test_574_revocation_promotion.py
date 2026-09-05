"""
Fabric tier — CC 5.3.2.2 consent-revocation promotion (`CLM-revocation-promotion`):
a subject-side consent revocation is written local-tier, then PROMOTED to
federation-tier.

CC 5.3.2.2 (part_5_transport_substrate.md §5.3.2.2,
"`consent-revocations` — Consent revocations are NOT local-tier-eligible") pins the
promotion discipline over the CC 5.3.2.4 attestation-tier model: a subject-side
consent revocation "MAY *transit* the local-tier write path while in flight … but
it MUST NOT *rest* there." Its only conformant terminal states are **promoted**
(federation-tier, hybrid-signed per CC 5.3.2.4.3) or **overdue-flagged** — never
settled-local. The substrate drives it to federation-tier promotion; promotion
"computes the hybrid signature and flips the row federation-visible … It is
**idempotent** (promoting a `federation` row returns it unchanged)" (§5.3.2.4.2).

What is REAL on the floor (persist v40.0.0), driven end-to-end here:

- **Local-tier write of a subject-side consent revocation.** A
  `consent:state:revoked` attestation carrying a subject in `subject_key_ids` (the
  subject holds revocation authority) is admitted to the local tier via
  `Engine.attestation_insert_local(input_json)` (returns the attestation id).
- **Promotion local → federation is TWO verbs, and the actor signs.** persist
  v39.0.0 retired `attestation_promote` — it re-signed the row with the NODE's
  key, cleared every co-scrub and rewrote `cohort_scope` inside the signed
  envelope, so the fabric became the author of an actor's claim (persist FSD
  "promotion preserves the actor signature"). What stands in its place:
  `Engine.enter_mesh(id, contextual_integrity)` flips the local row to the
  federation tier over the SAME bytes (§5.3.2.4.2 — `cohort_scope` is one of
  those bytes, so a `(local, self)` row enters as `(federation, self)`), and
  `Engine.widen_audience(id, contextual_integrity, strip)` writes a `supersedes`
  row the actor signs at the strictly wider `cohort_scope` (CC 4.4.3.3.1). Both
  take the nine-axis CC 4.5.1.1 ContextualIntegrity description, derived
  truthfully from the row by `Engine.describe_crossing(id, scope, cohort, basis)`;
  a caller that edits an axis to lie is refused by the axis's name. The engine
  carries a PQC identity so the CC 5.3.2.4.3 hybrid signature is computed.
- **Idempotency is TYPED.** A second `enter_mesh` of the same id reports
  `already_in_mesh`; a second `widen_audience` of the same prior by the same
  attester reports `already_widened` (CEG §6.1 dedup) — nothing is touched
  (§5.3.2.4.2). The `crossed → already_*` transition IS the observable tier flip.
- **v40.0.0 — the widening carries the CLAIM's instant.** The `supersedes` row's
  `asserted_at` is the prior's, verbatim; the placement's own instant is the
  signed `widened_at`. Asserted here so a re-dated widening (the v39 defect
  that made two widenings of one claim read as contradictory) cannot return.
- **The 24-hour SLA overdue detector — NOW REAL (persist 16.1.x, closes
  CIRISPersist#434 which this harness filed).** The
  `hard_case:consent_revocation_promotion_overdue` observability the substrate MUST
  raise when a subject-side revocation sits local-tier past the promotion window
  (§5.3.2.2 / §5.3.2.4 "observability for modeling") is exposed as
  `Engine.list_consent_revocation_promotion_overdue_json(sla_seconds)`. Driven here:
  an un-promoted subject-side `consent:state:revoked` is flagged overdue at
  `sla_seconds=0` (rests-local terminal state, forbidden by §5.3.2.2), and after
  it enters the mesh the overdue list no longer contains it — the detector
  tracks exactly the "must not rest local" invariant.

  (Historical note: this detector was previously **absent** from the Engine FFI —
  earlier revisions of this file disclaimed it as an open CIRISPersist gap. persist
  16.1.x ships it; the gap is closed and the leg below is genuinely green.)

Real surface: `Engine.attestation_insert_local(input_json)` (LocalAttestationInput
— requires a full CC 2.1 `attestation_envelope`), `Engine.describe_crossing(id,
scope, cohort_target, basis_json)`, `Engine.enter_mesh(id, ci_json)`,
`Engine.widen_audience(prior_id, ci_json, strip)`,
`Engine.list_consent_revocation_promotion_overdue_json(sla_seconds)`. The engine
is constructed with a PQC identity so the crossing's hybrid sign succeeds.
"""

from __future__ import annotations

import pytest

from conftest import get_database_url, run_python_script

pytestmark = pytest.mark.fabric

# The promotion path uses only the Engine (no init_edge_runtime), so it is
# postgres-safe. A single-engine scenario suffices — insert local, promote,
# re-promote. The backend is honored via INJECTED_URL (postgres already shared;
# sqlite gets an on-disk file so the tiered row survives the promote reconstruct).
_BODY = r"""
import json, sys, os, tempfile, secrets

def report(obj):
    print(json.dumps(obj)); sys.stdout.flush(); os._exit(0)

try:
    import ciris_persist as cp
except ImportError as exc:
    report({"_error": "import", "detail": str(exc)})

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
        # PQC identity: promotion computes the CC 5.3.2.4.3 hybrid Ed25519+ML-DSA-65
        # signature, so the engine must carry a PQC key or the sign is rejected.
        return cp.Engine(DB_URL, self.k, local_key_id=self.k, local_key_path=self.s,
                         local_pqc_key_id=self.k + "-pqc", local_pqc_key_path=self.p)


for surface in ("attestation_insert_local", "describe_crossing", "enter_mesh",
                "widen_audience", "list_consent_revocation_promotion_overdue_json"):
    if not hasattr(Ident("probe", "agent", "probe").engine(), surface):
        report({"_error": "absent", "surface": surface})

A = Ident("author", "agent", "author")           # the producing occurrence
Sub = Ident("subj", "user", "revoking-subject")  # the subject who holds revocation authority

r = {"A": A.kid, "Sub": Sub.kid}


def _attempt(label, fn):
    try:
        r[label] = {"outcome": "ok", "value": fn()}
    except Exception as exc:
        r[label] = {"outcome": "err", "token": str(exc)[:200]}


# persist v39.0.0: the crossing is described, not asserted. `describe_crossing`
# derives the nine CC 4.5.1.1 axes from the row for a stated audience + basis;
# the verbs re-derive and refuse a lie by the axis's name. The basis is
# producer authority — the actor publishes its own claim (CC 5.3.2.2).
_BASIS = json.dumps({"kind": "producer_authority"})


def _enter(engine, aid):
    return engine.enter_mesh(aid, engine.describe_crossing(aid, "self", None, _BASIS))


def _widen(engine, aid, audience="federation"):
    return engine.widen_audience(aid, engine.describe_crossing(aid, audience, None, _BASIS), [])


# ── Local-tier write of a subject-side consent revocation ──
# LocalAttestationInput requires the full CC 2.1 attestation_envelope committed at
# local-write time (attesting_key_id / attested_key_id / dimension / score /
# asserted_at). subject_key_ids names the subject who holds revocation authority —
# this is the CC 5.3.2.2 subject-side revocation that must NOT rest local.
_local_input = {
    "attesting_key_id": A.kid,
    "attestation_type": "consent:state:revoked",
    "attested_key_id": A.kid,
    "dimension": "consent:state:revoked",
    "witness_relation": "self",
    "subject_key_ids": [Sub.kid],
    "attestation_envelope": {
        "attesting_key_id": A.kid, "attested_key_id": A.kid,
        "dimension": "consent:state:revoked", "score": 1.0,
        "asserted_at": "2026-05-28T14:00:00.000Z", "witness_relation": "self",
        "subject_key_ids": [Sub.kid],
    },
}
_attempt("insert_local", lambda: A.engine().attestation_insert_local(json.dumps(_local_input)))

_aid = r["insert_local"].get("value")
# ── Promotion local → federation: enter (same bytes), then widen (actor-signed) ──
# `enter_mesh` flips the (local, self) row to (federation, self) over the SAME
# bytes — a self row is structurally undiscoverable (CC 5.2) and never advertised,
# so reaching any wider audience MUST go through `widen_audience`, which writes a
# `supersedes` the actor signs at the wider scope. The prior row is untouched.
#
# `federation`, NOT `community`, and the difference is the point. This row
# NAMES A THIRD PARTY — `subject_key_ids` carries the revoking subject, which
# is the whole shape of a subject-side revocation. The widening door (persist
# `check_promotion_cohort_standing`, CIRISPersist#589, AV-45) refuses exactly
# that for the TARGETED cohorts: to place a row at `family`/`community` it must
# name no party but its own producer, or it is an unverifiable claim about
# someone else's cohort. The broad belonging tiers (`affiliations`/`species`/
# `biosphere`/`federation`) have no cohort to have standing in, so they are the
# correct home for a row like this — and `federation` is what CC 5.3.2.2 means
# by promotion anyway.
_attempt("enter_1", lambda: _enter(A.engine(), _aid))
_attempt("widen_1", lambda: _widen(A.engine(), _aid))
# Idempotent re-crossing: typed outcomes, nothing touched (§5.3.2.4.2).
_attempt("enter_2", lambda: _enter(A.engine(), _aid))
_attempt("widen_2", lambda: _widen(A.engine(), _aid))


def _row(aid):
    page = json.loads(A.engine().list_attestations_for(A.kid, None, 50, A.kid))
    items = page.get("items", page.get("attestations", []))
    row = next(x for x in items if x.get("attestation_id") == aid)
    env = row.get("attestation_envelope")
    row["attestation_envelope"] = json.loads(env) if isinstance(env, str) else env
    return row


# v40.0.0: the widening carries the claim's `asserted_at` verbatim and its own
# signed `widened_at` — read both rows back to compare.
_wid = ((r["widen_1"].get("value") or {}).get("attestation_id")
        if r["widen_1"]["outcome"] == "ok" else None)
_attempt("prior_row", lambda: _row(_aid))
_attempt("widened_row", lambda: _row(_wid))

# ── 24-hour SLA overdue detector (persist 16.1.x, CIRISPersist#434) ──
# A SEPARATE, deliberately un-promoted subject-side revocation. At sla_seconds=0 it
# is instantly overdue (it "rests local", the §5.3.2.2-forbidden terminal state);
# once it enters the mesh the detector no longer lists it. `_aid` above is already
# federation-tier by now (enter_1), so it cannot pollute this observation.
_od_input = {
    "attesting_key_id": A.kid,
    "attestation_type": "consent:state:revoked",
    "attested_key_id": A.kid,
    "dimension": "consent:state:revoked",
    "witness_relation": "self",
    "subject_key_ids": [Sub.kid],
    "attestation_envelope": {
        "attesting_key_id": A.kid, "attested_key_id": A.kid,
        "dimension": "consent:state:revoked", "score": 1.0,
        "asserted_at": "2026-05-28T14:00:00.000Z", "witness_relation": "self",
        "subject_key_ids": [Sub.kid],
    },
}
_attempt("od_insert", lambda: A.engine().attestation_insert_local(json.dumps(_od_input)))
_od_aid = r["od_insert"].get("value")


def _overdue_ids():
    raw = A.engine().list_consent_revocation_promotion_overdue_json(0)
    rows = json.loads(raw) if isinstance(raw, str) else raw
    return [x["attestation_id"] for x in rows]


_attempt("overdue_before_promote", lambda: _od_aid in _overdue_ids())
_attempt("od_enter", lambda: _enter(A.engine(), _od_aid))
_attempt("overdue_after_enter", lambda: _od_aid in _overdue_ids())
_attempt("od_widen", lambda: _widen(A.engine(), _od_aid))
_attempt("overdue_after_promote", lambda: _od_aid in _overdue_ids())

r["stage"] = "done"
report(r)
"""


@pytest.fixture(scope="module")
def promotion():
    script = f"INJECTED_URL = {get_database_url()!r}\n" + _BODY
    payload = run_python_script(script).parsed_stdout()
    if payload.get("_error") == "absent":
        pytest.fail(f"persist promotion surface missing: {payload.get('surface')}")
    if payload.get("_error"):
        pytest.fail(f"probe failed: {payload}")
    assert payload.get("stage") == "done", payload
    return payload


@pytest.mark.requires_persist
def test_subject_revocation_is_written_local_then_promoted(promotion):
    """CC 5.3.2.2: a subject-side consent revocation is written local-tier, then
    promoted to federation-tier.

    `attestation_insert_local` admits the `consent:state:revoked` (subject-side,
    `subject_key_ids` names the revoking subject) and returns its id;
    `enter_mesh` reports `crossed` — the local→federation flip over the same bytes
    — and `widen_audience` reports `crossed` with a NEW attestation id: the
    actor-signed `supersedes` at `federation` that makes the revocation visible.
    """
    r = promotion
    assert r["insert_local"]["outcome"] == "ok", (
        f"local-tier write of the subject-side consent revocation failed: "
        f"{r['insert_local']}")
    assert isinstance(r["insert_local"]["value"], str) and r["insert_local"]["value"], (
        f"attestation_insert_local did not return an attestation id: {r['insert_local']}")
    assert r["enter_1"]["outcome"] == "ok", f"enter_mesh errored: {r['enter_1']}"
    assert r["enter_1"]["value"].get("outcome") == "crossed", (
        f"entering the mesh with the local-tier subject revocation did not report "
        f"`crossed` (the local→federation flip): {r['enter_1']}")
    assert r["enter_1"]["value"].get("attestation_id") == r["insert_local"]["value"], (
        f"enter_mesh crossed a DIFFERENT row than the one written — the same-bytes "
        f"contract of §5.3.2.4.2 is broken: {r['enter_1']}")
    assert r["widen_1"]["outcome"] == "ok", f"widen_audience errored: {r['widen_1']}"
    assert r["widen_1"]["value"].get("outcome") == "crossed", (
        f"widening the entered revocation to `federation` did not report `crossed`: "
        f"{r['widen_1']}")
    assert r["widen_1"]["value"].get("attestation_id") not in (None, r["insert_local"]["value"]), (
        f"the widening did not write a NEW `supersedes` row — the prior must stay "
        f"untouched and the wider claim must be its own actor-signed row: {r['widen_1']}")


@pytest.mark.requires_persist
def test_promotion_is_idempotent(promotion):
    """CC 5.3.2.4.2: promotion is idempotent — re-crossing a federation row returns
    it unchanged.

    A second `enter_mesh` of the same id reports `already_in_mesh`; a second
    `widen_audience` of the same prior by the same attester reports
    `already_widened` (CEG §6.1 dedup at the put door). Neither raises and neither
    writes. The `crossed → already_*` transition is the observable proof the row
    moved local→federation and stays there.
    """
    r = promotion
    assert r["enter_2"]["outcome"] == "ok", f"second enter_mesh errored: {r['enter_2']}"
    assert r["enter_2"]["value"].get("outcome") == "already_in_mesh", (
        f"re-entering an already-federation row was not the typed idempotent "
        f"outcome (expected `already_in_mesh`): {r['enter_2']}")
    assert r["widen_2"]["outcome"] == "ok", f"second widen_audience errored: {r['widen_2']}"
    assert r["widen_2"]["value"].get("outcome") == "already_widened", (
        f"re-widening the same prior was not deduplicated (expected "
        f"`already_widened`, CEG §6.1): {r['widen_2']}")


@pytest.mark.requires_persist
def test_widening_carries_the_claims_instant(promotion):
    """persist v40.0.0 / CC 2.6.7: a widening asserts the CLAIM's instant verbatim;
    the placement's own instant is the signed `widened_at`.

    The `supersedes` row written by `widen_audience` carries the prior's
    `asserted_at` byte-for-byte and a `widened_at` that is not before it. A
    widening stamped with its placement time would make two widenings of one
    claim read as two contradictory claims (the v39 defect v40 closed).
    """
    r = promotion
    assert r["prior_row"]["outcome"] == "ok", f"could not read the prior row back: {r['prior_row']}"
    assert r["widened_row"]["outcome"] == "ok", f"could not read the widening back: {r['widened_row']}"
    prior, widened = r["prior_row"]["value"], r["widened_row"]["value"]
    assert widened["attestation_envelope"].get("asserted_at") == prior["attestation_envelope"].get("asserted_at"), (
        f"the widening re-dated the claim: prior asserted_at="
        f"{prior['attestation_envelope'].get('asserted_at')!r} widening asserted_at="
        f"{widened['attestation_envelope'].get('asserted_at')!r}")
    widened_at = widened["attestation_envelope"].get("widened_at")
    assert isinstance(widened_at, str) and widened_at, (
        f"the widening carries no signed `widened_at` — the placement's own instant "
        f"is unrecorded (v40.0.0 W15): {widened['attestation_envelope']}")
    assert widened_at >= widened["attestation_envelope"]["asserted_at"], (
        f"`widened_at` {widened_at!r} precedes the claim's asserted_at "
        f"{widened['attestation_envelope']['asserted_at']!r}")
    assert widened["attestation_envelope"].get("references_attestation_id") == prior["attestation_id"], (
        f"the widening does not reference its prior: {widened['attestation_envelope']}")


@pytest.mark.requires_persist
def test_unpromoted_revocation_is_flagged_overdue(promotion):
    """CC 5.3.2.2 / §5.3.2.4 observability: a subject-side consent revocation that
    rests local-tier is flagged overdue by the SLA detector.

    `list_consent_revocation_promotion_overdue_json(sla_seconds=0)` lists the
    un-promoted `consent:state:revoked` — the "rests local" terminal state §5.3.2.2
    forbids. This is the detector (CIRISPersist#434, filed by this harness) that
    earlier persist floors did not expose; it is real as of persist 16.1.x.
    """
    r = promotion
    assert r["od_insert"]["outcome"] == "ok", (
        f"could not write the un-promoted subject-side revocation to drive the "
        f"overdue detector: {r['od_insert']}")
    assert r["overdue_before_promote"]["outcome"] == "ok", (
        f"the overdue detector errored — surface not exposed? "
        f"{r['overdue_before_promote']}")
    assert r["overdue_before_promote"]["value"] is True, (
        f"an un-promoted subject-side consent revocation was NOT flagged overdue at "
        f"sla_seconds=0 — the §5.3.2.2 'must not rest local' invariant is unobserved: "
        f"{r['overdue_before_promote']}")


@pytest.mark.requires_persist
def test_promotion_clears_the_overdue_flag(promotion):
    """CC 5.3.2.2: promotion is a conformant terminal state, so a promoted revocation
    is no longer overdue.

    After `enter_mesh` drives the revocation local→federation, the same
    `list_consent_revocation_promotion_overdue_json(0)` no longer lists it — the
    detector tracks exactly the un-promoted set, and the crossing resolves the SLA.
    """
    r = promotion
    assert r["od_enter"]["outcome"] == "ok" and r["od_enter"]["value"].get("outcome") == "crossed", (
        f"entering the mesh with the overdue revocation did not report `crossed`: {r['od_enter']}")
    assert r["overdue_after_promote"]["outcome"] == "ok", (
        f"the overdue re-check errored: {r['overdue_after_promote']}")
    assert r["overdue_after_promote"]["value"] is False, (
        f"a PROMOTED (federation-tier) revocation was still flagged overdue — the "
        f"detector does not clear on promotion: {r['overdue_after_promote']}")
