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

What is REAL on the floor (persist 16.1.1), driven end-to-end here:

- **Local-tier write of a subject-side consent revocation.** A
  `consent:state:revoked` attestation carrying a subject in `subject_key_ids` (the
  subject holds revocation authority) is admitted to the local tier via
  `Engine.attestation_insert_local(input_json)` (returns the attestation id).
- **Promotion local → federation.** `Engine.attestation_promote(attestation_id)`
  returns `True` — the local→federation promotion (the hybrid-sign-and-flip step;
  the engine carries a PQC identity so the CC 5.3.2.4.3 hybrid signature is
  computed at promote).
- **Idempotency.** A second `attestation_promote` of the same id returns `False` —
  an already-federation row is returned unchanged (§5.3.2.4.2). The `True → False`
  transition IS the observable tier flip local→federation.
- **The 24-hour SLA overdue detector — NOW REAL (persist 16.1.x, closes
  CIRISPersist#434 which this harness filed).** The
  `hard_case:consent_revocation_promotion_overdue` observability the substrate MUST
  raise when a subject-side revocation sits local-tier past the promotion window
  (§5.3.2.2 / §5.3.2.4 "observability for modeling") is exposed as
  `Engine.list_consent_revocation_promotion_overdue_json(sla_seconds)`. Driven here:
  an un-promoted subject-side `consent:state:revoked` is flagged overdue at
  `sla_seconds=0` (rests-local terminal state, forbidden by §5.3.2.2), and after
  `attestation_promote` the overdue list no longer contains it — the detector
  tracks exactly the "must not rest local" invariant.

  (Historical note: this detector was previously **absent** from the Engine FFI —
  earlier revisions of this file disclaimed it as an open CIRISPersist gap. persist
  16.1.x ships it; the gap is closed and the leg below is genuinely green.)

Real surface: `Engine.attestation_insert_local(input_json)` (LocalAttestationInput
— requires a full CC 2.1 `attestation_envelope`), `Engine.attestation_promote(
attestation_id)`, `Engine.list_consent_revocation_promotion_overdue_json(
sla_seconds)`. The engine is constructed with a PQC identity so promotion's hybrid
sign succeeds.
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


for surface in ("attestation_insert_local", "attestation_promote"):
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
# ── Promotion local → federation (True), then idempotent re-promote (False) ──
_attempt("promote_1", lambda: A.engine().attestation_promote(_aid))
_attempt("promote_2", lambda: A.engine().attestation_promote(_aid))

# ── 24-hour SLA overdue detector (persist 16.1.x, CIRISPersist#434) ──
# A SEPARATE, deliberately un-promoted subject-side revocation. At sla_seconds=0 it
# is instantly overdue (it "rests local", the §5.3.2.2-forbidden terminal state);
# after promotion the detector no longer lists it. `_aid` above is already
# federation-tier by now (promote_1), so it cannot pollute this observation.
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
_attempt("od_promote", lambda: A.engine().attestation_promote(_od_aid))
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
    `attestation_promote(id)` returns `True` — the local→federation promotion that
    computes the CC 5.3.2.4.3 hybrid signature and flips the row federation-visible.
    """
    r = promotion
    assert r["insert_local"]["outcome"] == "ok", (
        f"local-tier write of the subject-side consent revocation failed: "
        f"{r['insert_local']}")
    assert isinstance(r["insert_local"]["value"], str) and r["insert_local"]["value"], (
        f"attestation_insert_local did not return an attestation id: {r['insert_local']}")
    assert r["promote_1"]["outcome"] == "ok", f"promotion errored: {r['promote_1']}"
    assert r["promote_1"]["value"] is True, (
        f"promoting the local-tier subject revocation did not return True (the "
        f"local→federation flip): {r['promote_1']}")


@pytest.mark.requires_persist
def test_promotion_is_idempotent(promotion):
    """CC 5.3.2.4.2: promotion is idempotent — re-promoting a federation row returns
    it unchanged.

    A second `attestation_promote` of the same id returns `False` (already
    federation-tier, no-op). The `True → False` transition is the observable proof
    the row moved local→federation and stays there.
    """
    r = promotion
    assert r["promote_2"]["outcome"] == "ok", f"second promote errored: {r['promote_2']}"
    assert r["promote_2"]["value"] is False, (
        f"re-promoting an already-federation row was not idempotent (expected "
        f"False/unchanged): {r['promote_2']}")


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

    After `attestation_promote` drives the revocation local→federation, the same
    `list_consent_revocation_promotion_overdue_json(0)` no longer lists it — the
    detector tracks exactly the un-promoted set, and promotion resolves the SLA.
    """
    r = promotion
    assert r["od_promote"]["outcome"] == "ok" and r["od_promote"]["value"] is True, (
        f"promoting the overdue revocation did not return True: {r['od_promote']}")
    assert r["overdue_after_promote"]["outcome"] == "ok", (
        f"the overdue re-check errored: {r['overdue_after_promote']}")
    assert r["overdue_after_promote"]["value"] is False, (
        f"a PROMOTED (federation-tier) revocation was still flagged overdue — the "
        f"detector does not clear on promotion: {r['overdue_after_promote']}")
