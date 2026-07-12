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

What is REAL on the floor (persist 15.1.0), driven end-to-end here:

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

**What is NOT asserted here — a SEPARATE persist gap.** The 24-hour SLA overdue
detector — the `hard_case:consent_revocation_promotion_overdue` emission the
substrate MUST raise when a subject-side revocation sits local-tier past the
window (§5.3.2.2 / §5.3.2.4 "observability for modeling") — is **not exposed** on
the floor (no overdue/hard_case surface on the Engine). That SLA leg is a distinct
CIRISPersist gap and is NOT asserted by this test; this file drives only the
promotion mechanism, which is genuinely green.

Real surface: `Engine.attestation_insert_local(input_json)` (LocalAttestationInput
— requires a full CC 2.1 `attestation_envelope`), `Engine.attestation_promote(
attestation_id)`. The engine is constructed with a PQC identity so promotion's
hybrid sign succeeds.
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
