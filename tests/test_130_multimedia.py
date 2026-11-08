"""
Multimedia tier conformance (the CIRIS Constitution CC 0.4 — additive multimedia surface).

the CIRIS Constitution CC 0.4 (purely additive vs 0.2; 1+4 wire-format lockdown preserved) adds
the multimedia tier: media `external_content` sub_kinds, the
`takedown_notice` + `key_grant` subject_kinds, content-classification
dimension families, and operator-managed takedown + perceptual-hash
discipline. persist v3.6.0 (CIRISPersist#134, MEDIA_SHARING.md) ships the
substrate half. This file pins the load-bearing claim of the whole tier —
**multimedia rides the existing substrate; nothing new is invented below
the wire format** — plus the new takedown / perceptual-hash / key-grant
substrate primitives.

Verified against ciris-persist 61.0.4:

- ✅ **Media rides existing blob storage** (MEDIA_SHARING §2.6): a media
  blob stores through the same `put_blob_signing` (with a `media_type`)
  and emits the same holding claim — `custody:ack:v1` `here` since persist
  v55.0.0 (CC 3.1.3.3; `holds_bytes` retired, CC 2.4) — no new chunking
  primitive, no media-specific storage path.
- ✅ **Perceptual-hash gate** (CC 3.1.8): an installed matcher refuses a
  known-bad blob at write with `blob_hash_matched_known_bad`.
- ✅ **Takedown** (CC 3.1.1 / CC 3.3.2 / CC 4.5.3 / CC 4.5.5): since persist
  v60.0.0 (CIRISPersist#803) a notice is the duty-holder's signed
  `takedown_notice:{basis}:v1` row and `cirisnode_process_takedown_admission_json`
  executes it by row id. Immediate-removal bases (`ncmec_csam`,
  `tvec_terrorist`) destroy the bytes on receipt; counter-notice bases
  (`dmca512`, `dsa_article16`) withhold and settle after their window; a basis
  outside the closed set is refused at the put door.
- ✅ **Budget-driven eviction** (FEDERATION_SCALING_MODEL §1.2): a small
  `storage_budget_bytes` makes the popularity×freshness sweeper actually
  evict under capacity pressure.

Retired with their surfaces (persist v55.0.0): the key-grant SET retire gate
(a key grant is one `key_grant:{axis}:v1` row per recipient, never withdrawn,
CC 3.3.2) and the operator `MultimediaConfig` round-trip.

See MEDIA_SHARING.md + the CIRIS Constitution CC 0.4 CC 3.3 / §8.1.10 (vendored under reference/).
"""

from __future__ import annotations

import pytest

from conftest import ceg_local_signer_preamble, get_database_url, run_python_script


# ─── Substrate flows (no capacity pressure) ───────────────────────────


def _media_substrate_script(database_url: str) -> str:
    return ceg_local_signer_preamble(database_url, pqc=True) + r'''
report = {"stage": "start"}
kid = engine.register_self_federation_key("agent", "media-ref", None, None, None)

import datetime as _dt
def _iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%S.000Z")

# persist v60.0.0 (CIRISPersist#803; CC 3.1.1, CC 3.3.2): a takedown notice is a
# ROW, the signer's `scores` row on `takedown_notice:{basis}:v1` (score -1,
# `subject_kind: takedown_notice`, `claimant_key_id` == the signer). The put door
# admits it only from a CC 4.5.5 duty-holder over the content as THIS node holds
# it; the holder's own `custody:ack:v1` claim names it a subject of the content.
def _emit_notice(sha, basis):
    now = _dt.datetime.now(_dt.timezone.utc)
    return engine.emit_attestation_self(json.dumps({
        "attestation_type": "scores", "cohort_scope": "federation",
        "attested_key_id": kid,
        "expires_at": _iso(now + _dt.timedelta(days=30)),
        "attestation_envelope": {
            "dimension": "takedown_notice:" + basis + ":v1",
            "subject_kind": "takedown_notice", "score": -1.0,
            "content_sha256": sha, "claimant_key_id": kid, "legal_basis": basis,
            "jurisdiction": "US", "good_faith_statement": "conformance good faith",
            "claim_text": "conformance claim",
        },
    }))

# CC 4.5.5: whose content it is comes from a held row that BINDS it (its
# `evidence_refs` name the digest). A holding claim is custody, never a binding
# (`envelope_binds_content` skips `custody:*`), so the author establishes the
# content with its own `content:established:v1` row, as persist's own takedown
# fixtures do (`takedown_reversal_invariants::bind_into`).
def _bind(h):
    engine.emit_attestation_self(json.dumps({
        "attestation_type": "scores", "cohort_scope": "federation",
        "attested_key_id": kid,
        "attestation_envelope": {"dimension": "content:established:v1",
                                 "evidence_refs": [h]},
    }))

def _held_blob(tag):
    b = b"takedown-" + tag.encode() + b"-" + kid.encode()
    h = hashlib.sha256(b).hexdigest()
    engine.put_blob_signing(h, base64.b64encode(b).decode(), None, "image/png",
                            kid, _iso(_dt.datetime.now(_dt.timezone.utc)), str(uuid.uuid4()))
    _bind(h)
    return h

# (1) A media blob rides the same blob storage + holder attestation.
# Content + attestation_id are salted/unique per subprocess so tests stay
# isolated on a shared (postgres) backend.
body = b"\xff\xd8\xff\xe0 conformance-jpeg-" + kid.encode()
sha = hashlib.sha256(body).hexdigest()
engine.put_blob_signing(sha, base64.b64encode(body).decode(), None, "image/jpeg",
                        kid, "2026-05-28T13:45:09.000Z", str(uuid.uuid4()))
fetched = engine.get_blob_json(sha)
report["media_intact"] = fetched is not None and base64.b64decode(json.loads(fetched)["inline"]) == body
holders = json.loads(engine.list_attestations_for(kid))['items']
report["media_here_claim_emitted"] = any(
    _is_here_claim(h) for h in holders
)

# (2) Perceptual-hash gate refuses a known-bad blob at write.
bad = b"known-bad-content-" + kid.encode(); bad_sha = hashlib.sha256(bad).hexdigest()
class _Matcher:
    def check(self, sha256_hex, body):
        if sha256_hex == bad_sha:
            return {"database": "conformance-db", "score": 1.0, "threshold": 0.9}
        return None
engine.set_perceptual_hash_matcher(_Matcher())
try:
    engine.put_blob_signing(bad_sha, base64.b64encode(bad).decode(), None, "image/png",
                            kid, "2026-05-28T13:45:09.000Z", str(uuid.uuid4()))
    report["perceptual_refused"] = False
except ValueError as exc:
    report["perceptual_refused"] = True
    report["perceptual_error"] = str(exc)
# A non-matching blob is still admitted with the matcher installed.
ok = b"clean-content-" + kid.encode(); ok_sha = hashlib.sha256(ok).hexdigest()
try:
    engine.put_blob_signing(ok_sha, base64.b64encode(ok).decode(), None, "image/png",
                            kid, "2026-05-28T13:45:09.000Z", str(uuid.uuid4()))
    report["clean_admitted"] = engine.has_blob_json(ok_sha)
except Exception as exc:
    report["clean_admitted"] = False
    report["clean_error"] = str(exc)[:120]
engine.set_perceptual_hash_matcher(None)

# (3) Takedown disposition by basis (CC 4.5.3 / CC 3.3.2): an immediate-removal
# basis destroys the bytes on receipt; a counter-notice basis withholds them and
# settles (hard-deletes) after its window. Each basis runs on its own held blob.
sched = {}
for basis in ("ncmec_csam", "tvec_terrorist", "dmca512", "dsa_article16"):
    h = _held_blob(basis)
    r = json.loads(engine.cirisnode_process_takedown_admission_json(_emit_notice(h, basis)))
    sched[basis] = {"disposition": r["disposition"], "tombstoned": r["tombstoned"],
                    "settles_at": r["settles_at"], "bytes_destroyed": r["bytes_destroyed"],
                    "blob_held_after": engine.has_blob_json(h)}
report["takedown_scheduling"] = sched

# (4) The legal_basis enum is a validated closed set: a notice row on a basis
# outside it is refused at the put door.
try:
    _emit_notice(_held_blob("unknown"), "not_a_real_basis")
    report["unknown_basis_rejected"] = False
except ValueError as exc:
    report["unknown_basis_rejected"] = True
    report["unknown_basis_error"] = str(exc)[:300]

# Takedown sees + evicts the local holder of the content: this node's own
# holding claim is retracted and the bytes destroyed (CC 4.5.3).
# The blob is stored at the real clock: a holding claim is live 72 h from its
# signed instant (CC 3.1.3.3 rule 5), so a claim stamped months ago (as the media
# blob above is) has already lapsed and there is nothing live to retract.
_local = _held_blob("local-holder")
def _live_here_on(sha):
    # This node's `here` claims on `sha` that no `withdraws` row of its own retracts.
    rows = json.loads(engine.list_attestations_for(kid))["items"] + \
        json.loads(engine.list_attestations_by(kid, 1000))["items"]
    claims = {h["attestation_id"] for h in rows
              if _is_here_claim(h) and sha in json.dumps(h.get("attestation_envelope") or {})}
    retracted = set()
    for r in rows:
        blob = json.dumps(r)
        if r.get("attestation_type") == "withdraws" or '"withdraws"' in blob:
            retracted |= {c for c in claims if c in blob}
    return len(claims), len(claims - retracted)
report["takedown_here_before"] = _live_here_on(_local)[1]
_td = json.loads(engine.cirisnode_process_takedown_admission_json(_emit_notice(_local, "ncmec_csam")))
report["takedown_here_after"] = _live_here_on(_local)[1]
report["takedown_claims_retracted"] = _td["claims_retracted"]
report["takedown_bytes_destroyed"] = _td["bytes_destroyed"]
report["takedown_blob_evicted"] = not engine.has_blob_json(_local)

report["stage"] = "done"
print(json.dumps(report))
sys.exit(0)
'''


@pytest.fixture(scope="module")
def media_substrate():
    result = run_python_script(_media_substrate_script(get_database_url()))
    try:
        payload = result.parsed_stdout()
    except Exception:
        pytest.fail(
            f"media substrate script produced no parseable JSON (exit {result.returncode}):\n"
            f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}"
        )
    assert payload.get("stage") == "done", f"{payload}\nSTDERR: {result.stderr}"
    return payload


@pytest.mark.ceg
@pytest.mark.requires_persist
def test_media_blob_rides_existing_storage(media_substrate):
    """§2.6: a media blob uses the same put_blob_signing + holding claim — no new primitive.

    The holding claim is `custody:ack:v1` `here` since persist v55.0.0 (CC 3.1.3.3;
    `holds_bytes` is retired, CC 2.4)."""
    assert media_substrate["media_intact"] is True, media_substrate
    assert media_substrate["media_here_claim_emitted"] is True, media_substrate


@pytest.mark.ceg
@pytest.mark.requires_persist
def test_perceptual_hash_gate_refuses_known_bad(media_substrate):
    """CC 3.1.8: an installed perceptual-hash matcher refuses a known-bad blob at write."""
    assert media_substrate["perceptual_refused"] is True, media_substrate
    assert media_substrate.get("perceptual_error") == "blob_hash_matched_known_bad", media_substrate
    # A non-matching blob is unaffected.
    assert media_substrate["clean_admitted"] is True, media_substrate


@pytest.mark.ceg
@pytest.mark.requires_persist
def test_takedown_immediate_vs_windowed_scheduling(media_substrate):
    """CC 4.5.3 / CC 3.3.2: immediate-removal bases destroy on receipt; counter-notice
    bases withhold now and settle after their window (dmca512 10 d, dsa_article16 14 d)."""
    sched = media_substrate["takedown_scheduling"]
    for basis in ("ncmec_csam", "tvec_terrorist"):
        r = sched[basis]
        assert r["disposition"] == {"kind": "destroy_on_receipt"}, (basis, r)
        assert r["tombstoned"] is True, (basis, r)
        assert r["bytes_destroyed"] is True, (basis, r)
        assert r["blob_held_after"] is False, (basis, r)
    for basis, days in (("dmca512", 10), ("dsa_article16", 14)):
        r = sched[basis]
        assert r["disposition"] == {"kind": "withhold_then_delete", "window_days": days}, (basis, r)
        assert r["tombstoned"] is True, (basis, r)
        assert r["settles_at"] is not None, (basis, r)
        assert r["bytes_destroyed"] is False, (basis, r)


@pytest.mark.ceg
@pytest.mark.requires_persist
def test_takedown_rejects_unknown_legal_basis(media_substrate):
    """CC 3.3.2: the legal_basis set is closed; a notice row outside it is refused."""
    assert media_substrate["unknown_basis_rejected"] is True, media_substrate
    assert "not_a_real_basis" in media_substrate["unknown_basis_error"], media_substrate


# persist v55.0.0 retired the key-grant SET rows and `cirisnode_retire_key_grants_json`
# (a key grant is one `scores` row per recipient on `key_grant:{axis}:v1`, never
# withdrawn, CC 3.3.2), and removed `MultimediaConfig` (a basis's disposition is
# the CC 4.5.3 table, not operator config). Their two gates went with them; the
# disposition table is asserted above.


@pytest.mark.ceg
@pytest.mark.requires_persist
def test_takedown_evicts_local_holder(media_substrate):
    """CC 4.5.3: a takedown of content this node holds retracts this node's own
    holding claim and destroys the bytes (immediate-removal basis)."""
    # persist v61 (CIRISPersist#803): an immediate-removal basis settles at once
    # through `purge_finalize`, whose eviction retracts this node's holding claim
    # with its own `withdraws` row; the report's `claims_retracted` counts only the
    # counter-notice path and stays 0 here. What the rule requires is that no live
    # claim of this node's survives, so the claim is read before and after.
    assert media_substrate["takedown_here_before"] >= 1, media_substrate
    assert (media_substrate["takedown_here_after"] == 0
            or media_substrate["takedown_claims_retracted"] >= 1), media_substrate
    assert media_substrate["takedown_bytes_destroyed"] is True, media_substrate
    assert media_substrate["takedown_blob_evicted"] is True, media_substrate


# ─── Fabric flow: capacity-driven eviction (the §1.2 claim, now drivable) ──


def _budget_eviction_script(database_url: str) -> str:
    return ceg_local_signer_preamble(database_url, pqc=True) + r'''
report = {"stage": "start"}
kid = engine.register_self_federation_key("agent", "budget-ref", None, None, None)

# A tight storage budget puts the held set above the watermark; the
# popularity×freshness sweeper must then evict under pressure.
engine.set_storage_budget_bytes(2000)
stored = 0
for i in range(8):
    body = (b"media-payload-" + kid.encode() + bytes([i])) * 40
    sha = hashlib.sha256(body).hexdigest()
    engine.put_blob_signing(sha, base64.b64encode(body).decode(), None, "image/png",
                            kid, "2026-05-28T13:45:09.000Z", str(uuid.uuid4()))
    stored += 1
report["stored"] = stored
report["swept"] = engine.sweep_evictions_once()
report["stage"] = "done"
print(json.dumps(report))
sys.exit(0)
'''


@pytest.fixture(scope="module")
def budget_eviction():
    result = run_python_script(_budget_eviction_script(get_database_url()))
    try:
        payload = result.parsed_stdout()
    except Exception:
        pytest.fail(
            f"budget eviction script produced no parseable JSON (exit {result.returncode}):\n"
            f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}"
        )
    assert payload.get("stage") == "done", f"{payload}\nSTDERR: {result.stderr}"
    return payload


@pytest.mark.fabric
@pytest.mark.requires_persist
def test_budget_driven_eviction(budget_eviction):
    """§1.2: under a tight storage budget the sweeper evicts held blobs under pressure."""
    assert budget_eviction["stored"] == 8, budget_eviction
    assert budget_eviction["swept"] >= 1, (
        f"a tight storage budget did not drive any evictions: {budget_eviction}"
    )
