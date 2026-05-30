"""
Multimedia tier conformance (CEG 0.3 — additive multimedia surface).

CEG 0.3 (purely additive vs 0.2; 1+4 wire-format lockdown preserved) adds
the multimedia tier: media `external_content` sub_kinds, the
`takedown_notice` + `key_grant` subject_kinds, content-classification
dimension families, and operator-managed takedown + perceptual-hash
discipline. persist v3.6.0 (CIRISPersist#134, MEDIA_SHARING.md) ships the
substrate half. This file pins the load-bearing claim of the whole tier —
**multimedia rides the existing substrate; nothing new is invented below
the wire format** — plus the new takedown / perceptual-hash / key-grant
substrate primitives.

Verified against ciris-persist 3.6.3:

- ✅ **Media rides existing blob storage** (MEDIA_SHARING §2.6): a media
  blob stores through the same `put_blob_signing` (with a `media_type`)
  and emits the same `holds_bytes:sha256:*` holder attestation — no new
  chunking primitive, no media-specific storage path.
- ✅ **Perceptual-hash gate** (§5.6): an installed matcher refuses a
  known-bad blob at write with `blob_hash_matched_known_bad`.
- ✅ **Takedown admission** (§5.5 / §5.6.8.4): immediate legal bases
  (`ncmec_csam`, `tvec_terrorist`) evict now; windowed bases
  (`dmca_512`, `dsa_article_16`) schedule a future eviction; the
  `legal_basis` closed-set enum is validated.
- ✅ **Key-grant retire = `supersedes`, NOT `withdraws`** (§5.6.8.4
  option-b): the retire path reports `supersedes_emitted`.
- ✅ **Operator multimedia config** round-trips (§5).
- ✅ **Budget-driven eviction** (FEDERATION_SCALING_MODEL §1.2): a small
  `storage_budget_bytes` makes the popularity×freshness sweeper actually
  evict under capacity pressure.

Tracked gap (xfail, not worked around): takedown admission reports
`holders_seen: 0` for a *locally*-held blob — the same local-holder blind
spot as `list_holders_json` → **CIRISPersist#130**.

See MEDIA_SHARING.md + CEG 0.3 §5.6.8 / §8.1.10 (vendored under reference/).
"""

from __future__ import annotations

import pytest

from conftest import ceg_local_signer_preamble, get_database_url, run_python_script


# ─── Substrate flows (no capacity pressure) ───────────────────────────


def _media_substrate_script(database_url: str) -> str:
    return ceg_local_signer_preamble(database_url) + r'''
report = {"stage": "start"}
kid = engine.register_federation_key("agent", "media-ref", None, None, None)

def _notice(sha, basis):
    return json.dumps({
        "content_sha256": sha, "content_holder_key_ids": [kid], "claimant_key_id": kid,
        "legal_basis": basis, "jurisdiction": "US", "good_faith_statement": "x",
        "claim_text": "x", "evidence_refs": [], "perceptual_hash": None,
        "counter_notice_channel": None, "asserted_at": "2026-05-28T14:00:00.000Z",
        "expires_at": "2026-06-28T14:00:00.000Z",
    })

# (1) A media blob rides the same blob storage + holder attestation.
# Content + attestation_id are salted/unique per subprocess so tests stay
# isolated on a shared (postgres) backend.
body = b"\xff\xd8\xff\xe0 conformance-jpeg-" + kid.encode()
sha = hashlib.sha256(body).hexdigest()
engine.put_blob_signing(sha, base64.b64encode(body).decode(), None, "image/jpeg",
                        kid, "2026-05-28T13:45:09.000Z", str(uuid.uuid4()))
fetched = engine.get_blob_json(sha)
report["media_intact"] = fetched is not None and base64.b64decode(json.loads(fetched)["inline"]) == body
holders = json.loads(engine.list_attestations_for(kid))
report["media_holds_bytes_emitted"] = any(
    h.get("attestation_type", "").startswith("holds_bytes:sha256:") for h in holders
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

# (3) Takedown scheduling: immediate vs windowed by legal basis.
sched = {}
for basis in ("ncmec_csam", "tvec_terrorist", "dmca_512", "dsa_article_16"):
    r = json.loads(engine.cirisnode_process_takedown_admission_json(
        _notice("ab" * 32, basis), kid, "2026-05-28T14:00:00.000Z"))
    sched[basis] = r["scheduled_eviction_at"]
report["takedown_scheduling"] = sched

# (4) The legal_basis enum is a validated closed set.
try:
    engine.cirisnode_process_takedown_admission_json(
        _notice("cd" * 32, "not_a_real_basis"), kid, "2026-05-28T14:00:00.000Z")
    report["unknown_basis_rejected"] = False
except ValueError as exc:
    report["unknown_basis_rejected"] = "unknown variant" in str(exc) or "legal_basis" in str(exc)

# (5) Key-grant retire reports supersedes (option-b), not withdraws.
report["retire_report"] = json.loads(
    engine.cirisnode_retire_key_grants_json(kid, "2026-05-28T14:00:00.000Z"))

# (6) Operator multimedia config round-trips.
report["config_default"] = engine.get_multimedia_config_json()
engine.set_multimedia_config_json(json.dumps(
    {"immediate_legal_bases": ["ncmec_csam", "tvec_terrorist"], "counter_notice_window_days": 7}))
report["config_after_set"] = json.loads(engine.get_multimedia_config_json())

# (xfail #130) Takedown should see + evict the local holder of the content.
engine.set_multimedia_config_json(None)
report["takedown_local_holders_seen"] = json.loads(
    engine.cirisnode_process_takedown_admission_json(
        _notice(sha, "ncmec_csam"), kid, "2026-05-28T14:00:00.000Z"))["holders_seen"]

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
    """§2.6: a media blob uses the same put_blob_signing + holds_bytes — no new primitive."""
    assert media_substrate["media_intact"] is True, media_substrate
    assert media_substrate["media_holds_bytes_emitted"] is True, media_substrate


@pytest.mark.ceg
@pytest.mark.requires_persist
def test_perceptual_hash_gate_refuses_known_bad(media_substrate):
    """§5.6: an installed perceptual-hash matcher refuses a known-bad blob at write."""
    assert media_substrate["perceptual_refused"] is True, media_substrate
    assert media_substrate.get("perceptual_error") == "blob_hash_matched_known_bad", media_substrate
    # A non-matching blob is unaffected.
    assert media_substrate["clean_admitted"] is True, media_substrate


@pytest.mark.ceg
@pytest.mark.requires_persist
def test_takedown_immediate_vs_windowed_scheduling(media_substrate):
    """§5.5: child-safety/terrorist bases evict immediately; DMCA/DSA schedule a window."""
    sched = media_substrate["takedown_scheduling"]
    assert sched["ncmec_csam"] is None, sched
    assert sched["tvec_terrorist"] is None, sched
    assert sched["dmca_512"] is not None, sched
    assert sched["dsa_article_16"] is not None, sched


@pytest.mark.ceg
@pytest.mark.requires_persist
def test_takedown_rejects_unknown_legal_basis(media_substrate):
    """§5.6.8.4: the LegalBasis enum is a validated closed set."""
    assert media_substrate["unknown_basis_rejected"] is True, media_substrate


@pytest.mark.ceg
@pytest.mark.requires_persist
def test_key_grant_retire_uses_supersedes_not_withdraws(media_substrate):
    """§5.6.8.4 option-b: retire emits `supersedes` (with rotation_chain), not `withdraws`."""
    rep = media_substrate["retire_report"]
    assert set(rep) == {"grants_seen", "supersedes_emitted", "supersedes_failed"}, rep
    assert "withdraws_emitted" not in rep, rep


@pytest.mark.ceg
@pytest.mark.requires_persist
def test_multimedia_config_round_trips(media_substrate):
    """§5: the operator multimedia config installs and reads back."""
    assert media_substrate["config_default"] is None, media_substrate
    cfg = media_substrate["config_after_set"]
    assert cfg["counter_notice_window_days"] == 7, cfg
    assert set(cfg["immediate_legal_bases"]) == {"ncmec_csam", "tvec_terrorist"}, cfg


@pytest.mark.ceg
@pytest.mark.requires_persist
@pytest.mark.xfail(
    reason="takedown admission reports holders_seen=0 for a locally-held blob — the "
    "same local-holder blind spot as list_holders_json → CIRISPersist#130",
    strict=False,
)
def test_takedown_evicts_local_holder(media_substrate):
    """§5.4: a takedown for content this node holds should see (and evict) the local holder."""
    assert media_substrate["takedown_local_holders_seen"] >= 1, media_substrate


# ─── Fabric flow: capacity-driven eviction (the §1.2 claim, now drivable) ──


def _budget_eviction_script(database_url: str) -> str:
    return ceg_local_signer_preamble(database_url) + r'''
report = {"stage": "start"}
kid = engine.register_federation_key("agent", "budget-ref", None, None, None)

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
