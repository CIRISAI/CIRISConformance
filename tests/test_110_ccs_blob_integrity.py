"""
CEG-Conforming Substrate (CCS) — blob full-SHA integrity.

CEG §0.2 defines the **CCS** profile, which includes (§10.1 / §10.1.1)
*full-SHA blob verification before consumption*: the substrate MUST NOT
admit bytes whose SHA-256 does not match the claimed digest, and a
consumer MUST verify the full hash (not a prefix) before handing bytes
onward.

persist enforces this as **hash-on-write**: `put_blob_json` recomputes
the SHA-256 of the body and rejects a mismatch with `blob_hash_mismatch`
before any holder-attestation is emitted. That rejection is the
cross-wheel-observable half of §10.1.1 and is exercised here.

The *positive* round-trip (store a valid blob + read it back) uses
persist v3.3.0's one-call `put_blob_signing` (CIRISPersist#121 — the seam
filed as CIRISPersist#124, now shipped): persist owns the holds_bytes
envelope construction, canonicalization, signing (via the engine's
composed signer), and atomic commit. The attesting key must first be
registered in the federation directory, otherwise attestation emission
fails (`blob_attestation_emission_failed`).

See CEG §10.1 / §10.1.1 — CIRISRegistry/FSD/CEG/10_endpoints.md.
"""

from __future__ import annotations

import pytest

from conftest import ceg_local_signer_preamble, get_database_url, run_python_script


def _ccs_blob_script(database_url: str) -> str:
    return ceg_local_signer_preamble(database_url) + r'''
body = b"ceg-10.1.1-blob-under-test"
good_sha = hashlib.sha256(body).hexdigest()
bad_sha = "0" * 64
b64 = base64.b64encode(body).decode()

report = {"stage": "start"}

# Absent blob → None (clean miss, not an error).
report["absent_is_none"] = engine.get_blob_json(bad_sha) is None

# Hash-on-write: a body that does not hash to the claimed sha MUST be
# rejected at admission. (The attestation sub-object is intentionally a
# placeholder — the integrity gate fires before attestation emission.)
def _payload(sha):
    return json.dumps({
        "sha256": sha,
        "body": {"inline": b64},
        "media_type": None,
        "attestation": {
            "attesting_key_id": "ceg-conformance-key",
            "attestation_id": "00000000-0000-4000-8000-000000000001",
            "original_content_hash_hex": sha,
            "scrub_signature_classical": base64.b64encode(engine.local_sign(b"x")).decode(),
            "scrub_signature_pqc": None,
            "scrub_key_id": "ceg-conformance-key",
            "scrub_timestamp": "2026-05-28T13:45:09.000Z",
        },
    })

try:
    engine.put_blob_json(_payload(bad_sha))
    report["mismatch_rejected"] = False
    report["mismatch_error"] = None
except ValueError as exc:
    report["mismatch_rejected"] = True
    report["mismatch_error"] = str(exc)

# Positive round-trip via persist's one-call put_blob_signing (v3.3.0).
# The attesting key must be in the federation directory first.
key_id = engine.register_federation_key("agent", "ceg-ccs-ref", None, None, None)
try:
    engine.put_blob_signing(
        good_sha, b64, None, None, key_id,
        "2026-05-28T13:45:09.000Z", "33333333-3333-4333-8333-333333333333",
    )
    fetched = engine.get_blob_json(good_sha)
    report["positive_intact"] = (
        fetched is not None and base64.b64decode(json.loads(fetched)["inline"]) == body
    )
    report["positive_has_blob"] = engine.has_blob_json(good_sha)
    # The holds_bytes holder attestation was emitted for the attesting key.
    holders = json.loads(engine.list_attestations_for(key_id))
    report["holder_attestation_emitted"] = any(
        h.get("attestation_type", "").startswith("holds_bytes:sha256:") for h in holders
    )
except Exception as exc:
    report["positive_error"] = f"{type(exc).__name__}: {str(exc)[:160]}"

report["stage"] = "done"
print(json.dumps(report))
sys.exit(0)
'''


@pytest.fixture(scope="module")
def ccs_blob():
    result = run_python_script(_ccs_blob_script(get_database_url()))
    try:
        payload = result.parsed_stdout()
    except Exception:
        pytest.fail(
            f"CCS blob script produced no parseable JSON (exit {result.returncode}):\n"
            f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}"
        )
    assert payload.get("stage") == "done", f"{payload}\nSTDERR: {result.stderr}"
    return payload


@pytest.mark.xfail(strict=False, reason="CIRISConformance#6 — fixture federation_conflict after persist 3.5.0→3.6.3")
@pytest.mark.ceg
@pytest.mark.requires_persist
def test_mismatched_hash_rejected_at_admission(ccs_blob):
    """§10.1.1: a body that doesn't match the claimed SHA-256 is rejected."""
    assert ccs_blob["mismatch_rejected"], (
        f"blob with a mismatched hash was admitted — §10.1.1 hash-on-write "
        f"gate is not firing: {ccs_blob}"
    )
    assert ccs_blob["mismatch_error"] == "blob_hash_mismatch", ccs_blob["mismatch_error"]


@pytest.mark.xfail(strict=False, reason="CIRISConformance#6 — fixture federation_conflict after persist 3.5.0→3.6.3")
@pytest.mark.ceg
@pytest.mark.requires_persist
def test_absent_blob_returns_none(ccs_blob):
    """An unknown SHA-256 reads back as a clean miss (None), not an error."""
    assert ccs_blob["absent_is_none"] is True, ccs_blob


@pytest.mark.xfail(strict=False, reason="CIRISConformance#6 — fixture federation_conflict after persist 3.5.0→3.6.3")
@pytest.mark.ceg
@pytest.mark.requires_persist
def test_blob_positive_round_trip(ccs_blob):
    """§10.1: a valid blob stores via put_blob_signing and reads back intact."""
    assert "positive_error" not in ccs_blob, ccs_blob.get("positive_error")
    assert ccs_blob["positive_intact"] is True, ccs_blob
    assert ccs_blob["positive_has_blob"] is True, ccs_blob
    assert ccs_blob["holder_attestation_emitted"] is True, (
        f"put_blob_signing did not emit a holds_bytes holder attestation: {ccs_blob}"
    )
