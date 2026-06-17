"""
CEG-Conforming Producer (CCP) — canonical-bytes + sign/verify round-trip.

CEG §0.2 defines the **CCP** profile: a producer MUST emit well-formed
envelopes (§4) and sign them per the hybrid-sig reference. The
producer-side surface reachable at the cross-wheel boundary is persist's
canonicalization pair:

- `canonicalize_envelope`             — JCS-style: sort keys, no whitespace
- `canonicalize_envelope_for_signing` — same, but strips `signature` /
                                        `signature_pqc` before canonicalizing

These tests assert (a) canonicalization is deterministic regardless of
input key order, (b) the signing form strips the signature fields, and
(c) a producer can canonicalize → sign → and a CCC consumer verifies the
result — closing the CCP↔CCC loop on real bytes.

`test_canonicalization_rejects_noncanonical_timestamp` tracks the CEG
§0.5/§0.6/§0.7 canonicalization-discipline gap: the spec says consumers
MUST reject `+00:00` / uppercase-hex / future `signed_at`, but the wheel
does not yet enforce it at this surface (tracked upstream as
CIRISPersist#126). It is `xfail` until that lands.

See CEG §0.2 / §4 / §0.5-§0.7 — now the CIRIS Constitution Part II — The Grammar:
CIRISRegistry/FSD/CIRIS_Constitution/part_2_the_grammar.md (supersedes CEG;
map § → CC via codebook.json).
"""

from __future__ import annotations

import pytest

from conftest import ceg_local_signer_preamble, get_database_url, run_python_script


def _ccp_canonical_script(database_url: str) -> str:
    return ceg_local_signer_preamble(database_url) + r'''
report = {"stage": "start"}

# (a) Determinism: the same fields in different key order canonicalize
# to identical bytes.
env_a = json.dumps({"b": 2, "a": 1, "signed_at": "2026-05-28T13:45:09.000Z"})
env_b = json.dumps({"signed_at": "2026-05-28T13:45:09.000Z", "a": 1, "b": 2})
cb_a = engine.canonicalize_envelope(env_a)
cb_b = engine.canonicalize_envelope(env_b)
report["deterministic"] = (cb_a == cb_b)
report["canonical_form"] = cb_a.decode()

# (b) The signing form strips signature + signature_pqc.
signed_env = json.dumps({"a": 1, "signature": "SIG", "signature_pqc": "PQC", "z": 9})
for_signing = engine.canonicalize_envelope_for_signing(signed_env).decode()
report["signing_strips_sig"] = ("signature" not in for_signing and "PQC" not in for_signing)
report["for_signing"] = for_signing

# (c) CCP → CCC round-trip: canonicalize for signing, sign, verify.
envelope = json.dumps({
    "dimension": "scores:demo",
    "asserted_at": "2026-05-28T13:45:09.000Z",
    "signature": "",
})
canonical = engine.canonicalize_envelope_for_signing(envelope)
sig = base64.b64encode(engine.local_sign(canonical)).decode()
try:
    out = engine.verify_hybrid(canonical, sig, None, pk, None, "ed25519_fallback", None, None)
    report["roundtrip"] = out["outcome"]
except ValueError as exc:
    report["roundtrip_error"] = str(exc)

# (d) CEG §0.5/§0.6/§0.7 canonicalization rejection — the opt-in validator
# persist v3.5.0 shipped for CIRISPersist#126 (separate from canonicalize_*).
def _vchk(payload, now=None):
    try:
        engine.validate_envelope_canonical_form(json.dumps(payload), now)
        return "accepted"
    except ValueError as exc:
        return str(exc).split(":")[0]  # the rejection kind token

report["canon_validation"] = {
    "ts_ok":      _vchk({"signed_at": "2026-05-28T13:45:09.000Z"}),
    "ts_offset":  _vchk({"signed_at": "2026-05-28T13:45:09.000+00:00"}),
    "ts_lowerz":  _vchk({"signed_at": "2026-05-28T13:45:09.000z"}),
    "hex_lower":  _vchk({"root_hash": "ff00aa"}),
    "hex_upper":  _vchk({"root_hash": "FF00AA"}),
    # §0.7: signed_at more than 5 min in the future, relative to now_iso.
    "ts_present": _vchk({"signed_at": "2026-05-28T13:46:00.000Z"}, "2026-05-28T13:45:00.000Z"),
    "ts_future":  _vchk({"signed_at": "2026-05-28T13:51:00.000Z"}, "2026-05-28T13:45:00.000Z"),
}

report["stage"] = "done"
print(json.dumps(report))
sys.exit(0)
'''


@pytest.fixture(scope="module")
def ccp_canonical():
    result = run_python_script(_ccp_canonical_script(get_database_url()))
    try:
        payload = result.parsed_stdout()
    except Exception:
        pytest.fail(
            f"CCP canonical script produced no parseable JSON (exit {result.returncode}):\n"
            f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}"
        )
    assert payload.get("stage") == "done", f"{payload}\nSTDERR: {result.stderr}"
    return payload


@pytest.mark.ceg
@pytest.mark.ccp
@pytest.mark.requires_persist
def test_canonicalization_is_deterministic(ccp_canonical):
    """Key order doesn't change canonical bytes (JCS-style sorting)."""
    assert ccp_canonical["deterministic"], ccp_canonical
    # Sanity: keys are actually sorted in the output.
    assert ccp_canonical["canonical_form"].startswith('{"a":1,"b":2,'), (
        ccp_canonical["canonical_form"]
    )


@pytest.mark.ceg
@pytest.mark.ccp
@pytest.mark.requires_persist
def test_signing_form_strips_signature_fields(ccp_canonical):
    """`canonicalize_envelope_for_signing` removes signature + signature_pqc."""
    assert ccp_canonical["signing_strips_sig"], ccp_canonical["for_signing"]


@pytest.mark.ceg
@pytest.mark.ccp
@pytest.mark.requires_persist
def test_producer_consumer_round_trip(ccp_canonical):
    """CCP canonicalizes + signs; a CCC consumer verifies the bytes."""
    assert ccp_canonical.get("roundtrip") == "ed25519_fallback", ccp_canonical


@pytest.mark.ceg
@pytest.mark.ccp
@pytest.mark.requires_persist
def test_canonicalization_validator_rejects_noncanonical_forms(ccp_canonical):
    """CEG §0.5/§0.6/§0.7: validate_envelope_canonical_form rejects non-canonical forms.

    persist v3.5.0 (CIRISPersist#126) shipped this as an opt-in validator
    distinct from `canonicalize_envelope`; the harness opts in explicitly.
    """
    v = ccp_canonical["canon_validation"]
    # §0.5 datetime — only `…Z` with 3 fractional digits is canonical.
    assert v["ts_ok"] == "accepted", v
    assert v["ts_offset"] == "canonicalization_timestamp", v
    assert v["ts_lowerz"] == "canonicalization_timestamp", v
    # §0.6 hex — lowercase only.
    assert v["hex_lower"] == "accepted", v
    assert v["hex_upper"] == "canonicalization_hex", v
    # §0.7 — signed_at more than 5 min in the future is rejected.
    assert v["ts_present"] == "accepted", v
    assert v["ts_future"] == "signed_at_in_future", v
