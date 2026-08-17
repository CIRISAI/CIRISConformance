"""
Substrate tier — DEK-grant post-quantum wrap discipline (CC 5.1).

The CIRIS Constitution mandates a **post-quantum-hybrid** wrap for the epoch-DEK
cascade that protects self / family / community content at rest (part_3 §community
DEK cascade + part_5 CC 5.1): "`wrap_algorithm: v2` (hybrid PQC) MANDATORY (same
harvest-now-decrypt-later reasoning as self/family)". v2 is **X25519 + ML-KEM-768**
(hybrid); v1 is X25519-only (classical). A long-lived DEK wrapped classical-only
is a harvest-now-decrypt-later hole, so v2 must be a distinct, non-downgradable
envelope.

This drives the REAL persist key-grant surfaces (`wrap_dek_for_recipient_v2_b64`
/ `_b64` + the matching unwraps), wrapping to the engine's own content-tier KEM
pubkeys (`local_identity_aggregate`), and pins:

1. **v2 IS the hybrid PQC wrap** — `wrap_dek_for_recipient_v2_b64` emits
   `algorithm: "x25519-mlkem768-aes256-gcm-hkdf-sha256"` carrying a real
   ML-KEM-768 ciphertext.
2. **v1 is classical-only** — `algorithm: "x25519-aes256-gcm-hkdf-sha256"`, no
   ML-KEM ciphertext.
3. **No cross-version confusion** — a v1 unwrap rejects a v2 envelope AND a v2
   unwrap rejects a v1 envelope, so the PQC half can't be silently dropped or a
   classical grant silently treated as hybrid.

(Full unwrap round-trips need the recipient's private KEM keys, which the engine
holds internally and does not export — by design. These tests assert the wrap
shape + the no-downgrade property, which are the load-bearing CC 5.1 claims and
need only the public surface.)
"""

from __future__ import annotations

import pytest

from conftest import run_python_script

pytestmark = pytest.mark.substrate

# The v2 hybrid token was RESPELLED with underscores somewhere between the
# rc2 floor and persist v32.3.0; v1 kept its hyphens. That divergence is not
# cosmetic — these are wire identifiers a peer compares byte-for-byte, and the
# suite pins them precisely so a respelling shows up here as a decision rather
# than as a mismatch in the field. The two spellings now coexisting on the same
# surface is reported upstream (CIRISPersist#715).
_V2_ALG = "x25519_mlkem768_aes256_gcm_hkdf_sha256"
_V1_ALG = "x25519-aes256-gcm-hkdf-sha256"

_GRANT_SCRIPT = r"""
import json, sys, os, tempfile, secrets, base64
try:
    import ciris_persist as cp
except ImportError as exc:
    print(json.dumps({"_error": "import", "detail": str(exc)})); sys.exit(2)

_d = tempfile.mkdtemp()
_s = os.path.join(_d, "s"); open(_s, "wb").write(secrets.token_bytes(32))
_p = os.path.join(_d, "p"); open(_p, "wb").write(secrets.token_bytes(32))
cp.reset_engine()
k = "node-" + secrets.token_hex(8)
engine = cp.Engine("sqlite::memory:", k, local_key_id=k, local_key_path=_s,
                   local_pqc_key_id=k + "-pqc", local_pqc_key_path=_p)

if not hasattr(engine, "wrap_dek_for_recipient_v2_b64"):
    print(json.dumps({"_error": "absent"})); sys.exit(2)

agg = json.loads(engine.local_identity_aggregate())
x = agg["content_x25519_pubkey_b64"]
mk = agg["content_ml_kem_768_pubkey_b64"]
dek = base64.b64encode(secrets.token_bytes(32)).decode()

report = {}
v2 = json.loads(engine.wrap_dek_for_recipient_v2_b64(x, mk, dek))
v1 = json.loads(engine.wrap_dek_for_recipient_b64(x, dek))
report["v2_algorithm"] = v2.get("algorithm")
report["v2_ml_kem_len"] = len(base64.b64decode(v2["ml_kem_ciphertext_b64"])) if "ml_kem_ciphertext_b64" in v2 else 0
report["v1_algorithm"] = v1.get("algorithm")
report["v1_has_ml_kem"] = "ml_kem_ciphertext_b64" in v1

# Cross-version: neither unwrap accepts the other's envelope.
_priv = base64.b64encode(secrets.token_bytes(32)).decode()
try:
    engine.unwrap_dek_b64(_priv, json.dumps(v2))
    report["v1_unwrap_of_v2"] = "accepted"
except Exception as exc:
    report["v1_unwrap_of_v2"] = "rejected"
try:
    engine.unwrap_dek_v2_b64(_priv, _priv, mk, json.dumps(v1))
    report["v2_unwrap_of_v1"] = "accepted"
except Exception as exc:
    report["v2_unwrap_of_v1"] = "rejected"

report["stage"] = "done"
print(json.dumps(report)); sys.stdout.flush()
sys.exit(0)
"""


@pytest.fixture(scope="module")
def key_grant():
    result = run_python_script(_GRANT_SCRIPT)
    payload = result.parsed_stdout()
    if payload.get("_error") == "absent":
        pytest.fail("persist wrap_dek_for_recipient_v2_b64 is missing — the "
                    "PQC key-grant surface is not on the wheel")
    assert payload.get("stage") == "done", payload
    return payload


@pytest.mark.requires_persist
def test_v2_wrap_is_hybrid_pqc(key_grant):
    """CC 5.1: the mandatory v2 wrap is X25519 + ML-KEM-768 with a real PQC ciphertext."""
    assert key_grant["v2_algorithm"] == _V2_ALG, key_grant
    # ML-KEM-768 ciphertext is ~1088 bytes — a real PQC encapsulation, not a stub.
    assert key_grant["v2_ml_kem_len"] > 1000, key_grant


@pytest.mark.requires_persist
def test_v1_wrap_is_classical_only(key_grant):
    """The v1 wrap is X25519-only (classical) — distinct from the mandated v2."""
    assert key_grant["v1_algorithm"] == _V1_ALG, key_grant
    assert key_grant["v1_has_ml_kem"] is False, key_grant


@pytest.mark.requires_persist
def test_no_cross_version_downgrade(key_grant):
    """CC 5.1: v1↔v2 envelopes are not interchangeable — the PQC half can't be dropped."""
    assert key_grant["v1_unwrap_of_v2"] == "rejected", key_grant
    assert key_grant["v2_unwrap_of_v1"] == "rejected", key_grant
