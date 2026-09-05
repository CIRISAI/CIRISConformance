"""
Substrate tier — DEK-grant post-quantum wrap discipline (CC 5.1).

The CIRIS Constitution mandates a **post-quantum-hybrid** wrap for the epoch-DEK
cascade that protects self / family / community content at rest (part_3 §community
DEK cascade + part_5 CC 5.1): "`wrap_algorithm: v2` (hybrid PQC) MANDATORY (same
harvest-now-decrypt-later reasoning as self/family)". v2 is **X25519 + ML-KEM-768**
(hybrid); v1 is X25519-only (classical). A long-lived DEK wrapped classical-only
is a harvest-now-decrypt-later hole, so v2 must be a distinct, non-downgradable
envelope.

This drives the REAL persist key-grant surface (`wrap_dek_for_recipient_v2_b64`
+ `unwrap_dek_v2_b64`), wrapping to the engine's own content-tier KEM pubkeys
(`local_identity_aggregate`), and pins:

1. **v2 IS the hybrid PQC wrap** — `wrap_dek_for_recipient_v2_b64` emits
   `algorithm: "x25519_mlkem768_aes256_gcm_hkdf_sha256"` carrying a real
   ML-KEM-768 ciphertext.
2. **The classical wrap is GONE, not deprecated.** persist v34.0.0 removed the
   X25519-only v1 wrap from admission (variant, wire token, parse arm) and
   v35.0.0 removed `wrap_dek_for_recipient_b64` / `unwrap_dek_b64` from the
   Python surface (CIRISPersist#715 — "the wheel no longer mints what its own
   gate refuses"). A wheel that still exposes a classical minter is a
   harvest-now-decrypt-later hole the substrate itself closed.
3. **No downgrade, refused BY NAME.** A v1-shaped envelope (the retired
   hyphenated `x25519-aes256-gcm-hkdf-sha256` token, no ML-KEM ciphertext) and
   the rc2-era hyphenated v2 spelling are refused at the decode door with a
   refusal that NAMES the token — not serde's generic unknown-variant, which
   renders both tokens with no directive (persist v35.0.0 "retired wrap
   spellings refuse BY NAME"). The refusal must differ from a wrong-key
   refusal of a well-formed v2 envelope, or "rejected" proves nothing.

(Full unwrap round-trips need the recipient's private KEM keys, which the engine
holds internally and does not export — by design. These tests assert the wrap
shape + the no-downgrade property, which are the load-bearing CC 5.1 claims and
need only the public surface.)
"""

from __future__ import annotations

import pytest

from conftest import run_python_script

pytestmark = pytest.mark.substrate

# The v2 hybrid token was RESPELLED with underscores between the rc2 floor and
# persist v32.3.0; the classical v1 kept its hyphens until v34.0.0 removed it
# outright. These are wire identifiers a peer compares byte-for-byte, so the
# suite pins the live spelling AND drives the retired ones through the decode
# door: persist v35.0.0 (CIRISPersist#715) refuses each retired spelling by
# name — the hyphenated v2 as RESPELLED (naming the token to send), the v1
# spellings as REMOVED.
_V2_ALG = "x25519_mlkem768_aes256_gcm_hkdf_sha256"
_V2_ALG_RC2 = "x25519-mlkem768-aes256-gcm-hkdf-sha256"
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
report["v2_algorithm"] = v2.get("algorithm")
report["v2_ml_kem_len"] = len(base64.b64decode(v2["ml_kem_ciphertext_b64"])) if "ml_kem_ciphertext_b64" in v2 else 0

# The classical minter/unwrapper must be GONE from the surface (v35.0.0, #715).
report["classical_surface_present"] = [
    name for name in ("wrap_dek_for_recipient_b64", "unwrap_dek_b64") if hasattr(engine, name)]

# Decode-door refusals. A random private half means even the well-formed v2
# envelope cannot unwrap — that refusal is the CONTROL: a retired-spelling
# refusal must be a different, token-naming message, or "rejected" proves
# nothing about the downgrade gate.
_priv = base64.b64encode(secrets.token_bytes(32)).decode()

def _unwrap(env):
    try:
        engine.unwrap_dek_v2_b64(_priv, _priv, mk, json.dumps(env))
        return {"outcome": "accepted"}
    except Exception as exc:
        return {"outcome": "rejected", "token": str(exc)[:300]}

report["control_wrong_key"] = _unwrap(v2)
v1_shaped = {k: v for k, v in v2.items() if k != "ml_kem_ciphertext_b64"}
v1_shaped["algorithm"] = V1_ALG
report["v1_shaped"] = _unwrap(v1_shaped)
rc2_spelled = dict(v2); rc2_spelled["algorithm"] = V2_ALG_RC2
report["rc2_spelled_v2"] = _unwrap(rc2_spelled)
no_alg = {k: v for k, v in v2.items() if k != "algorithm"}
report["algorithm_absent"] = _unwrap(no_alg)

report["stage"] = "done"
print(json.dumps(report)); sys.stdout.flush()
sys.exit(0)
"""


@pytest.fixture(scope="module")
def key_grant():
    script = f"V1_ALG = {_V1_ALG!r}\nV2_ALG_RC2 = {_V2_ALG_RC2!r}\n" + _GRANT_SCRIPT
    result = run_python_script(script)
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
def test_classical_wrap_is_gone_from_the_surface(key_grant):
    """persist v35.0.0 / CIRISPersist#715: the classical X25519-only wrap is REMOVED
    from the Python surface, not deprecated — the wheel no longer mints what its
    own admission gate (v34.0.0) refuses."""
    assert key_grant["classical_surface_present"] == [], (
        f"the wheel still exposes a classical DEK wrap — a harvest-now-decrypt-later "
        f"minter the substrate retired: {key_grant['classical_surface_present']}")


@pytest.mark.requires_persist
def test_no_cross_version_downgrade(key_grant):
    """CC 5.1: a v1-shaped envelope (retired classical token, no ML-KEM ciphertext)
    is refused at the v2 decode door — the PQC half cannot be dropped."""
    assert key_grant["v1_shaped"]["outcome"] == "rejected", key_grant["v1_shaped"]
    assert key_grant["algorithm_absent"]["outcome"] == "rejected", (
        f"an envelope with NO `algorithm` was accepted — the field is REQUIRED "
        f"(v35.0.0): {key_grant['algorithm_absent']}")


@pytest.mark.requires_persist
@pytest.mark.parametrize("case,token", [("v1_shaped", _V1_ALG), ("rc2_spelled_v2", _V2_ALG_RC2)])
def test_retired_spelling_is_refused_by_name(key_grant, case, token):
    """persist v35.0.0: a retired wrap spelling is refused BY NAME at the decode
    door — the refusal names the token (v1: REMOVED; rc2 hyphenated v2: RESPELLED
    with the token to send) and is a different message from the wrong-key control,
    so the gate is observable rather than inferred from any exception at all."""
    got = key_grant[case]
    control = key_grant["control_wrong_key"]
    assert got["outcome"] == "rejected", got
    assert control["outcome"] == "rejected", control
    assert got["token"] != control["token"], (
        f"the retired-spelling refusal is byte-identical to the wrong-key refusal — "
        f"the decode door is not refusing by name: {got}")
    assert token in got["token"], (
        f"the refusal does not name the retired token {token!r}: {got}")
