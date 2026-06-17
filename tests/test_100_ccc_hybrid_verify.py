"""
CEG-Conforming Consumer (CCC) — hybrid-signature verification.

CEG §0.2 defines the **CCC** profile: a consumer MUST verify hybrid
(Ed25519 + ML-DSA-65) signatures and apply the §8 composition policies.
This is the cornerstone of consumer conformance and the one CEG-CCC
surface fully reachable at the cross-wheel boundary today: persist's
`Engine.verify_hybrid` / `verify_hybrid_via_directory`.

The three consumer policies (per ciris_edge's documented trust model):
- `strict`           — reject any sender whose row is hybrid-pending
                       (Ed25519-only, no ML-DSA-65 signature yet)
- `ed25519_fallback` — accept Ed25519-only verification
- `soft_freshness`   — accept hybrid-pending within a freshness window;
                       reject once the row ages past it

These tests sign real canonical bytes with the engine's own Ed25519
LocalSigner and assert the verify outcomes + the exact rejection tokens
the binary emits. ML-DSA-65 hybrid-complete verification is covered by
the `ed25519_fallback`/`soft_freshness` matrix here; the strict path
exercises the hybrid-pending rejection that is the CCC's §8 default.

See CEG §0.2 (profiles) + §8 (composition) — now the CIRIS Constitution
(Part II — The Grammar + Part IV — Composition & Governance):
CIRISRegistry/FSD/CIRIS_Constitution/ (supersedes CEG; map § → CC via codebook.json).
"""

from __future__ import annotations

import pytest

from conftest import ceg_local_signer_preamble, get_database_url, run_python_script


def _ccc_verify_script(database_url: str) -> str:
    return ceg_local_signer_preamble(database_url) + r'''
MSG = b"ceg-ccc-canonical-bytes"
sig = base64.b64encode(engine.local_sign(MSG)).decode()

def call(fn, *args):
    """Normalize a verify call to {"outcome": ...} or {"error": <token>}."""
    try:
        return {"outcome": fn(*args)["outcome"]}
    except ValueError as exc:
        return {"error": str(exc)}

results = {}
# Ed25519-only signature (ml_dsa args = None) → row is "hybrid-pending".
results["strict_pending"] = call(
    engine.verify_hybrid, MSG, sig, None, pk, None, "strict", None, None)
results["fallback_ok"] = call(
    engine.verify_hybrid, MSG, sig, None, pk, None, "ed25519_fallback", None, None)
results["tampered"] = call(
    engine.verify_hybrid, b"tampered-bytes", sig, None, pk, None, "ed25519_fallback", None, None)
results["soft_fresh_within"] = call(
    engine.verify_hybrid, MSG, sig, None, pk, None, "soft_freshness", 3600, 10)
results["soft_fresh_expired"] = call(
    engine.verify_hybrid, MSG, sig, None, pk, None, "soft_freshness", 3600, 7200)

# Directory path: register the local key, then verify by key_id.
key_id = engine.register_self_federation_key("agent", "ceg-ccc-ref", None, None, None)
results["directory_ok"] = call(
    engine.verify_hybrid_via_directory, MSG, key_id, sig, None, "ed25519_fallback", None, None)
results["directory_unknown_key"] = call(
    engine.verify_hybrid_via_directory, MSG, "no-such-key", sig, None, "ed25519_fallback", None, None)

print(json.dumps({"stage": "done", "results": results}))
sys.exit(0)
'''


@pytest.fixture(scope="module")
def ccc_results():
    result = run_python_script(_ccc_verify_script(get_database_url()))
    try:
        payload = result.parsed_stdout()
    except Exception:
        pytest.fail(
            f"CCC verify script produced no parseable JSON (exit {result.returncode}):\n"
            f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}"
        )
    assert payload.get("stage") == "done", f"{payload}\nSTDERR: {result.stderr}"
    return payload["results"]


@pytest.mark.ceg
@pytest.mark.ccc
@pytest.mark.requires_persist
def test_strict_policy_rejects_hybrid_pending(ccc_results):
    """`strict` rejects an Ed25519-only (hybrid-pending) row — CCC §8 default."""
    assert ccc_results["strict_pending"].get("error") == "verify_hybrid_pending_rejected", (
        ccc_results["strict_pending"]
    )


@pytest.mark.ceg
@pytest.mark.ccc
@pytest.mark.requires_persist
def test_ed25519_fallback_accepts_classical(ccc_results):
    """`ed25519_fallback` accepts a valid Ed25519-only signature."""
    assert ccc_results["fallback_ok"].get("outcome") == "ed25519_fallback", (
        ccc_results["fallback_ok"]
    )


@pytest.mark.ceg
@pytest.mark.ccc
@pytest.mark.requires_persist
def test_tampered_bytes_fail_crypto(ccc_results):
    """A signature over different bytes fails the crypto check."""
    assert ccc_results["tampered"].get("error") == "verify_hybrid_crypto", (
        ccc_results["tampered"]
    )


@pytest.mark.ceg
@pytest.mark.ccc
@pytest.mark.requires_persist
def test_soft_freshness_window(ccc_results):
    """`soft_freshness` accepts a fresh hybrid-pending row, rejects a stale one."""
    assert ccc_results["soft_fresh_within"].get("outcome") == "ed25519_hybrid_pending", (
        ccc_results["soft_fresh_within"]
    )
    assert ccc_results["soft_fresh_expired"].get("error") == "verify_hybrid_soft_freshness_expired", (
        ccc_results["soft_fresh_expired"]
    )


@pytest.mark.ceg
@pytest.mark.ccc
@pytest.mark.requires_persist
def test_directory_verify_and_unknown_key(ccc_results):
    """Verify-by-directory resolves a registered key; rejects an unknown one."""
    assert ccc_results["directory_ok"].get("outcome") == "ed25519_fallback", (
        ccc_results["directory_ok"]
    )
    assert ccc_results["directory_unknown_key"].get("error") == "verify_unknown_key", (
        ccc_results["directory_unknown_key"]
    )
