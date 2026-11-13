"""
CEG-Conforming Consumer (CCC) — hybrid-signature verification.

CC 2.2 defines the **CCC** profile: a consumer MUST verify hybrid
(Ed25519 + ML-DSA-65) signatures and apply the CC 4.4 composition policies.
This is the cornerstone of consumer conformance and the one CEG-CCC
surface fully reachable at the cross-wheel boundary today: persist's
`Engine.verify_hybrid` / `verify_hybrid_via_directory`.

**`strict` is the only verifier policy** (CC 5.3.2.4.3.1: a verifier's
hybrid-required check is always-on, never an operator toggle; persist
v61.1.0 CIRISPersist#1233, edge v45 CIRISEdge#957). The former
`ed25519_fallback` and `soft_freshness` policies are REFUSED with
`verify_policy_violation` before any decode, directory lookup or crypto
runs, and the `ed25519_fallback` / `ed25519_hybrid_pending` outcomes no
longer exist. The one success outcome is `hybrid_verified`.

These tests sign real canonical bytes with the engine's own hybrid
LocalSigner (`local_sign_hybrid`: Ed25519 over the message, ML-DSA-65 over
`message ‖ ed25519_sig`) and assert the verify outcomes + the exact
rejection tokens the binary emits:

- a full hybrid signature verifies under `strict`, directly and via the
  federation directory;
- a classical-only (hybrid-pending) signature is refused under `strict`;
- the retired policies are refused, even for a valid hybrid signature;
- tampered bytes under `strict` fail the hybrid crypto check;
- an unknown directory key is refused.

See CC 2.2 (profiles) + CC 4.4 (composition) + CC 5.3.2.4.3.1 —
CIRISRegistry/FSD/CIRIS_Constitution/.
"""

from __future__ import annotations

import pytest

from conftest import ceg_local_signer_preamble, get_database_url, run_python_script


def _ccc_verify_script(database_url: str) -> str:
    return ceg_local_signer_preamble(database_url, pqc=True) + r'''
MSG = b"ceg-ccc-canonical-bytes"
_h = engine.local_sign_hybrid(MSG)
sig = base64.b64encode(_h["classical_sig"]).decode()
pqc_sig = base64.b64encode(_h["pqc_sig"]).decode()
pqc_pk = engine.local_pqc_public_key_b64()

def call(fn, *args):
    """Normalize a verify call to {"outcome": ...} or {"error": <token>}."""
    try:
        return {"outcome": fn(*args)["outcome"]}
    except ValueError as exc:
        return {"error": str(exc)}

results = {}
# Full hybrid signature under the only policy → verified.
results["strict_hybrid_ok"] = call(
    engine.verify_hybrid, MSG, sig, pqc_sig, pk, pqc_pk, "strict", None, None)
# Ed25519-only signature (ml_dsa args = None) → row is "hybrid-pending".
results["strict_pending"] = call(
    engine.verify_hybrid, MSG, sig, None, pk, None, "strict", None, None)
# The retired policies are refused before any crypto, classical or hybrid.
results["fallback_classical_refused"] = call(
    engine.verify_hybrid, MSG, sig, None, pk, None, "ed25519_fallback", None, None)
results["fallback_hybrid_refused"] = call(
    engine.verify_hybrid, MSG, sig, pqc_sig, pk, pqc_pk, "ed25519_fallback", None, None)
results["soft_freshness_refused"] = call(
    engine.verify_hybrid, MSG, sig, None, pk, None, "soft_freshness", 3600, 10)
# A hybrid signature over different bytes fails the crypto check.
results["tampered"] = call(
    engine.verify_hybrid, b"tampered-bytes", sig, pqc_sig, pk, pqc_pk, "strict", None, None)

# Directory path: register the local (hybrid) key, then verify by key_id.
key_id = engine.register_self_federation_key("agent", "ceg-ccc-ref", None, None, None)
results["directory_ok"] = call(
    engine.verify_hybrid_via_directory, MSG, key_id, sig, pqc_sig, "strict", None, None)
results["directory_fallback_refused"] = call(
    engine.verify_hybrid_via_directory, MSG, key_id, sig, None, "ed25519_fallback", None, None)
results["directory_unknown_key"] = call(
    engine.verify_hybrid_via_directory, MSG, "no-such-key", sig, pqc_sig, "strict", None, None)

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
def test_strict_policy_accepts_hybrid(ccc_results):
    """`strict` accepts a full Ed25519 + ML-DSA-65 signature as `hybrid_verified`."""
    assert ccc_results["strict_hybrid_ok"].get("outcome") == "hybrid_verified", (
        ccc_results["strict_hybrid_ok"]
    )


@pytest.mark.ceg
@pytest.mark.ccc
@pytest.mark.requires_persist
def test_strict_policy_rejects_hybrid_pending(ccc_results):
    """`strict` rejects an Ed25519-only (hybrid-pending) row — CCC CC 4.4 default."""
    assert ccc_results["strict_pending"].get("error") == "verify_hybrid_pending_rejected", (
        ccc_results["strict_pending"]
    )


@pytest.mark.ceg
@pytest.mark.ccc
@pytest.mark.requires_persist
def test_ed25519_fallback_policy_refused(ccc_results):
    """`ed25519_fallback` is refused: a classical-only signature never verifies.

    Was `test_ed25519_fallback_accepts_classical`; CC 5.3.2.4.3.1 removed the
    policy (persist v61.1.0 CIRISPersist#1233, edge v45 CIRISEdge#957). The
    refusal precedes the crypto, so a valid hybrid signature is refused too.
    """
    for case in ("fallback_classical_refused", "fallback_hybrid_refused"):
        assert ccc_results[case].get("error") == "verify_policy_violation", (
            case, ccc_results[case]
        )


@pytest.mark.ceg
@pytest.mark.ccc
@pytest.mark.requires_persist
def test_tampered_bytes_fail_crypto(ccc_results):
    """A hybrid signature over different bytes fails the crypto check under `strict`."""
    assert ccc_results["tampered"].get("error") == "verify_hybrid_crypto", (
        ccc_results["tampered"]
    )


@pytest.mark.ceg
@pytest.mark.ccc
@pytest.mark.requires_persist
def test_soft_freshness_policy_refused(ccc_results):
    """`soft_freshness` is refused; no `ed25519_hybrid_pending` outcome exists.

    Was `test_soft_freshness_window` (accept a fresh pending row, reject a
    stale one). CC 5.3.2.4.3.1 removed the window along with the policy.
    """
    assert ccc_results["soft_freshness_refused"].get("error") == "verify_policy_violation", (
        ccc_results["soft_freshness_refused"]
    )


@pytest.mark.ceg
@pytest.mark.ccc
@pytest.mark.requires_persist
def test_directory_verify_and_unknown_key(ccc_results):
    """Verify-by-directory resolves a registered key under `strict`; rejects an
    unknown key and the retired fallback policy."""
    assert ccc_results["directory_ok"].get("outcome") == "hybrid_verified", (
        ccc_results["directory_ok"]
    )
    assert ccc_results["directory_unknown_key"].get("error") == "verify_unknown_key", (
        ccc_results["directory_unknown_key"]
    )
    assert ccc_results["directory_fallback_refused"].get("error") == "verify_policy_violation", (
        ccc_results["directory_fallback_refused"]
    )
