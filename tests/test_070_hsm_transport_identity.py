"""
Federation cohab-init transport-identity conformance (Conformance#2).

The cross-wheel regression this file gates against:

CIRISEdge v0.13.0 derived the ReticulumTransport's federation identity
from the *keyring* signer — the hardware-rooted, hybrid scrub-envelope
signer. Under `keyring_storage_kind = hardware_hsm_only` that signer's
public key is a 65-byte non-Ed25519 HSM key, and Reticulum strictly
requires a 32-byte Ed25519 identity, so cohab init blew up at:

    RuntimeError: ReticulumTransport::new: transport configuration
      error: federation Ed25519 pubkey must be 32 bytes, got 65

CIRISPersist#119 (v3.1.1) split the capsule surface in two:

  - `keyring_signer_capsule()` → hot-path scrub-envelope signing
    (hardware-rooted hybrid; may be 65-byte under hardware_hsm_only)
  - `local_signer_capsule()`   → a dedicated 32-byte Ed25519 LocalSigner
    for the ReticulumTransport identity

CIRISEdge v0.13.1 (CIRISEdge#43) consumes `local_signer_capsule()` and
threads that 32-byte LocalSigner into `ReticulumAuth.signer`, decoupling
transport identity from the keyring signer.

This is the cross-artifact mirror of the edge-side pin
`pyo3_tier2_tests::py_init_edge_runtime_local_signer_capsule_supplies_reticulum_identity`
(CIRISEdge v0.13.1, src/ffi/pyo3.rs) — exercised at the separate-wheel
boundary, which is the only place the cross-cdylib capsule extraction
can actually break.

See:
- https://github.com/CIRISAI/CIRISConformance/issues/2 — this gate
- https://github.com/CIRISAI/CIRISEdge/issues/43 — the v0.13.0 failure
- https://github.com/CIRISAI/CIRISPersist/issues/119 — local_signer_capsule
"""

from __future__ import annotations

import pytest

from conftest import get_database_url, run_python_script


# The exact v0.13.0 failure shape: transport identity fell back to the
# 65-byte keyring signer instead of the 32-byte LocalSigner.
SIXTYFIVE_BYTE_FALLBACK = "must be 32 bytes, got 65"


def _transport_identity_script(database_url: str, *, with_local_signer: bool) -> str:
    """Cohab-init scenario as a self-contained subprocess script.

    `with_local_signer=True` builds the engine with a 32-byte Ed25519
    seed (the v0.13.1 cohort — `local_signer_capsule()` available);
    `False` builds a bare engine that has no LocalSigner, so edge must
    fall back to the keyring signer for transport identity (the v0.13.0
    path). Runs in a fresh subprocess per the harness's process-isolation
    invariant. Always prints one JSON report to stdout and exits 0.
    """
    header = (
        f"DB_URL = {database_url!r}\n"
        f"WITH_LOCAL_SIGNER = {with_local_signer!r}\n"
    )
    body = r'''
import json, sys, base64, os, tempfile

try:
    import ciris_persist as cp
    from ciris_edge.ciris_edge import init_edge_runtime
except ImportError as exc:
    print(json.dumps({"stage": "import", "error": str(exc)}))
    sys.exit(2)

SIXTYFIVE_BYTE_FALLBACK = "must be 32 bytes, got 65"

workdir = tempfile.mkdtemp()
# A Reticulum identity file is required but its contents don't gate the
# transport-identity check we're exercising (that fires earlier, off the
# signer pubkey shape).
identity_path = os.path.join(workdir, "transport.id")
with open(identity_path, "wb") as fh:
    fh.write(b"\x00" * 64)

cp.reset_engine()
if WITH_LOCAL_SIGNER:
    # 32 raw bytes = an Ed25519 seed. persist then exposes a LocalSigner
    # whose public key is exactly 32 bytes — the transport identity edge
    # v0.13.1 pulls via local_signer_capsule() (CIRISPersist#119).
    seed_path = os.path.join(workdir, "local.seed")
    with open(seed_path, "wb") as fh:
        fh.write(b"\x11" * 32)
    # edge v17 (CIRISEdge#458, #393 item 2) refuses to bring up the Reticulum
    # transport on an Ed25519-only signer: without the ML-DSA-65 half it cannot
    # mint the hybrid-signed SignedTransportDestination, so peers would drop
    # its frames UNATTRIBUTED at the E3 gate. The 32-byte transport identity
    # this test is about is still the Ed25519 pubkey — the PQC half is
    # provisioning, not the subject, so it is added without changing what is
    # asserted below.
    pqc_path = os.path.join(workdir, "local.pqc.seed")
    with open(pqc_path, "wb") as fh:
        fh.write(b"\x22" * 32)
    engine = cp.Engine(
        DB_URL,
        "conformance-key",
        local_key_id="conformance-key",
        local_key_path=seed_path,
        local_pqc_key_id="conformance-key-pqc",
        local_pqc_key_path=pqc_path,
    )
else:
    # No LocalSigner configured -> local_signer_capsule() raises
    # local_signer_unavailable -> edge falls back to the keyring signer.
    engine = cp.Engine(DB_URL, "conformance-key")

report = {
    "stage": "engine_built",
    "with_local_signer": WITH_LOCAL_SIGNER,
    "keyring_storage_kind": engine.keyring_storage_kind(),
}

try:
    engine.local_signer_capsule()
    report["local_signer_capsule_ok"] = True
except Exception as exc:
    report["local_signer_capsule_ok"] = False
    report["local_signer_unavailable"] = "local_signer_unavailable" in str(exc)

if WITH_LOCAL_SIGNER:
    report["transport_pubkey_len"] = len(
        base64.b64decode(engine.local_public_key_b64())
    )

try:
    # Ephemeral port so the test never collides with a running agent / a
    # sibling test on the default Reticulum port (4242).
    init_edge_runtime(engine, identity_path, listen_addr="127.0.0.1:0")
    report["init"] = {"ok": True}
except Exception as exc:
    msg = str(exc)
    report["init"] = {
        "ok": False,
        "type": type(exc).__name__,
        "error": msg,
        "is_65byte_fallback": SIXTYFIVE_BYTE_FALLBACK in msg,
    }

report["stage"] = "done"
print(json.dumps(report))
sys.exit(0)
'''
    return header + body


def _run(*, with_local_signer: bool) -> dict:
    """Run one arm in a fresh subprocess; return the parsed JSON report."""
    result = run_python_script(
        _transport_identity_script(get_database_url(), with_local_signer=with_local_signer)
    )
    try:
        payload = result.parsed_stdout()
    except Exception:
        pytest.fail(
            f"transport-identity arm (with_local_signer={with_local_signer}) "
            f"produced no parseable JSON (exit {result.returncode}):\n"
            f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}"
        )
    assert payload.get("stage") == "done", (
        f"arm did not run to completion: {payload}\nSTDERR: {result.stderr}"
    )
    return payload


@pytest.mark.cohabitation
@pytest.mark.requires_persist
@pytest.mark.requires_edge
def test_local_signer_supplies_32byte_transport_identity():
    """init_edge_runtime takes the 32-byte LocalSigner as transport identity.

    The hard regression gate for Conformance#2: with a LocalSigner
    configured, persist v3.1.1 exposes `local_signer_capsule()`, its
    public key is exactly 32 bytes, and edge v0.13.1 wires that into the
    transport — so cohab init succeeds without the 65-byte keyring-signer
    fallback, regardless of the host's `keyring_storage_kind`.
    """
    payload = _run(with_local_signer=True)

    # CIRISPersist#119: the cross-cdylib transport-identity accessor exists.
    assert payload["local_signer_capsule_ok"], (
        f"local_signer_capsule() unavailable — persist#119 not consumed: {payload}"
    )

    # The transport identity is a 32-byte Ed25519 key — NOT the keyring
    # signer (which can be 65-byte under hardware_hsm_only).
    assert payload["transport_pubkey_len"] == 32, (
        f"transport-identity pubkey is not 32 bytes: {payload}"
    )

    # Edge v0.13.1 consumes that 32-byte identity and cohab init succeeds.
    init = payload["init"]
    assert init["ok"], (
        f"init_edge_runtime failed with a 32-byte LocalSigner configured — "
        f"the v0.13.1 dual-capsule wiring regressed: {init}"
    )


@pytest.mark.cohabitation
@pytest.mark.requires_persist
@pytest.mark.requires_edge
def test_hsm_only_transport_identity_decoupled_from_keyring_signer():
    """On a hardware_hsm_only host, the LocalSigner is load-bearing.

    Demonstrates the fix is real on hosts that actually exhibit the
    failure: where a *bare* engine's cohab init dies on the 65-byte
    keyring-signer fallback, the *same host* with a LocalSigner
    configured inits cleanly. This proves transport identity is
    decoupled from the keyring signer (CIRISEdge#43).

    Skips on hosts whose keyring signer is already Ed25519-compatible
    (32-byte) — there the 65-byte fallback never fires, so there's no
    contrast to draw and nothing regressed.
    """
    bare = _run(with_local_signer=False)

    if bare["keyring_storage_kind"] != "hardware_hsm_only":
        pytest.skip(
            f"host keyring is {bare['keyring_storage_kind']!r}, not "
            f"hardware_hsm_only — the 65-byte transport-identity fallback "
            f"only manifests when the keyring signer is a non-Ed25519 HSM key"
        )

    assert bare.get("local_signer_unavailable"), (
        f"bare engine unexpectedly exposed a LocalSigner: {bare}"
    )

    bare_init = bare["init"]
    if bare_init["ok"] or not bare_init.get("is_65byte_fallback"):
        # The keyring signer on this hardware_hsm_only host is not the
        # 65-byte shape that triggers the fallback — no failure to
        # contrast against. (e.g. an HSM that vends Ed25519.)
        pytest.skip(
            f"hardware_hsm_only host did not exhibit the 65-byte fallback on "
            f"the bare path; nothing to contrast: {bare_init}"
        )

    # The bare path genuinely fails here — now confirm the LocalSigner
    # closes it on the same host.
    local = _run(with_local_signer=True)
    assert local["init"]["ok"], (
        f"bare engine hit the 65-byte fallback but the LocalSigner arm did "
        f"NOT recover it — the v0.13.1 fix is not closing the hardware_hsm_only "
        f"path on this host:\n  bare={bare_init}\n  local={local['init']}"
    )
