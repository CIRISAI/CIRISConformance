"""
Mobile production-target conformance (substrate tier).

The CIRIS agent ships the three substrate sisters — persist + verify +
edge — bundled into one Android process (Chaquopy). That is *exactly*
the cohabitation surface this harness exists for, now load-bearing under
real users. These gates pin the three properties the mobile bring-up
depends on:

1. **Stable-ABI bundling** — Android/Chaquopy bundles the compiled wheels
   directly and runs them under its own Python 3.10 interpreter, bypassing
   pip's `Requires-Python`. That is only safe because the extensions are
   CPython **abi3** (persist + edge: `*.abi3.so`) / a version-independent
   uniffi FFI cdylib (verify). edge's wheel declares `Requires-Python
   >=3.11`, yet its abi3 `.so` is binary-compatible with 3.10 — this test
   pins that exact gap so a non-abi3 (version-tagged) build, which would
   silently break the Android bundle, fails here.

2. **Hardware-keystore storage kind** — on a phone the signer is the
   Android Keystore: a hardware-backed signer that reports
   `keyring_storage_kind ∈ {hardware_hsm_only, hardware_wrapped_blob}`.
   The engine must report a recognized token so edge's transport-identity
   branch and the app's `/health` surface handle it.

3. **Mobile bring-up cohab init** — importing in the app's load order and
   running `init_edge_runtime` must complete the handshake and yield a
   32-byte Ed25519 transport identity under *whatever* keystore the device
   has (the hardware_hsm_only path is the one that used to fail; see
   test_070).

On-device aarch64 / Android Keystore execution is a separate gate (CI
aarch64 cells + a device run); these run on any host and pin the
invariants that gate must also satisfy.
"""

from __future__ import annotations

import glob
import importlib.metadata
import importlib.util
import os

import sys
import pytest

from conftest import get_database_url, run_python_script


# The documented keyring_storage_kind tokens (ciris_persist
# Engine.keyring_storage_kind). Android Keystore reports one of the
# HARDWARE tokens; a phone with no hardware signer falls to software_*.
_ALL_STORAGE_KINDS = frozenset({
    "hardware_hsm_only",
    "hardware_wrapped_blob",
    "software_file",
    "software_os_keyring_user",
    "software_os_keyring_system",
    "software_os_keyring_unknown",
    "in_memory",
})
_HARDWARE_STORAGE_KINDS = frozenset({"hardware_hsm_only", "hardware_wrapped_blob"})


def _package_dir(module_name: str) -> str:
    """Locate an installed package's directory WITHOUT importing it.

    `find_spec` resolves the loader without executing the module body, so
    this stays clean of the conftest "no ciris imports at module level"
    rule.
    """
    spec = importlib.util.find_spec(module_name)
    assert spec is not None, f"{module_name} is not installed"
    if spec.submodule_search_locations:
        return list(spec.submodule_search_locations)[0]
    return os.path.dirname(spec.origin)


@pytest.mark.xfail(sys.platform == "darwin", strict=False, reason="CIRISConformance#6 — verify v4.4.2 macOS wheel FFI shape change; investigate")
@pytest.mark.requires_persist
@pytest.mark.requires_edge
def test_substrate_wheels_ship_stable_abi_extensions():
    """persist + edge ship abi3 `.so`s; verify ships a uniffi FFI cdylib.

    This is what lets Android/Chaquopy bundle the wheels and run them on
    its py3.10 interpreter regardless of the build interpreter.
    """
    for module in ("ciris_persist", "ciris_edge"):
        abi3 = glob.glob(os.path.join(_package_dir(module), "*.abi3.so"))
        assert abi3, (
            f"{module} ships no *.abi3.so — a version-tagged extension would "
            f"break the Android/Chaquopy bundle on py3.10"
        )
    # verify rides a uniffi FFI cdylib (version-independent by a different
    # mechanism than abi3).
    verify_so = glob.glob(os.path.join(_package_dir("ciris_verify"), "*.so"))
    assert verify_so, "ciris_verify ships no compiled FFI library"


@pytest.mark.requires_edge
def test_edge_abi3_outlives_its_requires_python_floor():
    """edge declares Requires-Python >=3.10 AND ships an abi3 .so.

    Edge's abi3-py310 build guarantees one wheel covers 3.10+ regardless
    of which interpreter installs it. The pyproject floor used to be
    >=3.11 (edge v1.0.x–v1.1.11) — a 3.10/abi3 misalignment that
    Chaquopy bypassed with --ignore-requires-python. v1.1.12 aligned the
    floor to >=3.10 to match the wheel's actual binary compatibility +
    the rest of the substrate (persist / verify / lens-core all >=3.10).

    Guards two things: (a) the floor stays at >=3.10 (a silent regression
    back to >=3.11 re-opens the misalignment), and (b) the wheel keeps
    shipping a *.abi3.so (a non-abi3 cp3xx-tagged .so breaks Chaquopy's
    Android bundle even with the aligned floor, since Chaquopy ships
    its own py3.10 interpreter and reuses one .so across all 3.10+ ABIs).
    """
    requires_python = importlib.metadata.metadata("ciris-edge").get("Requires-Python")
    assert requires_python is not None and "3.10" in requires_python, (
        f"edge Requires-Python regressed off >=3.10: {requires_python}"
    )
    abi3 = glob.glob(os.path.join(_package_dir("ciris_edge"), "*.abi3.so"))
    assert abi3, "edge ships no abi3 .so → Chaquopy py3.10 bundle would break"


def _mobile_bringup_script(database_url: str) -> str:
    db_url_repr = repr(database_url)
    return (
        "import json, sys, base64, os, tempfile\n"
        "report = {'stage': 'start'}\n"
        "try:\n"
        # Mobile load order: storage, then crypto, then transport.
        "    import ciris_persist\n"
        "    import ciris_verify\n"
        "    import ciris_edge\n"
        "    from ciris_edge.ciris_edge import init_edge_runtime\n"
        "except ImportError as exc:\n"
        "    print(json.dumps({'stage': 'import', 'error': str(exc)})); sys.exit(2)\n"
        "report['imported'] = True\n"
        "d = tempfile.mkdtemp()\n"
        "seed = os.path.join(d, 'k'); open(seed, 'wb').write(b'\\x11' * 32)\n"
        "idp = os.path.join(d, 't.id'); open(idp, 'wb').write(b'\\x00' * 64)\n"
        "ciris_persist.reset_engine()\n"
        f"engine = ciris_persist.Engine({db_url_repr}, 'mobile-key', local_key_id='mobile-key', local_key_path=seed)\n"
        "report['keyring_storage_kind'] = engine.keyring_storage_kind()\n"
        "report['transport_pubkey_len'] = len(base64.b64decode(engine.local_public_key_b64()))\n"
        "try:\n"
        "    init_edge_runtime(engine, idp, listen_addr='127.0.0.1:0')\n"
        "    report['init'] = {'ok': True}\n"
        "except Exception as exc:\n"
        "    msg = str(exc)\n"
        "    report['init'] = {'ok': False, 'error': msg, 'is_65byte': 'must be 32 bytes, got 65' in msg}\n"
        "report['stage'] = 'done'\n"
        "print(json.dumps(report)); sys.stdout.flush(); os._exit(0)\n"
    )


@pytest.fixture(scope="module")
def mobile_bringup():
    result = run_python_script(_mobile_bringup_script(get_database_url()))
    try:
        payload = result.parsed_stdout()
    except Exception:
        pytest.fail(
            f"mobile bring-up script produced no parseable JSON (exit {result.returncode}):\n"
            f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}"
        )
    assert payload.get("stage") == "done", f"{payload}\nSTDERR: {result.stderr}"
    return payload


@pytest.mark.cohabitation
@pytest.mark.requires_persist
def test_keyring_storage_kind_is_a_recognized_token(mobile_bringup):
    """The device's signer reports a documented storage kind (Android Keystore → hardware_*)."""
    assert mobile_bringup["keyring_storage_kind"] in _ALL_STORAGE_KINDS, (
        mobile_bringup["keyring_storage_kind"]
    )


@pytest.mark.cohabitation
@pytest.mark.requires_persist
@pytest.mark.requires_edge
def test_mobile_bringup_yields_32byte_transport_identity(mobile_bringup):
    """The app's load order completes cohab init with a 32-byte transport identity.

    This is the gate for edge landing in the mobile app: under whatever
    keystore the device has — including the hardware_hsm_only case that
    used to fail (test_070) — the transport identity is the 32-byte
    Ed25519 LocalSigner, not the (≤65-byte) keyring signer.
    """
    assert mobile_bringup["imported"] is True, mobile_bringup
    assert mobile_bringup["transport_pubkey_len"] == 32, mobile_bringup
    init = mobile_bringup["init"]
    assert init["ok"], (
        f"mobile cohab init failed under keyring_storage_kind="
        f"{mobile_bringup['keyring_storage_kind']!r}: {init}"
    )
