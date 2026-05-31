"""
HTTPS transport conformance (CIRISConformance#3 / #4).

CIRISEdge#49 landed the PyEdge HTTPS transport-init surface — edge 1.1.3's
`init_edge_runtime` exposes `https_listen_addr`, `https_tls_*`,
`https_mtls_required`, `https_bearer_secret`, `https_dev_self_signed`, and
`disable_reticulum`. But the **published PyPI wheel is built without the
`transport-http` feature**, so those params raise
`"…require the transport-http feature; this wheel was built without it"`.

So the blocker for the transport axis (#3) and the cross-transport
scenarios (#4) has moved from "no API" (closed) to "the published artifact
doesn't enable it" — tracked as CIRISEdge#56.

This file is the self-tracking gate: it asserts the published wheel can
stand up an HTTPS edge. It `xfail`s today and flips to a real green gate
the moment a `transport-http`-enabled wheel is published — at which point
the per-MessageType HTTPS round-trips + mTLS/bearer scenarios get built on
top of it.
"""

from __future__ import annotations

import pytest

from conftest import get_database_url, run_python_script


def _https_init_script(database_url: str) -> str:
    db_url_repr = repr(database_url)
    return (
        "import json, sys, os, tempfile, secrets\n"
        "try:\n"
        "    import ciris_persist as cp\n"
        "    from ciris_edge.ciris_edge import init_edge_runtime\n"
        "except ImportError as exc:\n"
        "    print(json.dumps({'stage': 'import', 'error': str(exc)})); sys.exit(2)\n"
        "d = tempfile.mkdtemp()\n"
        "seed = os.path.join(d, 's'); open(seed, 'wb').write(secrets.token_bytes(32))\n"
        "idp = os.path.join(d, 't.id'); open(idp, 'wb').write(b'\\x00' * 64)\n"
        "cp.reset_engine()\n"
        "k = 'https-' + secrets.token_hex(6)\n"
        f"engine = cp.Engine({db_url_repr}, k, local_key_id=k, local_key_path=seed)\n"
        "try:\n"
        # HTTPS-only edge with a dev self-signed cert — needs the
        # transport-http feature compiled into the wheel.
        "    init_edge_runtime(engine, idp, https_listen_addr='127.0.0.1:0',\n"
        "                      https_dev_self_signed=True, disable_reticulum=True)\n"
        "    print(json.dumps({'stage': 'done', 'https_ok': True}))\n"
        "except Exception as exc:\n"
        "    msg = str(exc)\n"
        "    print(json.dumps({'stage': 'done', 'https_ok': False, 'error': msg,\n"
        "                      'feature_missing': 'transport-http feature' in msg}))\n"
        "sys.stdout.flush(); os._exit(0)\n"
    )


@pytest.mark.cohabitation
@pytest.mark.requires_persist
@pytest.mark.requires_edge
@pytest.mark.xfail(
    reason="published edge wheel built without the transport-http feature — HTTPS "
    "init API present (edge#49) but raises 'built without it' → CIRISEdge#56. Blocks "
    "Conformance#3 (transport axis) + #4 (cross-transport).",
    strict=False,
)
def test_https_edge_stands_up():
    """The published edge wheel can init an HTTPS transport (mTLS/bearer build base)."""
    result = run_python_script(_https_init_script(get_database_url()))
    payload = result.parsed_stdout()
    assert payload.get("stage") == "done", payload
    assert payload.get("https_ok") is True, (
        f"HTTPS edge init failed — likely the transport-http feature is not in the "
        f"published wheel (CIRISEdge#56): {payload.get('error')}"
    )
