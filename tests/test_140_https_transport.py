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

from conftest import (
    get_database_url,
    run_python_script,
    xfail_if_pg_edge_runtime_crash,
)


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


def _https_config_script(database_url: str) -> str:
    db_url_repr = repr(database_url)
    return (
        "import json, sys, os, tempfile, secrets\n"
        "import ciris_persist as cp\n"
        "from ciris_edge.ciris_edge import init_edge_runtime\n"
        "d = tempfile.mkdtemp()\n"
        "seed = os.path.join(d, 's'); open(seed, 'wb').write(secrets.token_bytes(32))\n"
        "idp = os.path.join(d, 't.id'); open(idp, 'wb').write(b'\\x00' * 64)\n"
        "cp.reset_engine()\n"
        "k = 'https-' + secrets.token_hex(6)\n"
        f"engine = cp.Engine({db_url_repr}, k, local_key_id=k, local_key_path=seed)\n"
        "engine.register_self_federation_key('agent', 'https-ref', None, None, None)\n"
        "report = {}\n"
        "try:\n"
        # Full production HTTPS shape: mTLS required + bearer-token (CDN edge).
        "    edge = init_edge_runtime(engine, idp, https_listen_addr='127.0.0.1:0',\n"
        "                             https_dev_self_signed=True, https_mtls_required=True,\n"
        "                             https_bearer_secret=b'conformance-bearer', disable_reticulum=True)\n"
        "    report['mtls_bearer_init'] = True\n"
        "    report['metrics_keys'] = sorted(edge.metrics_snapshot().keys())\n"
        "    try:\n"
        # edge 8 (CIRISConformance#53): send_inline_text was ripped (calling it
        # raises AttributeError, not the transport refusal). The synchronous
        # opaque request is the class that resolves a destination and refuses
        # cleanly on the HTTPS path with 'no HTTPS URL configured'.
        "        edge.send_opaque_request('unresolvable-peer', 7, b'x', timeout_ms=2000)\n"
        "        report['unresolved'] = {'error': None}\n"
        "    except Exception as exc:\n"
        "        report['unresolved'] = {'type': type(exc).__name__,\n"
        "                                'no_https_url': 'no HTTPS URL configured' in str(exc)}\n"
        "except Exception as exc:\n"
        "    report['mtls_bearer_init'] = False; report['error'] = str(exc)[:160]\n"
        "report['stage'] = 'done'\n"
        "print(json.dumps(report)); sys.stdout.flush(); os._exit(0)\n"
    )


@pytest.fixture(scope="module")
def https_config():
    result = run_python_script(_https_config_script(get_database_url()))
    xfail_if_pg_edge_runtime_crash(result)  # CIRISPersist#354 (postgres native abort)
    try:
        payload = result.parsed_stdout()
    except Exception:
        pytest.fail(
            f"HTTPS config script produced no parseable JSON (exit {result.returncode}):\n"
            f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}"
        )
    assert payload.get("stage") == "done", payload
    return payload


@pytest.mark.cohabitation
@pytest.mark.requires_persist
@pytest.mark.requires_edge
def test_https_edge_stands_up():
    """The published edge wheel stands up an HTTPS transport (mTLS/bearer build base).

    Real gate as of edge 1.1.4 (CIRISEdge#56 closed — the published wheel is
    built with `transport-http`). The base for the #3 transport axis + the
    #4 cross-transport HTTPS round-trips.
    """
    result = run_python_script(_https_init_script(get_database_url()))
    xfail_if_pg_edge_runtime_crash(result)  # CIRISPersist#354 (postgres native abort)
    payload = result.parsed_stdout()
    assert payload.get("stage") == "done", payload
    assert payload.get("https_ok") is True, (
        f"HTTPS edge init failed — transport-http should be in the published "
        f"wheel as of edge 1.1.4 (CIRISEdge#56): {payload.get('error')}"
    )


@pytest.mark.cohabitation
@pytest.mark.requires_persist
@pytest.mark.requires_edge
def test_https_accepts_mtls_and_bearer_config(https_config):
    """§3: the HTTPS transport accepts the production shape — mTLS required + bearer token."""
    assert https_config["mtls_bearer_init"] is True, https_config
    # Observability counters are present for per-transport parity (#4).
    assert "envelopes_sent_total" in https_config["metrics_keys"], https_config


@pytest.mark.cohabitation
@pytest.mark.requires_persist
@pytest.mark.requires_edge
def test_https_send_to_unresolvable_peer_refuses_cleanly(https_config):
    """§3: an HTTPS send to a peer with no known HTTPS URL refuses cleanly (no crash)."""
    u = https_config["unresolved"]
    assert u.get("type") == "RuntimeError", u
    assert u.get("no_https_url") is True, u
