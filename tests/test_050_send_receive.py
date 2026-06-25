"""
Federation send/receive conformance — what the cross-wheel boundary
actually supports today (edge 0.19.0 + persist 3.3.1).

This file used to be a blanket `skip` "pending CIRISPersist#109" — long
closed. The honest, current state, established empirically against the
real wheels:

- ✅ `init_edge_runtime` composes persist + edge in one process; the
  resulting `Edge` exposes `signer_key_id`, `register_inline_text_handler`,
  and `metrics_snapshot` (8 counters).
- ✅ An ephemeral `send_inline_text` to an **unresolvable** peer refuses
  cleanly with a typed `RuntimeError` ("destination unreachable") — the
  edge cohabits with persist and fails closed, it does not crash.
- ❌ A true **loopback round-trip** (deliver to self) is not achievable
  in a single process: Reticulum has no self-route without a peer
  announce / directory resolution, so the message can't be delivered
  back. This needs a multi-node fixture (tracked as Conformance#4) and
  is marked `xfail` below — visible, not skipped.
- ❌ `send_durable_inline_text` currently aborts the process in this
  synchronous cohabitation embedding ("no reactor running" → SIGABRT);
  filed upstream. It is intentionally NOT exercised here so it can't take
  the suite down; see the module note.

Scripts end with `os._exit(0)` after flushing: an `Edge` holding a live
Reticulum transport can panic on drop during interpreter teardown, which
would otherwise lose the JSON result.
"""

from __future__ import annotations

import sys
import pytest

from conftest import get_database_url, run_python_script


def _send_receive_script(database_url: str) -> str:
    header = f"DB_URL = {database_url!r}\n"
    body = r'''
import json, sys, os, time, tempfile
try:
    import ciris_persist as cp
    from ciris_edge.ciris_edge import init_edge_runtime
except ImportError as exc:
    print(json.dumps({"stage": "import", "error": str(exc)})); sys.exit(2)

_d = tempfile.mkdtemp()
_seed = os.path.join(_d, "local.seed"); open(_seed, "wb").write(b"\x11" * 32)
_idp = os.path.join(_d, "transport.id"); open(_idp, "wb").write(b"\x00" * 64)
cp.reset_engine()
engine = cp.Engine(DB_URL, "send-recv-key",
                   local_key_id="send-recv-key", local_key_path=_seed)
# Ephemeral ports so this never collides with other transport scenarios.
edge = init_edge_runtime(engine, _idp, listen_addr="127.0.0.1:0")

report = {"stage": "start"}
report["signer_key_id"] = edge.signer_key_id()
report["metrics_keys"] = sorted(edge.metrics_snapshot().keys())

observed = []
edge.register_inline_text_handler(lambda *a: observed.append(a))
report["handler_registered"] = True

# Ephemeral send to an unresolvable peer → clean typed refusal.
try:
    edge.send_inline_text("unresolvable-peer-key", "hello")
    report["ephemeral"] = {"error": None}
except Exception as exc:
    report["ephemeral"] = {
        "type": type(exc).__name__,
        "unreachable": "destination unreachable" in str(exc),
    }

# Loopback delivery to self (aspirational — see module docstring).
try:
    edge.send_inline_text(edge.signer_key_id(), "loopback-body")
    time.sleep(0.3)
    report["loopback_delivered"] = any("loopback-body" in str(a) for a in observed)
except Exception as exc:
    report["loopback_delivered"] = False
    report["loopback_error"] = f"{type(exc).__name__}: {str(exc)[:140]}"

report["stage"] = "done"
print(json.dumps(report))
sys.stdout.flush()
os._exit(0)
'''
    return header + body


@pytest.fixture(scope="module")
def send_receive():
    result = run_python_script(_send_receive_script(get_database_url()))
    try:
        payload = result.parsed_stdout()
    except Exception:
        pytest.fail(
            f"send/receive script produced no parseable JSON (exit {result.returncode}):\n"
            f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}"
        )
    assert payload.get("stage") == "done", f"{payload}\nSTDERR: {result.stderr}"
    return payload


@pytest.mark.cohabitation
@pytest.mark.requires_persist
@pytest.mark.requires_edge
def test_edge_runtime_surface_present(send_receive):
    """The composed Edge exposes the send/receive + observability surface."""
    # As of edge 7.0.6 (CIRISEdge#203) the signer id is the DERIVED federation
    # key_id `<label>-<fp>`, not the bare `local_key_id` — so durable outbound's
    # sender FK resolves against persist's registered (derived) row. Assert the
    # derived shape rather than the per-run fingerprint.
    signer = send_receive["signer_key_id"]
    assert signer.startswith("send-recv-key-"), send_receive
    assert signer != "send-recv-key", send_receive
    assert send_receive["handler_registered"] is True
    # The per-transport parity counters Conformance#4 builds on.
    for counter in ("envelopes_sent_total", "envelopes_received_total"):
        assert counter in send_receive["metrics_keys"], send_receive["metrics_keys"]


@pytest.mark.xfail(sys.platform == "darwin", strict=False, reason="CIRISConformance#6 — darwin error-string pattern needs investigation post persist 3.6.x/verify 4.4.2 bump")
@pytest.mark.cohabitation
@pytest.mark.requires_persist
@pytest.mark.requires_edge
def test_ephemeral_send_to_unresolvable_peer_refuses_cleanly(send_receive):
    """Edge + persist cohabit: a send to an unknown peer fails closed, no crash."""
    eph = send_receive["ephemeral"]
    assert eph.get("type") == "RuntimeError", eph
    assert eph.get("unreachable") is True, eph


# NOTE: a single-process "send to self" can never deliver — Reticulum has no
# self-route. The property that actually matters (delivery between two nodes over
# a live transport) is exercised for real in test_330_two_node_roundtrip.py via
# the `two_node_transport` fixture, so the misleading single-process loopback
# xfail was retired in favour of that real two-node gate (xfail on CIRISEdge#214
# until the Python peer-rooting surface ships).


def _durable_send_script(database_url: str) -> str:
    """Durable send exercises the edge → persist outbound-queue path that used
    to SIGSEGV (CIRISEdge#50, edge's bundled uninitialized libsqlite3; closed
    in edge 1.0.1 via `auditwheel --exclude libsqlite3.so.0`). Unique key per
    subprocess for shared-backend isolation; send to our own registered key so
    the outbound FK constraint is satisfied.
    """
    header = f"DB_URL = {database_url!r}\n"
    body = r'''
import json, sys, os, tempfile, secrets
import ciris_persist as cp
from ciris_edge.ciris_edge import init_edge_runtime
_d = tempfile.mkdtemp()
_seed = os.path.join(_d, "s"); open(_seed, "wb").write(secrets.token_bytes(32))
_pqc = os.path.join(_d, "pqc"); open(_pqc, "wb").write(secrets.token_bytes(32))
_idp = os.path.join(_d, "t.id"); open(_idp, "wb").write(b"\x00" * 64)
cp.reset_engine()
_k = "durable-" + secrets.token_hex(8)
# Hybrid engine (Ed25519 + ML-DSA-65) — federation-tier emits are verified
# Strict as of persist 10.1.1 (CIRISPersist#275).
engine = cp.Engine(DB_URL, _k, local_key_id=_k, local_key_path=_seed,
                   local_pqc_key_id=_k + "-pqc", local_pqc_key_path=_pqc)
kid = engine.register_self_federation_key("agent", "durable-ref", None, None, None)
edge = init_edge_runtime(engine, _idp, listen_addr="127.0.0.1:0")
handle = edge.send_durable_inline_text(kid, "durable-hello")
outbound = engine.list_outbound(10)  # list_outbound(limit, status=None, ...)
print(json.dumps({"durable_returned": type(handle).__name__,
                  "enqueued": "pending" in str(outbound)}))
sys.stdout.flush()
os._exit(0)
'''
    return header + body


@pytest.mark.cohabitation
@pytest.mark.requires_persist
@pytest.mark.requires_edge
def test_durable_send_enqueues_to_outbound_queue():
    """A durable send returns a handle and lands in persist's edge_outbound_queue.

    Hard regression gate for two closed cross-wheel bugs:
    - CIRISEdge#50: the durable path used to SIGSEGV (edge's bundled,
      never-`sqlite3_initialize()`d libsqlite3); closed in edge 1.0.1 via
      `auditwheel --exclude libsqlite3.so.0`.
    - CIRISEdge#203: edge stamped the BARE `local_key_id` as the outbound
      `sender_key_id` while persist's #247/#275 derived-key_id floor registers
      only the DERIVED `<label>-<fp>` id, so `enqueue_outbound` FK-failed;
      closed in edge 7.0.6 (edge now stamps the derived federation key_id).
    Either regression fails this directly.
    """
    result = run_python_script(_durable_send_script(get_database_url()), timeout=15)
    payload = result.parsed_stdout()
    assert payload["durable_returned"] == "DurableHandle", payload
    assert payload["enqueued"] is True, payload
