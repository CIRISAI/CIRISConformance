"""
Federation send/receive conformance — what the cross-wheel boundary
actually supports today (edge 8.6.1 + persist 12.2.0).

This file used to be a blanket `skip` "pending CIRISPersist#109" — long
closed. The honest, current state, established empirically against the
real wheels:

- ✅ `init_edge_runtime` composes persist + edge in one process; the
  resulting `Edge` exposes `signer_key_id`, `register_opaque_handler`,
  and `metrics_snapshot` (8 counters). As of edge 8 (CIRISConformance#53)
  the inline-text surface was ripped and replaced by the opaque-envelope
  API (`register_opaque_handler` / `send_opaque_event` /
  `send_opaque_request`); `send_inline_text*` no longer exist.
- ✅ A synchronous `send_opaque_request` to an **unresolvable** peer
  refuses cleanly with a typed `RuntimeError` ("destination unreachable")
  — the edge cohabits with persist and fails closed, it does not crash.
  (`send_opaque_event` is the durable, fire-and-forget class; the
  request class is the one that awaits resolution and can refuse.)
- ❌ A true **loopback round-trip** (deliver to self) is not achievable
  in a single process: Reticulum has no self-route without a peer
  announce / directory resolution, so the message can't be delivered
  back. This needs a multi-node fixture (tracked as Conformance#4).
- ✅ `send_opaque_event` returns a `DurableHandle` and lands the payload
  in persist's edge_outbound_queue (`pending`) — the durable path is
  exercised below.

Scripts end with `os._exit(0)` after flushing: an `Edge` holding a live
Reticulum transport can panic on drop during interpreter teardown, which
would otherwise lose the JSON result.
"""

from __future__ import annotations

import sys
import pytest

from conftest import (
    get_database_url,
    run_python_script,
    xfail_if_pg_edge_runtime_crash,
)


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

# edge 8 opaque surface: register_opaque_handler(kind:int, cb) where
# cb(sender_key_id, payload)->(status:int, payload:bytes); subscribe_opaque
# fans OpaqueEvents out to per-kind callbacks.
_KIND = 7
observed = []
edge.register_opaque_handler(_KIND, lambda sender, payload: (200, b""))
edge.subscribe_opaque(_KIND, lambda sender, kind, payload: observed.append((sender, payload)))
report["handler_registered"] = True

# Synchronous request to an unresolvable peer → clean typed refusal.
try:
    edge.send_opaque_request("unresolvable-peer-key", _KIND, b"hello", timeout_ms=2000)
    report["ephemeral"] = {"error": None}
except Exception as exc:
    report["ephemeral"] = {
        "type": type(exc).__name__,
        "unreachable": "destination unreachable" in str(exc),
    }

# Loopback delivery to self (aspirational — see module docstring). Durable
# fire-and-forget; Reticulum has no single-process self-route so it never
# fans back to the local subscriber.
try:
    edge.send_opaque_event(edge.signer_key_id(), _KIND, b"loopback-body")
    time.sleep(0.3)
    report["loopback_delivered"] = any(b"loopback-body" in bytes(p) for _s, p in observed)
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
    xfail_if_pg_edge_runtime_crash(result)  # CIRISPersist#354 (postgres native abort)
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
# a live transport) is exercised for real in test_340_transport_delivery_modes.py,
# which drives A→B inline-text delivery across every holder mode (self / family /
# community / direct) over a 4-node / 3-owner fabric.


def _durable_send_script(database_url: str) -> str:
    """Durable send exercises the edge → persist outbound-queue path that used
    to SIGSEGV (CIRISEdge#50, edge's bundled uninitialized libsqlite3; closed
    in edge 1.0.1 via `auditwheel --exclude libsqlite3.so.0`). Unique key per
    subprocess for shared-backend isolation; send to our own registered key so
    the outbound FK constraint is satisfied. As of edge 8 the durable class is
    `send_opaque_event(recipient_key_id, kind, payload)` → `DurableHandle`.
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
handle = edge.send_opaque_event(kid, 7, b"durable-hello")
outbound = engine.list_outbound(10)  # list_outbound(limit, status=None, ...)
print(json.dumps({"durable_returned": type(handle).__name__,
                  "enqueued": "pending" in str(outbound),
                  "queue_id_present": bool(handle.queue_id)}))
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
    xfail_if_pg_edge_runtime_crash(result)  # CIRISPersist#354 (postgres native abort)
    payload = result.parsed_stdout()
    assert payload["durable_returned"] == "DurableHandle", payload
    assert payload["enqueued"] is True, payload
