"""
Fabric tier — tamper-evident audit accountability (compliance D02 / D23).

The CIRIS compliance frame names two controls that rest on one mechanism:
**D02 integrity** ("system holds together — auditable, reproducible") and
**D23 accountability** ("named accountability; tamper-evident logs + rationale
chains"). The substrate mechanism is persist's **hash-chained, hybrid-signed
audit log**: every action is recorded as an `AuditEntry` (canonical-bytes →
Ed25519 + ML-DSA-65 sign → append), and `audit_verify_chain` walks the chain and
returns a typed break diagnostic on the first integrity violation.

The cross-wheel write path is `ciris_server.LensAudit` (`log_action` /
`log_consent_event` / `log_wbd`): the server assembles each entry and drives the
three-step canonical+sign+record flow through the host persist Engine. So the
end-to-end accountability control is: **server writes audit entries → persist's
chain verifies → a tampered chain is detected.**

Real gate as of **server 0.5.49** (CIRISServer#93 closed). Earlier server wheels
(through 0.5.48) had every `LensAudit.log_*` fail because the client emitted
`sequence_number = 0` while persist's `audit_record_entry` requires `>= 1`; 0.5.49
seeds the sequence correctly, so the three entries land in persist's hash-chained
hybrid-signed audit log and `audit_verify_chain` walks them with outcome `ok`.
"""

from __future__ import annotations

import pytest

from conftest import get_database_url, run_python_script

pytestmark = pytest.mark.fabric

_AUDIT_BODY = r"""
import json, sys, os, tempfile, secrets
try:
    import ciris_persist as cp
    import ciris_server as cs
except ImportError as exc:
    print(json.dumps({"_error": "import", "detail": str(exc)})); sys.exit(2)

_d = tempfile.mkdtemp()
_seed = os.path.join(_d, "s"); open(_seed, "wb").write(secrets.token_bytes(32))
_pqc = os.path.join(_d, "p"); open(_pqc, "wb").write(secrets.token_bytes(32))
cp.reset_engine()
k = "aud-" + secrets.token_hex(8)
engine = cp.Engine(DB_URL, k, local_key_id=k, local_key_path=_seed,
                   local_pqc_key_id=k + "-pqc", local_pqc_key_path=_pqc)

if not hasattr(cs, "LensAudit"):
    print(json.dumps({"_error": "absent"})); sys.exit(2)

report = {}
audit = cs.LensAudit(k, engine=engine)

# Core D02/D23 gate: handler-action entries are accepted on BOTH backends.
# (log_action → action_type "handler_action_speak", in the audit_log CHECK
# vocabulary on sqlite AND postgres.) Three entries → a non-trivial chain.
try:
    for i in range(3):
        audit.log_action("speak", f"thought-{i}", "speak_handler", True, 42, "rationale")
    report["entries_written"] = True
except Exception as exc:
    report["entries_written"] = False
    report["write_error"] = str(exc)[:160]

# The chain persist recorded must verify clean (no integrity break).
# audit_verify_chain returns a dict (not a JSON string); sequences are
# 1-based, so the walk starts at from_sequence=1.
if report.get("entries_written"):
    try:
        v = engine.audit_verify_chain(k, 1, 1000)
        v = v if isinstance(v, dict) else json.loads(v)
        report["chain_verify"] = v
    except Exception as exc:
        report["chain_verify"] = {"_error": str(exc)[:160]}

# Backend-parity probe (CIRISPersist#283): consent_event + wisdom_based_deferral
# action types are accepted on sqlite but rejected by the postgres audit_log
# CHECK constraint. Record each outcome so the parity test can assert it.
for label, fn in (("consent_event", lambda: audit.log_consent_event("grant", "stream-1", "datum", 30)),
                  ("wbd", lambda: audit.log_wbd("ethical_boundary", "human_oversight", 3600))):
    try:
        fn(); report.setdefault("extra_types", {})[label] = "accepted"
    except Exception as exc:
        report.setdefault("extra_types", {})[label] = str(exc)[:120]

report["stage"] = "done"
print(json.dumps(report)); sys.stdout.flush()
sys.exit(0)
"""


def _audit_script(database_url: str) -> str:
    return f"DB_URL = {database_url!r}\n" + _AUDIT_BODY


@pytest.fixture(scope="module")
def audit_chain():
    result = run_python_script(_audit_script(get_database_url()))
    payload = result.parsed_stdout()
    if payload.get("_error") == "absent":
        pytest.fail("ciris_server.LensAudit is missing — the audit-log "
                    "accountability surface is not on the wheel")
    assert payload.get("stage") == "done", payload
    return payload


@pytest.mark.requires_persist
@pytest.mark.requires_lens
def test_server_audit_writes_verify_clean_chain(audit_chain):
    """D02/D23: server-written audit entries form a clean, verifiable persist chain.

    Real gate as of **server 0.5.49** (CIRISServer#93 closed) — `LensAudit.log_*`
    now seeds the audit sequence correctly (was emitting `sequence_number=0`
    against persist's `>= 1` requirement). Three `log_action` entries land in
    persist's hash-chained, hybrid-signed audit log, and `audit_verify_chain`
    walks them with outcome `ok`. Uses `log_action` (a `handler_action_*` type in
    the audit_log CHECK vocabulary on BOTH backends) so the core gate is
    backend-agnostic — the consent/wbd action-type parity gap is asserted
    separately below.
    """
    assert audit_chain.get("entries_written") is True, (
        f"LensAudit could not write audit entries: {audit_chain.get('write_error')}"
    )
    v = audit_chain["chain_verify"]
    # audit_verify_chain → {tenant_id, from_sequence, to_sequence,
    #                       entries_walked, outcome: {outcome: "ok"}}
    assert v.get("entries_walked") == 3, v
    assert (v.get("outcome") or {}).get("outcome") == "ok", v


@pytest.mark.requires_persist
@pytest.mark.requires_lens
def test_consent_and_wbd_action_types_accepted(audit_chain):
    """All LensAudit action types are accepted on every backend.

    Real gate as of **persist 10.2.1** (CIRISPersist#283 closed) — the postgres
    `audit_log.action_type` CHECK vocabulary now includes `consent_event` and
    `wisdom_based_deferral`, so `LensAudit.log_consent_event` / `log_wbd` land on
    BOTH sqlite and postgres (was sqlite-only; the CHECK omitted them on postgres).
    """
    extra = audit_chain.get("extra_types") or {}
    assert extra.get("consent_event") == "accepted", extra
    assert extra.get("wbd") == "accepted", extra
