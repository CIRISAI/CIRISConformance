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

Status: `xfail` on **CIRISServer#93** — on the persist 10.1.2 / server 0.5.43
floor, every `LensAudit.log_*` fails because the server emits
`sequence_number = 0` while persist's `audit_record_entry` requires `>= 1`
(re-verified). The audit-log write path is broken at the wheel boundary, so the
D02/D23 control has no working implementation to gate yet. This test asserts the
behavior we WANT; it flips to a real gate when #93 ships a fixed server wheel.
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

# Write a few accountability entries via the server audit surface.
try:
    audit.log_action("speak", "thought-1", "speak_handler", True, 42, "rationale")
    audit.log_consent_event("grant", "stream-1", "datum", 30)
    audit.log_wbd("ethical_boundary", "human_oversight", 3600)
    report["entries_written"] = True
except Exception as exc:
    report["entries_written"] = False
    report["write_error"] = str(exc)[:160]

# The chain persist recorded must verify clean (no integrity break).
if report.get("entries_written"):
    try:
        v = json.loads(engine.audit_verify_chain(k, 0, 1000))
        report["chain_verify"] = v
    except Exception as exc:
        report["chain_verify"] = {"_error": str(exc)[:160]}

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
@pytest.mark.xfail(
    strict=True,
    reason="CIRISServer#93 — every LensAudit.log_* fails: the server emits "
    "sequence_number=0 but persist's audit_record_entry requires >=1, so the "
    "D02/D23 audit-chain write path is broken at the wheel boundary (persist "
    "10.1.2 / server 0.5.43). Flips to a real gate when a fixed server wheel ships.",
)
def test_server_audit_writes_verify_clean_chain(audit_chain):
    """D02/D23: server-written audit entries form a clean, verifiable persist chain."""
    assert audit_chain.get("entries_written") is True, (
        f"LensAudit could not write audit entries: {audit_chain.get('write_error')}"
    )
    v = audit_chain["chain_verify"]
    assert v.get("valid") is True or v.get("ok") is True, v
