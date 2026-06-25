"""
Fabric tier — fail-secure peer-key admission (CC 5.3.2.4.3 / federation enroll).

The federation directory is the trust root: a peer's `federation_keys` row is
what every later signature verifies against. So key *enrollment* is the
load-bearing admission gate — if a tampered key record were stored, every
downstream verify would anchor to bad bytes. The Constitution's answer is
fail-secure: a `SignedKeyRecord` whose scrub signature does not verify over its
canonical registration bytes MUST be rejected **before storage**
(CIRISServer's peer_replication enrollment discipline; persist's
`verify_signed_key_record` is the cross-wheel surface for it).

This drives the REAL persist `verify_signed_key_record` (the verify-before-store
gate consumers use on inbound key registrations from gossip/direct peers) and
pins the fail-secure contract:

- A genuinely-signed record **verifies** (`hybrid_verified`).
- A record whose `registration_envelope` was tampered after signing is
  **rejected** (`verify_hybrid_crypto`) — the canonical bytes no longer match
  the scrub signature.
- A record whose scrub signature was corrupted is **rejected**.

The verify is anchored to the `scrub_key_id`'s directory pubkeys (not the
record's self-asserted pubkey field), which is itself the fail-secure property:
an attacker cannot swap in their own pubkey to make a forged envelope verify.
"""

from __future__ import annotations

import pytest

from conftest import get_database_url, run_python_script

pytestmark = pytest.mark.fabric

_ADMISSION_BODY = r"""
import json, sys, os, tempfile, secrets, base64
try:
    import ciris_persist as cp
except ImportError as exc:
    print(json.dumps({"_error": "import", "detail": str(exc)})); sys.exit(2)

_d = tempfile.mkdtemp()
_seed = os.path.join(_d, "s"); open(_seed, "wb").write(secrets.token_bytes(32))
_pqc = os.path.join(_d, "p"); open(_pqc, "wb").write(secrets.token_bytes(32))
cp.reset_engine()
k = "host-" + secrets.token_hex(8)
engine = cp.Engine(DB_URL, k, local_key_id=k, local_key_path=_seed,
                   local_pqc_key_id=k + "-pqc", local_pqc_key_path=_pqc)

if not hasattr(engine, "verify_signed_key_record"):
    print(json.dumps({"_error": "absent"})); sys.exit(2)

# A genuinely-signed key record: register self, read the row back as the
# SignedKeyRecord a federation peer would receive.
kid = engine.register_self_federation_key("agent", "peer-ref", None, None, None)
row = json.loads(engine.lookup_keys_for_identity("peer-ref"))[0]

def verify(rec):
    try:
        r = engine.verify_signed_key_record(json.dumps(rec), "strict")
        return {"accepted": True, "outcome": r.get("outcome")}
    except Exception as exc:  # ValueError on rejection
        return {"accepted": False, "error": str(exc)[:80]}

report = {"kid": kid}

# (1) Valid record verifies.
report["valid"] = verify({"record": row})

# (2) Tamper the registration_envelope after signing → canonical bytes diverge
#     from the scrub signature → reject.
tampered = json.loads(json.dumps(row))
env = dict(tampered.get("registration_envelope") or {})
env["id"] = "forged-identity-" + secrets.token_hex(4)
tampered["registration_envelope"] = env
report["tampered_envelope"] = verify({"record": tampered})

# (3) Corrupt the classical scrub signature → reject.
corrupt = json.loads(json.dumps(row))
raw = bytearray(base64.b64decode(corrupt["scrub_signature_classical"]))
raw[0] ^= 0xFF
corrupt["scrub_signature_classical"] = base64.b64encode(bytes(raw)).decode()
report["corrupt_signature"] = verify({"record": corrupt})

report["stage"] = "done"
print(json.dumps(report)); sys.stdout.flush()
sys.exit(0)
"""


def _admission_script(database_url: str) -> str:
    return f"DB_URL = {database_url!r}\n" + _ADMISSION_BODY


@pytest.fixture(scope="module")
def peer_admission():
    result = run_python_script(_admission_script(get_database_url()))
    payload = result.parsed_stdout()
    if payload.get("_error") == "absent":
        pytest.fail("persist.verify_signed_key_record is missing — the "
                    "fail-secure peer-admission gate is not on the wheel surface")
    assert payload.get("stage") == "done", payload
    return payload


@pytest.mark.requires_persist
def test_genuine_key_record_verifies(peer_admission):
    """A properly-signed SignedKeyRecord verifies hybrid (Ed25519 + ML-DSA-65)."""
    v = peer_admission["valid"]
    assert v["accepted"] is True, v
    assert v["outcome"] == "hybrid_verified", v


@pytest.mark.requires_persist
def test_tampered_registration_envelope_is_rejected(peer_admission):
    """Mutating the registration_envelope after signing fails verification (fail-secure)."""
    t = peer_admission["tampered_envelope"]
    assert t["accepted"] is False, (
        "a tampered registration_envelope verified — the canonical-bytes / "
        f"signature binding is not enforced: {t}"
    )
    assert "verify_hybrid_crypto" in t["error"], t


@pytest.mark.requires_persist
def test_corrupted_signature_is_rejected(peer_admission):
    """A corrupted scrub signature fails verification (no silent admit)."""
    c = peer_admission["corrupt_signature"]
    assert c["accepted"] is False, c
    assert "verify_hybrid_crypto" in c["error"], c
