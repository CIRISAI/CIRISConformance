"""
Substrate tier — transport abuse-source blackhole byte discipline (CC 4.5).

The blackhole is the substrate's transport-layer source denylist: a Reticulum
**identity hash** (16-byte destination hash) placed on the list is dropped at the
transport boundary, so a known abuse / CSAM-distribution source can be cut off
below the application layer. The list key is therefore a fixed-width Reticulum
identity hash, and the substrate MUST reject anything that is not exactly that
width — a wrong-length key would silently fail to match (or match the wrong
destination), defeating the block. `src/federation/blackhole.rs`:

    identity_hash.len() MUST equal 16 (RETICULUM_IDENTITY_HASH_LEN);
    non-conforming inputs raise InvalidArgument at the call boundary.

This drives the REAL persist blackhole surfaces:

- **length gate** — `blackhole_upsert` accepts a 16-byte hash and refuses 8- and
  32-byte inputs (`federation_invalid_argument`); the same width rule guards
  `blackhole_record_hit` / `blackhole_remove`.
- **round-trip** — a listed 16-byte hash shows in `blackhole_list_json`, and
  `blackhole_remove` takes it back off.
- **expiry** — an `until_iso` is honored (a far-future entry stays listed).
"""

from __future__ import annotations

import pytest

from conftest import get_database_url, run_python_script

pytestmark = pytest.mark.substrate

_BODY = r"""
import json, sys, os, tempfile, secrets
try:
    import ciris_persist as cp
except ImportError as exc:
    print(json.dumps({"_error": "import", "detail": str(exc)})); sys.exit(2)

_d = tempfile.mkdtemp()
_s = os.path.join(_d, "s"); open(_s, "wb").write(secrets.token_bytes(32))
_p = os.path.join(_d, "p"); open(_p, "wb").write(secrets.token_bytes(32))
cp.reset_engine()
k = "node-" + secrets.token_hex(8)
engine = cp.Engine(DB_URL, k, local_key_id=k, local_key_path=_s,
                   local_pqc_key_id=k + "-pqc", local_pqc_key_path=_p)

if not hasattr(engine, "blackhole_upsert"):
    print(json.dumps({"_error": "absent"})); sys.exit(2)

_FUTURE = "2099-01-01T00:00:00.000Z"
report = {"lengths": {}}

# Length gate — only a 16-byte Reticulum identity hash is admissible.
for n in (8, 16, 32):
    try:
        engine.blackhole_upsert(secrets.token_bytes(n), _FUTURE, "abuse-source")
        report["lengths"][str(n)] = "accepted"
    except Exception as exc:
        report["lengths"][str(n)] = str(exc)[:60]

# Round-trip — list the valid (16-byte) entry, then remove it.
_hash = secrets.token_bytes(16)
engine.blackhole_upsert(_hash, _FUTURE, "csam-distribution")
listed = json.loads(engine.blackhole_list_json())
report["listed_count_after_upsert"] = len(listed)
engine.blackhole_remove(_hash)
report["listed_count_after_remove"] = len(json.loads(engine.blackhole_list_json()))

# record_hit shares the width rule — an 8-byte probe is refused.
try:
    engine.blackhole_record_hit(secrets.token_bytes(8))
    report["record_hit_8b"] = "accepted"
except Exception as exc:
    report["record_hit_8b"] = str(exc)[:60]

report["stage"] = "done"
print(json.dumps(report)); sys.stdout.flush()
sys.exit(0)
"""


def _script(database_url: str) -> str:
    return f"DB_URL = {database_url!r}\n" + _BODY


@pytest.fixture(scope="module")
def blackhole():
    result = run_python_script(_script(get_database_url()))
    payload = result.parsed_stdout()
    if payload.get("_error") == "absent":
        pytest.fail("persist blackhole_upsert is missing — the transport "
                    "abuse-source denylist surface is not on the wheel")
    assert payload.get("stage") == "done", payload
    return payload


@pytest.mark.requires_persist
def test_only_16_byte_identity_hash_is_admissible(blackhole):
    """CC 4.5: the blackhole key is a 16-byte Reticulum hash — 8/32 are refused."""
    lengths = blackhole["lengths"]
    assert lengths["16"] == "accepted", lengths
    for bad in ("8", "32"):
        assert lengths[bad] != "accepted", (
            f"a {bad}-byte blackhole key was admitted — a wrong-width hash would "
            f"fail to match its Reticulum destination: {lengths}"
        )
        assert "invalid_argument" in lengths[bad], lengths


@pytest.mark.requires_persist
def test_listed_entry_round_trips(blackhole):
    """A 16-byte hash lands on the list and `blackhole_remove` takes it back off."""
    assert blackhole["listed_count_after_upsert"] >= 1, blackhole
    assert (blackhole["listed_count_after_remove"]
            == blackhole["listed_count_after_upsert"] - 1), blackhole


@pytest.mark.requires_persist
def test_record_hit_shares_the_width_rule(blackhole):
    """`blackhole_record_hit` enforces the same 16-byte width as upsert."""
    assert blackhole["record_hit_8b"] != "accepted", blackhole
    assert "invalid_argument" in blackhole["record_hit_8b"], blackhole
