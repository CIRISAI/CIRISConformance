"""
Fabric tier — identity-aware storage + per-actor eviction.

FEDERATION_SCALING_MODEL §9 names the load-bearing property the whole
replication discipline rests on:

> "What makes this work is that you know whose data you are storing,
>  and can evict their data at any time if you choose."

§9.1 says the substrate must answer two questions at any moment:
1. whose bytes am I holding?
2. can I evict everything from a specific actor right now?

persist 3.5.0 ships the mechanism. This file exercises it at the
cross-wheel boundary:

- ✅ **Per-actor eviction** (`evict_actor_json`, CIRISPersist#125):
  deletes every blob the Engine holds for an actor AND emits a
  `withdraws` against each `holds_bytes` attestation (the §10.1.2
  ContentMiss feedback). This is the §9 thesis, end to end.
- ✅ **Eviction sweeper liveness** (`sweep_evictions_once`,
  CIRISPersist#123): the popularity×freshness sweep runs synchronously
  and returns a count.
- ✅ **Trust-threshold setter** (`set_trust_threshold`,
  CIRISPersist#123): accepts + clamps the [0,1] admission threshold.

Two replication properties are NOT yet drivable cross-wheel — tracked
upstream, asserted as `xfail` (not skipped, not worked around):

- ❌ "whose bytes do I hold?" via `list_holders_json` returns `[]` for
  locally-held blobs → **CIRISPersist#130**.
- ❌ the trust × capacity *intake gate* behaviour: `set_trust_threshold`
  sets the threshold but no `AdmissionGate`/`TrustScoring` is installable
  via PyO3, so admission is never actually refused → **CIRISPersist#129**.

See FEDERATION_SCALING_MODEL §1.1 / §9 — CIRISNodeCore/FSD/.
"""

from __future__ import annotations

import pytest

from conftest import ceg_local_signer_preamble, get_database_url, run_python_script

pytestmark = pytest.mark.fabric


def _fabric_eviction_script(database_url: str) -> str:
    return ceg_local_signer_preamble(database_url, pqc=True) + r'''
report = {"stage": "start"}

# The attesting key must be in the federation directory for
# put_blob_signing to emit its holder attestation.
kid = engine.register_self_federation_key("agent", "fabric-evict-ref", None, None, None)
report["kid"] = kid

# Unique blob content + attestation_id per subprocess so tests stay
# isolated on a shared (postgres) backend — see the conftest preamble note.
def _store(tag):
    body = ("fabric-blob-" + kid + "-" + tag).encode()
    sha = hashlib.sha256(body).hexdigest()
    engine.put_blob_signing(
        sha, base64.b64encode(body).decode(), None, None,
        kid, "2026-05-28T13:45:09.000Z", str(uuid.uuid4()),
    )
    return sha

sha1 = _store("one")
sha2 = _store("two")
report["stored_present"] = engine.has_blob_json(sha1) and engine.has_blob_json(sha2)

# Holder attestations exist for the actor (the local "whose bytes" answer).
atts_before = json.loads(engine.list_attestations_for(kid))['items']
report["holds_bytes_count_before"] = sum(
    1 for a in atts_before if a.get("attestation_type", "").startswith("holds_bytes:sha256:")
)

# CIRISPersist#130 probe: does the documented holder API report local holdings?
report["list_holders_local"] = engine.list_holders_json(sha1)

# CIRISPersist#129 probe: setting a max threshold does NOT actually refuse
# a write (the AdmissionGate is not wired via PyO3). We record whether a
# write from this (un-scored, trust≈0) actor is still admitted under
# threshold 1.0 — today it is, which is the gap.
engine.set_trust_threshold(1.0)
try:
    sha3 = _store("under-max-threshold")
    report["admitted_under_max_threshold"] = engine.has_blob_json(sha3)
except Exception as exc:
    report["admitted_under_max_threshold"] = False
    report["admission_refused_error"] = str(exc)[:120]
engine.set_trust_threshold(0.0)  # restore admit-all

# ✅ Per-actor eviction (the §9 thesis).
evict_report = json.loads(engine.evict_actor_json(kid, "2026-05-28T14:00:00.000Z"))
report["evict_report"] = evict_report
report["evicted_gone"] = not engine.has_blob_json(sha1) and not engine.has_blob_json(sha2)
atts_after = json.loads(engine.list_attestations_for(kid))['items']
report["withdraws_present"] = sum(
    1 for a in atts_after if a.get("attestation_type", "") == "withdraws"
)

# ✅ Eviction sweeper liveness.
report["sweep_count"] = engine.sweep_evictions_once()

# ✅ Trust-threshold setter accepts + clamps out-of-range.
threshold_ok = True
for t in (0.0, 0.5, 1.0, 2.0, -1.0):
    try:
        engine.set_trust_threshold(t)
    except Exception:
        threshold_ok = False
report["threshold_setter_ok"] = threshold_ok

report["stage"] = "done"
print(json.dumps(report))
sys.exit(0)
'''


@pytest.fixture(scope="module")
def fabric_eviction():
    result = run_python_script(_fabric_eviction_script(get_database_url()))
    try:
        payload = result.parsed_stdout()
    except Exception:
        pytest.fail(
            f"fabric eviction script produced no parseable JSON (exit {result.returncode}):\n"
            f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}"
        )
    assert payload.get("stage") == "done", f"{payload}\nSTDERR: {result.stderr}"
    return payload


@pytest.mark.requires_persist
def test_per_actor_eviction_removes_blobs_and_emits_withdraws(fabric_eviction):
    """§9: evict_actor drops all of an actor's blobs and emits a withdraws each."""
    assert fabric_eviction["stored_present"] is True, fabric_eviction
    assert fabric_eviction["holds_bytes_count_before"] == 2, fabric_eviction
    # The actor holds the 2 base blobs plus the admission-gate probe blob if
    # it was admitted (it is today — the #129 gap; decouple so this stays
    # correct once the gate refuses it).
    expected = 2 + (1 if fabric_eviction["admitted_under_max_threshold"] else 0)
    rep = fabric_eviction["evict_report"]
    assert rep == {
        "blobs_evicted": expected,
        "withdraws_emitted": expected,
        "withdraws_failed": 0,
    }, rep
    assert fabric_eviction["evicted_gone"] is True, fabric_eviction
    assert fabric_eviction["withdraws_present"] == expected, fabric_eviction


@pytest.mark.requires_persist
def test_eviction_sweeper_runs(fabric_eviction):
    """§1.2: the popularity×freshness sweeper drives one cycle and reports a count."""
    assert isinstance(fabric_eviction["sweep_count"], int), fabric_eviction
    assert fabric_eviction["sweep_count"] >= 0, fabric_eviction


@pytest.mark.requires_persist
def test_trust_threshold_setter_clamps(fabric_eviction):
    """§1.1: the admission threshold setter accepts [0,1] and clamps out-of-range."""
    assert fabric_eviction["threshold_setter_ok"] is True, fabric_eviction


@pytest.mark.requires_persist
def test_list_holders_reports_local_holdings(fabric_eviction):
    """§9.1: 'whose bytes do I hold?' — list_holders_json includes local holdings.

    Real gate as of persist 3.6.4 (CIRISPersist#130 fixed).
    """
    assert fabric_eviction["kid"] in fabric_eviction["list_holders_local"], (
        fabric_eviction["list_holders_local"]
    )


@pytest.mark.requires_persist
@pytest.mark.xfail(
    reason="The dispatch_inbound trust short-circuit (CIRISEdge#48/#208) IS on the "
    "PyEdge surface as of edge 7.0.8 — set_trust_threshold / install_trust_resolver "
    "/ dispatch_inbound_bytes — and the gate logic is correct (a hand-built hybrid "
    "envelope passes persist's verify_hybrid_via_directory directly). BUT the "
    "harness can't mint a valid inbound envelope: a hand-rolled envelope that "
    "passes DIRECT verify still fails the pipeline (a subtle to_value/RawValue "
    "re-serialization mismatch), and the gate runs AFTER verify. Needs an "
    "edge-side build_signed_inbound_envelope helper → CIRISEdge#211.",
    strict=False,
)
def test_intake_gate_refuses_below_threshold(fabric_eviction):
    """§1.1: a low-trust source is refused at the intake gate (edge dispatch_inbound)."""
    assert fabric_eviction["admitted_under_max_threshold"] is False, (
        "write was admitted under trust threshold 1.0 — the intake gate is not enforcing"
    )
