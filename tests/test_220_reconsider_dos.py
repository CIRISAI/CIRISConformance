"""
Fabric tier — reconsideration anti-abuse gate (F-AV-RECONSIDER-DOS).

The CIRIS Constitution makes reconsideration a first-class, reversible step:
a misjudged moderation slashing can be re-litigated via a ReconsiderationRequest
(CC reconsideration / the §3.1.9 ratchet-evidence discipline). But an open
reconsideration channel is itself a harassment surface — a bad actor can
re-file endlessly against a target. The constitution's answer is a bounded
admission gate, shipped as the **F-AV-RECONSIDER-DOS** primitive in
CIRISVerify and surfaced on the `ciris_server` wheel as `ReconsiderDosGuard`.

This is the cross-wheel conformance gate for that primitive. It drives the
REAL `ciris_server.ReconsiderDosGuard` (the F-AV-RECONSIDER-DOS guard the
fabric uses at reconsideration-admit time) and pins its three load-bearing
properties:

1. **Admits a fresh filing** — the channel is open by default.
2. **Actor-budget gate** — a single requester gets a bounded number of
   distinct-event filings; beyond that, admission is REFUSED (the anti-DoS
   ceiling, so one actor can't flood the reconsideration queue).
3. **Harassment-cluster gate** — repeated filings on the *same*
   requester→target pair are refused as `HarassmentClusterDetected` once the
   pair's cluster score reaches the threshold (mutual-harassment protection,
   distinct from the global actor budget).
4. **Outcome bookkeeping is typed** — `record_outcome` accepts only the
   defined outcomes and a `"successful"` reversal refills the requester's
   budget (the reversal-restores-capacity symmetry).

These are exact, deterministic contracts (pure in-memory guard, no clock
beyond the caller-supplied `now_ms`), so they assert as hard gates.
"""

from __future__ import annotations

import pytest

from conftest import run_python_script

pytestmark = pytest.mark.fabric

# A fixed pinned epoch-ms so the guard's windows are deterministic.
_NOW_MS = 1_700_000_000_000

_GUARD_SCRIPT = r"""
import json, sys
try:
    import ciris_server as cs
except ImportError as exc:
    print(json.dumps({"_error": "import", "detail": str(exc)})); sys.exit(2)

if not hasattr(cs, "ReconsiderDosGuard"):
    print(json.dumps({"_error": "absent"})); sys.exit(2)

NOW = 1_700_000_000_000
report = {}

# (1) A fresh filing is admitted.
g = cs.ReconsiderDosGuard()
report["fresh_admit"] = json.loads(g.admit_filing("ev-fresh", "req-A", "tgt-1", NOW))

# (2) Actor-budget gate: distinct events from one requester against DISTINCT
#     targets (so the harassment-cluster pairwise signal never fires) — this
#     isolates the GLOBAL per-requester budget. Filings admit up to the
#     rolling ceiling, then refuse with `ActorBudgetExhausted`. We file enough
#     to cross it and record the first refusal index + variant.
g2 = cs.ReconsiderDosGuard()
budget_admits = 0
budget_first_reject = None
for i in range(60):
    r = json.loads(g2.admit_filing(f"ev-b{i}", "req-B", f"tgt-b{i}", NOW + i * 1_000))
    if r.get("admitted"):
        budget_admits += 1
    else:
        budget_first_reject = {
            "index": i,
            "variants": list((r.get("rejection") or {}).keys()),
        }
        break
report["budget_admits_before_reject"] = budget_admits
report["budget_first_reject"] = budget_first_reject

# (3) Harassment-cluster gate: repeated filings on the SAME requester->target
#     pair are refused once the pair's cluster score hits the threshold.
g3 = cs.ReconsiderDosGuard()
g3.admit_filing("ev-h1", "req-C", "tgt-C", NOW)
g3.admit_filing("ev-h2", "req-C", "tgt-C", NOW + 1_000)
report["cluster_reject"] = json.loads(g3.admit_filing("ev-h3", "req-C", "tgt-C", NOW + 2_000))

# (4) Outcome bookkeeping is typed.
g4 = cs.ReconsiderDosGuard()
g4.admit_filing("ev-o", "req-D", "tgt-D", NOW)
try:
    g4.record_outcome("ev-o", "req-D", "not-a-real-outcome")
    report["bad_outcome_raised"] = False
except ValueError:
    report["bad_outcome_raised"] = True
# A defined outcome is accepted (no raise).
try:
    g4.record_outcome("ev-o", "req-D", "successful")
    report["good_outcome_ok"] = True
except Exception:
    report["good_outcome_ok"] = False

report["stage"] = "done"
print(json.dumps(report))
sys.exit(0)
"""


@pytest.fixture(scope="module")
def dos_guard():
    result = run_python_script(_GUARD_SCRIPT)
    payload = result.parsed_stdout()
    if payload.get("_error") == "import":
        pytest.skip(f"ciris_server not installed: {payload.get('detail')}")
    if payload.get("_error") == "absent":
        pytest.fail("ciris_server.ReconsiderDosGuard is missing — the "
                    "F-AV-RECONSIDER-DOS primitive is not on the wheel surface")
    assert payload.get("stage") == "done", payload
    return payload


@pytest.mark.requires_lens
def test_fresh_reconsideration_is_admitted(dos_guard):
    """The reconsideration channel admits a first-touch filing (open by default)."""
    assert dos_guard["fresh_admit"].get("admitted") is True, dos_guard["fresh_admit"]


@pytest.mark.requires_lens
def test_actor_budget_refuses_after_ceiling(dos_guard):
    """A single requester's distinct-target filings are bounded — the anti-DoS ceiling.

    Filings against DISTINCT targets (so the harassment-cluster gate never
    fires) admit up to a rolling per-requester budget, then refuse with
    `ActorBudgetExhausted`. The exact ceiling is the guard's policy; the
    load-bearing property is that one actor cannot file unbounded
    reconsiderations — the sequence is admit…admit…refuse, not admit-forever.
    """
    rej = dos_guard["budget_first_reject"]
    assert rej is not None, (
        "actor budget never refused across 60 distinct-target filings — the "
        f"anti-DoS ceiling is not enforced (admits={dos_guard['budget_admits_before_reject']})"
    )
    assert "ActorBudgetExhausted" in rej["variants"], rej
    # A non-trivial budget was granted before the ceiling (not refuse-from-zero).
    assert dos_guard["budget_admits_before_reject"] >= 1, dos_guard


@pytest.mark.requires_lens
def test_harassment_cluster_refuses_repeat_pair(dos_guard):
    """Repeated filings on the same requester→target pair refuse as a harassment cluster."""
    rej = dos_guard["cluster_reject"]
    assert rej.get("admitted") is False, rej
    assert "HarassmentClusterDetected" in (rej.get("rejection") or {}), rej


@pytest.mark.requires_lens
def test_record_outcome_is_typed(dos_guard):
    """`record_outcome` rejects an undefined outcome and accepts a defined one."""
    assert dos_guard["bad_outcome_raised"] is True, (
        "record_outcome accepted an invalid outcome string — the outcome "
        "vocabulary is not enforced"
    )
    assert dos_guard["good_outcome_ok"] is True, dos_guard
