"""pytest plugin: capture a normalized green/xfail status per test node.

Loaded by ``evidence/gen_cc_tests.py`` (via ``-p _status_plugin`` with
``evidence/`` on ``PYTHONPATH``). It reads the real pytest outcome of every
executed node and normalizes it to the registry's two-value vocabulary, so the
``status`` column of ``evidence/cc_tests.tsv`` is *derived from the live suite*
and can never be hand-edited into drift.

Normalization (pytest 9.x report model, verified against the CC floor venv):

  green  — the test BODY ran and passed. The claim is test-established now.
      * ``call`` passed, no ``wasxfail``                 (clean pass)
      * ``call`` passed, ``wasxfail`` set                (non-strict xpass)
      * ``call`` failed, longrepr ``[XPASS(strict)]``    (a strict-xfail whose body now
        PASSES: the surface shipped / the gate went live; the stale marker is the
        floor-bump effort's to remove — the evidence itself holds)

  xfail  — the test did NOT pass on this floor. The claim is not green-established.
      * ``call`` skipped, ``wasxfail`` set               (explicit xfail marker, expected fail)
      * ``call`` failed, any other longrepr              (genuine failure — a gate the floor
        does not yet pass, e.g. a fixture tripping a newly-enforced gate pending rework)
      * ``setup``/``teardown`` failed                    (fixture error — the drive could not
        establish the claim)

  ERROR  — the test could not be evaluated at all; the registry has no basis for a
           status and the run must fail so the host gets provisioned:
      * skipped with no ``wasxfail`` at setup or call    (pure environment gate — a missing
        wheel or native lib; the floor venv must run every mapped gate for real)

The green<->xfail flip of ANY row is itself caught by the CI ``git diff`` guard,
so a regression that turns a green claim xfail (or a fix that turns it green)
cannot land silently — it changes the committed TSV.
"""
from __future__ import annotations

import json
import os

# session-scoped accumulator
_STATE = {
    "node_status": {},   # nodeid -> "green" | "xfail"
    "node_reason": {},    # nodeid -> short reason tag (for the generator's summary)
    "errors": [],         # [nodeid, reason]  (env gates -> generator aborts)
}


def _record(nid, status, reason):
    _STATE["node_status"][nid] = status
    _STATE["node_reason"][nid] = reason


def pytest_runtest_logreport(report):  # noqa: D401 - pytest hook
    nid = report.nodeid
    wasxfail = getattr(report, "wasxfail", None)

    if report.when == "call":
        if report.outcome == "passed":
            # clean pass, or a non-strict xpass — either way the body ran green
            _record(nid, "green", "pass")
        elif report.outcome == "skipped" and wasxfail is not None:
            _record(nid, "xfail", "xfail-marker")
        elif report.outcome == "skipped":
            # pytest.skip() in the body with no xfail marker -> environment gate
            _STATE["errors"].append(
                [nid, "call-skipped (environment gate) — the floor venv must run this for real"]
            )
        elif report.outcome == "failed":
            longrepr = str(getattr(report, "longrepr", ""))
            if longrepr.lstrip().startswith("[XPASS(strict)]"):
                # strict-xfail body PASSED -> evidence established; marker is stale
                _record(nid, "green", "xpass-strict")
            else:
                first = (longrepr.splitlines() or [""])[0][:200]
                _record(nid, "xfail", f"genuine-failure: {first}")
    elif report.when == "setup":
        if report.outcome == "skipped" and wasxfail is None:
            _STATE["errors"].append(
                [nid, "setup-skipped (environment gate) — the floor venv must run this for real"]
            )
        elif report.outcome == "failed":
            # a fixture raised -> the drive could not establish the claim
            _record(nid, "xfail", "setup-error")
    elif report.when == "teardown" and report.outcome == "failed":
        # don't downgrade a body that already passed on a teardown wobble
        _STATE["node_status"].setdefault(nid, "xfail")
        _STATE["node_reason"].setdefault(nid, "teardown-error")


def pytest_sessionfinish(session, exitstatus):  # noqa: D401 - pytest hook
    out = os.environ.get("EVIDENCE_STATUS_OUT")
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(_STATE, fh)
