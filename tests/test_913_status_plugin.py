"""
Unit coverage for the evidence status plugin (`evidence/_status_plugin.py`).

The `status` column of `evidence/cc_tests.tsv` is DERIVED from the live suite so
it can never be hand-edited into drift, and the Constitution resolves its `test:`
pointers against that file. So the plugin's report→status mapping is a contract,
and a hole in it does not surface as a wrong status — it surfaces as the
generator aborting with a message that blames the wrong file.

That is exactly what happened on the v0.5.176 floor bump:

    error: claim CC-3.2-minor-stewardship-node-revocation-fails-secure references
    'tests/…::test_node_binding_revocation_fails_secure' which the suite did not
    run — a stale test id (rename?) or a wrong path in claim_map.tsv

The claim map was correct and the test had run. It had been xfailed
IMPERATIVELY from a fixture (`conftest.xfail_if_unconferred_assurance_scope`),
which lands as `when="setup", outcome="skipped", wasxfail=<reason>` — a
combination no branch handled, so the node was recorded nowhere.

The hole predates that change: `xfail_if_pg_edge_runtime_crash` takes the same
path, but only fires on postgres while the evidence job runs sqlite-only, so
nothing had ever reached it. These cases pin every branch so the next one is
caught here instead of as a misleading abort.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_PLUGIN = Path(__file__).resolve().parent.parent / "evidence" / "_status_plugin.py"

pytestmark = pytest.mark.substrate


@pytest.fixture
def plugin():
    """A FRESH plugin module per test — `_STATE` is a module-level accumulator."""
    spec = importlib.util.spec_from_file_location("_status_plugin_under_test", _PLUGIN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Report:
    """The pytest report attributes the plugin actually reads."""

    def __init__(self, when, outcome, nodeid="tests/t.py::x", wasxfail=None, longrepr=""):
        self.when = when
        self.outcome = outcome
        self.nodeid = nodeid
        self.longrepr = longrepr
        if wasxfail is not None:
            self.wasxfail = wasxfail


@pytest.mark.parametrize("when, outcome, wasxfail, longrepr, status, reason", [
    # ── the branch whose absence caused the misleading abort ──
    ("setup", "skipped", "unconferred scope", "", "xfail", "xfail-fixture"),
    # ── the branches that already existed ──
    ("call", "passed", None, "", "green", "pass"),
    ("call", "passed", "r", "", "green", "pass"),                 # non-strict xpass
    ("call", "skipped", "r", "", "xfail", "xfail-marker"),
    ("setup", "failed", None, "", "xfail", "setup-error"),
    ("call", "failed", None, "[XPASS(strict)] gate shipped", "green", "xpass-strict"),
])
def test_status_mapping(plugin, when, outcome, wasxfail, longrepr, status, reason):
    rep = _Report(when, outcome, wasxfail=wasxfail, longrepr=longrepr)
    plugin.pytest_runtest_logreport(rep)
    assert plugin._STATE["node_status"].get(rep.nodeid) == status
    assert plugin._STATE["node_reason"].get(rep.nodeid) == reason
    assert not plugin._STATE["errors"], (
        f"a classifiable outcome was reported as an un-evaluatable error: "
        f"{plugin._STATE['errors']}")


def test_genuine_call_failure_is_xfail_with_the_reason_carried(plugin):
    """A real failure is `xfail` and keeps its first line, for the summary."""
    rep = _Report("call", "failed", longrepr="AssertionError: gate not enforced\n  more")
    plugin.pytest_runtest_logreport(rep)
    assert plugin._STATE["node_status"][rep.nodeid] == "xfail"
    assert "gate not enforced" in plugin._STATE["node_reason"][rep.nodeid]


@pytest.mark.parametrize("when", ["setup", "call"])
def test_environment_gate_is_an_error_not_a_status(plugin, when):
    """A skip with no xfail is a missing wheel or native lib — NOT evidence.

    This must stay an error: recording it as `xfail` would let an
    under-provisioned host publish "the floor does not establish this claim"
    when the truth is that the floor never ran the gate. The distinction is the
    whole reason the registry can be trusted.
    """
    rep = _Report(when, "skipped")
    plugin.pytest_runtest_logreport(rep)
    assert rep.nodeid not in plugin._STATE["node_status"]
    assert plugin._STATE["errors"] and plugin._STATE["errors"][0][0] == rep.nodeid


def test_teardown_wobble_does_not_downgrade_a_passed_body(plugin):
    nid = "tests/t.py::x"
    plugin.pytest_runtest_logreport(_Report("call", "passed", nid))
    plugin.pytest_runtest_logreport(_Report("teardown", "failed", nid))
    assert plugin._STATE["node_status"][nid] == "green"


def test_every_fixture_xfail_guard_in_conftest_is_covered(plugin):
    """Each `xfail_if_*` guard lands on the setup/skipped/wasxfail path.

    A new guard added to conftest inherits this classification automatically;
    this asserts the set is non-empty so the coupling stays visible if the
    guards are ever renamed or removed.
    """
    import conftest

    guards = [n for n in dir(conftest) if n.startswith("xfail_if_")]
    assert guards, "conftest no longer defines any xfail_if_* fixture guard"
    for name in guards:
        assert callable(getattr(conftest, name)), name
