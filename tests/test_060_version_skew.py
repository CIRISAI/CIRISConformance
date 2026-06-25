"""
Version-skew conformance: known-good and known-bad version pairs that
exercise the cohabitation contract under NON-current pins.

`matrices/current.yaml` pins the canonical "works today" floor. This file
installs OTHER combos into isolated venvs (via the `skew_venv` fixture) to
verify two distinct properties of the version-skew envelope:

- **In-range tolerance** — the pinned wheels declare a *range* of compatible
  sisters (edge 7.0.7 declares `ciris-persist >=10.0.0,<11`). The matrix pins
  one point in that range; a consumer is free to pin a different in-range
  point. These tests prove the *edges* of the declared range actually cohabit,
  not just the matrix's chosen point.
- **Cap enforcement** — a declared upper/lower bound must be REAL: pip has to
  refuse a below-floor sister, not silently install a broken combo. This is
  the test that the version metadata is load-bearing, not decorative.

The current skew envelope (edge 7.0.x caps `ciris-persist >=10.0.0,<11`):

| Case | Combo | Expectation |
|---|---|---|
| range-floor | edge 7.0.7 + persist **10.0.0** (range floor) | cohabits |
| range-ceiling | edge 7.0.7 + persist **10.2.0** (current top) | cohabits |
| below-floor | edge 7.0.7 + persist **9.11.0** (< the >=10 cap) | pip REFUSES |

Heavyweight (real pip + venv per case), so they carry `@pytest.mark.version_skew`
and run in their own lane rather than the fast inner-loop suite.
"""

from __future__ import annotations

import pytest

# Pinned points of the edge-7.0.x ↔ persist-10.x skew envelope. When the
# matrix floor moves to edge 8 / persist 11, refresh these three constants.
_EDGE = "7.0.10"
_PERSIST_RANGE_FLOOR = "10.0.0"     # the >= bound edge 7.0.7 declares
_PERSIST_RANGE_CEILING = "10.2.0"   # current top of the 10.x line
_PERSIST_BELOW_FLOOR = "9.11.0"     # one minor under the >=10 cap → must refuse

# A probe that proves real cohabitation, not just successful install: both
# wheels import in one process and edge's cohabitation entry point is callable.
_COHAB_PROBE = r"""
import json
import ciris_persist  # noqa: F401
from ciris_edge.ciris_edge import init_edge_runtime
import importlib.metadata as md
print(json.dumps({
    "cohab": True,
    "persist": md.version("ciris-persist"),
    "edge": md.version("ciris-edge"),
    "init_edge_runtime_callable": callable(init_edge_runtime),
}))
"""

pytestmark = [pytest.mark.version_skew, pytest.mark.cohabitation]


def test_edge_cohabits_with_range_floor_persist(skew_venv):
    """edge 7.0.7 cohabits with persist 10.0.0 — the bottom of its declared range."""
    r = skew_venv({"ciris-persist": _PERSIST_RANGE_FLOOR, "ciris-edge": _EDGE},
                  _COHAB_PROBE)
    assert r.installed, f"range-floor combo failed to install:\n{r.install_output[-1500:]}"
    assert r.probe.get("cohab") is True, r.probe
    assert r.probe["persist"] == _PERSIST_RANGE_FLOOR, r.probe
    assert r.probe["edge"] == _EDGE, r.probe
    assert r.probe["init_edge_runtime_callable"] is True, r.probe


def test_edge_cohabits_with_range_ceiling_persist(skew_venv):
    """edge 7.0.7 cohabits with persist 10.2.0 — the current top of the 10.x line."""
    r = skew_venv({"ciris-persist": _PERSIST_RANGE_CEILING, "ciris-edge": _EDGE},
                  _COHAB_PROBE)
    assert r.installed, f"range-ceiling combo failed to install:\n{r.install_output[-1500:]}"
    assert r.probe.get("cohab") is True, r.probe
    assert r.probe["persist"] == _PERSIST_RANGE_CEILING, r.probe


def test_below_floor_persist_refused_cleanly(skew_venv):
    """Pairing edge 7.0.7 with persist 9.11.0 (< its >=10 cap) must be REFUSED.

    Proves edge's declared `ciris-persist>=10.0.0` lower bound is load-bearing:
    pip resolves it impossible rather than installing a broken cohabitation.
    """
    r = skew_venv({"ciris-persist": _PERSIST_BELOW_FLOOR, "ciris-edge": _EDGE}, None)
    assert not r.installed, (
        "below-floor combo INSTALLED — edge's persist>=10 cap is not enforced; "
        f"this is a real cohabitation hazard:\n{r.install_output[-1500:]}"
    )
    assert r.resolution_refused, (
        "install failed but not via a resolver refusal — the failure mode is "
        f"unexpected (network? build?):\n{r.install_output[-1500:]}"
    )
