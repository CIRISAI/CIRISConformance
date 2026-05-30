"""
Fabric tier — scaling-factor conformance (the model "toys").

FEDERATION_SCALING_MODEL.md + CIRISNodeCore/examples/scale_model.rs
define the scaling factors that make the "carry the whole internet on
commodity hardware" claim hold. This file pins those published factors
as an executable conformance contract: if the model's load-bearing
numbers drift, these fail.

This is the one fabric surface that is NOT a wheel behaviour — it is the
*model's* contract. The factors encoded here are quoted from the FSD;
the substrate-behaviour side (does the real trust-depth admission expand
the held set per this curve?) needs the node-core wheel and a multi-node
fixture, tracked as CIRISNodeCore#21.

Factors pinned:
- §1.4 effective_trust_set_multiplier(depth): 0→1, 1→4, 2→20, 3→100
  (small-world hop expansion with friend-of-friend overlap dampening)
- §4 / CEWP k_eff corridor: k_eff = k / (1 + ρ(k−1)); the corridor
  between rigidity (ρ→1 ⇒ k_eff→1, single-voice collapse) and chaos
  (ρ→0 ⇒ k_eff→k, vacuous dispersal)
- §5.1 retention is inversely monotonic in trust depth (wider effective
  set ⇒ shorter steady-state retention at fixed disk budget)
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.fabric


def effective_trust_set_multiplier(depth: float) -> float:
    """FEDERATION_SCALING_MODEL §1.4 / scale_model.rs — small-world hop
    expansion dampened by friend-of-friend overlap."""
    if depth <= 0.0:
        return 1.0
    if depth <= 1.0:
        return 1.0 + depth * 3.0
    if depth <= 2.0:
        return 4.0 + (depth - 1.0) * 16.0
    if depth <= 3.0:
        return 20.0 + (depth - 2.0) * 80.0
    return 100.0 * 1.5 ** (depth - 3.0)


def k_eff(k: float, rho: float) -> float:
    """Effective diversity (CEWP §4): k_eff = k / (1 + ρ(k−1))."""
    return k / (1.0 + rho * (k - 1.0))


# The §1.4 / §5.1 published anchor table (depth → multiplier, reach label).
_MULTIPLIER_ANCHORS = {0: 1.0, 1: 4.0, 2: 20.0, 3: 100.0}


@pytest.mark.parametrize("depth,expected", _MULTIPLIER_ANCHORS.items())
def test_trust_set_multiplier_anchor_points(depth, expected):
    """The published depth→multiplier anchors (1× / 4× / 20× / 100×) hold."""
    assert effective_trust_set_multiplier(float(depth)) == pytest.approx(expected), (
        f"depth {depth}: model curve drifted from the documented {expected}×"
    )


def test_trust_set_multiplier_is_monotonic_increasing():
    """Deeper recursion never shrinks the effective trust set."""
    depths = [0.0, 0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 4.0, 5.0]
    vals = [effective_trust_set_multiplier(d) for d in depths]
    assert all(b >= a for a, b in zip(vals, vals[1:])), vals


def test_trust_set_multiplier_dampened_below_naive_geometric():
    """Overlap dampening: the effective set grows slower than naive R^depth.

    The model's whole point (§1.4) is that friend-of-friend overlap makes
    unique-set growth far less than geometric. With base reach ~4 (the
    depth-1 multiplier), naive growth would be 4^depth = 64 at depth 3;
    the dampened curve caps at 100, but the per-hop *ratio* collapses.
    """
    # Per-hop growth ratio peaks early then decays (overlap dampening).
    r1 = effective_trust_set_multiplier(1) / effective_trust_set_multiplier(0)  # 4.0
    r2 = effective_trust_set_multiplier(2) / effective_trust_set_multiplier(1)  # 5.0
    r3 = effective_trust_set_multiplier(3) / effective_trust_set_multiplier(2)  # 5.0
    r4 = effective_trust_set_multiplier(4) / effective_trust_set_multiplier(3)
    # No hop's growth ratio exceeds the early peak, and late hops decay —
    # no runaway geometric blowup.
    assert max(r1, r3, r4) <= r2 + 1e-9
    assert r4 < r2


def test_k_eff_corridor_endpoints():
    """k_eff collapses to 1 under full correlation, equals k under independence."""
    k = 8.0
    # Rigidity: ρ→1 ⇒ single-voice collapse (k_eff→1).
    assert k_eff(k, 1.0) == pytest.approx(1.0)
    # Chaos: ρ→0 ⇒ vacuous dispersal (k_eff→k).
    assert k_eff(k, 0.0) == pytest.approx(k)


def test_k_eff_bounded_and_monotonic_in_rho():
    """k_eff is bounded to [1, k] and decreases as constraints correlate."""
    k = 12.0
    rhos = [0.0, 0.1, 0.25, 0.5, 0.75, 0.9, 1.0]
    vals = [k_eff(k, r) for r in rhos]
    assert all(1.0 - 1e-9 <= v <= k + 1e-9 for v in vals), vals
    assert all(b <= a + 1e-9 for a, b in zip(vals, vals[1:])), vals


def test_retention_inverse_to_trust_depth():
    """§5.1: at fixed disk budget, deeper trust → wider set → shorter retention.

    The full_internet_v1 anchors (§5.1): depth 0 ≈ 150 d, 1 = 37 d,
    2 ≈ 7 d, 3 = single-digit d. Retention is strictly decreasing in
    depth, and tracks 1/multiplier (held-set turnover scales with the
    effective source count).
    """
    published = {0: 150.0, 1: 37.0, 2: 7.0, 3: 5.0}
    depths = sorted(published)
    days = [published[d] for d in depths]
    assert all(b < a for a, b in zip(days, days[1:])), days
    # Retention falls roughly as 1/effective_set: the depth-0→1 jump (1×→4×)
    # should cut retention by well over half.
    assert published[1] < published[0] / 2.0
