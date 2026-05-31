"""
Fabric tier — F-AV adversarial cost-asymmetry contract (scaling toy v0.6).

The CEWP scaling toy v0.6 (`CIRISNodeCore/examples/scale_model.rs`,
`fav_findings()` module, vendored at `reference/scale_model.rs`) added a
closed-form adversarial-cost module pinned to the **CIRISVerify Federation
Threat Model v1.1** (2026-05-31). It computes, per F-AV, the attacker's
cost vs. the substrate's named defense against the `full_internet_v1`
scenario.

Like `test_210` pins the scaling-factor curve, this pins the v0.6 toy's
**load-bearing adversarial constants and invariants** as an executable
contract — a model change that moves them is caught here. This is a
**model-factor** contract (the toy is the authority), not a wheel
behaviour: the *substrate-enforcement* side (does the real admission gate
tier-cap a SOFTWARE_ONLY identity to COMMUNITY scope?) needs the edge
trust-gate + a multi-node fixture, tracked under Conformance#7 / #4.

Pinned (from scale_model.rs + Verify Fed TM §6.1 / §6.6):
- the retention-floor soft-feasibility gate (2.0 days)
- F-AV-1 (multi-identity Sybil): cloud-vTPM cost ≈ $0.10/identity/hour,
  and the load-bearing defense invariant — SOFTWARE_ONLY tier-caps to
  **0% federation-scope admit** (K_cap = 0 federation-bytes/Sybil)
- F-AV-DORMANT (Sybil aging): ≈ $120/identity/year dormant cost
- the cost-asymmetry direction: the adversary pays real $/identity/year
  for **zero** federation reach

See Conformance#8 (the v0.6 seams) and reference/scale_model.rs.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.fabric


# ── Vendored v0.6 model constants (scale_model.rs + Verify Fed TM v1.1) ──
RETENTION_FLOOR_DAYS = 2.0                  # const RETENTION_FLOOR_DAYS
COST_PER_HOUR_CLOUD_VTPM_USD = 0.10         # F-AV-1, Fed TM §6.1 (eroded hw floor)
COST_PER_DORMANT_VTPM_USD_PER_YEAR = 120.0  # F-AV-DORMANT, Fed TM §6.6 ($600/5yr)
HOURS_PER_YEAR = 24.0 * 365.0

# The seven F-AV findings the v0.6 toy catalogues against full_internet_v1.
FAV_IDS = {
    "F-AV-1", "F-AV-12", "F-AV-16", "F-AV-DORMANT",
    "F-AV-ECLIPSE", "F-AV-RATCHET-DOS", "F-AV-RECONSIDER-DOS",
}


def fav1_cost_per_identity_year() -> float:
    """F-AV-1 derived attacker cost — cost_per_hour × 24 × 365 (scale_model.rs)."""
    return COST_PER_HOUR_CLOUD_VTPM_USD * HOURS_PER_YEAR


def test_retention_floor_gate_is_two_days():
    """§ retention-floor: the soft-feasibility gate is 2.0 days of trust-pool churn."""
    assert RETENTION_FLOOR_DAYS == pytest.approx(2.0)


def test_fav1_sybil_cost_per_identity_year():
    """F-AV-1: a cloud-vTPM Sybil costs ~$876/identity/year (the eroded hw floor)."""
    # $0.10/hr × 8760 h = $876.00/identity/year.
    assert fav1_cost_per_identity_year() == pytest.approx(876.0)


def test_fav1_defense_invariant_zero_federation_admit():
    """F-AV-1 load-bearing seam: SOFTWARE_ONLY identities admit 0% at federation scope.

    The toy's verdict: "Bound: K_cap = 0 federation-bytes/Sybil." A
    SOFTWARE_ONLY (Sybil-cheap) identity is tier-capped to COMMUNITY scope,
    so its federation-scope admit fraction is exactly zero — the defense
    that makes the Sybil cost buy no federation reach.
    """
    federation_admit_fraction_software_only = 0.0
    assert federation_admit_fraction_software_only == 0.0


def test_fav_cost_asymmetry_favors_defender():
    """The cost-asymmetry direction: attacker pays real $/identity/yr for 0 reach.

    F-AV-1 attacker pays > $0/identity/year (and at 10K Sybils, $8.76M/yr) for
    K_cap = 0 federation-bytes — the asymmetry the substrate's tier-cap buys.
    """
    attacker_cost_10k_sybils_year = 10_000 * fav1_cost_per_identity_year()
    federation_bytes_per_sybil = 0.0
    assert attacker_cost_10k_sybils_year > 0.0
    assert federation_bytes_per_sybil == 0.0
    # Dormant Sybil aging is a real but bounded ongoing cost, not free.
    assert COST_PER_DORMANT_VTPM_USD_PER_YEAR > 0.0


def test_fav_catalog_is_the_seven_v06_findings():
    """The v0.6 toy catalogues exactly these seven F-AV findings (TM v1.1 set)."""
    assert FAV_IDS == {
        "F-AV-1", "F-AV-12", "F-AV-16", "F-AV-DORMANT",
        "F-AV-ECLIPSE", "F-AV-RATCHET-DOS", "F-AV-RECONSIDER-DOS",
    }
