"""
SCOPE_PRIVACY §9 (acceptance bullet 4) — 20-holder cross-fragment
cluster-detection KS-test at p > 0.01.

[CEWP `FSD/SCOPE_PRIVACY.md` §7.5](https://github.com/CIRISAI/CEWP/blob/main/FSD/SCOPE_PRIVACY.md#75-cross-fragment-timing-correlation)
names "K=6 holders cluster correlation" as a residual attack: if the
publisher emits all K reconstruction symbols within a narrow window, a
network observer who can attribute the holders sees the symbols as a
TIME CLUSTER and links them as fragments of one record. The
substrate-tier defense is the per-holder Poisson-jittered emission
scheduler — each of the n=20 holders' symbols leaves the publisher at
an independent `Exp(λ_per_holder)` interval, smearing the K=6 viable-
reconstruction set across the lifetime of the publication.

The §9 acceptance bullet 4: set up an n=20 holder federation, publish
one community-scope record (20 symbols, K=6 viable for reconstruction
per FSD §2.4), collect per-holder arrival times, KS-test against a
clustered-arrival null hypothesis. Assert p > 0.01 — **cannot reject
"arrivals are NOT clustered" at the 1% significance level**.

## What "not clustered" means precisely

The clustered null hypothesis is: "all symbols arrive within a narrow
window `[t_0, t_0 + ε]` for some `ε` small relative to the publication
lifetime". Under the §3.1 Poisson scheduler, arrivals are uniformly
distributed on `[0, T]` in expectation (T = window length); under the
clustered null, they're concentrated.

The two-sample KS test against a uniform-on-[0,T] reference distinguishes
these. A real Poisson scheduler's arrival times pass KS-vs-uniform at
p > 0.01 (we accept the uniform null); a clustered scheduler fails.

## Methodology — substrate-side gap (same as test_420)

Same gap: edge v6.1.0 keeps the Poisson scheduler internal to the Rust
send-path. This file simulates the §3.1 construction in Python against
the FSD's mathematical contract. When the scheduler is PyO3-exposed,
an additional test driving the real edge.publish_record() under a
20-holder fixture will land alongside this. The substrate-side gap is
tracked in `docs/SCOPE_PRIVACY_CONFORMANCE.md`.
"""

from __future__ import annotations

import math
import os
import random
from dataclasses import dataclass

import pytest

pytestmark = pytest.mark.ceg


# Same deterministic-CI seed convention as test_420 (per-file so test
# matrices can't accidentally cross-talk through the global RNG).
_DEFAULT_SEED = "20"
_SEED_ENV = "CIRIS_CONFORMANCE_CLUSTER_SEED"
_seed = os.environ.get(_SEED_ENV, _DEFAULT_SEED)
_RNG = random.Random(int(_seed))


# FSD §2.4 defaults — n=20 symbols per record, K=6 viable for reconstruction.
N_HOLDERS = 20
K_REPAIR = 6


# ─── Simulators ──────────────────────────────────────────────────────


@dataclass
class HolderArrivals:
    """Per-holder symbol arrival times for one published record."""
    times: list[float]                # arrival timestamps, len = N_HOLDERS
    window_seconds: float


def simulate_poisson_jittered(window_seconds: float,
                              rng: random.Random) -> HolderArrivals:
    """The CONFORMANT scheduler: each holder gets an independent
    inter-emission interval drawn from `Exp(N_HOLDERS / window)`.

    Equivalent to "all N_HOLDERS symbols sampled from Exp(λ)" with
    `λ = N_HOLDERS / window`. Resulting arrival times are uniformly
    distributed on [0, window] in expectation.
    """
    times: list[float] = []
    while len(times) < N_HOLDERS:
        t = rng.random() * window_seconds
        times.append(t)
    times.sort()
    return HolderArrivals(times=times, window_seconds=window_seconds)


def simulate_clustered(window_seconds: float, cluster_width_ratio: float,
                       rng: random.Random) -> HolderArrivals:
    """The ATTACK scheduler: all N_HOLDERS symbols arrive within a narrow
    cluster `[t_0, t_0 + ε]` where `ε = cluster_width_ratio * window`.

    Models a publisher that batches the K reconstruction symbols (and the
    rest) instead of jittering — the §7.5 cross-fragment cluster-correlation
    threat the §3.1 construction is designed to defeat.
    """
    eps = cluster_width_ratio * window_seconds
    t0 = rng.random() * (window_seconds - eps)
    times = sorted(t0 + rng.random() * eps for _ in range(N_HOLDERS))
    return HolderArrivals(times=times, window_seconds=window_seconds)


# ─── KS-test vs. Uniform(0, T) ────────────────────────────────────────


def _ks_pvalue_uniform(times: list[float], window: float) -> float:
    """Two-sided KS test: are `times` from Uniform(0, window)?

    Same Kolmogorov asymptotic series as test_420's `_ks_pvalue_exp`,
    just with `F(x) = x/window`.
    """
    n = len(times)
    s = sorted(times)
    D = 0.0
    for i, x in enumerate(s, start=1):
        fn = i / n
        fn_prev = (i - 1) / n
        f = max(0.0, min(1.0, x / window))
        D = max(D, abs(fn - f), abs(f - fn_prev))
    lam = math.sqrt(n) * D
    if lam <= 0:
        return 1.0
    p = 0.0
    for k in range(1, 101):
        term = ((-1) ** (k - 1)) * math.exp(-2.0 * (k * lam) ** 2)
        p += term
        if abs(term) < 1e-12:
            break
    return max(0.0, min(1.0, 2.0 * p))


# ─── Tests ───────────────────────────────────────────────────────────


# The "publication lifetime" the Poisson scheduler smears across. At the
# default community-scope λ from test_420 (lam=0.5 every 2s), 20 symbols
# at rate 1/2s gives ~40s window. We use 60s to give the KS test enough
# samples-vs-window range.
WINDOW_SECONDS = 60.0


@pytest.mark.ccs
def test_conformant_jittered_arrivals_pass_uniform_ks_at_p_gt_0_01():
    """§9 bullet 4 (positive): the §3.1 Poisson scheduler's per-holder
    arrival times are uniform on `[0, window]` to within KS-test
    significance — cannot reject the "NOT clustered" null at p > 0.01.

    Single-run check on N_HOLDERS=20 arrivals (the FSD §2.4 default).
    """
    a = simulate_poisson_jittered(WINDOW_SECONDS, _RNG)
    p = _ks_pvalue_uniform(a.times, WINDOW_SECONDS)
    assert p > 0.01, (
        f"KS p={p:.4f} ≤ 0.01 — Poisson-jittered arrivals incorrectly "
        f"flagged as clustered at the 1% level; §9 bullet 4 acceptance "
        f"fails (this is the publisher-side cover claim, not the "
        f"attacker-side detection claim)"
    )


@pytest.mark.ccs
@pytest.mark.parametrize("cluster_width_ratio", [0.05, 0.1, 0.15])
def test_clustered_arrivals_are_rejected_by_uniform_ks(cluster_width_ratio):
    """§9 bullet 4 (self-check / discriminative power): the KS test
    CORRECTLY rejects a known-clustered arrival pattern.

    Pin the test's discriminative power — without this, a buggy KS
    implementation could silently pass everything (the same risk
    test_420's `test_simulator_self_check_known_non_poisson_fails_ks`
    addresses for the Exp(λ) gate).

    The §7.5 attack model: K=6 symbols emitted within a narrow burst.
    Run the cluster-width through three values; assert KS p ≤ 0.01 at
    each — the test is strong enough to detect the attack at all three
    cluster scales the FSD considers plausible.
    """
    # Use a fresh seeded RNG per-test so all three params see the same
    # statistical surface (otherwise the global _RNG state diverges
    # across parametrize cases).
    rng = random.Random(99 + int(cluster_width_ratio * 1000))
    a = simulate_clustered(WINDOW_SECONDS, cluster_width_ratio, rng)
    p = _ks_pvalue_uniform(a.times, WINDOW_SECONDS)
    assert p <= 0.01, (
        f"KS test failed its own self-check — clustered arrivals "
        f"(width={cluster_width_ratio * WINDOW_SECONDS:.1f}s of "
        f"{WINDOW_SECONDS}s window) passed the 'NOT clustered' gate "
        f"at p={p:.4f}, which should have rejected. §9 bullet 4 "
        f"discriminative power FAILED — the test cannot tell apart "
        f"the conformant case and the §7.5 attack."
    )


@pytest.mark.ccs
def test_aggregate_pass_rate_over_independent_publications():
    """§9 bullet 4 (aggregate): across many published records, the
    pass-rate of the Poisson scheduler against the "NOT clustered" gate
    is ≥ 95% (the natural rate for a p > 0.01 gate when the null is true
    is 99%; we hold the threshold at 95% to absorb sampling noise on
    n=20 small-sample KS).

    A scheduler that mostly-but-not-always jittered (e.g. a buggy timer
    that occasionally collapsed K symbols into a burst) would fail this
    aggregate gate without failing any single-run test.
    """
    n_records = 200
    pass_count = 0
    for _ in range(n_records):
        a = simulate_poisson_jittered(WINDOW_SECONDS, _RNG)
        if _ks_pvalue_uniform(a.times, WINDOW_SECONDS) > 0.01:
            pass_count += 1
    fraction = pass_count / n_records
    assert fraction >= 0.95, (
        f"only {fraction:.0%} of {n_records} published records passed "
        f"the 'NOT clustered' KS gate — §9 bullet 4 aggregate cover "
        f"posture below the 95% lifetime threshold"
    )


@pytest.mark.ccs
def test_k_repair_subset_uniformly_distributed_too():
    """§7.5 attack lens: the cluster-correlation attack only needs to
    identify K_REPAIR=6 viable symbols out of N_HOLDERS=20. Assert that
    NOT ONLY the full N-symbol arrival set but ALSO every random K-subset
    of size K_REPAIR within it passes the uniform-KS test.

    Why this matters: a scheduler that smears the FIRST few symbols
    widely but bursts the last few would have a uniform N-symbol stream
    but a clustered K-subset. The attacker chooses which K to inspect;
    the substrate must defend EVERY K-subset.

    The Poisson scheduler trivially defends this (every subset of uniform
    samples is itself uniform), but pinning the property prevents a
    future "optimization" that prioritizes the first K differently from
    the last (N-K) from silently sneaking in.
    """
    a = simulate_poisson_jittered(WINDOW_SECONDS, _RNG)
    rng = random.Random(123)
    n_subsets = 50
    pass_count = 0
    for _ in range(n_subsets):
        subset = rng.sample(a.times, K_REPAIR)
        if _ks_pvalue_uniform(subset, WINDOW_SECONDS) > 0.01:
            pass_count += 1
    fraction = pass_count / n_subsets
    # K=6 is a small sample; KS sensitivity drops, so we hold at 80%
    # (more generous than the N=20 aggregate gate — see the test_420
    # KS-power scaling discussion in `docs/SCOPE_PRIVACY_CONFORMANCE.md`).
    assert fraction >= 0.80, (
        f"only {fraction:.0%} of K={K_REPAIR}-subsets passed uniform-KS — "
        f"the §7.5 K-subset cluster defense holds only weakly"
    )
