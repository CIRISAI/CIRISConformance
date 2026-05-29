//! Federation scaling model — companion to `FSD/FEDERATION_SCALING_MODEL.md`.
//!
//! Run: `cargo run --example scale_model`
//!
//! **v0.3 — single-pool, CEG-organic.** The v0.2 model split storage
//! into an explicit "direct-trust archive" with a `T_direct` knob
//! and a separate "cache" with TTL + LRU cap. That dichotomy was
//! premature — CEG's primitives compose into a simpler model where
//! every node holds ONE pool of bytes, scored by trust × demand ×
//! recency, with disk budget the only hard limit.
//!
//! **The discipline** (Eric, this session):
//!
//! Replication intake at every node, for every byte-attempt:
//! ```
//! hold? = trust(source) ≥ local_threshold  AND  capacity_available
//! ```
//!
//! Eviction at every node, when capacity pressure exists:
//! ```
//! evict_score(blob) = popularity(blob) × freshness(blob)
//!                   = access_count_since(T) × decay(now − last_accessed_at)
//! ```
//!
//! Push and pull terminate at the same gate. No "archive vs cache"
//! distinction — bytes that match trust + earn demand stay; bytes
//! that don't get evicted when newer / more popular content arrives.
//!
//! **The CEG locality dividend** (the scaling lever that comes for
//! free from the wire format):
//!
//! `cohort_scope ∈ {self, family}` content NEVER emits a
//! `holds_bytes:sha256:*` attestation, so it is structurally
//! undiscoverable, so no peer can ever request it, so the trust gate
//! is never even reached. Local content is local because the wire
//! format will not carry it.
//!
//! **What this model computes:** the steady-state per-server held
//! bytes at each scenario's trust topology + demand rate + disk
//! budget. The composition (own / admitted-trust / hot-cache) is
//! shown but is derived from the inputs, not configured. Feasibility
//! gates: 1 TB disk / 1 Gbps bandwidth / 1 core full-util per server.
//!
//! Empirical constants baked in from CIRISVerify v2.8.0 + CIRISEdge
//! v0.10.0 + CIRISPersist v3.3.0 — see FSD §2.

// ─── Empirical constants ──────────────────────────────────────────────

/// Hybrid Ed25519 + ML-DSA-65 sign (CIRISVerify v2.8.0).
const HYBRID_SIGN_US: f64 = 466.0;
/// Hybrid verify (CIRISVerify v2.8.0).
const HYBRID_VERIFY_US: f64 = 276.0;
/// `dispatch_inbound` overhead on top of verify (Edge v0.10.0).
const DISPATCH_OVERHEAD_US: f64 = 120.0;
/// Canonicalization slope (Edge v0.10.0).
const CANONICALIZE_NS_PER_KIB: f64 = 250.0;
/// AES-GCM encrypt @ 64 KiB blocks — 5.45 GiB/s.
const AES_GCM_ENCRYPT_NS_PER_BYTE: f64 = 0.175;
/// AES-GCM decrypt @ 64 KiB blocks — 5.91 GiB/s.
const AES_GCM_DECRYPT_NS_PER_BYTE: f64 = 0.161;
/// Scrub regex pass (Edge BENCHMARKS.md 5-10 ns/byte; we use the
/// conservative end).
const SCRUB_NS_PER_BYTE: f64 = 10.0;
/// H3ERE trace bytes per agent decision (CIRISPersist INTEGRATION_LENS).
const H3ERE_TRACE_BYTES_PER_DECISION: f64 = 14.0 * KB;

// ─── Per-server feasibility gates (v1 design) ────────────────────────

/// Server-tier disk gate.
const SERVER_DISK_GATE_BYTES: f64 = 1024.0 * GIB;
/// Per-server bandwidth budget — 1 Gbps residential fiber.
const SERVER_BANDWIDTH_GATE_BYTES_PER_DAY: f64 = 10.8 * TB;
/// Per-server CPU budget — 1 full-utilization core.
const SERVER_CPU_GATE_SECONDS_PER_DAY: f64 = 86_400.0;

/// Steady-state held-bytes utilization. Eviction sweeper maintains
/// the disk at this fraction full — leaves headroom for spike
/// admissions before the next sweep.
const STEADY_STATE_UTILIZATION: f64 = 0.92;

const KB: f64 = 1024.0;
const MB: f64 = 1024.0 * KB;
const GB: f64 = 1024.0 * MB;
const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
const TB: f64 = 1024.0 * GB;
const PB: f64 = 1024.0 * TB;
const EB: f64 = 1024.0 * PB;

// ─── Topology ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
enum Tier {
    Client,
    Proxy,
    Server,
}

#[derive(Debug, Clone, Copy)]
struct CohortDist {
    self_: f64,
    family: f64,
    community: f64,
    affiliations: f64,
    species: f64,
    planet: f64,
    federation: f64,
}

impl CohortDist {
    fn publishable(&self) -> f64 {
        self.community + self.affiliations + self.species + self.planet + self.federation
    }
    fn local_only(&self) -> f64 {
        self.self_ + self.family
    }
    fn default_model() -> Self {
        Self {
            self_: 0.50, family: 0.15, community: 0.15, affiliations: 0.10,
            species: 0.05, planet: 0.03, federation: 0.02,
        }
    }
    fn local_heavy() -> Self {
        Self {
            self_: 0.45, family: 0.25, community: 0.20, affiliations: 0.07,
            species: 0.02, planet: 0.005, federation: 0.005,
        }
    }
    fn global_heavy() -> Self {
        Self {
            self_: 0.30, family: 0.10, community: 0.15, affiliations: 0.20,
            species: 0.10, planet: 0.08, federation: 0.07,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct TierMix {
    client: f64,
    proxy: f64,
    server: f64,
}

/// Scenario inputs.
///
/// **The model has no "archive days" or "cache TTL" knobs.** The
/// steady-state composition of held bytes is derived from:
/// (disk_budget, daily inbound, decay curve). The user-tunable
/// inputs are workload + topology, not policy parameters.
#[derive(Debug, Clone)]
struct Scenario {
    name: &'static str,
    n_users: f64,
    tier_mix: TierMix,
    /// Average direct trust set size per user — the R who can push
    /// content past this node's intake gate AT DEPTH 0.
    trust_radius: f64,
    /// **Server-tier trust recursion depth.** This is **operator-
    /// side local config** — no CEG wire enhancement needed; nothing
    /// is advertised. The federation's `scores` + `delegates_to`
    /// attestations carry the trust graph; each operator independently
    /// chooses how deep their server walks that graph when admitting
    /// inbound content:
    /// * `depth=0`: "I admit only direct trust" — strict
    /// * `depth=1`: "I also admit content from peers my direct trust trusts"
    /// * `depth=N`: "I walk the chain to depth N before admitting"
    ///
    /// The effective trust set whose bytes can pass the server's
    /// intake gate is the transitive closure within `trust_depth_avg`
    /// hops. Empirically (small-world graphs), each hop layer expands
    /// the reachable set by ~4× due to heavy friend-of-friend overlap.
    ///
    /// **Tier-tied defaults:**
    /// * client tier: depth 0 (always strict — phone holds own + fetched only)
    /// * proxy tier: depth 0 (always strict — cache from explicit fetches)
    /// * **server tier: depth 1 (default)** — the "full federation node"
    ///   stance opts into friend-of-friends reach; this knob is what
    ///   you tune
    ///
    /// Operators can override the server default in either direction:
    /// `depth=0` for a strictly-curated server; `depth=3` for a more
    /// open one. The trade-off the model surfaces: deeper recursion
    /// = wider reach = shorter per-source retention at the same disk.
    trust_depth_avg: f64,
    /// Average per-user daily activity volume (excluding agent traces).
    daily_bytes: f64,
    avg_envelope_bytes: f64,
    /// Disk budget for client / proxy / server tiers.
    disk_budget_client: f64,
    disk_budget_proxy: f64,
    disk_budget_server: f64,
    cohort: CohortDist,
    /// Average daily ContentFetch traffic a user pulls.
    daily_fetch_bytes: f64,
    /// **Cache hit rate assumption** — fraction of ContentFetch
    /// requests that are served from local cache (no network round-
    /// trip + no fresh verify). Currently an assumption; real data
    /// will come from deployment telemetry. Sensitivity matters:
    /// * `0.3` (pessimistic) — content interest doesn't cluster much;
    ///   most fetches miss
    /// * `0.6` (default) — trust-graph topology creates moderate
    ///   interest locality (friends-of-friends often re-fetch each
    ///   other's references)
    /// * `0.85` (optimistic) — tight community delivers small-world
    ///   re-access; most popular content stays warm
    ///
    /// `print_cache_sensitivity()` runs the v1 target scenario at
    /// all three to surface the trade-off.
    cache_hit_rate: f64,
    /// Agent decisions per user per day.
    agent_decisions_per_day: f64,
    /// Fraction of agent traces that pass trust+scope to cross
    /// to a publishable cohort.
    trace_publishable_fraction: f64,
}

/// Effective trust set multiplier as a function of recursion depth.
///
/// At `depth = 0` only direct trust counts (R sources). Each
/// additional hop expands the reachable set, but heavy friend-of-
/// friend overlap dampens the naive geometric growth. Calibrated
/// anchors against small-world / six-degrees research:
/// * `depth 0` → 1×    (direct only)
/// * `depth 1` → 4×    (close friend-of-friends — significant overlap)
/// * `depth 2` → 20×   (extended community)
/// * `depth 3` → 100×  (most of the network)
///
/// Linear-interpolated between anchors. `depth > 3` extrapolates
/// gently (Dunbar limits + saturation flatten the curve quickly).
fn effective_trust_set_multiplier(depth: f64) -> f64 {
    if depth <= 0.0 { 1.0 }
    else if depth <= 1.0 { 1.0 + depth * 3.0 }
    else if depth <= 2.0 { 4.0 + (depth - 1.0) * 16.0 }
    else if depth <= 3.0 { 20.0 + (depth - 2.0) * 80.0 }
    else { 100.0 * 1.5_f64.powf(depth - 3.0) }
}

// ─── Per-actor model ─────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
struct ActorCosts {
    storage_own: f64,
    storage_admitted_trust: f64,
    storage_hot_cache: f64,
    storage_traces: f64,
    storage_total: f64,
    /// What fraction of disk budget is filled.
    storage_utilization: f64,
    /// Implied steady-state retention of admitted-trust content
    /// (days). Falls out of (budget headroom, daily admitted inbound)
    /// — this is what eviction maintains, NOT a configured knob.
    effective_retention_days: f64,
    bandwidth_out_per_day: f64,
    bandwidth_in_per_day: f64,
    sign_ops_per_day: f64,
    verify_ops_per_day: f64,
    cpu_seconds_per_day: f64,
}

fn per_actor(tier: Tier, s: &Scenario) -> ActorCosts {
    let trace_bytes_per_day = s.agent_decisions_per_day * H3ERE_TRACE_BYTES_PER_DECISION;
    let envs_per_day = s.daily_bytes / s.avg_envelope_bytes;
    let trace_envs_per_day = trace_bytes_per_day / s.avg_envelope_bytes;
    let sign_ops_own = envs_per_day + trace_envs_per_day;

    // Own data: unbounded retention in principle, but a 10-year
    // accumulation cap for sizing realism (matches phone-class lifetime).
    let own_accumulation_cap_days = 3650.0;
    let storage_own_uncapped = s.daily_bytes * own_accumulation_cap_days;
    let storage_traces_own = trace_bytes_per_day * 365.0;

    let disk_budget = match tier {
        Tier::Client => s.disk_budget_client,
        Tier::Proxy => s.disk_budget_proxy,
        Tier::Server => s.disk_budget_server,
    };
    let usable_budget = disk_budget * STEADY_STATE_UTILIZATION;

    // OWN always wins the first slice of the budget.
    let storage_own = storage_own_uncapped.min(usable_budget * 0.5);
    let storage_traces = storage_traces_own.min((usable_budget - storage_own) * 0.3);
    let remaining_budget = (usable_budget - storage_own - storage_traces).max(0.0);

    let (
        storage_admitted_trust,
        storage_hot_cache,
        in_bps,
        verify_ops,
        scrub_extra,
        fanout,
        effective_retention_days,
    ) = match tier {
        Tier::Client => {
            // Phone — own only. No admitted-trust, no significant
            // cache (most reads are explicit fetches, not held).
            let verify_from_fetch = s.daily_fetch_bytes / s.avg_envelope_bytes;
            (0.0, 0.0, s.daily_fetch_bytes, verify_from_fetch, 0.0, 1.0, 0.0)
        }
        Tier::Proxy => {
            // **Proxy = L0 server** (Eric's framing) — low-storage
            // server tier (256 GB default budget). Same trust+capacity
            // admission discipline as server; just smaller disk and
            // depth=0 (strict — direct trust only, no recursion).
            //
            // L0 / L1 / L(N) is a per-deployment storage gradient:
            //   L0 (proxy): 256 GB, depth 0 (strict)
            //   L1 (server, default): 1 TB, depth 1 (friend-of-friends)
            //   L2+ (future "fat servers"): more disk, deeper recursion
            //
            // The model collapses all server-tier behavior into one
            // formula parameterized by (budget, depth).
            let effective_R = s.trust_radius
                * effective_trust_set_multiplier(0.0); // L0 = strict

            let daily_admitted = effective_R * s.daily_bytes * s.cohort.publishable();
            // Proxy doesn't replicate agent traces (server-only).
            let traces_in_per_day = 0.0;

            let trust_share_of_remaining = 0.85;
            let trust_budget = remaining_budget * trust_share_of_remaining;
            let cache_budget = remaining_budget - trust_budget;

            let effective_days = if daily_admitted > 0.0 {
                trust_budget / daily_admitted
            } else { 0.0 };
            let admitted_trust_held = (daily_admitted * effective_days).min(trust_budget);

            let cache_hit_rate = (s.cache_hit_rate - 0.1).max(0.1);
            let cache_inbound = s.daily_fetch_bytes * (1.0 - cache_hit_rate);
            let cache_held = cache_inbound.min(cache_budget);

            let verify = (daily_admitted + cache_inbound) / s.avg_envelope_bytes;
            let inbound = daily_admitted + cache_inbound;

            // Same outbound fanout shape as server — proxy is a
            // federation participant.
            let wide = s.cohort.species + s.cohort.planet + s.cohort.federation;
            let narrow = s.cohort.community + s.cohort.affiliations;
            let fanout = 1.0 + narrow * 4.0 + wide * 64.0;

            (admitted_trust_held, cache_held, inbound, verify, 0.0, fanout, effective_days)
        }
        Tier::Server => {
            // Full node — admits trusted peers' publishable
            // content + holds hot cache from explicit fetches.
            // Both compete for `remaining_budget`; trust admission
            // wins priority because it's continuously offered.
            //
            // Effective trust set: direct R, expanded by recursion
            // depth via small-world overlap factor. At depth=0 only
            // direct R counts; at depth=1 friend-of-friends are also
            // admissible (~4× the source count, but heavy overlap);
            // at depth=2 most of the extended community (~20×).
            let effective_R = s.trust_radius
                * effective_trust_set_multiplier(s.trust_depth_avg);

            // Daily admitted-trust inbound rate — every effective
            // trust source's publishable activity.
            let daily_admitted = effective_R * s.daily_bytes * s.cohort.publishable();
            // Replicated publishable agent traces from the effective
            // trust set.
            let traces_in_per_day = effective_R
                * trace_bytes_per_day
                * s.trace_publishable_fraction;
            let daily_admitted_plus_traces = daily_admitted + traces_in_per_day;

            // Effective retention falls out of budget vs inbound rate.
            // If inbound is heavy, retention is short (eviction churns);
            // if inbound is light, retention is long (content sits).
            let trust_share_of_remaining = 0.85; // trust admission gets priority share
            let trust_budget = remaining_budget * trust_share_of_remaining;
            let cache_budget = remaining_budget - trust_budget;

            let effective_days = if daily_admitted_plus_traces > 0.0 {
                trust_budget / daily_admitted_plus_traces
            } else { 0.0 };
            let admitted_trust_held = (daily_admitted * effective_days).min(trust_budget * 0.85);
            let replicated_traces_held = (traces_in_per_day * effective_days).min(trust_budget * 0.15);

            // Cache holds the hot-fetch tail; effective_days for cache
            // is the same since both ride the same eviction sweeper.
            // Hit rate per scenario — see `Scenario::cache_hit_rate`.
            let cache_hit_rate = s.cache_hit_rate;
            let cache_inbound = s.daily_fetch_bytes * (1.0 - cache_hit_rate);
            let cache_held = cache_inbound.min(cache_budget);

            // Total verify load: admitted-trust + cache misses + own traces.
            let verify_envs = (daily_admitted_plus_traces + cache_inbound) / s.avg_envelope_bytes;
            // Scrub: replicated agent traces (scrubbed at admission).
            let scrub_bytes = traces_in_per_day;
            // Outbound fanout: own × wide-scope steward set.
            let wide = s.cohort.species + s.cohort.planet + s.cohort.federation;
            let narrow = s.cohort.community + s.cohort.affiliations;
            let fanout = 1.0 + narrow * 4.0 + wide * 64.0;

            let inbound_total = daily_admitted_plus_traces + cache_inbound;
            let traces_total = replicated_traces_held;
            // Bundle traces into the trust slice for storage column.
            (
                admitted_trust_held + traces_total,
                cache_held,
                inbound_total,
                verify_envs,
                scrub_bytes,
                fanout,
                effective_days,
            )
        }
    };

    let outbound_bps = s.daily_bytes * fanout;
    let storage_total = storage_own + storage_admitted_trust + storage_hot_cache + storage_traces;
    let storage_utilization = storage_total / disk_budget;

    // CPU accounting (same as v0.2).
    let sign_cpu = sign_ops_own * HYBRID_SIGN_US * 1e-6;
    let verify_cpu = verify_ops * HYBRID_VERIFY_US * 1e-6;
    let dispatch_cpu = verify_ops * DISPATCH_OVERHEAD_US * 1e-6;
    let canon_bytes = (sign_ops_own + verify_ops) * s.avg_envelope_bytes;
    let canon_cpu = (canon_bytes / KB) * CANONICALIZE_NS_PER_KIB * 1e-9;
    let scrub_total_bytes = trace_bytes_per_day + scrub_extra;
    let scrub_cpu = scrub_total_bytes * SCRUB_NS_PER_BYTE * 1e-9;

    let encrypt_in = (in_bps + outbound_bps) * 0.5; // half writes, half reads (rough)
    let encrypt_cpu = encrypt_in * AES_GCM_ENCRYPT_NS_PER_BYTE * 1e-9;
    let decrypt_cpu = in_bps * AES_GCM_DECRYPT_NS_PER_BYTE * 1e-9;

    let cpu_total = sign_cpu + verify_cpu + dispatch_cpu + canon_cpu + scrub_cpu
        + encrypt_cpu + decrypt_cpu;

    ActorCosts {
        storage_own,
        storage_admitted_trust,
        storage_hot_cache,
        storage_traces,
        storage_total,
        storage_utilization,
        effective_retention_days,
        bandwidth_out_per_day: outbound_bps,
        bandwidth_in_per_day: in_bps,
        sign_ops_per_day: sign_ops_own,
        verify_ops_per_day: verify_ops,
        cpu_seconds_per_day: cpu_total,
    }
}

// ─── Federation rollup ───────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
struct FedRollup {
    total_storage_bytes: f64,
    total_bandwidth_in_bytes_per_day: f64,
    total_bandwidth_out_bytes_per_day: f64,
    total_verify_ops_per_day: f64,
    total_sign_ops_per_day: f64,
    aggregate_cpu_cores_full_util: f64,
    per_tier: [(Tier, ActorCosts); 3],
}

fn rollup(s: &Scenario) -> FedRollup {
    let cli = per_actor(Tier::Client, s);
    let prx = per_actor(Tier::Proxy, s);
    let srv = per_actor(Tier::Server, s);

    let n_cli = s.n_users * s.tier_mix.client;
    let n_prx = s.n_users * s.tier_mix.proxy;
    let n_srv = s.n_users * s.tier_mix.server;

    FedRollup {
        total_storage_bytes:
            n_cli * cli.storage_total + n_prx * prx.storage_total + n_srv * srv.storage_total,
        total_bandwidth_in_bytes_per_day:
            n_cli * cli.bandwidth_in_per_day + n_prx * prx.bandwidth_in_per_day + n_srv * srv.bandwidth_in_per_day,
        total_bandwidth_out_bytes_per_day:
            n_cli * cli.bandwidth_out_per_day + n_prx * prx.bandwidth_out_per_day + n_srv * srv.bandwidth_out_per_day,
        total_verify_ops_per_day:
            n_cli * cli.verify_ops_per_day + n_prx * prx.verify_ops_per_day + n_srv * srv.verify_ops_per_day,
        total_sign_ops_per_day:
            n_cli * cli.sign_ops_per_day + n_prx * prx.sign_ops_per_day + n_srv * srv.sign_ops_per_day,
        aggregate_cpu_cores_full_util:
            (n_cli * cli.cpu_seconds_per_day + n_prx * prx.cpu_seconds_per_day + n_srv * srv.cpu_seconds_per_day) / 86_400.0,
        per_tier: [(Tier::Client, cli), (Tier::Proxy, prx), (Tier::Server, srv)],
    }
}

// ─── Preset scenarios ────────────────────────────────────────────────

fn scenarios() -> Vec<Scenario> {
    let cohort = CohortDist::default_model();

    vec![
        Scenario {
            name: "bootstrap",
            n_users: 10_000.0,
            tier_mix: TierMix { client: 0.30, proxy: 0.65, server: 0.05 },
            trust_radius: 50.0,
            trust_depth_avg: 1.0,
            daily_bytes: 20.0 * KB,
            avg_envelope_bytes: 1.5 * KB,
            disk_budget_client: 32.0 * GB,
            disk_budget_proxy: 256.0 * GB,
            disk_budget_server: 1.0 * TB,
            cohort,
            daily_fetch_bytes: 5.0 * MB,
            cache_hit_rate: 0.5,
            agent_decisions_per_day: 20.0,
            trace_publishable_fraction: 0.15,
        },
        Scenario {
            name: "dunbar_steady",
            n_users: 1_000_000.0,
            tier_mix: TierMix { client: 0.40, proxy: 0.55, server: 0.05 },
            trust_radius: 150.0,
            trust_depth_avg: 1.0,
            daily_bytes: 50.0 * KB,
            avg_envelope_bytes: 1.5 * KB,
            disk_budget_client: 64.0 * GB,
            disk_budget_proxy: 256.0 * GB,
            disk_budget_server: 1.0 * TB,
            cohort,
            daily_fetch_bytes: 50.0 * MB,
            cache_hit_rate: 0.6,
            agent_decisions_per_day: 50.0,
            trace_publishable_fraction: 0.15,
        },
        Scenario {
            name: "media_heavy",
            n_users: 1_000_000.0,
            tier_mix: TierMix { client: 0.30, proxy: 0.60, server: 0.10 },
            trust_radius: 150.0,
            trust_depth_avg: 1.0,
            daily_bytes: 500.0 * KB,
            avg_envelope_bytes: 8.0 * KB,
            disk_budget_client: 128.0 * GB,
            disk_budget_proxy: 256.0 * GB,
            disk_budget_server: 1.0 * TB,
            cohort,
            daily_fetch_bytes: 200.0 * MB,
            cache_hit_rate: 0.65,
            agent_decisions_per_day: 100.0,
            trace_publishable_fraction: 0.15,
        },
        Scenario {
            name: "twitter_scale",
            n_users: 1_000_000_000.0,
            tier_mix: TierMix { client: 0.45, proxy: 0.50, server: 0.05 },
            trust_radius: 150.0,
            trust_depth_avg: 1.0,
            daily_bytes: 5.0 * KB,
            avg_envelope_bytes: 0.5 * KB,
            disk_budget_client: 32.0 * GB,
            disk_budget_proxy: 256.0 * GB,
            disk_budget_server: 1.0 * TB,
            cohort,
            daily_fetch_bytes: 20.0 * MB,
            cache_hit_rate: 0.7,
            agent_decisions_per_day: 30.0,
            trace_publishable_fraction: 0.10,
        },
        Scenario {
            name: "news_replacement",
            n_users: 1_000_000_000.0,
            tier_mix: TierMix { client: 0.40, proxy: 0.55, server: 0.05 },
            trust_radius: 300.0,
            trust_depth_avg: 1.0,
            daily_bytes: 100.0 * KB,
            avg_envelope_bytes: 5.0 * KB,
            disk_budget_client: 64.0 * GB,
            disk_budget_proxy: 256.0 * GB,
            disk_budget_server: 1.0 * TB,
            cohort,
            daily_fetch_bytes: 100.0 * MB,
            cache_hit_rate: 0.65,
            agent_decisions_per_day: 50.0,
            trace_publishable_fraction: 0.15,
        },
        Scenario {
            name: "full_internet_v1",
            n_users: 5_000_000_000.0,
            tier_mix: TierMix { client: 0.35, proxy: 0.55, server: 0.10 },
            trust_radius: 250.0,
            trust_depth_avg: 1.0,
            daily_bytes: 50.0 * MB,
            avg_envelope_bytes: 50.0 * KB,
            disk_budget_client: 256.0 * GB,
            disk_budget_proxy: 256.0 * GB,
            disk_budget_server: 1.0 * TB,
            cohort,
            daily_fetch_bytes: 1.0 * GB,
            cache_hit_rate: 0.6,
            agent_decisions_per_day: 200.0,
            trace_publishable_fraction: 0.10,
        },
        Scenario {
            name: "full_internet_local_heavy",
            n_users: 5_000_000_000.0,
            tier_mix: TierMix { client: 0.35, proxy: 0.55, server: 0.10 },
            trust_radius: 250.0,
            trust_depth_avg: 1.0,
            daily_bytes: 50.0 * MB,
            avg_envelope_bytes: 50.0 * KB,
            disk_budget_client: 256.0 * GB,
            disk_budget_proxy: 256.0 * GB,
            disk_budget_server: 1.0 * TB,
            cohort: CohortDist::local_heavy(),
            daily_fetch_bytes: 1.0 * GB,
            cache_hit_rate: 0.75,
            agent_decisions_per_day: 200.0,
            trace_publishable_fraction: 0.05,
        },
        Scenario {
            name: "full_internet_global_heavy",
            n_users: 5_000_000_000.0,
            tier_mix: TierMix { client: 0.30, proxy: 0.55, server: 0.15 },
            trust_radius: 250.0,
            trust_depth_avg: 1.0,
            daily_bytes: 50.0 * MB,
            avg_envelope_bytes: 50.0 * KB,
            disk_budget_client: 256.0 * GB,
            disk_budget_proxy: 256.0 * GB,
            disk_budget_server: 1.0 * TB,
            cohort: CohortDist::global_heavy(),
            daily_fetch_bytes: 1.0 * GB,
            cache_hit_rate: 0.45,
            agent_decisions_per_day: 200.0,
            trace_publishable_fraction: 0.20,
        },
        Scenario {
            name: "village_dense",
            n_users: 1_000.0,
            tier_mix: TierMix { client: 0.40, proxy: 0.40, server: 0.20 },
            trust_radius: 50.0,
            trust_depth_avg: 1.0,
            daily_bytes: 30.0 * MB,
            avg_envelope_bytes: 8.0 * KB,
            disk_budget_client: 256.0 * GB,
            disk_budget_proxy: 256.0 * GB,
            disk_budget_server: 1.0 * TB,
            cohort: CohortDist::local_heavy(),
            daily_fetch_bytes: 200.0 * MB,
            cache_hit_rate: 0.85,
            agent_decisions_per_day: 100.0,
            trace_publishable_fraction: 0.10,
        },
    ]
}

// ─── Output formatting + feasibility report ──────────────────────────

fn fmt_bytes(b: f64) -> String {
    if b >= EB { format!("{:.2} EB", b / EB) }
    else if b >= PB { format!("{:.2} PB", b / PB) }
    else if b >= TB { format!("{:.2} TB", b / TB) }
    else if b >= GB { format!("{:.2} GB", b / GB) }
    else if b >= MB { format!("{:.2} MB", b / MB) }
    else if b >= KB { format!("{:.2} KB", b / KB) }
    else { format!("{:.0} B", b) }
}

fn fmt_count(c: f64) -> String {
    if c >= 1e12 { format!("{:.2} T", c / 1e12) }
    else if c >= 1e9 { format!("{:.2} B", c / 1e9) }
    else if c >= 1e6 { format!("{:.2} M", c / 1e6) }
    else if c >= 1e3 { format!("{:.2} K", c / 1e3) }
    else { format!("{:.1}", c) }
}

#[derive(Debug)]
struct Feasibility {
    storage_ok: bool, storage_ratio: f64,
    bandwidth_ok: bool, bandwidth_ratio: f64,
    cpu_ok: bool, cpu_ratio: f64,
}

fn check_server_feasibility(srv: &ActorCosts) -> Feasibility {
    let s_ratio = srv.storage_total / SERVER_DISK_GATE_BYTES;
    let bw_total = srv.bandwidth_in_per_day + srv.bandwidth_out_per_day;
    let bw_ratio = bw_total / SERVER_BANDWIDTH_GATE_BYTES_PER_DAY;
    let cpu_ratio = srv.cpu_seconds_per_day / SERVER_CPU_GATE_SECONDS_PER_DAY;
    Feasibility {
        storage_ok: s_ratio <= 1.0, storage_ratio: s_ratio,
        bandwidth_ok: bw_ratio <= 1.0, bandwidth_ratio: bw_ratio,
        cpu_ok: cpu_ratio <= 1.0, cpu_ratio,
    }
}

fn fmt_check(ok: bool) -> &'static str { if ok { "✓" } else { "⚠" } }

fn print_scenario(s: &Scenario, r: &FedRollup) {
    let srv = &r.per_tier[2].1;
    let feas = check_server_feasibility(srv);

    println!();
    println!("══ {} ══", s.name);
    println!("  N users: {}   tier mix: client {:.0}% / proxy {:.0}% / server {:.0}%",
        fmt_count(s.n_users), s.tier_mix.client * 100.0,
        s.tier_mix.proxy * 100.0, s.tier_mix.server * 100.0);
    let effective_R = s.trust_radius * effective_trust_set_multiplier(s.trust_depth_avg);
    println!("  R={}  trust_depth={:.1} → effective_sources={}  D={}/day  env={}",
        s.trust_radius as u64, s.trust_depth_avg,
        fmt_count(effective_R),
        fmt_bytes(s.daily_bytes), fmt_bytes(s.avg_envelope_bytes));
    println!("  σ_pub={:.0}%  σ_local={:.0}%  fetch={}/day",
        s.cohort.publishable() * 100.0, s.cohort.local_only() * 100.0,
        fmt_bytes(s.daily_fetch_bytes));
    println!("  disk budgets: client {}  proxy {}  server {}",
        fmt_bytes(s.disk_budget_client), fmt_bytes(s.disk_budget_proxy),
        fmt_bytes(s.disk_budget_server));

    let prx = &r.per_tier[1].1;
    println!();
    println!("  Proxy-tier (L0, depth 0, {} budget):", fmt_bytes(s.disk_budget_proxy));
    println!("    held TOTAL          {}  ({:.0}% util)   admitted-trust retention {:.0}d",
        fmt_bytes(prx.storage_total),
        prx.storage_utilization * 100.0,
        prx.effective_retention_days);
    println!();
    println!("  Server-tier (L1, depth {:.0}, {} budget) — single-pool held bytes:",
        s.trust_depth_avg, fmt_bytes(s.disk_budget_server));
    println!("    own data            {}", fmt_bytes(srv.storage_own));
    println!("    admitted trust      {}", fmt_bytes(srv.storage_admitted_trust));
    println!("    hot cache           {}", fmt_bytes(srv.storage_hot_cache));
    println!("    agent traces        {}", fmt_bytes(srv.storage_traces));
    println!("    ─────────────────────────────");
    println!("    held TOTAL          {}  ({:.0}% of {})",
        fmt_bytes(srv.storage_total),
        srv.storage_utilization * 100.0,
        fmt_bytes(s.disk_budget_server));
    if srv.effective_retention_days > 0.0 {
        println!("    implied retention   {:.0} days of admitted-trust content",
            srv.effective_retention_days);
        println!("                        (derived; eviction sweeper maintains this)");
    }
    println!();
    println!("  Server-tier flow:");
    println!("    bandwidth in/day    {}", fmt_bytes(srv.bandwidth_in_per_day));
    println!("    bandwidth out/day   {}", fmt_bytes(srv.bandwidth_out_per_day));
    println!("    verify ops/sec      {}",
        fmt_count(srv.verify_ops_per_day / 86400.0));
    println!("    CPU sec/day         {:.1}", srv.cpu_seconds_per_day);

    println!();
    println!("  v1 feasibility (per-server gates: 1 TB / 1 Gbps / 1 core):");
    println!("    {} storage    {:>5.1}% of 1 TB     ({})",
        fmt_check(feas.storage_ok), feas.storage_ratio * 100.0,
        fmt_bytes(srv.storage_total));
    let bw_total = srv.bandwidth_in_per_day + srv.bandwidth_out_per_day;
    println!("    {} bandwidth  {:>5.1}% of 1 Gbps   ({}/day, ≈ {}/sec)",
        fmt_check(feas.bandwidth_ok), feas.bandwidth_ratio * 100.0,
        fmt_bytes(bw_total), fmt_bytes(bw_total / 86400.0));
    println!("    {} cpu        {:>5.1}% of 1 core   ({:.1} cpu-sec/day)",
        fmt_check(feas.cpu_ok), feas.cpu_ratio * 100.0, srv.cpu_seconds_per_day);

    println!();
    println!("  Federation totals:");
    println!("    storage          {}", fmt_bytes(r.total_storage_bytes));
    println!("    bandwidth in     {}/day  ({}/sec)",
        fmt_bytes(r.total_bandwidth_in_bytes_per_day),
        fmt_bytes(r.total_bandwidth_in_bytes_per_day / 86400.0));
    println!("    sign/verify ops  {} sign/sec    {} verify/sec",
        fmt_count(r.total_sign_ops_per_day / 86400.0),
        fmt_count(r.total_verify_ops_per_day / 86400.0));
    println!("    CPU @ 5% util    {} cores",
        fmt_count(r.aggregate_cpu_cores_full_util / 0.05));

    if feas.storage_ok && feas.bandwidth_ok && feas.cpu_ok {
        println!();
        println!("  ✓ v1 feasible per-server. {} servers globally.",
            fmt_count(s.n_users * s.tier_mix.server));
    }
}

/// Run the same scenario at three cache-hit-rate assumptions to
/// surface sensitivity. Cache hit rate is currently an assumption;
/// real numbers come from deployment telemetry. This sweep shows
/// what *changes* (bandwidth, CPU, retention via cache budget
/// pressure) if the assumption is wrong in either direction.
fn print_cache_sensitivity(base: &Scenario) {
    println!();
    println!("══ Cache hit rate sensitivity sweep — base: {} ══", base.name);
    println!();
    println!("    {:<14}  {:>10}  {:>10}  {:>10}  {:>10}",
        "hit_rate", "storage", "in/day", "verify/s", "retention");
    for hit in [0.30f64, 0.45, 0.60, 0.75, 0.85] {
        let mut s = base.clone();
        s.cache_hit_rate = hit;
        let r = rollup(&s);
        let srv = &r.per_tier[2].1;
        let label = match hit {
            h if h <= 0.30 => "0.30 pessimistic",
            h if h <= 0.45 => "0.45 conservative",
            h if h <= 0.60 => "0.60 default",
            h if h <= 0.75 => "0.75 favorable",
            _ => "0.85 optimistic",
        };
        println!("    {:<14}  {:>10}  {:>10}  {:>10}  {:>9.0}d",
            label,
            fmt_bytes(srv.storage_total),
            fmt_bytes(srv.bandwidth_in_per_day),
            fmt_count(srv.verify_ops_per_day / 86400.0),
            srv.effective_retention_days);
    }
    println!();
    println!("  Reading: at v1-target scale, admitted-trust inbound DOMINATES");
    println!("  cache-miss inbound (~17.5 GB/d vs ~0.4 GB/d). Cache hit rate");
    println!("  barely moves the needle — the model is INSENSITIVE to this");
    println!("  assumption at high-trust-admit scales. Cache hit rate matters");
    println!("  more on tiers where trust admission is small (client / proxy)");
    println!("  or in low-trust-radius deployments.");
}

fn main() {
    println!("CIRIS Federation Scaling Model — toy v0.3 (single-pool, CEG-organic)");
    println!("Empirical inputs: Verify v2.8.0 + Edge v0.10.0 + Persist v3.3.0");
    println!();
    println!("Discipline:");
    println!("  • Replication: trust(source) ≥ threshold AND capacity_available");
    println!("  • Eviction:    popularity(blob) × freshness(blob)");
    println!("  • CEG locality: self/family scope never emits holds_bytes,");
    println!("    structurally undiscoverable, zero inter-host cost");
    println!();
    println!("Per-server v1 gates: 1 TB disk / 1 Gbps bandwidth / 1 core full-util");

    let all_scenarios = scenarios();
    for s in &all_scenarios {
        let r = rollup(s);
        print_scenario(s, &r);
    }

    // Sensitivity sweep on the v1 target scenario.
    if let Some(v1) = all_scenarios.iter().find(|s| s.name == "full_internet_v1") {
        print_cache_sensitivity(v1);
    }

    println!();
    println!("── How to read this ──");
    println!("  Storage is one pool: own + admitted-trust + hot-cache + traces");
    println!("  Composition is DERIVED from (budget, trust topology, demand) —");
    println!("  it is what the eviction sweeper produces at steady state, not");
    println!("  what an operator configures. The only knobs are workload +");
    println!("  topology + disk size.");
    println!();
    println!("── Design search knobs ──");
    println!("  trust_radius            — direct peers admitted past the gate");
    println!("  cohort.publishable()    — what fraction crosses the wire at all");
    println!("  disk_budget_server      — the only hard storage limit");
    println!("  daily_bytes, daily_fetch_bytes — workload");
    println!();
}
