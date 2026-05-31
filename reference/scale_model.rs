//! Federation scaling model — companion to `FSD/FEDERATION_SCALING_MODEL.md`.
//!
//! Run: `cargo run --example scale_model`
//!
//! **v0.6 — post Verify Fed TM v1.1.** Adversarial findings module
//! (added in v0.5) updated to reflect Verify Fed TM v1.1 (2026-05-31):
//! 3 of 4 §3.3 structural gaps closed in one shipping cycle (Gap A R1
//! timeliness + Gap B Q1 CAP specified; Gap C C4 KEX shipped in
//! v4.6.0 as X25519 + ML-KEM-768). F-AV-RECONSIDER-DOS promoted from
//! candidate to catalog §6.5 with the v0.5 toy's cost-asymmetry
//! numbers cited verbatim in the TM entry. Three downstream
//! enforcement issues filed (CIRISPersist#143 + CIRISRegistry#46 +
//! CIRISNodeCore#28) + CIRISConformance#7 umbrella for the three new
//! regression scenarios. Only Gap D (N1+N2 Edge transport) remains.
//!
//! **v0.4 — device classes + 9-region realism.** Extends v0.3's
//! single-pool CEG-organic model with:
//!
//!   1. **Device-class power accounting** — phones / laptops / tablets /
//!      ARM mini-PCs / home x86 / old desktops, each with per-class
//!      idle_W, marginal_share, always_on_factor, efficiency_factor,
//!      and net_new flag. Replaces an implicit "50 W per server"
//!      constant with truer numbers per device class.
//!   2. **Fleet styles** — `PhoneFirst` / `Realistic2026` / `Homelab`
//!      presets for the device mix per tier.
//!   3. **9 GSMA-aligned regions** with real 2024-2026 data:
//!      population (UN WPP 2024 medium variant), smartphone penetration
//!      (GSMA Mobile Economy 2024), broadband reach (ITU 2024 + Speedtest),
//!      grid CO2 intensity (IEA 2024 weighted regional avg), and
//!      derived home-server-capable fraction. Per-region tier mix is
//!      computed from these, not hand-set.
//!   4. **Environmental footprint** — internet (datacenter-counted)
//!      vs CEWP (device-class-counted, marginal-share-discounted).
//!   5. **Latency model** — first-order p50 RTT estimate for CEWP vs
//!      centralized internet, decomposed into cache + local hop +
//!      regional + global + trust-depth + sparseness penalty.
//!   6. **Retention floor gate** — soft feasibility failure if the
//!      admitted-trust pool churns under 2 days.
//!
//! v0.3 was single-pool CEG-organic — every node holds ONE pool of
//! bytes, scored by trust × demand × recency, disk budget the only
//! hard limit. The v0.2 model split storage into "direct-trust
//! archive" with a `T_direct` knob and a separate "cache" with TTL +
//! LRU cap; that dichotomy was premature.
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

// ─── Environment (energy + CO2) ────────────────────────────────────
//
// Numbers are rough; the toy shows the math so anyone can dispute the
// inputs. Sources cited inline. Tracks two perspectives in parallel:
//
//   1. Centralized internet substrate today — datacenter-counted.
//      Calibrated against IEA's 2024 global DC electricity estimate
//      (~415 TWh/yr) at 5 B users.
//
//   2. CEWP substrate — device-class-counted. Most participation
//      rides hardware that's already on for other reasons (phones,
//      laptops); marginal power per device, not full draw.

const HOURS_PER_YEAR: f64 = 8760.0;
const TODAY_DC_COUNT_AT_5B: f64 = 10_000.0;
const HYPERSCALE_DC_AVG_MW: f64 = 5.0;
const DC_FLOOR: f64 = 100.0;
const GLOBAL_GRID_CO2_KG_PER_KWH: f64 = 0.40; // IEA global avg 2023

// 30-50% of today's substrate spend goes to value extraction
// (ad targeting, recommender training, surveillance analytics, A/B
// test platforms). SemiAnalysis ML breakdowns at large ad-funded
// platforms show 30-50% of accelerator hours on personalization /
// targeting workloads; Sandvine 2024 traffic dominated by
// recommender-driven content. CEWP removes this layer
// architecturally — every joule it spends goes to the user's actual
// task.
#[allow(dead_code)]
const EXTRACTION_OVERHEAD: f64 = 0.40;

// Retention floor — if the trust pool churns faster than 2 days, the
// server is mostly a pass-through cache. Feasibility-failure soft gate.
const RETENTION_FLOOR_DAYS: f64 = 2.0;

// ─── Device class model ──────────────────────────────────────────────
//
// Replaces the implicit "50W per server" constant with per-class
// energy accounting. Ported + extended from the website's lib/model.ts
// device-class table. Each class carries:
//
//   - idle_W: typical continuous idle draw
//   - marginal_share: fraction attributable to CEWP vs the device's
//     primary purpose. A phone running a CEWP client costs ~5% of its
//     idle draw, not 100% — the human is already paying the rest.
//   - always_on_factor: fraction of the day the device is reachable
//     (no sleep, no NAT). Phones float around 15%; ARM mini-PCs are
//     100%. Multiplies into per-device storage / fanout utility.
//   - efficiency_factor: useful-work-per-watt vs hyperscale baseline
//     (1.0). Commodity SoCs at low utilization are worse than a
//     custom-silicon facility with PUE 1.1 and pooled cooling.
//   - net_new: does the participant need to buy new hardware?
//   - typical_storage_gb: stock storage capacity on the device class
//   - typical_uplink_mbps: stock uplink available to the device
//     class on its dominant connectivity tier

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum DeviceClass {
    Phone,
    Laptop,
    Tablet,
    ArmBox,
    HomeX86,
    OldDesktop,
}

#[derive(Debug, Clone, Copy)]
struct DeviceSpec {
    label: &'static str,
    idle_w: f64,
    marginal_share: f64,
    always_on_factor: f64,
    efficiency_factor: f64,
    net_new: bool,
    typical_storage_gb: f64,
    typical_uplink_mbps: f64,
}

fn device_spec(c: DeviceClass) -> DeviceSpec {
    match c {
        DeviceClass::Phone => DeviceSpec {
            label: "phone", idle_w: 2.5, marginal_share: 0.05,
            always_on_factor: 0.15, efficiency_factor: 0.5, net_new: false,
            typical_storage_gb: 128.0, typical_uplink_mbps: 25.0,
        },
        DeviceClass::Laptop => DeviceSpec {
            label: "laptop", idle_w: 10.0, marginal_share: 0.10,
            always_on_factor: 0.20, efficiency_factor: 0.4, net_new: false,
            typical_storage_gb: 512.0, typical_uplink_mbps: 100.0,
        },
        DeviceClass::Tablet => DeviceSpec {
            label: "tablet", idle_w: 5.0, marginal_share: 0.07,
            always_on_factor: 0.10, efficiency_factor: 0.45, net_new: false,
            typical_storage_gb: 128.0, typical_uplink_mbps: 50.0,
        },
        DeviceClass::ArmBox => DeviceSpec {
            label: "ARM mini-PC", idle_w: 5.0, marginal_share: 1.0,
            always_on_factor: 1.0, efficiency_factor: 0.6, net_new: true,
            typical_storage_gb: 1024.0, typical_uplink_mbps: 1000.0,
        },
        DeviceClass::HomeX86 => DeviceSpec {
            label: "home x86", idle_w: 25.0, marginal_share: 1.0,
            always_on_factor: 1.0, efficiency_factor: 0.4, net_new: true,
            typical_storage_gb: 4096.0, typical_uplink_mbps: 1000.0,
        },
        DeviceClass::OldDesktop => DeviceSpec {
            label: "old desktop", idle_w: 60.0, marginal_share: 1.0,
            always_on_factor: 1.0, efficiency_factor: 0.2, net_new: false,
            typical_storage_gb: 1024.0, typical_uplink_mbps: 200.0,
        },
    }
}

/// Per-tier device composition. Fractions in each tier sum to ~1.0.
#[derive(Debug, Clone)]
struct DeviceMix {
    items: Vec<(DeviceClass, f64)>,
}

impl DeviceMix {
    fn new(items: &[(DeviceClass, f64)]) -> Self {
        Self { items: items.to_vec() }
    }
}

/// Fleet styles — global presets for the device mix across all three
/// tiers. Clients and proxies are mostly phones in every style;
/// phones don't dominate the L1 mix because they're poor at
/// always-on reachability.
#[derive(Debug, Clone, Copy)]
enum FleetStyle {
    PhoneFirst,
    Realistic2026,
    Homelab,
}

fn fleet_mix(style: FleetStyle, tier: Tier) -> DeviceMix {
    use DeviceClass::*;
    match (style, tier) {
        (FleetStyle::PhoneFirst, Tier::Client) =>
            DeviceMix::new(&[(Phone, 0.95), (Laptop, 0.05)]),
        (FleetStyle::PhoneFirst, Tier::Proxy) =>
            DeviceMix::new(&[(Phone, 0.70), (Laptop, 0.30)]),
        (FleetStyle::PhoneFirst, Tier::Server) =>
            DeviceMix::new(&[(Phone, 0.05), (Laptop, 0.15), (ArmBox, 0.70), (HomeX86, 0.05), (OldDesktop, 0.05)]),
        (FleetStyle::Realistic2026, Tier::Client) =>
            DeviceMix::new(&[(Phone, 0.85), (Laptop, 0.15)]),
        (FleetStyle::Realistic2026, Tier::Proxy) =>
            DeviceMix::new(&[(Phone, 0.50), (Laptop, 0.40), (ArmBox, 0.10)]),
        (FleetStyle::Realistic2026, Tier::Server) =>
            DeviceMix::new(&[(Phone, 0.05), (Laptop, 0.20), (ArmBox, 0.40), (HomeX86, 0.25), (OldDesktop, 0.10)]),
        (FleetStyle::Homelab, Tier::Client) =>
            DeviceMix::new(&[(Phone, 0.70), (Laptop, 0.30)]),
        (FleetStyle::Homelab, Tier::Proxy) =>
            DeviceMix::new(&[(Phone, 0.30), (Laptop, 0.40), (ArmBox, 0.30)]),
        (FleetStyle::Homelab, Tier::Server) =>
            DeviceMix::new(&[(Laptop, 0.10), (ArmBox, 0.30), (HomeX86, 0.45), (OldDesktop, 0.15)]),
    }
}

// ─── Regional realism ────────────────────────────────────────────────
//
// Nine GSMA-aligned regions with real 2024-2026 data. The website's
// model assumes a uniform global pool; in reality smartphone
// penetration, broadband reach, and grid CO2 differ by an order of
// magnitude across the world.
//
// **Sources** (all rough — uncertainty bars are wide):
//   - Population 2026: UN World Population Prospects 2024 medium variant
//   - Smartphone penetration: GSMA Mobile Economy reports 2024
//   - Broadband reach (4G+ or fixed ≥ 25 Mbps): ITU + Speedtest Global Index 2024
//   - Grid CO2: IEA 2024 Energy Statistics, regional weighted average

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Region {
    NorthAmerica,
    Europe,
    EastAsia,
    SouthAsia,
    SoutheastAsia,
    Mena,            // Middle East + North Africa
    SubSaharanAfrica,
    LatinAmerica,
    Oceania,
}

#[derive(Debug, Clone, Copy)]
struct RegionStats {
    label: &'static str,
    population_2026: f64,          // millions (UN WPP 2024 medium variant)
    smartphone_penetration: f64,   // fraction with smartphones (GSMA 2024)
    broadband_penetration: f64,    // 4G+ or fixed ≥ 25 Mbps (ITU 2024)
    grid_co2_kg_per_kwh: f64,      // regional grid intensity (IEA 2024)
    /// Fraction of population realistically capable of hosting an
    /// always-on L1 server — needs phone/PC + persistent broadband +
    /// stable grid power. Conservative under-estimate.
    home_server_capable: f64,
}

fn region_stats(r: Region) -> RegionStats {
    match r {
        Region::NorthAmerica => RegionStats {
            label: "North America", population_2026: 378.0,
            smartphone_penetration: 0.85, broadband_penetration: 0.82,
            grid_co2_kg_per_kwh: 0.38, home_server_capable: 0.75,
        },
        Region::Europe => RegionStats {
            label: "Europe", population_2026: 743.0,
            smartphone_penetration: 0.83, broadband_penetration: 0.77,
            grid_co2_kg_per_kwh: 0.27, home_server_capable: 0.70,
        },
        Region::EastAsia => RegionStats {
            label: "East Asia", population_2026: 1660.0,
            smartphone_penetration: 0.79, broadband_penetration: 0.73,
            grid_co2_kg_per_kwh: 0.51, home_server_capable: 0.65,
        },
        Region::SouthAsia => RegionStats {
            label: "South Asia", population_2026: 2010.0,
            smartphone_penetration: 0.61, broadband_penetration: 0.42,
            grid_co2_kg_per_kwh: 0.71, home_server_capable: 0.25,
        },
        Region::SoutheastAsia => RegionStats {
            label: "Southeast Asia", population_2026: 695.0,
            smartphone_penetration: 0.70, broadband_penetration: 0.55,
            grid_co2_kg_per_kwh: 0.55, home_server_capable: 0.35,
        },
        Region::Mena => RegionStats {
            label: "MENA", population_2026: 581.0,
            smartphone_penetration: 0.66, broadband_penetration: 0.58,
            grid_co2_kg_per_kwh: 0.55, home_server_capable: 0.40,
        },
        Region::SubSaharanAfrica => RegionStats {
            label: "Sub-Saharan Africa", population_2026: 1280.0,
            smartphone_penetration: 0.52, broadband_penetration: 0.28,
            grid_co2_kg_per_kwh: 0.45, home_server_capable: 0.12,
        },
        Region::LatinAmerica => RegionStats {
            label: "Latin America", population_2026: 660.0,
            smartphone_penetration: 0.72, broadband_penetration: 0.65,
            grid_co2_kg_per_kwh: 0.21, home_server_capable: 0.45,
        },
        Region::Oceania => RegionStats {
            label: "Oceania", population_2026: 45.0,
            smartphone_penetration: 0.80, broadband_penetration: 0.75,
            grid_co2_kg_per_kwh: 0.55, home_server_capable: 0.65,
        },
    }
}

fn all_regions() -> [Region; 9] {
    [
        Region::NorthAmerica, Region::Europe, Region::EastAsia,
        Region::SouthAsia, Region::SoutheastAsia, Region::Mena,
        Region::SubSaharanAfrica, Region::LatinAmerica, Region::Oceania,
    ]
}

/// Sum of population × smartphone_penetration across all regions —
/// the realistic CEWP-reachable population at 100% adoption among
/// smartphone-owning humans.
fn realistic_world_population_smartphone() -> f64 {
    all_regions().iter()
        .map(|r| { let s = region_stats(*r); s.population_2026 * s.smartphone_penetration * 1e6 })
        .sum()
}

/// Per-region tier mix derived from real penetration data. Server
/// tier is gated by home_server_capable; proxy tier scales with
/// broadband_penetration; client tier picks up the smartphone
/// remainder. Returns (client_frac, proxy_frac, server_frac)
/// normalized to the smartphone-having population.
fn region_tier_mix(r: Region) -> (f64, f64, f64) {
    let s = region_stats(r);
    // Server: home_server_capable share of smartphone owners
    let server_frac = (s.home_server_capable / s.smartphone_penetration.max(0.01)).min(0.15);
    // Proxy: broadband-having smartphone owners who AREN'T servers
    let proxy_frac = ((s.broadband_penetration / s.smartphone_penetration.max(0.01)) - server_frac).max(0.0).min(0.80);
    // Client: the rest of smartphone owners
    let client_frac = (1.0 - proxy_frac - server_frac).max(0.0);
    (client_frac, proxy_frac, server_frac)
}

// ─── Connectivity tiers ──────────────────────────────────────────────
//
// Smartphones aren't all equally connected. A 5G phone in Seoul has a
// different substrate role than a 3G phone in rural Uttar Pradesh.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum ConnectivityTier {
    Fiber,         // 100+ Mbps symmetric uplink
    Cable5g,       // 100+ Mbps DL, 10+ Mbps UL
    MobileLte,     // 25+ Mbps DL, 5+ Mbps UL (typical 4G)
    Mobile3g,      // 1-5 Mbps DL, <1 Mbps UL
    Mobile2g,      // sub-1 Mbps; voice + SMS feasible only
    Sparse,        // intermittent / satellite / no persistent connection
}

#[allow(dead_code)]
fn connectivity_uplink_mbps(t: ConnectivityTier) -> f64 {
    match t {
        ConnectivityTier::Fiber => 1000.0,
        ConnectivityTier::Cable5g => 100.0,
        ConnectivityTier::MobileLte => 10.0,
        ConnectivityTier::Mobile3g => 1.0,
        ConnectivityTier::Mobile2g => 0.1,
        ConnectivityTier::Sparse => 0.02,
    }
}

// ─── Environmental footprint ─────────────────────────────────────────

#[derive(Debug, Clone)]
struct Footprint {
    datacenters: f64,
    power_mw: f64,
    electricity_twh_per_year: f64,
    co2_mt_per_year: f64,
    marginal_power_mw: f64,
    new_buildout_power_mw: f64,
    useful_work_per_watt: f64,
    by_class: Vec<(DeviceClass, f64, f64, bool)>, // (class, count, power_MW, net_new)
}

fn envelope(power_mw: f64, grid_co2: f64) -> (f64, f64) {
    let twh = (power_mw * 1000.0 * HOURS_PER_YEAR) / 1e9;
    let co2 = twh * grid_co2;
    (twh, co2)
}

fn internet_footprint(n_users: f64) -> Footprint {
    let dcs = DC_FLOOR.max((n_users / 5e9) * TODAY_DC_COUNT_AT_5B);
    let power_mw = dcs * HYPERSCALE_DC_AVG_MW;
    let (twh, co2) = envelope(power_mw, GLOBAL_GRID_CO2_KG_PER_KWH);
    Footprint {
        datacenters: dcs, power_mw,
        electricity_twh_per_year: twh, co2_mt_per_year: co2,
        marginal_power_mw: 0.0,
        new_buildout_power_mw: power_mw,
        useful_work_per_watt: 1.0,
        by_class: Vec::new(),
    }
}

fn tier_power(count: f64, mix: &DeviceMix) -> (f64, f64, f64, f64, Vec<(DeviceClass, f64, f64, bool)>) {
    let mut power_mw = 0.0;
    let mut marginal_mw = 0.0;
    let mut new_buildout_mw = 0.0;
    let mut weighted_eff = 0.0;
    let mut mix_sum = 0.0;
    let mut by_class = Vec::new();
    for (cls, frac) in &mix.items {
        if *frac <= 0.0 { continue; }
        let spec = device_spec(*cls);
        let tier_count = count * frac;
        let tier_w = tier_count * spec.idle_w * spec.marginal_share;
        let tier_mw = tier_w / 1e6;
        power_mw += tier_mw;
        if spec.marginal_share < 1.0 || !spec.net_new { marginal_mw += tier_mw; }
        if spec.net_new && spec.marginal_share >= 0.5 { new_buildout_mw += tier_mw; }
        weighted_eff += frac * spec.efficiency_factor;
        mix_sum += frac;
        by_class.push((*cls, tier_count, tier_mw, spec.net_new));
    }
    let efficiency = if mix_sum > 0.0 { weighted_eff / mix_sum } else { 1.0 };
    (power_mw, marginal_mw, new_buildout_mw, efficiency, by_class)
}

fn cewp_footprint(s: &Scenario, style: FleetStyle, grid_co2: f64) -> Footprint {
    let n_cli = s.n_users * s.tier_mix.client;
    let n_prx = s.n_users * s.tier_mix.proxy;
    let n_srv = s.n_users * s.tier_mix.server;
    let cli = tier_power(n_cli, &fleet_mix(style, Tier::Client));
    let prx = tier_power(n_prx, &fleet_mix(style, Tier::Proxy));
    let srv = tier_power(n_srv, &fleet_mix(style, Tier::Server));
    let power_mw = cli.0 + prx.0 + srv.0;
    let marginal_mw = cli.1 + prx.1 + srv.1;
    let new_buildout_mw = cli.2 + prx.2 + srv.2;
    let efficiency = if power_mw > 0.0 {
        (cli.3 * cli.0 + prx.3 * prx.0 + srv.3 * srv.0) / power_mw
    } else { 1.0 };
    let (twh, co2) = envelope(power_mw, grid_co2);
    let mut by_class = cli.4;
    by_class.extend(prx.4);
    by_class.extend(srv.4);
    by_class.retain(|(_, _, p, _)| *p > 0.0);
    Footprint {
        datacenters: 0.0, power_mw,
        electricity_twh_per_year: twh, co2_mt_per_year: co2,
        marginal_power_mw: marginal_mw,
        new_buildout_power_mw: new_buildout_mw,
        useful_work_per_watt: efficiency,
        by_class,
    }
}

/// CEWP footprint summed across all regions, using each region's own
/// grid CO2 intensity rather than the global average. The truer
/// number: South Asia's grid is dirtier than Europe's; CEWP power
/// spent in Latin America is greener than in MENA. Caller supplies a
/// base scenario (typically `full_internet_v1`); we override n_users
/// + tier_mix per region from the regional realism data.
fn cewp_regional_footprint(base: &Scenario, style: FleetStyle) -> (Footprint, Vec<(Region, f64, f64)>) {
    let total_smartphone_pop = realistic_world_population_smartphone();
    let mut total_power_mw = 0.0;
    let mut total_marginal_mw = 0.0;
    let mut total_new_buildout_mw = 0.0;
    let mut total_co2_mt = 0.0;
    let mut total_twh = 0.0;
    let mut weighted_eff = 0.0;
    let mut by_class_agg: std::collections::HashMap<DeviceClass, (f64, f64, bool)> = std::collections::HashMap::new();
    let mut per_region = Vec::new();
    for r in all_regions() {
        let stats = region_stats(r);
        let region_smartphone_pop = stats.population_2026 * stats.smartphone_penetration * 1e6;
        let region_user_share = base.n_users * (region_smartphone_pop / total_smartphone_pop);
        let (cli_f, prx_f, srv_f) = region_tier_mix(r);
        let mut region_scenario = base.clone();
        region_scenario.name = stats.label;
        region_scenario.n_users = region_user_share;
        region_scenario.tier_mix = TierMix { client: cli_f, proxy: prx_f, server: srv_f };
        let fp = cewp_footprint(&region_scenario, style, stats.grid_co2_kg_per_kwh);
        total_power_mw += fp.power_mw;
        total_marginal_mw += fp.marginal_power_mw;
        total_new_buildout_mw += fp.new_buildout_power_mw;
        total_twh += fp.electricity_twh_per_year;
        total_co2_mt += fp.co2_mt_per_year;
        weighted_eff += fp.useful_work_per_watt * fp.power_mw;
        for (cls, count, p_mw, net_new) in &fp.by_class {
            let entry = by_class_agg.entry(*cls).or_insert((0.0, 0.0, *net_new));
            entry.0 += count;
            entry.1 += p_mw;
        }
        per_region.push((r, fp.power_mw, fp.co2_mt_per_year));
    }
    let efficiency = if total_power_mw > 0.0 { weighted_eff / total_power_mw } else { 1.0 };
    let by_class: Vec<(DeviceClass, f64, f64, bool)> = by_class_agg
        .into_iter()
        .map(|(k, (count, p_mw, net_new))| (k, count, p_mw, net_new))
        .collect();
    let fp = Footprint {
        datacenters: 0.0,
        power_mw: total_power_mw,
        electricity_twh_per_year: total_twh,
        co2_mt_per_year: total_co2_mt,
        marginal_power_mw: total_marginal_mw,
        new_buildout_power_mw: total_new_buildout_mw,
        useful_work_per_watt: efficiency,
        by_class,
    };
    (fp, per_region)
}

// ─── Latency model (CEWP vs centralized internet) ────────────────────
//
// First-order RTT estimate driven by the same sliders that drive
// storage and bandwidth. Numbers come from measured residential ISP
// RTTs, CDN edge cache RTTs, and great-circle backbone delays — not
// from the substrate benchmarks. Shifts with cohort + cache + depth.

const L_CACHE_LOCAL_MS: f64 = 2.0;
const L_LOCAL_HOP_MS: f64 = 18.0;
const L_REGIONAL_MS: f64 = 55.0;
const L_GLOBAL_MS: f64 = 195.0;
const L_TRUST_HOP_MS: f64 = 14.0;
const L_CDN_EDGE_MS: f64 = 28.0;
const L_ORIGIN_FETCH_MS: f64 = 180.0;

#[derive(Debug, Clone)]
struct LatencyEstimate {
    cewp_p50_ms: f64,
    internet_p50_ms: f64,
    cewp_from_cache_ms: f64,
    cewp_from_local_ms: f64,
    cewp_from_regional_ms: f64,
    cewp_from_global_ms: f64,
    cewp_trust_hop_ms: f64,
}

fn estimate_latency(s: &Scenario) -> LatencyEstimate {
    let cache = s.cache_hit_rate;
    let miss = 1.0 - cache;
    let local_scope = s.cohort.self_ + s.cohort.family + s.cohort.community;
    let regional_scope = s.cohort.affiliations;
    let global_scope = s.cohort.species + s.cohort.planet + s.cohort.federation;
    let trust_hop = s.trust_depth_avg * L_TRUST_HOP_MS;
    let users_per_server = 1.0 / s.tier_mix.server.max(0.001);
    let sparseness_penalty = (users_per_server / 10.0).log10().max(0.0) * 5.0;

    let from_cache = cache * L_CACHE_LOCAL_MS;
    let from_local = miss * local_scope * (L_LOCAL_HOP_MS + sparseness_penalty);
    let from_regional = miss * regional_scope * L_REGIONAL_MS;
    let from_global = miss * global_scope * L_GLOBAL_MS;
    let trust_hop_penalty = miss * trust_hop;
    let cewp = from_cache + from_local + from_regional + from_global + trust_hop_penalty;
    let internet = cache * L_CDN_EDGE_MS + miss * L_ORIGIN_FETCH_MS;

    LatencyEstimate {
        cewp_p50_ms: cewp,
        internet_p50_ms: internet,
        cewp_from_cache_ms: from_cache,
        cewp_from_local_ms: from_local,
        cewp_from_regional_ms: from_regional,
        cewp_from_global_ms: from_global,
        cewp_trust_hop_ms: trust_hop_penalty,
    }
}

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
    /// **Fraction of daily_fetch_bytes that's external_ref pointers**
    /// to off-substrate object stores (S3-class) — per FSD/MEDIA_
    /// SHARING.md §2.6-2.7. External fetches contribute to bandwidth
    /// but NOT to bytes_held in the substrate (the publisher's own
    /// S3 is the effective storage). For TikTok-class short-form
    /// video (≤ 16 MiB), this is 0 (all inline). For Netflix-class
    /// streaming, this is ~1.0 (all external). Default 0 for
    /// existing scenarios.
    external_fetch_fraction: f64,
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
            // Inline fetch contributes to bandwidth AND cache; external
            // fetch contributes to bandwidth ONLY (bytes ride the
            // publisher's S3, not the substrate) per FSD/MEDIA_SHARING
            // §2.7. inbound is total bandwidth (full daily_fetch);
            // cache_inbound is only the inline share that grows held bytes.
            let inline_fetch = s.daily_fetch_bytes * (1.0 - s.external_fetch_fraction);
            let cache_inbound = inline_fetch * (1.0 - cache_hit_rate);
            let cache_held = cache_inbound.min(cache_budget);

            let verify = (daily_admitted + cache_inbound) / s.avg_envelope_bytes;
            let inbound = daily_admitted + s.daily_fetch_bytes * (1.0 - cache_hit_rate);

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
            // Inline fetch grows the cache; external fetch is bandwidth-
            // only (publisher's S3 holds the bytes) per FSD/MEDIA_SHARING
            // §2.7. Hit rate per scenario — see `Scenario::cache_hit_rate`.
            let cache_hit_rate = s.cache_hit_rate;
            let inline_fetch = s.daily_fetch_bytes * (1.0 - s.external_fetch_fraction);
            let cache_inbound = inline_fetch * (1.0 - cache_hit_rate);
            let cache_held = cache_inbound.min(cache_budget);
            // Bandwidth includes BOTH inline and external fetch.
            let total_fetch_bw = s.daily_fetch_bytes * (1.0 - cache_hit_rate);

            // Total verify load: admitted-trust + inline cache misses
            // + own traces. External fetches don't verify in our substrate
            // (publisher's S3 handles its own auth).
            let verify_envs = (daily_admitted_plus_traces + cache_inbound) / s.avg_envelope_bytes;
            // Scrub: replicated agent traces (scrubbed at admission).
            let scrub_bytes = traces_in_per_day;
            // Outbound fanout: own × wide-scope steward set.
            let wide = s.cohort.species + s.cohort.planet + s.cohort.federation;
            let narrow = s.cohort.community + s.cohort.affiliations;
            let fanout = 1.0 + narrow * 4.0 + wide * 64.0;

            let inbound_total = daily_admitted_plus_traces + total_fetch_bw;
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
            external_fetch_fraction: 0.0,
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
            external_fetch_fraction: 0.0,
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
            external_fetch_fraction: 0.0,
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
            external_fetch_fraction: 0.0,
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
            external_fetch_fraction: 0.0,
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
            external_fetch_fraction: 0.0,
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
            external_fetch_fraction: 0.0,
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
            external_fetch_fraction: 0.0,
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
            external_fetch_fraction: 0.0,
            agent_decisions_per_day: 100.0,
            trace_publishable_fraction: 0.10,
        },
        // ─── Multimedia / TikTok-YouTube-Netflix replacement scenarios ───
        //
        // Real-world traffic anchors (Cisco/Sandvine/DataReportal/Ericsson):
        // • TikTok: ~95 min/day average per user × ~1 MB/min compressed
        //   shorts = ~95 MB/user/day consumed. ~3% post daily, avg 15 MB
        //   upload (60 sec, 1080p H.264) → ~0.5 MB/user/day produced.
        // • YouTube: 1B+ hours watched/day globally / 2.5B MAU = ~24 min/day
        //   consumed. Mix of inline shorts (~20 MB) and external long-form
        //   (100 MB - 2 GB). 0.1% upload daily.
        // • Netflix-class streaming: ~2 hours/day at HD = ~1.5 GB/day per
        //   active viewer. 0% UGC. Pure external_ref (publisher's CDN /
        //   Open Connect-equivalent).
        //
        // FSD/MEDIA_SHARING.md §2.6-2.7: inline content (≤ 16 MiB) rides
        // federation natively; external content rides BlobBody::External
        // pointing to publisher's S3-class store; replication is demand-
        // driven (every successful fetch creates a new holder).

        // TikTok replacement — all inline short-form video.
        // 5B users, 95 MB/day consumed, ~0.5 MB/day produced (avg).
        Scenario {
            name: "tiktok_replacement",
            n_users: 5_000_000_000.0,
            tier_mix: TierMix { client: 0.40, proxy: 0.55, server: 0.05 },
            trust_radius: 250.0,
            trust_depth_avg: 1.0,
            daily_bytes: 500.0 * KB, // averaged producer rate: 3% × 15 MB
            avg_envelope_bytes: 15.0 * MB, // short-form video envelope
            disk_budget_client: 256.0 * GB,
            disk_budget_proxy: 256.0 * GB,
            disk_budget_server: 1.0 * TB,
            cohort: CohortDist::default_model(), // social-graph driven
            daily_fetch_bytes: 95.0 * MB,
            cache_hit_rate: 0.70, // viral short-form clusters hard
            external_fetch_fraction: 0.0, // ALL inline; ≤ 16 MiB per clip
            agent_decisions_per_day: 50.0,
            trace_publishable_fraction: 0.05,
        },
        // YouTube replacement — mix of inline shorts + external long-form.
        // 5B users, ~30 min watch/day across mix, ~0.5 MB/day produced.
        Scenario {
            name: "youtube_replacement",
            n_users: 5_000_000_000.0,
            tier_mix: TierMix { client: 0.40, proxy: 0.55, server: 0.05 },
            trust_radius: 200.0,
            trust_depth_avg: 1.0,
            daily_bytes: 500.0 * KB, // averaged producer rate
            avg_envelope_bytes: 30.0 * MB, // mixed: shorts inline, long-form metadata
            disk_budget_client: 256.0 * GB,
            disk_budget_proxy: 256.0 * GB,
            disk_budget_server: 1.0 * TB,
            cohort: CohortDist::default_model(),
            daily_fetch_bytes: 1000.0 * MB, // 30 min consumed × ~30 MB/min avg
            cache_hit_rate: 0.55,
            external_fetch_fraction: 0.75, // 75% long-form (external_ref); 25% shorts (inline)
            agent_decisions_per_day: 50.0,
            trace_publishable_fraction: 0.05,
        },
        // Netflix/Hulu/streaming replacement — pure external_ref pointers.
        // 5B users (assume universal), ~2 hours/day HD streaming = 1.5 GB/d.
        // Publisher (studio) holds the bytes; federation routes metadata.
        Scenario {
            name: "netflix_replacement",
            n_users: 5_000_000_000.0,
            tier_mix: TierMix { client: 0.40, proxy: 0.55, server: 0.05 },
            trust_radius: 100.0, // narrower trust set for studio publishers
            trust_depth_avg: 1.0,
            daily_bytes: 1.0 * KB, // negligible UGC
            avg_envelope_bytes: 5.0 * KB, // metadata-only envelope
            disk_budget_client: 256.0 * GB,
            disk_budget_proxy: 256.0 * GB,
            disk_budget_server: 1.0 * TB,
            cohort: CohortDist::default_model(),
            daily_fetch_bytes: 1500.0 * MB, // 2 hours HD × 750 MB/hour
            cache_hit_rate: 0.30, // long-form less popularity-clustered than shorts
            external_fetch_fraction: 1.0, // ALL external; substrate routes metadata only
            agent_decisions_per_day: 30.0,
            trace_publishable_fraction: 0.05,
        },
        // AdultHUB-class verified-adult publisher.
        // Real-world anchors: PornHub ~100M subscribers, ~1M verified
        // creators (post Dec-2020 verified-uploader purge); OnlyFans
        // ~2M creators, ~210M registered users (~50M active).
        //
        // Substrate profile: publisher runs canonical S3-class storage
        // for the full video catalog (their existing business model);
        // subscribers admit content via delegates_to:publisher:adulthub
        // (the trusted-publisher trust-graph path per FSD/MEDIA_SHARING
        // §1.2); content carries content_rating:mpaa:NC-17 attestations
        // + content_class:adult; substrate refuses to amplify into
        // community/global feeds (per §1.1 discipline). Federation
        // carries metadata + ACL + per-creator-eviction surface;
        // bytes ride external_ref pointers.
        //
        // 100M subscribers = a SUBSET of the federation, not all 5B
        // users — those who explicitly opted in by emitting
        // delegates_to:publisher attestation with age_assurance.
        Scenario {
            name: "adulthub_replacement",
            n_users: 100_000_000.0,
            tier_mix: TierMix { client: 0.45, proxy: 0.50, server: 0.05 },
            trust_radius: 50.0, // subscribers' curated creator subset
            trust_depth_avg: 1.0,
            daily_bytes: 100.0 * KB, // averaged subscriber upload (most don't post)
            avg_envelope_bytes: 50.0 * KB, // metadata-heavy envelopes (ExternalRefs)
            disk_budget_client: 256.0 * GB,
            disk_budget_proxy: 256.0 * GB,
            disk_budget_server: 1.0 * TB,
            cohort: CohortDist::default_model(),
            daily_fetch_bytes: 1000.0 * MB, // ~30 min/day adult-video consumption
            cache_hit_rate: 0.40, // long-tail content; less popularity clustering
            external_fetch_fraction: 0.95, // almost all video external; thumbs inline
            agent_decisions_per_day: 30.0,
            trace_publishable_fraction: 0.05,
        },
        // Full internet with video — combined: text + shorts + long-form +
        // streaming + everything. The realistic "we replaced everything"
        // scenario. Per-user daily ~1.7 GB consumed, ~11 MB produced.
        Scenario {
            name: "full_internet_with_video",
            n_users: 5_000_000_000.0,
            tier_mix: TierMix { client: 0.35, proxy: 0.55, server: 0.10 },
            trust_radius: 250.0,
            trust_depth_avg: 1.0,
            daily_bytes: 11.0 * MB, // combined produced rate
            avg_envelope_bytes: 50.0 * KB, // weighted-avg across content types
            disk_budget_client: 256.0 * GB,
            disk_budget_proxy: 256.0 * GB,
            disk_budget_server: 1.0 * TB,
            cohort: CohortDist::default_model(),
            daily_fetch_bytes: 1700.0 * MB, // 95 MB tiktok + 100 MB youtube inline + 1.5 GB netflix external + 5 MB misc
            cache_hit_rate: 0.55,
            external_fetch_fraction: 0.88, // 1500 MB external out of 1700 MB total fetch
            agent_decisions_per_day: 200.0,
            trace_publishable_fraction: 0.10,
        },
        // ── Regional scenarios — phones as primary, real penetration data ──
        //
        // These use real per-region tier mixes (region_tier_mix) and
        // regional sub-population (smartphone_penetration × pop). They
        // surface what the substrate looks like when the dominant
        // device class is a phone with mobile-LTE connectivity, not a
        // desktop with home fiber.
        Scenario {
            name: "south_asia_dense", // India + Pakistan + Bangladesh, 61% smartphone, 42% broadband
            n_users: (region_stats(Region::SouthAsia).population_2026
                * region_stats(Region::SouthAsia).smartphone_penetration * 1e6),
            tier_mix: {
                let (c, p, s) = region_tier_mix(Region::SouthAsia);
                TierMix { client: c, proxy: p, server: s }
            },
            trust_radius: 120.0, // dense kinship + neighborhood graphs
            trust_depth_avg: 1.0,
            daily_bytes: 8.0 * MB, // lower bytes/day given mobile-LTE uplinks
            avg_envelope_bytes: 30.0 * KB,
            disk_budget_client: 128.0 * GB, // phones at low end
            disk_budget_proxy: 256.0 * GB,
            disk_budget_server: 1.0 * TB,
            cohort: CohortDist::default_model(),
            daily_fetch_bytes: 800.0 * MB,
            cache_hit_rate: 0.6,
            external_fetch_fraction: 0.85,
            agent_decisions_per_day: 150.0,
            trace_publishable_fraction: 0.10,
        },
        Scenario {
            name: "sub_saharan_bootstrap", // 52% smartphone, 28% broadband, 12% L1-capable
            n_users: (region_stats(Region::SubSaharanAfrica).population_2026
                * region_stats(Region::SubSaharanAfrica).smartphone_penetration * 1e6),
            tier_mix: {
                let (c, p, s) = region_tier_mix(Region::SubSaharanAfrica);
                TierMix { client: c, proxy: p, server: s }
            },
            trust_radius: 60.0, // smaller direct-trust set early
            trust_depth_avg: 1.0,
            daily_bytes: 4.0 * MB,
            avg_envelope_bytes: 20.0 * KB,
            disk_budget_client: 64.0 * GB,
            disk_budget_proxy: 256.0 * GB,
            disk_budget_server: 1.0 * TB,
            cohort: CohortDist::default_model(),
            daily_fetch_bytes: 300.0 * MB,
            cache_hit_rate: 0.55,
            external_fetch_fraction: 0.85,
            agent_decisions_per_day: 80.0,
            trace_publishable_fraction: 0.10,
        },
        Scenario {
            name: "north_america_realistic", // 85% smartphone, 82% broadband, 0.38 grid CO2
            n_users: (region_stats(Region::NorthAmerica).population_2026
                * region_stats(Region::NorthAmerica).smartphone_penetration * 1e6),
            tier_mix: {
                let (c, p, s) = region_tier_mix(Region::NorthAmerica);
                TierMix { client: c, proxy: p, server: s }
            },
            trust_radius: 200.0,
            trust_depth_avg: 1.0,
            daily_bytes: 15.0 * MB, // higher bytes/day given fiber/cable uplinks
            avg_envelope_bytes: 50.0 * KB,
            disk_budget_client: 256.0 * GB,
            disk_budget_proxy: 256.0 * GB,
            disk_budget_server: 1.0 * TB,
            cohort: CohortDist::default_model(),
            daily_fetch_bytes: 1500.0 * MB,
            cache_hit_rate: 0.6,
            external_fetch_fraction: 0.88,
            agent_decisions_per_day: 250.0,
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

    // Retention floor: if the trust pool churns faster than 2 days,
    // the server is mostly a pass-through cache and the federation
    // has lost the persistence the trust gate was supposed to give it.
    let retention_ok = srv.effective_retention_days >= RETENTION_FLOOR_DAYS;
    println!("    {} retention {:>5.0} days (floor {:.0} days)",
        fmt_check(retention_ok),
        srv.effective_retention_days,
        RETENTION_FLOOR_DAYS);

    if feas.storage_ok && feas.bandwidth_ok && feas.cpu_ok && retention_ok {
        println!();
        println!("  ✓ v1 feasible per-server. {} servers globally.",
            fmt_count(s.n_users * s.tier_mix.server));
    }

    // Latency comparison
    let lat = estimate_latency(s);
    println!();
    println!("  Latency p50 (RTT, derived from cohort + cache + depth + tier mix):");
    println!("    CEWP      {:>6.1} ms   (cache {:.1} + local {:.1} + regional {:.1} + global {:.1} + trust-hop {:.1})",
        lat.cewp_p50_ms,
        lat.cewp_from_cache_ms, lat.cewp_from_local_ms,
        lat.cewp_from_regional_ms, lat.cewp_from_global_ms,
        lat.cewp_trust_hop_ms);
    println!("    Internet  {:>6.1} ms   (CDN edge cache + hyperscale origin fetch)",
        lat.internet_p50_ms);
    let savings = lat.internet_p50_ms - lat.cewp_p50_ms;
    if savings > 0.0 {
        println!("    ↓ CEWP saves {:.1} ms p50 ({:.0}% reduction)",
            savings, savings / lat.internet_p50_ms * 100.0);
    } else {
        println!("    ↑ Internet faster by {:.1} ms p50", -savings);
    }
}

/// Print energy + CO2 footprint comparison — CEWP vs centralized
/// internet substrate, with regional breakdown for the realistic case.
fn print_footprint(s: &Scenario) {
    println!();
    println!("══ Environmental footprint — {} ══", s.name);
    let internet = internet_footprint(s.n_users);
    println!();
    println!("  Centralized internet substrate (today):");
    println!("    datacenters       {}", fmt_count(internet.datacenters));
    println!("    power             {:.1} MW", internet.power_mw);
    println!("    electricity       {:.1} TWh/yr", internet.electricity_twh_per_year);
    println!("    CO2               {:.1} Mt/yr (grid avg {:.2} kg/kWh)",
        internet.co2_mt_per_year, GLOBAL_GRID_CO2_KG_PER_KWH);
    println!();
    println!("  CEWP substrate (fleet styles, no datacenters):");
    for style in [FleetStyle::PhoneFirst, FleetStyle::Realistic2026, FleetStyle::Homelab] {
        let label = match style {
            FleetStyle::PhoneFirst => "phone-first    ",
            FleetStyle::Realistic2026 => "realistic 2026 ",
            FleetStyle::Homelab => "homelab        ",
        };
        let fp = cewp_footprint(s, style, GLOBAL_GRID_CO2_KG_PER_KWH);
        let ratio = internet.power_mw / fp.power_mw.max(0.001);
        println!("    [{}] {:>7.1} MW  (marginal {:>6.1} / new-build {:>5.1})  {:>5.1} TWh/yr  {:>5.1} Mt CO2/yr  ({}× less)",
            label,
            fp.power_mw,
            fp.marginal_power_mw,
            fp.new_buildout_power_mw,
            fp.electricity_twh_per_year,
            fp.co2_mt_per_year,
            fmt_count(ratio));
    }
}

/// Print per-region CEWP footprint using each region's real grid CO2 +
/// real population × smartphone penetration share. The truer number
/// than a single global average. Direction Eric asked for: phones,
/// by region/capability/availability, as a class.
fn print_regional_breakdown(base: &Scenario, style: FleetStyle) {
    println!();
    println!("══ Regional CEWP footprint — base scenario: {} ══", base.name);
    println!("    Fleet style: {}", match style {
        FleetStyle::PhoneFirst => "phone-first",
        FleetStyle::Realistic2026 => "realistic 2026",
        FleetStyle::Homelab => "homelab",
    });
    println!();
    println!("    Per-region realism (UN 2024 pop / GSMA 2024 smartphone / ITU 2024 broadband / IEA 2024 grid):");
    println!("    {:<22} {:>9}  {:>5}  {:>5}  {:>5}  {:>6}  {:>10}  {:>10}",
        "region", "pop (M)", "smart", "bband", "L1cap", "gridCO2",
        "power MW", "CO2 Mt/yr");
    for r in all_regions() {
        let stats = region_stats(r);
        let (_, fp_mw, fp_co2) = {
            let total_pop = realistic_world_population_smartphone();
            let region_smartphone_pop = stats.population_2026 * stats.smartphone_penetration * 1e6;
            let region_user_share = base.n_users * (region_smartphone_pop / total_pop);
            let (cli_f, prx_f, srv_f) = region_tier_mix(r);
            let mut sc = base.clone();
            sc.n_users = region_user_share;
            sc.tier_mix = TierMix { client: cli_f, proxy: prx_f, server: srv_f };
            let fp = cewp_footprint(&sc, style, stats.grid_co2_kg_per_kwh);
            (r, fp.power_mw, fp.co2_mt_per_year)
        };
        println!("    {:<22} {:>9.0}  {:>4.0}%  {:>4.0}%  {:>4.0}%   {:>4.2}  {:>10.1}  {:>10.2}",
            stats.label,
            stats.population_2026,
            stats.smartphone_penetration * 100.0,
            stats.broadband_penetration * 100.0,
            stats.home_server_capable * 100.0,
            stats.grid_co2_kg_per_kwh,
            fp_mw, fp_co2);
    }
    let (fp_total, _) = cewp_regional_footprint(base, style);
    let internet = internet_footprint(base.n_users);
    println!();
    println!("    ─────────────────────────────────────────────────────────────────────────────────────────");
    println!("    Federation total (regional realism):");
    println!("      power               {:.1} MW", fp_total.power_mw);
    println!("      ├─ marginal         {:.1} MW  (rides existing phones/laptops — zero net buildout)",
        fp_total.marginal_power_mw);
    println!("      └─ new buildout     {:.1} MW  (ARM mini-PCs + home x86 — new hardware)",
        fp_total.new_buildout_power_mw);
    println!("      electricity         {:.1} TWh/yr", fp_total.electricity_twh_per_year);
    println!("      CO2                 {:.2} Mt/yr  (regional grids, NOT global avg)",
        fp_total.co2_mt_per_year);
    println!("      useful work/watt    {:.2}× (relative to hyperscale baseline 1.0)",
        fp_total.useful_work_per_watt);
    println!();
    println!("    Internet substrate baseline at same N users: {} MW / {:.0} TWh/yr / {:.0} Mt CO2/yr",
        fmt_count(internet.power_mw), internet.electricity_twh_per_year, internet.co2_mt_per_year);
    let power_ratio = internet.power_mw / fp_total.power_mw.max(0.001);
    let co2_ratio = internet.co2_mt_per_year / fp_total.co2_mt_per_year.max(0.001);
    println!("    CEWP is {}× lower power, {}× lower CO2 vs centralized internet substrate.",
        fmt_count(power_ratio), fmt_count(co2_ratio));
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

// ─── Adversarial findings — F-AV cost-asymmetry against scenarios ────
//
// Pinned to the canonical CIRISVerify Federation Threat Model (v1.1,
// 2026-05-31; supersedes v1.0 2026-05-02). v1.1 closed three of the
// four §3.3 structural gaps (A R1 timeliness + B Q1 CAP specified;
// C C4 KEX shipped in v4.6.0) and added F-AV-RECONSIDER-DOS to the
// §6.5 catalog with the v0.5 toy's cost-asymmetry numbers cited
// verbatim. v0.6 toy reflects the new status of every finding.
//
// Methodology discipline per RATCHET (KNOWN_LIMITATIONS.md §4
// "Correct Statement" template): every claim states its assumptions
// (non-adaptive adversary, n ≥ 100 samples, etc.) and which limitation
// (L-01..L-08) binds.

#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
enum FavStatus {
    /// Verify Fed TM names this F-AV AND the substrate ships a
    /// load-bearing defense.
    SpecifiedMitigated,
    /// Named in the TM with partial defense; named gaps remain
    /// (research-grade / structural).
    Partial,
    /// Named in the TM but the defense is currently spec-only,
    /// unimplemented at the substrate layer.
    SpecOnly,
    /// Named in the TM but no defense filled. Live exposure today.
    UnfilledGap,
    /// Not currently in the TM; toy proposes as candidate-new F-AV
    /// for the maintainer to evaluate.
    CandidateNew,
}

impl FavStatus {
    fn label(self) -> &'static str {
        match self {
            FavStatus::SpecifiedMitigated => "SPECIFIED + MITIGATED",
            FavStatus::Partial            => "PARTIAL",
            FavStatus::SpecOnly           => "SPEC ONLY",
            FavStatus::UnfilledGap        => "UNFILLED — LIVE EXPOSURE",
            FavStatus::CandidateNew       => "CANDIDATE NEW F-AV",
        }
    }
    fn glyph(self) -> &'static str {
        match self {
            FavStatus::SpecifiedMitigated => "✓",
            FavStatus::Partial            => "◐",
            FavStatus::SpecOnly           => "◔",
            FavStatus::UnfilledGap        => "⚠",
            FavStatus::CandidateNew       => "📝",
        }
    }
}

struct FavFinding {
    fav_id: &'static str,
    name: &'static str,
    doc_ref: &'static str,
    status: FavStatus,
    /// What the attacker does + observable
    mechanism: &'static str,
    /// Substrate's named defense (or "—" for UnfilledGap)
    defense: &'static str,
    /// Limitations from RATCHET KNOWN_LIMITATIONS.md that bind
    limits: &'static str,
    /// Computed numbers (free-form; populated by fav_findings()
    /// from the scenario)
    findings: Vec<(String, String)>,
    /// One-line verdict honest about what the toy can and cannot say
    verdict: String,
}

fn cost_per_dormant_vtpm_usd_per_year() -> f64 {
    // Per Verify Fed TM §6.6 F-AV-DORMANT: cloud-vTPM-rented identities
    // ~$200-$1,000 per identity per 5 years. Midpoint: $600 / 5 = $120/yr.
    120.0
}

fn cost_per_hour_cloud_vtpm_usd() -> f64 {
    // Per Verify Fed TM §6.1 F-AV-1 known weakness: ~$0.10/identity/hour
    // on cloud vTPMs (the eroded hardware floor).
    0.10
}

/// CommonsCredits stake required to file a Reconsideration per
/// MISSION.md §4.10. Proportional to alleged severity of original
/// adjudication error. Use a representative midpoint for the toy.
fn p11_reconsideration_stake_credits() -> f64 {
    100.0
}

fn fav_findings(s: &Scenario, lat: &LatencyEstimate) -> Vec<FavFinding> {
    let mut out = Vec::new();

    // ── F-AV-1 Multi-identity Sybil ──────────────────────────────────
    {
        let cost_per_identity_year = cost_per_hour_cloud_vtpm_usd() * 24.0 * 365.0;
        let n_attacker = 10_000.0;
        let total_attacker_cost_yr = n_attacker * cost_per_identity_year;
        // Defense: SOFTWARE_ONLY → COMMUNITY tier cap (per-repo
        // Verify TM §5 critical invariant). At cohort_scope=community
        // a Sybil's bytes only reach community-scope subscribers, not
        // federation-wide. Toy: published cohort_publishable carries
        // species+planet+federation share; community share is local.
        let federation_admit_fraction = s.cohort.species + s.cohort.planet + s.cohort.federation;
        let federation_admit_bytes_per_attacker_year =
            s.daily_bytes * 365.0 * federation_admit_fraction;
        out.push(FavFinding {
            fav_id: "F-AV-1",
            name: "Multi-identity Sybil (cheap key generation)",
            doc_ref: "CIRISVerify Fed TM §6.1",
            status: FavStatus::SpecifiedMitigated,
            mechanism:
                "Adversary spins N cloud-vTPM-rented identities, each individually substrate-valid. \
                 Cluster manifests in PC1 variance ↓ + HwDiv ↓ + clustering coefficient ↑.",
            defense:
                "C1 hardware-tier cap (SOFTWARE_ONLY ⇒ COMMUNITY tier permanently) + bond + \
                 RATCHET cluster detection (N_eff joint manifold dim < 11).",
            limits: "L-02 (adaptive adversary cap; cluster detection assumes non-adaptive)",
            findings: vec![
                ("Cost / identity / year".into(),
                    format!("${:.2}", cost_per_identity_year)),
                ("Cost @ 10K Sybils / year".into(),
                    format!("${:.2}M", total_attacker_cost_yr / 1e6)),
                ("Federation-scope admit fraction (tier-capped to COMMUNITY)".into(),
                    "0% — SOFTWARE_ONLY identities cap at COMMUNITY scope".into()),
                ("Community-scope bytes / Sybil / year (NOT cross-cohort)".into(),
                    format!("{}", fmt_bytes(federation_admit_bytes_per_attacker_year))),
            ],
            verdict:
                "Defense holds at full_internet_v1 IF SOFTWARE_ONLY tier cap enforced. \
                 Bound: K_cap = 0 federation-bytes/Sybil. Caveat: cloud-vTPM erosion of \
                 hardware floor is a known weakness (Fed TM §6.1).".into(),
        });
    }

    // ── F-AV-DORMANT Sybil aging ─────────────────────────────────────
    {
        let cost_per_dormant_id_yr = cost_per_dormant_vtpm_usd_per_year();
        let n_dormant = 10_000.0;
        let dormant_corpus_cost_5yr = n_dormant * cost_per_dormant_id_yr * 5.0;
        // Activation density tier defense (per Fed TM §6.6): Active
        // ≥100 traces / 30d ⇒ standing accrues; Dormant <10 ⇒ baseline only.
        out.push(FavFinding {
            fav_id: "F-AV-DORMANT",
            name: "Sybil aging via dormant cloud-vTPM cohort",
            doc_ref: "CIRISVerify Fed TM §6.6",
            status: FavStatus::Partial,
            mechanism:
                "Cohort of cheap vTPMs idles ~5y at $200-$1000 each, then activates with \
                 minimal trace history. σ-decay rate inconsistent with claimed temporal history.",
            defense:
                "Activity-density tier (Active ≥100/30d ⇒ Standing accrues; Dormant <10 ⇒ \
                 baseline-only) + σ-decay rate vs claimed history + post-activation \
                 embedding-cluster proximity (RATCHET signal).",
            limits: "L-05 finite sample (n ≥ 100 floor) + L-08 slow capture",
            findings: vec![
                ("Cost / dormant identity / year".into(),
                    format!("${:.2}", cost_per_dormant_id_yr)),
                ("5-year corpus cost @ 10K Sybils".into(),
                    format!("${:.2}M", dormant_corpus_cost_5yr / 1e6)),
                ("Activation-density floor (Active tier)".into(),
                    "≥100 traces / 30 days per identity".into()),
                ("Cost-asymmetry inequality".into(),
                    "dC/dw grows linearly in N×t; dB/dw → 0 until activation crosses density floor".into()),
            ],
            verdict:
                "Cost floor at $1.2M / 5y / 10K identities is non-trivial but ~3 OOMs below \
                 nation-state budgets. Defense partial: activation-density catches naïve attacks; \
                 F-AV-TIMESHIFT σ-decay paraphrase replay (research-grade) remains open.".into(),
        });
    }

    // ── F-AV-ECLIPSE per-peer view manipulation ──────────────────────
    {
        let local_share = s.cohort.self_ + s.cohort.family + s.cohort.community;
        out.push(FavFinding {
            fav_id: "F-AV-ECLIPSE",
            name: "Eclipse attack on a peer's S2 read-view",
            doc_ref: "CIRISVerify Fed TM §6.5 — LIVE EXPOSURE",
            status: FavStatus::UnfilledGap,
            mechanism:
                "All of a target peer's S2 directory read paths controlled, served a curated view. \
                 Target's local cohort-scope traffic UNAFFECTED (CEG locality dividend); \
                 cross-cohort moderation/policy/accord visibility poisoned.",
            defense:
                "Pending — N1 cryptographic addressing (content-hash destinations) + N2 \
                 multi-medium transport + witness-signed snapshots. Per Fed TM §3.3 Gap D: \
                 N1+N2 are Spec ONLY today, pending CIRISEdge Phase 1.",
            limits: "L-02 (no detector exists; attacker is adaptive)",
            findings: vec![
                ("Local cohort fraction (UNEXPOSED by eclipse)".into(),
                    format!("{:.1}%", local_share * 100.0)),
                ("Cross-cohort fraction (EXPOSED to view manipulation)".into(),
                    format!("{:.1}%", (1.0 - local_share) * 100.0)),
                ("Detection by eclipsed peer (own resources)".into(),
                    "0% — by definition, eclipsed peer cannot detect locally".into()),
                ("Detection by non-eclipsed observers".into(),
                    "Possible after cross-witness reconciliation; latency unspecified (Gap D)".into()),
            ],
            verdict:
                "LIVE EXPOSURE today. The CEG locality dividend bounds eclipse damage to \
                 cross-cohort traffic only — for full_internet_v1's default cohort, that's \
                 ~30% of total. Substrate has NO answer until Edge Phase 1 ships N1+N2.".into(),
        });
    }

    // ── F-AV-12 Replication-lag exploitation ─────────────────────────
    {
        // Cross-region replication lag uses raw cross-ocean RTT
        // (L_GLOBAL_MS submarine-cable great-circle), not cohort-
        // weighted user-facing latency. Conservative: 2× one-way for
        // commit-and-acknowledge round-trip. Real lag also includes
        // queue + processing + multi-hop ISP; toy underestimates.
        let _ = lat; // bind for future per-tier extension
        let cross_region_one_way_ms = L_GLOBAL_MS;
        let est_replication_lag_s = (2.0 * cross_region_one_way_ms) / 1000.0;
        let proposed_tau_normal_s = 60.0;
        let proposed_tau_partial_s = 300.0;
        out.push(FavFinding {
            fav_id: "F-AV-12",
            name: "Replication-lag exploitation (Q1 unspecified — Gap B)",
            doc_ref: "CIRISVerify Fed TM §6.4 + Gap B",
            status: FavStatus::Partial,
            mechanism:
                "Register key in region A, act, get revoked before replicating to region B. \
                 Attacker exploits the τ-window between revocation and worldwide propagation.",
            defense:
                "Q1 bounded-staleness CAP — SPECIFIED v1.1: quorum-write ⌈2N/3⌉ + bounded-\
                 staleness reads (local iff staleness ≤ τ_partial; else transparent read-\
                 amplification to fresh-quorum) + merge rule 'higher-quorum-weight wins' + \
                 τ_normal ≤ 60s / τ_partial ≤ 300s composed with Gap A R1 bound.",
            limits: "L-06 correlation (multi-region clocks correlated by jurisdiction)",
            findings: vec![
                ("Toy-estimated cross-region 2× RTT (proxy for rep-lag)".into(),
                    format!("{:.2}s", est_replication_lag_s)),
                ("Contract τ_normal (v1.1)".into(), format!("≤ {:.0}s", proposed_tau_normal_s)),
                ("Contract τ_partial (v1.1)".into(), format!("≤ {:.0}s", proposed_tau_partial_s)),
                ("Toy estimate vs τ_normal contract".into(),
                    if est_replication_lag_s <= proposed_tau_normal_s {
                        format!("INSIDE bound ({:.0}× headroom)", proposed_tau_normal_s / est_replication_lag_s.max(0.001))
                    } else {
                        format!("OUTSIDE bound ({:.1}× over)", est_replication_lag_s / proposed_tau_normal_s)
                    }),
                ("v1.1 status".into(),
                    "Q1 CAP specified; downstream impl pending CIRISPersist#143 + CIRISRegistry#46".into()),
                ("Cross-substrate test".into(),
                    "CIRISConformance#7 Scenario 3 (partition + heal + merge-rule verification)".into()),
            ],
            verdict:
                "Gap B SPECIFIED v1.1: bounded-staleness CAP + merge rule contract is in place. \
                 Toy's RTT estimate (0.39s) is 154× inside τ_normal — the bound is feasible at \
                 substrate physics. Tier A9 downgraded TIER-HIGH → TIER-MED per v1.1; drops to \
                 TIER-LOW once impl ships + Conformance#7 Scenario 3 passes.".into(),
        });
    }

    // ── F-AV-16 Substrate-availability denial (fail-secure forcing) ─
    {
        // Per CIRISVerify per-repo §7 + Fed TM §8.3: sliding window
        // W=600s with D_max=180s cumulative degraded time triggers
        // forced RESTRICTED. An adversary holding the substrate
        // degraded for 180s out of every 600s achieves perpetual
        // forced-RESTRICTED at ε cost above the gate.
        let w_s = 600.0;
        let d_max_s = 180.0;
        let max_forced_restricted_pct = d_max_s / w_s * 100.0;
        out.push(FavFinding {
            fav_id: "F-AV-16",
            name: "Substrate-availability denial / forced fail-secure RESTRICTED",
            doc_ref: "CIRISVerify Fed TM §6.5 + per-repo §7 + §8.3 fail-secure",
            status: FavStatus::Partial,
            mechanism:
                "DoS S2 endpoints for τ_grace+ε in a loop. Cumulative-degraded-time in the \
                 sliding window trips substrate into RESTRICTED. Anti-grace-loop sliding \
                 window prevents reset-on-recovery but does not prevent forced RESTRICTED.",
            defense:
                "Fail-secure protocol §8.3: τ_grace=60s, τ_max=300s, sliding W=600s, \
                 D_max=180s cumulative-degraded-time threshold within W. Ring buffer fallback \
                 (N=1024 signed decisions) when S3 degraded.",
            limits: "L-02 (adaptive adversary can pace DoS to maximize RESTRICTED fraction)",
            findings: vec![
                ("Sliding window W".into(), format!("{:.0}s", w_s)),
                ("D_max cumulative-degraded-time threshold".into(), format!("{:.0}s", d_max_s)),
                ("Max forced-RESTRICTED fraction at minimum DoS cost".into(),
                    format!("{:.0}% of operational time", max_forced_restricted_pct)),
                ("Substrate state during DoS".into(),
                    "Signed-RESTRICTED decisions; not silent failure".into()),
            ],
            verdict:
                "Substrate FAILS-SECURE (every decision signed; no silent misroute). But \
                 attacker CAN hold RESTRICTED ~30% of the time at cost ~D_max/W × DoS-budget. \
                 N2 multi-medium transport (Gap D, pending Edge) would raise this attack's cost.".into(),
        });
    }

    // ── F-AV-RATCHET-DOS evaluator denial ────────────────────────────
    {
        // Synthetic adversarial trace cost is ~$0.0001/trace (LLM
        // inference at $0.001/1K tokens × short trace). RATCHET
        // per-evaluation cost: cohort-centroid + manifold projection
        // + N_eff calculation, ~10ms CPU + DB read → ~$0.001
        // amortized on commodity infra. 10× attacker advantage at
        // per-trace ratio.
        let attacker_cost_per_trace = 0.0001;
        let ratchet_cost_per_eval = 0.001;
        let cost_ratio = ratchet_cost_per_eval / attacker_cost_per_trace;
        out.push(FavFinding {
            fav_id: "F-AV-RATCHET-DOS",
            name: "DoS on the RATCHET evaluator",
            doc_ref: "CIRISVerify Fed TM §6.5 (Spec only)",
            status: FavStatus::SpecOnly,
            mechanism:
                "Flood RATCHET with expensive-analysis traces (e.g. high-entropy multimedia \
                 reasoning chains). Legitimate evaluations starve. Cost asymmetry favors \
                 attacker by per-trace generation cost vs per-eval substrate cost.",
            defense:
                "Per-identity compute budget; trace-cost prediction; backpressure → baseline; \
                 sharding by identity-hash. Per Fed TM §6.5: Spec only, unimplemented.",
            limits: "L-05 finite sample at evaluator (rate-limit interaction with sample floor)",
            findings: vec![
                ("Attacker cost / synthetic trace".into(),
                    format!("~${:.4} (LLM inference, short trace)", attacker_cost_per_trace)),
                ("RATCHET cost / evaluation".into(),
                    format!("~${:.4} (manifold + centroid + N_eff)", ratchet_cost_per_eval)),
                ("Cost-asymmetry ratio (defender pays more)".into(),
                    format!("{:.1}× attacker advantage", cost_ratio)),
                ("F-AV-RATCHET-DOS defense status".into(),
                    "Spec only — per-identity budget + sharding UNIMPLEMENTED".into()),
            ],
            verdict:
                "Cost asymmetry FAVORS attacker by ~10×. Substrate's named defenses \
                 (per-identity compute budget + backpressure) are Spec only. Live exposure \
                 to RATCHET-eval starvation at full_internet_v1 scale.".into(),
        });
    }

    // ── Candidate new F-AV: P11 reconsideration weaponization ────────
    {
        // Per MISSION.md §4.10: "a target may file at most one
        // Reconsideration per SlashingAttestation per hash-pinned
        // evidence package per ground (NEW_EVIDENCE, PROCEDURAL_ERROR,
        // QUORUM_COMPROMISE separately)." Three filings without
        // success triggers harassment-pattern review via RATCHET.
        let stake_per_filing = p11_reconsideration_stake_credits();
        let max_filings_per_event = 3.0;
        let grounds = 3.0; // NEW_EVIDENCE / PROCEDURAL_ERROR / QUORUM_COMPROMISE
        // Each filing forces fresh-quorum recusal + adjudication.
        // Assume per-adjudication substrate cost = K × per-filing cost.
        let attacker_total = stake_per_filing * max_filings_per_event * grounds;
        let substrate_cost_multiplier = 5.0; // fresh-quorum recusal cost > attacker stake
        let substrate_total = attacker_total * substrate_cost_multiplier;
        out.push(FavFinding {
            fav_id: "F-AV-RECONSIDER-DOS",
            name: "P11 reconsideration weaponization (catalog v1.1 §6.5)",
            doc_ref:
                "Verify Fed TM v1.1 §6.5 (promoted from candidate to catalog 2026-05-31). \
                 Toy's 5× cost-asymmetry numbers cited verbatim in the TM entry.",
            status: FavStatus::Partial,
            mechanism:
                "Adversary (organized group) files maximum-allowed reconsiderations against \
                 every moderation event affecting their bloc. Per-filing stake is sub-quorum cost; \
                 fresh-quorum recusal multiplies substrate burden. Goal: collapse moderation \
                 decision-throughput by saturating the appeals pipeline.",
            defense:
                "Three additive defenses specified v1.1: (1) per-event rate limit \
                 (RECONSIDERATION_RATE_LIMITED), (2) per-actor cumulative budget \
                 (ACTOR_BUDGET_EXHAUSTED), (3) cross-event harassment-pattern review (RATCHET \
                 signal on (requester_id, targeted_actor_id) clustering at sub-3-per-event \
                 thresholds — fires BEFORE §4.10's existing 3rd-unsuccessful trigger).",
            limits:
                "L-02 (adaptive single-shot pacing evades cluster scoring) + L-05 (detector \
                 needs sufficient filing history before firing)",
            findings: vec![
                ("Stake per filing (CommonsCredits)".into(),
                    format!("{:.0} credits (proportional to severity)", stake_per_filing)),
                ("Max filings / SlashingAttestation".into(),
                    format!("{:.0} grounds × {:.0} evidence-pkg = up to 9 filings",
                        grounds, max_filings_per_event)),
                ("Attacker total stake / targeted event".into(),
                    format!("{:.0} credits", attacker_total)),
                ("Substrate-burden ratio (fresh-quorum recusal cost)".into(),
                    format!("~{:.0}× attacker stake — substrate pays {:.0} credits-equivalent",
                        substrate_cost_multiplier, substrate_total)),
                ("Throughput collapse @ N targeted events".into(),
                    "Decision throughput drops ~ (1 / (1 + filings × recusal_factor))".into()),
                ("v1.1 status".into(),
                    "Defenses specified; primitive impl in CIRISVerify v4.5.0+; downstream P11 \
                     wiring at CIRISNodeCore#28; conformance scenario CIRISConformance#7 Scenario 1".into()),
            ],
            verdict:
                "Promoted candidate → v1.1 catalog. Three additive defenses specified. Cost \
                 asymmetry REMAINS 5× attacker-favoring at the bare protocol path, but per-event \
                 + per-actor + cross-event detectors should collapse the effective throughput \
                 hit. Pending CIRISNodeCore#28 P11 dispatcher consumer of the reconsider-DOS \
                 budget trait surface (`ciris_verify_core::reconsider_dos`).".into(),
        });
    }

    out
}

fn print_fav_findings(s: &Scenario, lat: &LatencyEstimate) {
    let findings = fav_findings(s, lat);
    println!();
    println!("══ Adversarial findings — pinned to CIRISVerify Fed TM v1.0 F-AV catalog ══");
    println!();
    println!("  Scenario: {} ({} users, depth {:.0}, cohort_publishable={:.0}%)",
        s.name, fmt_count(s.n_users), s.trust_depth_avg, s.cohort.publishable() * 100.0);
    println!();
    for f in &findings {
        println!("  {} {} — {}", f.status.glyph(), f.fav_id, f.name);
        println!("    Status   : {}", f.status.label());
        println!("    Doc ref  : {}", f.doc_ref);
        println!("    Mechanism: {}", f.mechanism);
        println!("    Defense  : {}", f.defense);
        println!("    Limits   : {}", f.limits);
        for (k, v) in &f.findings {
            println!("      • {:<58}  {}", k, v);
        }
        println!("    Verdict  : {}", f.verdict);
        println!();
    }

    println!("══ Structural-gap status — CIRISVerify Fed TM §3.3 (v1.1 update 2026-05-31) ══");
    println!();
    println!("  Gap A — R1 revocation timeliness:                    ✓ SPECIFIED v1.1");
    println!("    Contract: τ_normal ≤ 60s, τ_partial ≤ 300s, 'most recent observed wins'");
    println!("    Affected F-AVs collapsed: F-AV-11/12/13/ROLLBACK/FRONTRUN");
    println!("    Downstream impl: CIRISPersist#143 + CIRISRegistry#46");
    println!("    Conformance: CIRISConformance#7 Scenario 3 (regression test)");
    println!("    Tier: A8 R1 timeliness TIER-HIGH → TIER-MED (drops to LOW once impl + test pass)");
    println!();
    println!("  Gap B — Q1 quorum / bounded-staleness CAP:           ✓ SPECIFIED v1.1");
    println!("    Contract: quorum-write ⌈2N/3⌉ + bounded-staleness reads + merge rule");
    println!("    Affected F-AVs collapsed: F-AV-12/13/ROLLBACK");
    println!("    Downstream impl: CIRISPersist#143 + CIRISRegistry#46 (same impl issue as Gap A)");
    println!("    Tier: A9 Q1 bounded-staleness TIER-HIGH → TIER-MED (drops to LOW once impl + test pass)");
    println!();
    println!("  Gap C — C4 hybrid KEX + KDF:                         ✓ SHIPPED v4.6.0");
    println!("    Primitive: X25519 + ML-KEM-768 KEX + HKDF-SHA256 binding");
    println!("    Domain sep: 'CIRIS-FED-KEX-V1' — composes with C2 hybrid-signing pattern");
    println!("    Affected: harvest-now-decrypt-later vulnerability closed for new transport");
    println!("    Tier: A4 forward secrecy TIER-HIGH → resolved");
    println!("    Downstream consumer: CIRISEdge#54 FederationHandshake");
    println!();
    println!("  Gap D — N1 + N2 (Reticulum + multi-medium transport): ◐ SPEC ONLY (still)");
    println!("    Affected: F-AV-ECLIPSE, F-AV-16, F-AV-RATCHET-DOS, F-AV-17");
    println!("    Pending: CIRISEdge Phase 1 implementation (CIRISEdge#53)");
    println!();
    println!("  Net v1.0 → v1.1: 3 of 4 structural gaps closed in one shipping cycle.");
    println!("  Toy cited verbatim in TM v1.1 §3.3 Gap A: 'cross-ocean RTT (toy-derived");
    println!("  from CIRISNodeCore scale_model.rs v0.5) is ~0.39s — 154× inside τ_normal.'");
    println!();

    println!("══ Out-of-scope (substrate has NO answer; simulator must NOT claim detection) ══");
    println!();
    println!("  L-01 Emergent deception from honest components — RATCHET impossibility result");
    println!("  L-02 Adaptive adversary with detector query access — degrades all detector power");
    println!("  L-03 ETH dependency for exponential complexity gap");
    println!("  L-08 Slow capture > 1/3 Byzantine fraction — outside BFT bound");
    println!("  Malicious behavior with valid license (per-repo TM §1)");
    println!("  HSM/TEE manufacturer supply-chain compromise");
    println!("  Physical access (TEE.fail / DDR5 bus interposition)");
    println!("  Simultaneous Ed25519 AND ML-DSA-65 break (hybrid requires both)");
    println!("  Clock manipulation > 5 minutes (assumption §6.5)");
    println!("  F-AV-CROSS cross-federation attackers (Fed TM §6.7 stub)");
    println!();
    println!("  These are the 'CORRECT STATEMENT' (RATCHET KNOWN_LIMITATIONS §4) assumptions");
    println!("  every claim above is conditional on.");
}

fn main() {
    println!("CIRIS Federation Scaling Model — toy v0.6 (post Verify Fed TM v1.1)");
    println!("Empirical baseline : Verify v2.8.0 + Edge v0.10.0 + Persist v3.3.0");
    println!("Substrate triple   : keyring v4.4.3 + persist v3.6.9 + edge v1.1.3 (Conformance pin)");
    println!("Verify HEAD        : v4.6.0 — Gap C hybrid KEX (X25519+ML-KEM-768) SHIPPED");
    println!("Regional realism   : UN WPP 2024 + GSMA Mobile Economy 2024 + ITU 2024 + IEA 2024");
    println!("Threat-model anchor: CIRISVerify Fed TM v1.1 (2026-05-31 — 3/4 §3.3 gaps closed)");
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

        // Environmental footprint comparison at v1 target.
        print_footprint(v1);

        // Per-region realism breakdown at v1 target — the direction
        // beyond the website's uniform-global model. Uses real GSMA /
        // UN / ITU / IEA 2024-2026 data.
        print_regional_breakdown(v1, FleetStyle::Realistic2026);

        // Adversarial findings — F-AV cost-asymmetry against the v1
        // target scenario. Pinned to CIRISVerify Fed TM v1.0.
        let v1_lat = estimate_latency(v1);
        print_fav_findings(v1, &v1_lat);
    }

    println!();
    println!("── How to read this ──");
    println!("  Storage is one pool: own + admitted-trust + hot-cache + traces");
    println!("  Composition is DERIVED from (budget, trust topology, demand) —");
    println!("  it is what the eviction sweeper produces at steady state, not");
    println!("  what an operator configures. The only knobs are workload +");
    println!("  topology + disk size.");
    println!();
    println!("  Environmental footprint compares CEWP against a hyperscale");
    println!("  baseline calibrated to ~10K facilities × 5 MW (IEA 2024 ≈");
    println!("  415 TWh/yr at 5 B users). CEWP power is per-device-class,");
    println!("  marginal-share-discounted (phones spend ~5% of their idle");
    println!("  draw on substrate work); the regional breakdown uses each");
    println!("  region's real grid CO2 (Iceland 0.05, India 0.71 kg/kWh).");
    println!();
    println!("── Design search knobs ──");
    println!("  trust_radius            — direct peers admitted past the gate");
    println!("  cohort.publishable()    — what fraction crosses the wire at all");
    println!("  disk_budget_server      — the only hard storage limit");
    println!("  daily_bytes, daily_fetch_bytes — workload");
    println!("  FleetStyle              — phone_first / realistic_2026 / homelab");
    println!("  Region                  — 9 GSMA-aligned regions with real");
    println!("                            population × smartphone × broadband ×");
    println!("                            grid CO2 from 2024-2026 sources");
    println!();
}
