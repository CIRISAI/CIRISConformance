# Federation Scaling Model

**Status:** model v0.3 — single-pool, CEG-organic, trust-depth recursive.
**Empirical inputs:** Verify v2.7.0 / v2.8.0 measured on
ubuntu-latest CI; Edge v0.10.0 targets carrying into v1.0; Persist
v3.3.0 storage floor.
**Companion:** `examples/scale_model.rs` — `cargo run --example
scale_model`.

This is a design-search tool. The question is not "how big can it
get" — it's "what intake + eviction discipline makes CIRIS substrate
carry the entire internet from day one on commodity hardware,
without inventing a replication layer above CEG's primitives?"

---

## 1. The CEG-organic replication discipline

CEG already has every primitive the replication policy needs. There
is no separate "replication layer" — reading the existing wire format
honestly IS the policy.

### 1.1 The intake gate (every node, every byte-attempt)

```
hold? = trust(source) ≥ local_threshold  AND  capacity_available
```

| Element | CEG primitive |
|---|---|
| `trust(source)` | weighted_aggregate over `scores` attestations targeting source's key (P1 + P7) — already computed for vote-weight |
| `capacity_available` | persist's disk budget vs configured cap |
| Push terminates here | `Contribution{Submit}` → persist `put_blob` / `put_contribution` |
| Pull terminates here | `ContentFetch` → `ContentBody` → recipient's `put_blob` |

Push and pull are mechanically distinct paths but the *decision*
is identical: same trust score, same capacity check, same answer.

### 1.2 The eviction sweeper (every node, on capacity pressure)

```
evict_score(blob) = popularity(blob) × freshness(blob)
                  = access_count_since(T) × decay(now − last_accessed_at)
```

| Element | CEG primitive |
|---|---|
| Popularity (local) | `last_accessed_at` + access counter on persist's blob rows |
| Popularity (federation-observable) | Count of `holds_bytes:sha256:{prefix}` advertisers for this content_sha |
| Freshness floor | 24h TTL on `holds_bytes` per CEG §10.1.2 |
| Eviction wire-event | `withdraws` against own prior `holds_bytes` — the §10.1.2 ContentMiss feedback loop |
| Decay curve | Per-deployment config (Pi-at-home wants slow decay; phone wants aggressive) |

### 1.3 The locality dividend (structural, free)

```
cohort_scope ∈ {self, family}  ⇒  no holds_bytes emission
                                ⇒  undiscoverable
                                ⇒  intake gate never reached
                                ⇒  ZERO inter-host cost
```

The 65% local-only fraction in the default cohort distribution
disappears from every inter-host bandwidth, storage, and CPU column
because the wire format will not carry it. Privacy and scale share
the same load-bearing primitive.

### 1.4 Trust recursion depth (operator-side, no CEG enhancement)

**People can trust an entity to be trusted, and choose a depth of
recursion for that trust.** This is a **local operator-config knob**,
not a CEG wire-format addition — nothing is advertised, no new field
on `delegates_to`, no schema change. The federation's existing
`scores` + `delegates_to` attestations already carry the entire
trust graph; each operator independently chooses how deep their
server walks that graph when admitting inbound content.

- `depth=0`: admit only direct trust — strict
- `depth=1`: also admit content from peers your direct trust trusts
- `depth=N`: walk the chain to depth N before admitting

The effective trust set whose bytes can pass the server's intake
gate is the **transitive closure within depth-N hops**. CEG stays
minimal (no new wire surface); the trust graph is already there for
anyone who wants to walk it; operators just choose how far.

**Tier-tied defaults:**

| Tier | Default depth | Rationale |
|---|---|---|
| client | **0** (always) | Phone / tablet holds own + explicit fetches only. No recursion, no admission of trust-chain content. |
| **proxy = L0 server** | **0** (default) | Entry-level federation participant — admits direct trust only (no recursion); 256 GB budget. Same admission discipline as L1, narrower depth. |
| **server = L1** | **1** (default) | Full federation node — admits friend-of-friends; 1 TB budget. Operator-tunable to 0 (strict) or 2-3 (extended). |

**Empirical hop-expansion** (small-world / six-degrees research,
calibrated in `effective_trust_set_multiplier()`):

| Depth | Effective multiplier | Reach |
|---|---|---|
| 0 | 1× | direct only |
| 1 | 4× | close friend-of-friends (heavy overlap) |
| 2 | 20× | extended community |
| 3 | 100× | most of the network |
| ≥3 | gentle extrapolation | saturation |

The geometric growth is dampened by friend-of-friend overlap — in
small-world graphs, my friend's friends are mostly already my
friends, so the unique-set growth per hop is far less than `R^depth`.

---

## 2. Empirical inputs (measured)

All numbers wall-clock on GitHub Actions `ubuntu-latest` —
conservative-by-design baseline. Dev-host CPUs run 2–3× faster.

### 2.1 Crypto (CIRISVerify v2.8.0)

| Op | Cost |
|---|---|
| `hybrid_sign` (Ed25519 + ML-DSA-65) | **466 µs** (~2.15 K sign/s/core) |
| `hybrid_verify` | **276 µs** (~3.62 K verify/s/core) |
| `aes_gcm_encrypt` @ 64 KiB | 11.2 µs (**5.45 GiB/s**) — cache encryption is free |
| `aes_gcm_decrypt` @ 64 KiB | 10.3 µs (**5.91 GiB/s**) |

### 2.2 Edge (v0.10.0 → v1.0 contract)

| Op | Target |
|---|---|
| `envelope_canonicalize` slope | ~250 ns/KiB |
| `envelope_verify` (single) | ~280 µs |
| `dispatch_inbound` (256 B) | < 400 µs → ~2.5 K msg/s/thread |
| `outbound_enqueue Durable` | < 1.5 ms |
| `content_fetch_roundtrip` 1 MiB | < 500 ms |
| `inline_text_pipeline` Classify+Scrub | **5–10 ns/byte** |

### 2.3 Persist (v3.3.0)

| Op | Cost |
|---|---|
| SQLite per-row write (incl. async wrapper) | ~1.5 ms |
| Ingest pipeline @ 768 rows (release) | ~9 ms (~85 K rows/s) |
| Software signer | ~100 µs/sign |
| H3ERE trace per agent decision | ~14 KB |

### 2.4 Multimedia primitives (Persist v3.6.x)

| Op | Cost / shape |
|---|---|
| `put_blob_signing` (16 MiB inline cap; matcher off) | per-row write + hybrid_sign, ~1.6 ms |
| Perceptual-hash check at `put_blob_signing` (matcher on) | matcher-dependent; PDQ ~1 ms / image, fails closed if unreachable per operator policy |
| `takedown_notice` Contribution write + propagation | ~1.5 ms write + `withdraws` emission against matched `holds_bytes` rows |
| `key_grant` Contribution write | ~1.5 ms write + per-subscriber wrap (~10 µs HKDF-SHA256 + ~10 µs AES-256-GCM + ~250 µs X25519) |
| `list_held_by(actor_key)` (identity-aware-storage seam) | indexed read |
| `evict_actor(actor_key)` (per-actor eviction + `withdraws` emission) | linear in actor's holdings; fail-honest contract |
| `list_local_holders` (local-truth bypass of CEG §10.1.2 TTL) | indexed read |

**Triple currency note.** Empirical inputs §2.1-§2.3 reference the
substrate baselines circa Verify v2.8.0 / Edge v0.10.0 / Persist
v3.3.0. The model now ships at the substrate triple keyring v4.4.2 /
persist v3.6.4 / edge v1.0.1 (FY2026 spring federation triple).
Underlying op costs (hybrid_sign, envelope_canonicalize, SQLite row
write) are within noise of the baselines; the §2.4 multimedia
primitives are net-new since CEG 0.3. Refresh cadence is per
substrate release per [NodeCore#23](https://github.com/CIRISAI/CIRISNodeCore/issues/23)
living-document audit.

---

## 3. v1 tier model (L0 / L1 server gradient)

The tier model collapses to **server-gradient + client**. "Proxy"
isn't a distinct architecture — it's an L0 server, the entry-level
storage gradient. Same trust+capacity admission discipline as L1
server, just smaller disk and shallower default trust depth.

| Tier | Storage gradient | Default disk | Default depth | Behavior |
|---|---|---|---|---|
| **client** | n/a | n/a | 0 | No inbound serving. Holds own contributions + own traces. Fetches via L0/L1 proxy/server. Phone / tablet. |
| **proxy = L0 server** | L0 | **256 GB** | 0 (strict) | Full trust+capacity admission. Holds direct-trust content + hot cache. No agent-trace replication. Laptop / desktop. |
| **server = L1** | L1 | **1 TB** | 1 (friend-of-friends) | Full participant. Holds own + admitted-trust + hot cache + replicated agent traces. Home server / VPS. |
| (future) L2+ | L2+ | TBD | 2+ | "Fat servers" with deeper recursion + more disk. Not in v1. |

Each tier still runs the same `trust(source) ≥ threshold AND
capacity_available` intake discipline; the gradient just changes
(budget, depth). All three storage tiers (L0/L1/L2) are real
federation participants — they admit content, sign holds_bytes
attestations, become discoverable as holders.

**Per-server feasibility gates** (the model checks at every tier):

| Resource | L0 gate | L1 gate | Source |
|---|---|---|---|
| Disk | 256 GB | 1 TB | Eric's spec |
| Bandwidth | 1 Gbps (10.8 TB/day sustained) | 1 Gbps | Residential fiber |
| CPU | 1 full-utilization core (86.4 K cpu-sec/day) | Per-process CIRIS share |
| Retention | 2-day admitted-trust floor (soft failure under this) | v0.4 — anti-thrash gate |

### 3.4 Device-class realism (v0.4)

The tier model `client / proxy / server` says *what a node does* in
the federation; the device class says *what hardware it runs on*.
Different device classes have radically different idle power,
marginal-share availability (a phone serving CEWP costs ~5% of its
idle draw — the human pays the rest), always-on reachability, and
useful-work-per-watt efficiency.

| Class | idle_W | marginal_share | always_on | efficiency | net_new |
|---|---|---|---|---|---|
| phone | 2.5 W | 5% | 15% | 0.50× | no |
| laptop | 10 W | 10% | 20% | 0.40× | no |
| tablet | 5 W | 7% | 10% | 0.45× | no |
| ARM mini-PC | 5 W | 100% | 100% | 0.60× | yes |
| home x86 | 25 W | 100% | 100% | 0.40× | yes |
| old desktop | 60 W | 100% | 100% | 0.20× | no |

Fleet styles (per-tier device composition presets):

- **PhoneFirst** — substrate rides hardware that's already on.
  Server slice is mostly ARM mini-PCs; very few dedicated x86 boxes.
- **Realistic 2026** — what you'd see today: phones for clients and
  proxies; L1 is a mix of dedicated ARM boxes, laptops left on, and
  some x86 home servers.
- **Homelab** — dedicated home servers everywhere. Worst-case for
  net-new buildout + per-watt efficiency.

### 3.5 Regional realism (v0.4)

Nine GSMA-aligned regions with real 2024-2026 data. The website's
model assumed a uniform global pool; in reality smartphone
penetration, broadband reach, and grid CO2 differ by an order of
magnitude across the world. Per-region tier mix is computed from
penetration data, not hand-set.

| Region | Pop (M) | Smartphone | Broadband | L1-capable | Grid CO2 |
|---|---|---|---|---|---|
| North America | 378 | 85% | 82% | 75% | 0.38 |
| Europe | 743 | 83% | 77% | 70% | 0.27 |
| East Asia | 1660 | 79% | 73% | 65% | 0.51 |
| South Asia | 2010 | 61% | 42% | 25% | 0.71 |
| Southeast Asia | 695 | 70% | 55% | 35% | 0.55 |
| MENA | 581 | 66% | 58% | 40% | 0.55 |
| Sub-Saharan Africa | 1280 | 52% | 28% | 12% | 0.45 |
| Latin America | 660 | 72% | 65% | 45% | 0.21 |
| Oceania | 45 | 80% | 75% | 65% | 0.55 |

**Sources** — UN World Population Prospects 2024 medium variant /
GSMA Mobile Economy 2024 / ITU Facts and Figures 2024 + Speedtest
Global Index 2024 / IEA Energy Statistics 2024 weighted regional
averages.

The regional model surfaces the truer comparison: South Asia's grid
is 3× dirtier than Latin America's; CEWP power spent in hydro-heavy
Iceland or Norway has near-zero CO2 cost; sub-Saharan Africa's home-
server capability is real but small (12%), so substrate participation
there is dominated by the phone-class client tier at first.

### 3.6 Environmental footprint (v0.4)

Two perspectives in parallel:

1. **Centralized internet substrate today** — datacenter-counted.
   Calibrated against the IEA 2024 global DC electricity estimate
   (~415 TWh/yr at 5 B users); ~10 K facilities × 5 MW avg.
2. **CEWP substrate** — device-class-counted. Most participation
   rides hardware already on for other reasons; marginal power per
   device, not full draw. Regional CEWP footprint uses each region's
   grid CO2 (Latin America 0.21 / South Asia 0.71 kg/kWh).

At the `full_internet_v1` scenario (5 B users):

| Posture | Power | Electricity | CO2 | vs Internet |
|---|---|---|---|---|
| Internet substrate (today) | 50 GW | 438 TWh/yr | 175 Mt/yr | baseline |
| CEWP PhoneFirst | 5.3 GW | 47 TWh/yr | 18.6 Mt/yr | **9.4× less** |
| CEWP Realistic 2026 | 10.3 GW | 90 TWh/yr | 36.2 Mt/yr | **4.8× less** |
| CEWP Homelab | 16.9 GW | 148 TWh/yr | 59.3 Mt/yr | 3.0× less |
| CEWP Regional Realism (Realistic 2026, per-region grid CO2) | 14.3 GW | 125 TWh/yr | 61.4 Mt/yr | 3.5× less power, 2.9× less CO2 |

The marginal vs new-buildout split shows where the joules actually
come from: at Realistic 2026, ~47% is marginal (rides phones /
laptops already on) and ~53% is new buildout (ARM mini-PCs + home
x86). At PhoneFirst it flips to ~55% marginal / ~45% new buildout —
the phone-class population is the largest fleet but contributes
little new hardware.

### 3.7 Latency model (v0.4)

First-order p50 RTT estimate driven by the same sliders that drive
storage and bandwidth. Numbers come from measured residential ISP
RTTs, CDN edge cache RTTs, and great-circle backbone delays.

| Component | Cost | Source |
|---|---|---|
| CEWP cache hit (same box / metro) | 2 ms | local SSD read + LAN hop |
| CEWP local-cohort hop (metro) | 18 ms | typical residential ISP intra-metro |
| CEWP regional hop (continent) | 55 ms | continental backbone RTT |
| CEWP global hop (cross-ocean) | 195 ms | submarine cable great-circle |
| CEWP trust-depth hop penalty | 14 ms / hop | friend-of-friends resolution |
| Internet CDN edge cache | 28 ms | Akamai / Cloudflare typical |
| Internet hyperscale origin fetch | 180 ms | TLS + auth + cross-region |
| Sparseness penalty | +5 ms / decade above 10 users/server | server density |

At `full_internet_v1` with default cohort + 60% cache hit rate +
depth 1: CEWP p50 ≈ 22.6 ms vs Internet ≈ 88.8 ms (**75% reduction**).

---

## 4. Per-actor formula (the v0.3 model)

```
effective_R = trust_radius × effective_trust_set_multiplier(trust_depth_avg)
daily_admitted = effective_R × daily_bytes × σ_publishable
held(t) = min(disk_budget(t),
              own_unbounded
              + admitted_trust_at_steady_state
              + hot_cache_at_steady_state
              + replicated_traces)
```

Where each term is bounded by its share of `disk_budget × utilization`
(0.92 default), and the eviction sweeper maintains the bound.

**`effective_retention_days`** is what the eviction sweeper produces
at steady state — a *derived* quantity:

```
effective_retention_days = trust_budget_share / daily_admitted
```

Higher trust depth (wider effective set) → higher daily inbound →
shorter per-source retention at the same disk budget. The
eviction-popularity-weighting determines *which* sources keep their
content fresh in the held set.

---

## 5. v1 scenarios (server depth 1 default)

All scenarios use the **server-tier default depth=1** (friend-of-friends).
The implied retention is what the eviction sweeper produces at steady
state — derived from (disk_budget, trust topology, demand), not
configured.

| Scenario | N | Tier (c/p/s) | R | effective | D/user | σ_pub | Storage / BW / CPU | Implied retention |
|---|---|---|---|---|---|---|---|---|
| `bootstrap` | 10⁴ | 30/65/5 | 50 | 200 | 20 KB | 35% | 235 GB / tiny / tiny | ✓ ~234 yr |
| `dunbar_steady` | 10⁶ | 40/55/5 | 150 | 600 | 50 KB | 35% | 235 GB / tiny / tiny | ✓ ~31 yr |
| `media_heavy` | 10⁶ | 30/60/10 | 150 | 600 | 500 KB | 35% | 485 GB / 1 KB/s / 1 sec/d | ✓ ~10 yr |
| `twitter_scale` | 10⁹ | 45/50/5 | 150 | 600 | 5 KB | 35% | 152 GB / tiny / tiny | ✓ ~87 yr |
| `news_replacement` | 10⁹ | 40/55/5 | 300 | 1.2K | 100 KB | 35% | 321 GB / 1 MB/s / 6 s/d | ✓ ~14 yr |
| **`full_internet_v1`** | **5×10⁹** | **35/55/10** | **250** | **1K** | **50 MB** | **35%** | **741 GB / 62 KB/s / 43 s/d** | **✓ 37 d** |
| `full_internet_local_heavy` | 5×10⁹ | 35/55/10 | 250 | 1K | 50 MB | 30% | 736 GB / 50 KB/s / 36 s/d | ✓ 44 d |
| `full_internet_global_heavy` | 5×10⁹ | 30/55/15 | 250 | 1K | 50 MB | 60% | 743 GB / 109 KB/s / 73 s/d | ✓ 22 d |
| `village_dense` | 10³ | 40/40/20 | 50 | 200 | 30 MB | 30% | 721 GB / 8 KB/s / 27 s/d | ✓ ~1.1 yr |

**Multimedia / video-replacement scenarios** (added per
[FSD/MEDIA_SHARING.md §2.6-2.7](MEDIA_SHARING.md) inline/external
split + real-world traffic anchors from
Sandvine/DataReportal/Ericsson Mobility Report):

| Scenario | N | Tier (c/p/s) | R | env | D/user | fetch/u | ext_frac | Storage / BW / CPU |
|---|---|---|---|---|---|---|---|---|
| `tiktok_replacement` | 5×10⁹ | 40/55/5 | 250 | 15 MB | 0.5 MB | 95 MB | 0.0 (all inline) | 788 GB / 3 KB/s / 0.5 s/d |
| `youtube_replacement` | 5×10⁹ | 40/55/5 | 200 | 30 MB | 0.5 MB | 1 GB | 0.75 (mix) | 788 GB / 7 KB/s / 0.5 s/d |
| `netflix_replacement` | 5×10⁹ | 40/55/5 | 100 | 5 KB | 1 KB | 1.5 GB | 1.0 (all external) | 133 GB / 13 KB/s / 1 s/d |
| **`full_internet_with_video`** | **5×10⁹** | **35/55/10** | **250** | **50 KB** | **11 MB** | **1.7 GB** | **0.88** | **743 GB / 55 KB/s / 40 s/d** |

The `full_internet_with_video` numbers (11 MB/user/day produced,
1.7 GB/user/day consumed — combined TikTok + YouTube + Netflix +
text + photos + everything) **all fit per-server at v1**.
Netflix-class streaming is *the easiest scenario* — at 13% of disk
because external_fetch_fraction=1.0 means the substrate routes
metadata and the bytes ride the publisher's CDN (Netflix's own Open
Connect / studio S3 / community film co-op MinIO). The substrate's
"no datacenters required" claim holds for streaming because
*publishers' existing storage IS the substrate's storage tier for
that content* — we compose with what already exists.

### 5.1 What the numbers say

**Compute and bandwidth never gate.** Even at 5 B users with depth 1
(effective_sources = R × 4 ≈ 1K), per-server CPU stays below 0.2% of
1 core and bandwidth below 0.2% of 1 Gbps. The hybrid PQC verify
cost (276 µs) is invisible in aggregate.

**Disk budget is the only knob that bites — and the model shows
exactly why.** Two terms compete for the budget:
1. Own content (priority — your data is always yours)
2. Admitted-trust content at `daily_admitted × T_effective`

The eviction sweeper sets `T_effective` so the held set equals 92%
of disk. Wider trust set or higher activity → shorter `T_effective`.
Smaller → longer.

**Trust depth is a meaningful operator knob.** At `full_internet_v1`:
- depth 0 → ~150 days retention (strict, direct trust only)
- depth 1 → 37 days (default — friend-of-friends, R × 4 sources)
- depth 2 → ~7 days (extended community, R × 20 sources)
- depth 3 → single-digit days (most of the network)

Operators trade reach for retention. The federation doesn't dictate
the trade-off; each server picks its own depth as a local config.

**Cache hit rate is bounded sensitivity.** The sensitivity sweep
(`print_cache_sensitivity`) on `full_internet_v1` shows < 1 GB/day
bandwidth variation from 0.3 (pessimistic) to 0.85 (optimistic) and
no change in implied retention. At v1 scale, admitted-trust inbound
(~17 GB/day) dominates cache-miss inbound (~0.4 GB/day) by ~40×;
the cache assumption barely moves the needle. Real telemetry will
matter more on tiers where trust admission is small (client / proxy)
or in low-R deployments.

**Village-scale is essentially free.** R=50 + depth 1 (200 effective
sources) gives ~1.1 years of admitted-trust content held on a Pi-class
home server. Substrate is deployable in small communities day one.

---

## 6. What's NEW in v0.3 vs v0.2

- **No more `direct_trust_archive_days` / `cache_ttl_minutes` /
  `cache_hit_rate` / `server_cache_max_bytes` knobs.** Those were
  modeling a policy layer that doesn't need to exist. Replaced by
  one knob: `disk_budget_server`. The composition is derived.
- **Trust recursion depth** is first-class: `trust_depth_avg` per
  scenario, with the `effective_trust_set_multiplier()` curve
  reflecting small-world hop expansion + overlap dampening.
- **Implied retention** is a derived output, not a configured input.
  The model now shows what the eviction sweeper *will* produce at
  steady state for each scenario.
- **CEG-primitive mapping** (§1) — every model element is mapped to
  the existing wire-format primitive it rides on. No new mechanisms
  invented.

---

## 7. What this model is NOT

- **Not a capacity guarantee.** Bench numbers are CI ubuntu-latest.
- **Not a network simulator.** Steady-state averages; not congestion
  or Reticulum reachability dynamics.
- **Not a privacy certifier.** The CEG-locality dividend is enforced
  by the wire format; the model only costs it.
- **Not a final answer.** Trust-depth multiplier curve is empirically
  anchored but not measured against real CIRIS topology; cache-hit
  rates are assumptions; agent decision rate at population scale is
  a guess. All inputs are honest about being inputs.

The model is a planning tool. Run scenarios, see where the knobs
matter, calibrate against real federation data as it accumulates.

---

## 8. What this implies upstream

The substrate primitives needed to execute this discipline:

**Persist** (filed as CIRISPersist replication-policy issue):
- Trust-score lookup at `put_blob` / `put_attestation` /
  `put_contribution` admission
- `last_accessed_at` + access counter on `federation_blobs` rows
- Eviction sweeper computing `popularity × freshness`
- Configurable disk budget + steady-state utilization watermark
- Encrypted-at-rest for cache content (already shipped in persist)

**Edge** (filed as CIRISEdge trust-gate issue):
- Trust-score short-circuit at `dispatch_inbound` (before handler)
- `cohort_scope` check at `outbound_enqueue` (refuse self/family
  outbound — the wire-format locality enforcement)

**Trust recursion depth needs NO upstream change** — it's a local
operator config consuming the existing `scores` + `delegates_to`
attestation graph. CEG's 1+4 wire format stays locked.

**NodeCore** (already done):
- The Phase 2B ingest path (CIRISNodeCore#19) produces the wire
  artifacts that ride these primitives. Node-core does not own
  any replication policy — by design.

---

## 9. Why this works at all — the identity-aware-storage property

> **Eric's thesis:** "What makes this work is that you know whose
> data you are storing, and can evict their data at any time if
> you choose."

This isn't just a feature — it's the load-bearing property the
entire discipline rests on. The whole `trust(source) ≥ threshold
AND capacity_available` intake + `popularity × freshness` eviction
model presumes the substrate can answer two questions at any moment:

1. **Whose bytes am I holding?**
2. **Can I evict everything from a specific actor right now?**

### 9.1 How CIRIS guarantees both

Every blob admission is one atomic call:

```rust
BlobStorage::put_blob_signing(
    sha256, body, media_type,
    attesting_key_id,        // ← identity of the holder
    signer,                  // ← cryptographic witness
    now, attestation_id,
)
```

The call commits THREE things atomically:
* the bytes (`federation_blobs` row)
* the holder attestation (`federation_attestations` row with
  `attesting_key_id`, `attestation_type=holds_bytes:sha256:{prefix}`,
  `evidence_refs` containing the SHA)
* the signature over the canonical envelope (persist's
  `PythonJsonDumpsCanonicalizer`, per CIRISPersist#121's
  identity-pin)

After this returns, the substrate can answer:
* "whose bytes do I hold?" — `SELECT attesting_key_id FROM
  federation_attestations WHERE attestation_type LIKE
  'holds_bytes:%' AND blob_sha = ?`
* "evict everything from author X" — query `federation_blobs` JOIN
  `federation_attestations` ON the holder's `attesting_key_id`,
  delete the rows + emit `withdraws` against each `holds_bytes`
  attestation

The attribution chain is **at the byte level**, not the application
layer. Eviction granularity is **per-actor**, not just LRU-tail.
Both properties ride the same atomic primitive.

### 9.2 Prior art — no deployed system has this as a unified mechanism

Surveyed against IPFS, Veilid, Hypercore, SSB, Storj, Filecoin, Sia,
Tahoe-LAFS, Mastodon, Tor, Freenet. The two-property combination
(identity-aware byte-level storage + per-actor eviction granularity
as a substrate primitive) does not appear unified anywhere:

| System | Identity-aware bytes? | Per-actor eviction? | Pattern |
|---|---|---|---|
| **IPFS / Kubo** | No | No | Anonymous content-addressing; LRU watermark only |
| **IPFS Cluster** | Partial | Partial | Knows "the peer who asked us to pin," not the author |
| **Veilid** | Partial | Couldn't verify | Signed DHT records; block storage hash-addressed |
| **Hypercore / Holepunch** | Yes (feed-level) | Yes (feed-level) | Identity rides the feed; cross-feed blobs re-attributed |
| **Storj** | Partial (satellite) | Partial | Nodes see only erasure-coded ciphertext |
| **Filecoin** | Partial | **No** (by design) | Contract binds host to keep data; eviction = slashed |
| **Sia** | Partial | **No** (by design) | Same — contract-bound hosting |
| **Tor exit relay** | No (by design) | No | Unlinkability is the threat model |
| **Freenet** | No (by design) | No | "Infeasible to discover origin" — by design |
| **Tahoe-LAFS** | Partial (planned) | Partial | Accounting design proposed, not deployed |
| **Mastodon / ActivityPub** | Yes (object-level) | Yes | But at **application layer**, not byte-storage substrate |
| **SSB (Scuttlebutt)** | Yes (feed-level) | Partial | Replicated blobs decouple from feed identity |

**The closest analogs are SSB and Hypercore** (feed-level identity)
and **Mastodon** (object-level identity at the application layer).
None weld attribution and eviction into a single byte-storage-
substrate primitive the way `put_blob_signing` does.

### 9.3 Why the contract-storage systems explicitly REJECT this

**Filecoin / Sia / Storj are the inverse design.** Their entire
commercial value proposition is that the host *cannot* evict the
renter — the host signs a contract, posts collateral, and gets
slashed if they drop data. Operator-side per-actor eviction is the
threat model they sell against.

CIRIS makes the opposite call because it's a **federation of
mutually-attesting peers**, not a paid marketplace. Trust changes
over time (a peer slashed today should not have their content
held indefinitely); the substrate's authority to evict is exactly
what makes federation governance enforceable at the storage layer.

### 9.4 Why anonymous content-addressing (IPFS, Freenet) hits the wall

The well-documented scaling pains in those systems are exactly the
failures this property prevents:

* **IPFS pin-set bloat** — no popularity-or-trust signal to drive
  eviction; pinning services manually curate at the operator level
  outside the protocol
* **Freenet inability to handle abuse** — by-design anonymity means
  operators legally hold opaque content with no surface to refuse
  specific actors
* **IPFS Cluster's "untrusted peers lying about free space"** —
  resource attestation has no identity-tied recourse

These are the failure modes CIRIS's `holds_bytes` +
`attesting_key_id` + admission gate forecloses *structurally*. The
substrate doesn't need a curation layer above it; the substrate
itself is curatable because every byte carries its provenance.

### 9.5 The precise privacy trade-off

The substrate exposes four federation-queryable surfaces (the
public directory; this is HOW discovery works):

| Query | Returns | Leaks |
|---|---|---|
| `list_holders(sha256)` | `attesting_key_id`s holding this content | Where the bytes are |
| `list_attestations_by(key_id)` | All `holds_bytes` rows by this holder | What this peer holds |
| `list_attestations_for(key_id)` | Inbound `scores` / `delegates_to` rows | Who vouches for this peer |
| `list_contributions(filter)` | Contribution envelopes (carry `author_id`) | Who authored what |

The **join across these tables** is the actual privacy surface:
`author X created content C` ⨝ `peer P holds C` = **inference that
peer P admits author X's content**, which transitively reveals
**P's trust graph at the public-cohort scope**.

So precisely: **the published trust graph is observable for content
at `community` scope or wider**. Not the access patterns, not the
bytes — the *admission relations*.

**What's NOT observable** (precisely):

| Surface | Visible to federation? |
|---|---|
| Cleartext bytes of any blob | No — only the SHA + signature; bytes are encrypted at rest |
| Who fetched what (browse history) | No — fetch logs are local to the serving peer |
| Local popularity / access counters | No — eviction signal stays local |
| Local trust thresholds | No — operator config, private |
| Trust recursion depth choice | No — local config, nothing advertised |
| `self` / `family` scope content (existence, author, holders) | No — locality dividend, never in `federation_attestations` |

The per-fetch leak still exists but is *bilateral*: when I
`ContentFetch` from peer P, P learns I'm interested in that SHA —
same property a CDN edge has about its viewers — but no other peer
sees that interaction.

### 9.6 What CIRIS does NOT allow at protocol level

There is **no "publish anonymously" mode** at federation scope.
Content at `community` / `affiliations` / `species` / `planet` /
`federation` scope carries `author_id` cryptographically and *is*
the author's identity attestation. You cannot publish-but-hide-
author on the main path — that would break the trust-enforceability
story.

For content where the author wants publication without identity-
attribution on the main substrate, the operator-side options are:

1. **Pseudonymous federation key** — operator practice, not a system
   feature. The substrate sees a key; whether that key maps to a
   real-world identity is outside CIRIS's concern. Same posture as
   Bitcoin: keys are pseudonymous unless de-anonymized off-chain.
2. **Stay at `self` or `family` scope** — never federated, never
   observable.

A third path — *protocol-level deniability* — is a v2 design
possibility, sketched in §9.9.

### 9.7 Comparison to anonymity systems

| System | Trust graph observable? | Author observable? | Holder observable? |
|---|---|---|---|
| **CIRIS public-scope** | **Yes (by design)** | Yes (`author_id`) | Yes (`attesting_key_id`) |
| CIRIS local-scope | No | n/a (never federated) | n/a |
| IPFS / Kubo | No (no trust concept) | No | Pseudonymous |
| Freenet | No (by design) | No (by design) | No (by design) |
| Tor hidden services | No (unlinkable) | Onion key, pseudonymous | n/a (no storage layer) |
| Signal sealed sender | No (one-sided) | Server doesn't see; recipient does | Server forgets after delivery |
| Veilid | No (DHT only sees ciphertext) | No (owner key) | Pseudonymous DHT node |
| Mastodon | Yes (federation-level) | Yes (`attributedTo`) | Yes (instance-level) |
| SSB | Yes (follow graph) | Yes (`author` per message) | Yes (per-feed) |

CIRIS sits closest to **Mastodon + SSB** on the privacy axis —
federated systems that chose identity-aware-publication, accepting
the trust-graph observability as the cost of trust-enforceability +
governance.

### 9.8 Bottom line — the trade in one sentence

**CIRIS makes the published trust graph observable in exchange for
the operator-side ability to govern admission and eviction by
actor; it preserves anonymity for everything at self/family scope,
and offers pseudonymous federation keys as the operator-practice
escape hatch — there is no protocol-level "publish anonymously"
on the main path because that would dissolve the trust-
enforceability the whole substrate rests on.**

### 9.9 Could we add deniability? — totalitarian threat model

**Yes, as an opt-in parallel publication path.** The identity-aware
substrate stays unchanged; a separate anonymous tier rides
alongside, addressed by blinded keys, holding opaque ciphertext.

#### How Veilid / Signal sealed sender / Tor v3 do this

All three achieve storage-/forwarder-layer deniability through the
same structural pattern: **the holder's input is ciphertext bound
to an ephemeral or blinded public key, never to the originator's
long-term identity, plus routing indirection severs the network-
layer link.**

| System | Storage record | Blinding | Discoverability |
|---|---|---|---|
| **Veilid** | DHT tuple `(record_key, subkey, ciphertext, sig)` keyed by *owner* pubkey; AEAD-encrypted with keys the storage node lacks; arrives via onion-routed *private route* | Owner key may rotate per record; signature schema (DFLT / SMPL) authorizes writers without revealing them | Reader must know `record_key` out-of-band; no global directory |
| **Signal sealed sender** | Forwarded envelope; server sees recipient address + opaque inner blob | Two-layer envelope — ephemeral X25519 outer wraps static-key inner carrying `sender_cert ‖ ciphertext` | Sender presents 96-bit delivery token derived from recipient's profile key |
| **Tor v3 onion** | HSDir holds AEAD-encrypted descriptor keyed by **per-period blinded Ed25519 key** + subcredential | Ed25519 key blinding rotates per time-period; HSDir never sees the underlying onion identity | Client independently derives the same `blinded_public_key` from public onion identity + current period |

The common primitive set: **(a) Ed25519 key blinding or ephemeral
key derivation** that severs the holder's view from the originator's
stable identity, plus **(b) onion-routed transport** that severs
network-layer linkage.

#### Could CIRIS overlay this without sacrificing the main path?

Architecturally, **yes** — all three deniability designs run as
*parallel paths* on their substrates (Signal runs sealed sender
alongside identified delivery on the same server; Tor onion services
coexist with identified relays; Veilid DHT records can carry both
signed-by-known-key payloads and routed-via-private-route payloads
on the same node). None of them require *uniform* anonymity.

**Minimum primitive set CIRIS would need** for a parallel anonymous
publication path:

1. **Per-publication blinded keys** — Ed25519 key blinding,
   Tor-style. Each anonymous record's signing key is unlinkable to
   the holder's federation identity.
2. **AEAD on the payload** — XChaCha20-Poly1305 keyed by
   `KDF(blinded_pk, period)`, so the storage node holds ciphertext
   under a key it never sees.
3. **Onion-routed write path** — Sphinx-style or Veilid-style
   3-hop, so the publishing node's IP is not the record's network
   origin.
4. **Discoverability rendezvous** — either a recipient-derived
   delivery token (Signal model, for targeted publication) or a
   time-rotated blinded index (Tor model, for open publication).

#### What the anonymous tier loses (and that's the point)

A new wire-format record class — call it `AnonymousContribution` —
sits parallel to the identity-aware `Contribution`. It cannot ride
the existing trust+capacity admission discipline because there's
no identity to gate on:

| Property | Identity-aware tier (main) | Anonymous tier (proposed) |
|---|---|---|
| Trust-weighted admission | Yes | **No** (no identity to score) |
| Per-actor eviction | Yes | **No** (LRU only) |
| Operator-side governance | Yes | **No** (operator holds opaque ciphertext) |
| Trust graph observable | Yes | **No** |
| Compelled disclosure resistance | Limited | **Strong** (operator literally cannot decrypt) |
| Abuse handling | Trust-graph + slashing | LRU + capacity gating only |
| Discoverability | Federation directory | Out-of-band rendezvous |

The author chooses per-publication. The operator runs both
substrates. For totalitarian threat model: dissident publication
uses the anonymous tier → coerced operator sees only opaque
ciphertext → no proof of holding specific content, no proof of
trust relationship → cryptographic deniability instead of legal /
operator-discretionary deniability.

#### Important: the anonymous tier needs to be MANDATORY infrastructure

If only some operators run the anonymous tier, those operators
become identification targets (raid the nodes that run the
deniable storage). For meaningful deniability, the anonymous tier
must be **standard substrate-level infrastructure that every
L0/L1 server runs**, indistinguishably — much like every Tor relay
runs the same code regardless of which onion services it happens to
be holding descriptors for. The operator's deniability is "I'm
running the standard substrate; I have no way to know which
records on my disk belong to which publication."

#### What this would cost CIRIS to build

* **CEG**: a parallel record class (`AnonymousContribution` with
  blinded-key signature instead of `author_id`). Wire-format
  addition, not a change to existing primitives. The 1+4 stays
  locked.
* **Persist**: a parallel storage table for opaque-blinded records;
  same put/get/has surface but no trust-score lookup at admission
  (capacity only).
* **Edge**: onion-routing layer (Sphinx-style packets). This is
  substantial — likely a new transport class alongside Reticulum
  and HTTPS.
* **NodeCore**: minimal — node-core doesn't own replication
  policy. Maybe a publish_anonymously() entry point.

**Roughly the size of a v2 release.** v1 ships the identity-aware
substrate; v2 could add the anonymous tier without disrupting v1
deployments.

#### Why this matters for the mission

CIRIS's first audience is humans + agents operating in tractable
trust contexts (communities, governance, federation). The identity-
aware substrate is right for that. But the mission goal is to serve
*all* of humanity — including humans operating in totalitarian
contexts where federation-attribution would put them at lethal
risk. The anonymous tier closes the gap: dissidents, journalists,
whistleblowers can publish onto CIRIS using the same wire format
substrate as everyone else, with cryptographic guarantees the
identity-aware tier doesn't offer.

**The right mental model:** the main substrate is the *public
square*; the anonymous tier is the *encrypted letter dropped in
a mailbox*. Both are first-class postal-system functions; neither
breaks the other. CIRIS v1 builds the public square. CIRIS v2
adds the mailbox.

Sources for §9.9:
- [Veilid: Private Routing](https://veilid.com/how-it-works/private-routing/)
- [Veilid: Cryptography](https://veilid.com/how-it-works/cryptography/)
- [Veilid Developer Book](https://veilid.gitlab.io/developer-book/)
- [Signal: Sealed Sender](https://signal.org/blog/sealed-sender/)
- [Tor rend-spec-v3: Deriving Keys](https://spec.torproject.org/rend-spec/deriving-keys.html)
- [Tor rend-spec-v3: Descriptor Encryption](https://spec.torproject.org/rend-spec/hsdesc-encrypt.html)

### 9.6 Summary

| Property | CIRIS substrate guarantee | Achieved by |
|---|---|---|
| Identity-aware at the byte level | Yes | `put_blob_signing` atomic commit |
| Per-actor eviction granularity | Yes | `federation_attestations` index on `attesting_key_id` + `withdraws` primitive |
| Operator authority to evict | Yes | Local config consuming `scores` trust graph |
| Anonymity for sensitive content | Yes (via opt-out) | `cohort_scope ∈ {self, family}` blocks `holds_bytes` emission |
| Per-byte attribution at app layer | NO | Substrate property, not app concern |

This is the load-bearing property. Without it, the trust × capacity
intake + popularity × freshness eviction discipline collapses to
"LRU on opaque blobs" — which is exactly what IPFS does, and
exactly the regime the scaling model says doesn't work at
full-internet scale.

Sources for the prior-art comparison (§9.2):

- [IPFS Kubo garbage collection](https://docs.ipfs.tech/how-to/kubo-garbage-collection/)
- [IPFS Cluster allocator](https://github.com/ipfs-cluster/ipfs-cluster/blob/master/allocate.go)
- [Veilid cryptography](https://veilid.com/how-it-works/cryptography/)
- [Hypercore DEP-0002](https://www.datprotocol.com/deps/0002-hypercore/)
- [Storj v3 whitepaper](https://static.storj.io/storjv3.pdf)
- [Filecoin Storage Market spec](https://spec.filecoin.io/systems/filecoin_markets/storage_market/)
- [Sia hosting best practices](https://sia.tech/hosting-best-practices)
- [Tahoe-LAFS Accounting design](https://tahoe-lafs.org/trac/tahoe-lafs/wiki/NewAccountingDesign)
- [Mastodon ActivityPub federation](https://docs.joinmastodon.org/spec/activitypub/)
- [Scuttlebutt protocol guide](https://ssbc.github.io/scuttlebutt-protocol-guide/)
- [Freenet paper (Clarke et al.)](https://www.cs.cornell.edu/people/egs/615/freenet.pdf)
- [Tor intro spec](https://spec.torproject.org/intro/index.html)
