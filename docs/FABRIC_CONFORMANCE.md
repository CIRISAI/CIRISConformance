# The two conformance tiers

CIRISConformance verifies the CIRIS federation at **two tiers**, matching
the layering in [`FEDERATION_SCALING_MODEL.md`](https://github.com/CIRISAI/CIRISNodeCore/blob/main/FSD/FEDERATION_SCALING_MODEL.md)
and [`CEWP.md`](https://github.com/CIRISAI/CIRISNodeCore/blob/main/FSD/CEWP.md).

| Tier | Marker | What it proves | Lives in |
|---|---|---|---|
| **Substrate** | `substrate` | The independently-built ciris-* wheels cohabit in one process and each primitive behaves per the CIRIS Constitution (CC 0.4) | `test_0xx` (cohabitation), `test_1xx` (CC 2.2 CCP/CCC/CCS) |
| **Fabric** | `fabric` | The *emergent* federation behaviour — the replication discipline + the scaling factors that make "carry the internet on commodity hardware" hold | `test_2xx` |

```bash
pytest -m substrate    # per-primitive cohabitation + Constitution profiles
pytest -m fabric       # replication discipline + scaling factors
```

Any test not explicitly marked `fabric` is auto-tagged `substrate`
(see `conftest.pytest_collection_modifyitems`), so the two markers
partition the whole suite.

## Fabric coverage — replication discipline (FEDERATION_SCALING_MODEL §1 / §9)

Status: ✅ real test against the wheels · ⏳ xfail tracked to an upstream
seam (never worked around) · 🏛 needs a multi-node fixture.

| Property (§) | Status | Where / why |
|---|---|---|
| Per-actor eviction + `withdraws` emission (§9.1) | ✅ | `test_200` — `evict_actor_json` (CIRISPersist#125) |
| Eviction sweeper liveness — popularity×freshness (§1.2) | ✅ | `test_200` — `sweep_evictions_once` (CIRISPersist#123) |
| Trust-threshold setter + clamp (§1.1) | ✅ | `test_200` — `set_trust_threshold` (CIRISPersist#123) |
| "Whose bytes do I hold?" — local holders (§9.1) | ⏳ | `list_holders_json` returns `[]` for local holdings → **CIRISPersist#130** |
| Trust × capacity intake gate *behaviour* (§1.1) | ⏳ | threshold set but no `AdmissionGate` wired via PyO3 → **CIRISPersist#129** |
| Durable send → `edge_outbound_queue` | ⏳ | `send_durable_inline_text` SIGSEGVs cross-wheel → **CIRISEdge#50** |
| Locality dividend — `cohort_scope` suppresses `holds_bytes` (§1.3) | ⏳ | edge `cohort_scope` outbound refusal not cross-wheel-observable → **CIRISEdge#48** |
| Trust-recursion-depth admission (§1.4) | 🏛 | depth-N graph walk → **CIRISNodeCore#21** (node-core wheel + multi-node) |
| Multi-actor / multi-node replication (§4–§5) | 🏛 | one local signer per Engine — needs a multi-process fixture (Conformance#4) |

## Fabric coverage — scaling factors (the model "toys")

`test_210` pins the **published model factors** as an executable
contract (these are the *model's* claims, not a wheel behaviour — the
substrate-behaviour side is tracked under CIRISNodeCore#21):

| Factor (§) | Status | Pinned contract |
|---|---|---|
| `effective_trust_set_multiplier(depth)` (§1.4) | ✅ | anchors 0→1×, 1→4×, 2→20×, 3→100×; monotonic; overlap-dampened (sub-geometric) |
| `k_eff = k/(1+ρ(k−1))` corridor (CEWP §4) | ✅ | ρ→1 ⇒ k_eff→1 (rigidity); ρ→0 ⇒ k_eff→k (chaos); bounded [1,k], monotonic in ρ |
| retention ∝ 1/effective-set (§5.1) | ✅ | retention strictly decreasing in trust depth (full_internet_v1 anchors) |
| retention-floor gate (v0.6) | ✅ | `test_211` — soft-feasibility floor = 2.0 days of trust-pool churn |
| F-AV cost-asymmetry (v0.6 `fav_findings`, Verify Fed TM v1.1) | ✅ | `test_211` — F-AV-1 Sybil ≈ $876/identity/yr for **0% federation admit** (SOFTWARE_ONLY tier-cap); F-AV-DORMANT $120/yr; the 7-finding catalog |
| F-AV substrate *enforcement* (tier-cap actually refuses Sybil at federation scope) | ⏳ | edge trust-gate + multi-node fixture → **Conformance#7 / #4** |

When an ⏳ upstream seam lands, the corresponding `xfail` flips and the
row moves to ✅. The fabric tier is how the CEWP "we don't need big tech"
scaling claim becomes a checked property rather than a slide.

## Multi-node federation (`test_300`)

Some fabric properties only exist *between* nodes. The `federation` fixture
(`conftest.py`) runs N PyO3-isolated node subprocesses sharing one
substrate — a single on-disk SQLite federation directory + blob store
(persist's `sqlite:////abs.db` 4-slash DSN). No transport is needed: a
shared store *is* how peers see each other at the substrate level, which
sidesteps the Reticulum-self-route / HTTPS-not-in-wheel blockers. (Field
precedent: libp2p dropped heavyweight multi-node frameworks for "start N
nodes and have them interact" — the simplest thing that works.)

| Property (§) | Status | Where |
|---|---|---|
| Cross-node directory visibility (§10.1) | ✅ | `test_300` — node B sees node A's blob + `holds_bytes` |
| Multi-holder discovery (§9.1) | ✅ | `test_300` — two holders → `list_holders` returns both (federation-scoped; `list_holders` is relative to content the querying node holds) |
| Per-operator eviction (§9.5) | ✅ | `test_300` — B evicting its own holdings doesn't withdraw A's holder attestation |

This fixture is the **foundation** for the still-pending multi-node
scenarios — they build on `federation(...)` rather than needing new infra:

| Pending scenario | Tracking |
|---|---|
| Trust × capacity intake gate refuses a low-trust peer | #129/edge#48 — needs the edge trust-gate consumed cross-node |
| Trust-recursion-depth admission (depth-0/1/N) | CIRISNodeCore#21 + node-core wheel |
| F-AV enforcement (SOFTWARE_ONLY tier-caps to 0% federation admit) | Conformance#8 substrate half + the tier-cap surface |
| Cross-transport delivery (HTTPS↔Reticulum) | Conformance#4 — needs the transport-http wheel (CIRISEdge#56) |
