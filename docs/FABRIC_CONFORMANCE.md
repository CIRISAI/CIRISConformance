# The two conformance tiers

CIRISConformance verifies the CIRIS federation at **two tiers**, matching
the layering in [`FEDERATION_SCALING_MODEL.md`](https://github.com/CIRISAI/CIRISNodeCore/blob/main/FSD/FEDERATION_SCALING_MODEL.md)
and [`CEWP.md`](https://github.com/CIRISAI/CIRISNodeCore/blob/main/FSD/CEWP.md).

| Tier | Marker | What it proves | Lives in |
|---|---|---|---|
| **Substrate** | `substrate` | The independently-built ciris-* wheels cohabit in one process and each primitive behaves per the CEG contract | `test_0xx` (cohabitation), `test_1xx` (CEG CCP/CCC/CCS) |
| **Fabric** | `fabric` | The *emergent* federation behaviour — the replication discipline + the scaling factors that make "carry the internet on commodity hardware" hold | `test_2xx` |

```bash
pytest -m substrate    # per-primitive cohabitation + CEG profiles
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

When an ⏳ upstream seam lands, the corresponding `xfail` flips and the
row moves to ✅. The fabric tier is how the CEWP "we don't need big tech"
scaling claim becomes a checked property rather than a slide.
