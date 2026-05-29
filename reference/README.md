# CEWP reference materials

CIRISConformance is the neutral cross-artifact conformance suite for the
CIRIS / CEWP stack — and therefore also serves as a **CEWP reference**:
the authoritative specs the suite tests against are vendored here so the
repo is self-contained, and so a reader can see *what* is being conformed
to alongside the tests that check it.

These are **snapshots**, not the source of truth. The source of truth is
the originating repo; update the snapshot (and note the new commit below)
when the upstream spec moves. The conformance tests cite the section
numbers in these documents.

## What's here

| File | Vendored from | Source commit |
|---|---|---|
| [`CEWP.md`](CEWP.md) — the CIRIS Epistemic Web Platform FSD ("soup") | `CIRISNodeCore/FSD/CEWP.md` | NodeCore @ `0a94a64` |
| [`FEDERATION_SCALING_MODEL.md`](FEDERATION_SCALING_MODEL.md) — what carrying the internet costs at v1 | `CIRISNodeCore/FSD/FEDERATION_SCALING_MODEL.md` | NodeCore @ `0a94a64` |
| [`scale_model.rs`](scale_model.rs) — the scaling "toy" (`cargo run --example scale_model`) | `CIRISNodeCore/examples/scale_model.rs` | NodeCore @ `0a94a64` |
| [`CEG/`](CEG/) — the CEG 0.x wire-format spec (19 sections) | `CIRISRegistry/FSD/CEG/` | Registry @ `fd37a30` |
| [`synthesis/Corridor_Dynamics.tex`](synthesis/) — the flagship synthesis paper, *Corridor Dynamics in Coordinated Systems* (v2; reasoning-shape / ρ / k_eff corridor / trace commons) | `coherence-ratchet/papers/Corridor Dynamics.tex` | coherence-ratchet @ `ffcd62a` |
| [`synthesis/research_status_entry.md`](synthesis/research_status_entry.md) — the ciris.ai/research-status catalog entry (DOI + summary) | `coherence-ratchet/copy/web/` | coherence-ratchet @ `ffcd62a` |

Snapshot date: 2026-05-29.

## How the tiers map to these specs

- **Substrate tier** (`pytest -m substrate`) conforms the wheels to
  [`CEG/`](CEG/) — the CCP/CCC/CCS profiles (§0.2) and the per-primitive
  contracts. See [`../docs/CEG_CONFORMANCE.md`](../docs/CEG_CONFORMANCE.md).
- **Fabric tier** (`pytest -m fabric`) conforms the federation's emergent
  behaviour to [`FEDERATION_SCALING_MODEL.md`](FEDERATION_SCALING_MODEL.md)
  (replication discipline §1/§9) and pins the [`scale_model.rs`](scale_model.rs)
  scaling factors (§1.4 / §4) as an executable contract. See
  [`../docs/FABRIC_CONFORMANCE.md`](../docs/FABRIC_CONFORMANCE.md).
- [`CEWP.md`](CEWP.md) is the platform-identity umbrella: the "we don't
  need big tech" premise these tiers turn into checked properties.

## External references (not vendored)

- Research-status index — `https://ciris.ai/research-status/`
- *Corridor Dynamics in Coordinated Systems* (the vendored synthesis, published PDF) — `https://doi.org/10.5281/zenodo.20300774` (v1, 2026-05-20; the vendored `.tex` is v2)
- CIRISAgent Framework v2 — `https://doi.org/10.5281/zenodo.18137161`
- Coherence Ratchet paper — `https://doi.org/10.5281/zenodo.18142668`
- The Accord — `https://ciris.ai/ciris_accord.pdf`
