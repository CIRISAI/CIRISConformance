# CEWP reference materials

CIRISConformance is the neutral cross-artifact conformance suite for the
CIRIS / CEWP stack — and therefore also serves as a **CEWP reference**:
the authoritative specs the suite tests against are vendored here so the
repo is self-contained, and so a reader can see *what* is being conformed
to alongside the tests that check it.

The authoritative standard the suite conforms against is the **CIRIS
Constitution** (`CC 0.5.1`) — the **superalignment standard** for the CIRIS
ecosystem. CIRISConformance tests the substrate's compliance with it; the
CIRISAgent suite + safety batteries test the agent's; together they are the
system's constitutional-compliance claim. **The Constitution superseded CEG** —
the old CEG wire-grammar spec is absorbed into the Constitution (the grammar is
`part_2`, the namespace `part_3`, transport/substrate `part_5`, …); `CC N.x`
clauses live in `part_N`. The vendored `CEG/` tree is kept only for historical
section-number cross-references.

These are **snapshots**, not the source of truth. The source of truth is
the originating repo; update the snapshot (and note the new commit below)
when the upstream spec moves. The conformance tests cite the section
numbers in these documents.

## What's here

| File | Vendored from | Source commit |
|---|---|---|
| [`CIRIS_Constitution/`](CIRIS_Constitution/) — **the CIRIS Constitution `CC 0.5.1`, the superalignment standard** (parts 1–8; superseded + absorbed CEG) | `CIRISRegistry/FSD/CIRIS_Constitution/` | Registry @ `c81a3b5` |
| [`CEWP.md`](CEWP.md) — the CIRIS Epistemic Web Platform FSD ("soup") | `CIRISNodeCore/FSD/CEWP.md` | NodeCore @ `dfd158e` |
| [`FEDERATION_SCALING_MODEL.md`](FEDERATION_SCALING_MODEL.md) — what carrying the internet costs at v1 | `CIRISNodeCore/FSD/FEDERATION_SCALING_MODEL.md` | NodeCore @ `dfd158e` |
| [`scale_model.rs`](scale_model.rs) — the scaling "toy" **v0.6** (`cargo run --example scale_model`; adds the `fav_findings()` adversarial-cost module vs Verify Fed TM v1.1) | `CIRISNodeCore/examples/scale_model.rs` | NodeCore @ `dfd158e` |
| [`CEG/`](CEG/) — the CEG 0.x wire-grammar spec (19 sections) — **SUPERSEDED**, absorbed into the Constitution above; retained for historical section-number cross-refs | `CIRISRegistry/FSD/CEG/` | Registry @ `fd37a30` |
| [`synthesis/Corridor_Dynamics.tex`](synthesis/) — the flagship synthesis paper, *Corridor Dynamics in Coordinated Systems* (v2; reasoning-shape / ρ / k_eff corridor / trace commons) | `coherence-ratchet/papers/Corridor Dynamics.tex` | coherence-ratchet @ `ffcd62a` |
| [`synthesis/research_status_entry.md`](synthesis/research_status_entry.md) — the ciris.ai/research-status catalog entry (DOI + summary) | `coherence-ratchet/copy/web/` | coherence-ratchet @ `ffcd62a` |

Snapshot date: 2026-06-26 (re-vendored the CIRIS Constitution at `CC 0.5.1` — the stewardship reframe `owner`→`steward`, the `affiliations` institutional cohort, `age_assurance`/`age_self_declared` namespace split, reverse-quorum moderation + moderator-existence gate, and the infohazard glossary/consent gate; conformed by the persist 11 / verify 8.1 / edge 7.3 / server 0.5.54 floor). Prior: 2026-06-26 (CIRIS Constitution `CC 0.4`, CEG marked superseded); 2026-05-31 (scaling toy re-vendored at v0.6).

## Prior art & state-of-the-art comparison

[`comparison/`](comparison/) positions CEWP **as a whole platform** against
the deployed/published state of the art — decentralized storage,
AI governance, the federated web, and crypto/transparency — complementing
the per-layer `STANDARDS_COMPARISON.md` docs the substrate sisters carry.
It names the property the field has not unified (identity-aware storage +
per-actor eviction) and is honest about where the prior art is better.

## How the tiers map to these specs

- **Substrate tier** (`pytest -m substrate`) conforms the wheels to the
  [CIRIS Constitution](CIRIS_Constitution/) — the grammar (`part_2`), namespace
  (`part_3`), and transport/substrate (`part_5`), incl. the CCP/CCC/CCS
  conformance profiles. See [`../docs/CC_CONFORMANCE.md`](../docs/CC_CONFORMANCE.md).
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
