# CIRIS Constitution conformance profiles in this harness

The **[CIRIS Constitution](../reference/CIRIS_Constitution/) `CC 1.0-rc2`** — the
ecosystem's **superalignment standard** — defines three normative conformance
profiles in **CC 2.2**. (The Constitution **superseded CEG**: the CEG wire-grammar
is absorbed into it — grammar → `part_2`, namespace → `part_3`, transport →
`part_5`; `CC N.x` lives in `part_N`. The profile *names* CCP/CCC/CCS are retained
verbatim from CEG §0.2.) CIRISConformance adopts these as the **organizing
principle** for cross-artifact conformance tests, alongside the cohabitation
scenarios. This suite tests the **substrate's** compliance with the standard; the
CIRISAgent suite + safety batteries test the **agent's** — together, the system's
constitutional-compliance claim.

| Profile | Who | What it MUST do (CC 2.2) |
|---|---|---|
| **CCP** — Conforming Producer | emitters (Agent, Verify, LensCore, NodeCore, …) | emit well-formed envelopes (CC 2.1), sign per hybrid-sig, respect reserved-prefix rules (CC 3.4), declare `oversight_mode` + `witness_relation` (CC 2.1) |
| **CCC** — Conforming Consumer | composers (Agent, Verify, Portal) | verify hybrid signatures, enforce reserved-prefix at admission, implement ≥ Policy A (CC 4.4.3.8) + default aggregation (CC 4.4.2), honor `null` hardware-class rejection (CC 4.2.2) |
| **CCS** — Conforming Substrate | persist + edge + verify | storage/transport guarantees (CC 5.3.2 / CC 5.3.1), idempotent replication, full-SHA blob verify before consumption (CC 5.3.2.5), witness-quorum admission (CC 5.3.1) |

Tests carry the `ceg` marker plus their profile marker (`ccp` / `ccc` /
`ccs`). Run a profile with `pytest -m ccc`.

## Reading discipline — self-as-subject (CC 2.3.4 / part_1 anti-Cartesian)

Per the Constitution's anti-Cartesian / Ubuntu foundation (**part_1** "the self is
constituted relationally," + **CC 2.3.4** `self-as-subject`): a conformant
**substrate admits, it does not gate, self-attestation**. A `witness_relation:
self` row is accepted even with zero prior cross-attestations, because the
cross-attestation that constitutes the self is *upstream* — there is no
pre-relational atomic entity available to do the admitting. This harness therefore
tests that substrates **accept** self-attestation, and treats a substrate that
adds a Cartesian admission gate on self-attestation as **non-conformant**.
(`witness_relation` and `oversight_mode` are normatively defined in **CC 2.1**
— `oversight_mode` enum `HITL|HOTL|HOOTL`, default `null` — but remain
consumer-policy-weighted with no substrate enforcement gate; gated at the Rust
layer where applicable, see CIRISServer below.)

## Why this harness can't yet cover all of CC 1.0-rc2

This harness drives the **real published wheels** (persist / verify /
edge). A test is only meaningful if it exercises actual binary behavior —
asserting a spec MUST-rule the wheel doesn't expose or enforce would be
fake coverage. Each row below is honest about its status, and every gap is
tracked by an upstream test-seam issue so it converts to a real test when
the surface lands.

## Coverage matrix

Status legend: ✅ implemented (real Python cohabitation test) · 🦀 covered at the
**Rust layer** (a CIRISServer Rust conformance test against the pinned crate
triple — the feature runs Rust-to-Rust and is not on the Python wheel surface, so
the agent's brain never drives it; testing it via Python would mean adding an
artificial PyO3 surface) · ⏳ pending an upstream seam · 🏛 governance/process tier
(not a substrate behavior).

> **Two-lane conformance.** Features the agent's Python brain drives through the
> PyO3 wheels are gated here (✅). Substrate-internal features that execute
> Rust-to-Rust inside CIRISServer (STH consistency-proof, hybrid KEX, realtime-A/V
> seal, witness/anti-replay admission) are gated in CIRISServer's Rust suite
> against the same pinned triple (🦀) — this doc indexes both lanes.

| CC clause (legacy CEG §) | Profile | Status | Where / why |
|---|---|---|---|
| CC 2.2 profile organizing principle | — | ✅ | `ccp`/`ccc`/`ccs`/`ceg` markers; this doc |
| Hybrid-signature verify + policy matrix | CCC | ✅ | `test_100_ccc_hybrid_verify.py` (strict / ed25519_fallback / soft_freshness / directory) |
| CC 5.3.2.5 blob full-SHA integrity (reject mismatch) | CCS | ✅ | `test_110_ccs_blob_integrity.py` (`blob_hash_mismatch`) |
| CC 5.3.2.5 blob positive round-trip + holder attestation | CCS | ✅ | `test_110` via persist v3.3.0 `put_blob_signing` (CIRISPersist#124 shipped) |
| Canonical-bytes determinism + sign/verify round-trip | CCP | ✅ | `test_120_ccp_canonical_bytes.py` |
| CC 3.3.6.2.1 RNS destination-hash recompute | CCS | ✅ | `test_150_rns_dest_hash.py` — executable golden vector of the pinned two-stage construction + the anti-flat-form regression (CIRISRegistry#80 / CIRISVerify#28). The wheel-recompute cross-check is now a **real gate** (`ciris_verify.rns_destination_hash`, exposed in **verify v7.3.0**); it skips only on a matrix pin < verify 7.3.0 |
| CC 3.5.1 concurrent-write precedence + dedup-on-triple | CCS | ⏳ | needs generic `put_attestation` schema (arbitrary dimension) → **CIRISPersist#124** |
| CC 3.4.7 reserved-prefix admission rejection | CCS | ✅ | `test_240` — `emit_attestation_self` refuses `accord:*`/`capacity:*`-self/`system:*` from an agent key (persist 10.4.0, CIRISPersist#288) |
| CC 2.6.2/2.6.3/2.6.7 canonicalization rejection | CCC | ✅ | `test_120` (timestamp/hex/future) + `test_240` (uppercase-hex `subject_key_ids`, persist 10.5.0 / CIRISPersist#293) |
| CC 2.1/2.3.4 `witness_relation` + self-attestation | CCP/CCC | 🦀 | CIRISServer `tests/peer_replication.rs::peer_b_registered_admits_b_liveness_and_a_emits_directed_consent` asserts `witness_relation=="self"` + self-attestation admission / forged-peer rejection, vs the pinned triple. (`oversight_mode` itself is untested — see the Rust-harness gap below.) |
| CC 4.2.1.1 HUMANITY_ACCORD invocation anti-replay | CCC | 🦀 | CIRISServer `tests/accord.rs::register_holders_list_roster_and_verify_2_of_3_invocation` — cosigns `Invocation::canonical_bytes()`, asserts 2-of-3 verifies, 1-of-3 fails threshold, and a replayed `invocation_id` → 409 `duplicate_invocation` |
| CC 5.3.1.1 STH cosignature consistency-proof | CCS | ⏳🦀 | the proof lives in `ciris-persist::federation::stream_sth::consistency_proof`, but **no CIRISServer Rust test drives it** (gap). This is the substrate basis for compliance **D17 transparency_log**. Closed by the server Rust conformance harness (in progress). |
| CC 3.3 `key_grant` wrap (`x25519-aes256-gcm-hkdf-sha256`) | CCS | ⏳ | verify v4.4.0 multimedia tier (CIRISVerify#44) — wrap primitive not on the Python wheel surface |
| F-AV-RECONSIDER-DOS rate-limit / cumulative budget | CCC | ⏳ | verify v4.5.0 (CIRISVerify#46) — **Conformance#7** Scenario 1 |
| Hybrid KEX (X25519 + ML-KEM-768) | CCC | ◷🦀 | **bench-only** at the Rust layer — CIRISServer `benches/pqc_av_streaming.rs` runs the `ciris_edge::transport::federation_session` handshake for *timing*, but there is no correctness assertion (shared-secret agreement / fail-closed on tampered ciphertext). Correctness gate added by the server Rust conformance harness (in progress). |
| Realtime A/V mesh two-layer hybrid-PQC seal (CC 5.3.3.2.5) | CCS | 🦀 | CIRISServer `tests/alm_chain.rs::inner_e2e_survives_relay_chain` (inner E2E plaintext recovered byte-identical through 1–5 relay reseal hops) + `::wrong_outer_key_at_a_hop_fails_closed` (outer AEAD fails closed), vs the pinned edge |
| CC 2.6.4 hash-pinned two-tier wire vocabulary (CC 0.7) | CCP/CCC | ✅ | `test_520` — `build_signed_inbound_envelope` accepts exactly the manifest's Tier-1 ∪ opaque ∪ DSAR variant set and rejects the CC 0.7 migrants (`InlineText`/`AccordEventsBatch`/`FederationKeyDirectoryQuery`, `unknown variant`); cross-checked against the vendored [`WIRE_VOCABULARY.md`](../reference/CIRIS_Constitution/WIRE_VOCABULARY.md) so wheel/manifest drift goes red; `CODEC_OPAQUE==255`, `SUPPORTED_SCHEMA_VERSIONS==['1.0.0']`. Hash-pin itself is a DRAFT placeholder with no recompute surface — accept/reject membership is what's gated |
| CC 6.1.5.2 storage-contention `StorageBudgetV1`/`CorpusWantV1` + pin-never-defeats-revocation | CCS | ✅ | `test_530` — build/verify/supersede (anti-rollback) + corpus-want admission (persist 12.5, **#356**); **pin-never-defeats-revocation (B6/N5) now real** (persist 13, **CIRISPersist#370**): `install_storage_budget_v1` pins a corpus class, yet `evict_fountain_content_hard_delete` on revocation still purges the pinned content to `envelope_only` — the pin survives, the pinned content doesn't |
| CC 4.2.6 live-quorum roster-capture / `accord_contest` + `accord_restore` (CC 1.0-rc1 G-A) | CCS | 🦀 | not on the persist FFI (only accord proposal/participation/decision *storage* — `put_accord_*_json`); the removal-gate (`2·\|L\| ≤ N_standing` steward co-sign), lame-duck fire, and log-snapshot contest resolution live in CIRISVerify `accord_live_quorum` + CIRISServer's authoritative tally — a Rust-lane gate (pending the CIRISServer crate-pin bump to verify 8.7.0) |
| Live transport bring-up + delivery (4-node fabric) | CCS | ✅ | `test_340` — **rock-solid gates**: (1) the 4-node/3-steward fabric stands up — every `init_edge_runtime(enable_transport=True)` returns, all reach ready (**CIRISPersist#320** closed; the deadlock/crash is fixed); (2) real Reticulum delivery demonstrably works end-to-end (a robust majority of routes deliver). Strict *per-route* delivery is not gated — edge 8.7.2 intermittently drops ~1 of 4 routes under contention (**CIRISEdge#276**, persistent-within-a-run) — and per-*mode holder-scoping* awaits the opaque scope selector (**CIRISEdge#265**); both return when those land |
| Holder-*scoped* delivery (non-holder ⇒ no delivery) | CCS | ⏳ | edge 8's `send_opaque_event` is a raw primed-peer push with no scope selector, so a non-holder still receives — the CEWP "no membership ⇒ no delivery" property is **not** gated until the opaque holder/scope selector returns → **CIRISEdge#265** (was a real gate on the edge-7 / CC 0.5.1 floor) |
| Edge-runtime cohabitation on postgres (send/receive, intake, https) | CCS | ⏳ | `test_050`/`test_140`/`test_230` — real green gates on sqlite; on **postgres** persist 12.2.0 non-deterministically aborts `init_edge_runtime` (background tokio `net/addr` panic → SIGABRT) so they imperatively xfail only when the crash fires → **CIRISPersist#354** |
| CC 6.1.2 fountain below-floor classification (Full/Partial/EnvelopeOnly) | CCS | ✅ | `test_540` (Python behavioral — `get_fountain_content` `state` across tier descent, boundaries cross-checked with the Rust lane) **+** 🦀 CIRISServer `tests/noise_floor_verdicts.rs` (pure `FountainContent::classify` boundary table) |
| CC 6.1.2 / §19.7 N5 revocation → below floor (hard-delete purge, rarity can't resurrect) | CCS | ✅ | `test_540` (Python — `evict_fountain_content_hard_delete` → `envelope_only`/present=0, signed manifest survives) **+** 🦀 `tests/noise_floor.rs::revocation_purges_member_tiers_but_not_the_composite` (tier-pyramid: member purged every tier, composite stays `Full`) |
| CC 6.1.2.3 EjectionVerdict routing (Keep/EjectToTier/EjectHardDelete/AggregatedTierOnly) | CCS | ✅ | `test_541` (Python behavioral via `descend_aggregated_sources` + a byte-exact Python-built signed `AggregationMetaV1` + negative gates) **+** 🦀 `tests/noise_floor_verdicts.rs` (pure `ejection_verdict` matrix + `EjectionAction::from_verdict`) |
| CC 6.1.2 measured recoverability below floor (structured + known-plaintext) | CCS | 🦀 | CIRISServer `tests/noise_floor.rs::structured_and_known_plaintext_stay_below_floor` — the RaptorQ residual-fidelity sweep needs edge's `fountain_decode`, not on the Python wheel; worst-case fidelity 0.0 ≤ ε for compressible + partial-known-plaintext payloads |
| CC 6.1.2 faithful N→1 aggregation-erasure | CCS | ⏳ | `tests/noise_floor.rs::..._pending_ciris_edge_266` (`#[ignore]`) — the prior test was true-by-construction (fabricated composite); a real measurement needs a pub edge resampling operator → **CIRISEdge#266** |
| CC 6.1.2 / §19.7.1.2 aggregation dominance / N_eff gate (CC 1.0-rc1 G-B) | CCS | ✅ | `test_542` — verify 8.7.0 shipped the gate (**CIRISVerify#167** closed): `AggregationMetaV1` v2 carries a **signed `n_eff`**; `put_aggregated_tier` rejects a fold with `2·n_eff < source_count` as `aggregation_meta_dominated` (v1 tier unconditionally rejected). The 900/1000 fold (Kish n_eff≈1.2 < floor 5) is rejected. **R9 residual pinned:** the gate *trusts* the signed n_eff (no mass recompute at this surface), so a fold that signs a lying `n_eff==N` is admitted (CC 8.3.1 acknowledged bet) |
| — (Rust-lane note) the CIRISServer `noise_floor.rs::dominance_undetectable_pending_ciris_verify_167` gap-pin inverts when the server crate-pins bump to verify 8.7.0 | CCS | 🦀 | currently green on the server's pinned verify 8.5.0 (dominated fold accepted); flips to assert rejection at the bump |
| R1/Q1 partition+heal merge contracts (Fed TM v1.1) | CCS | ⏳ | CIRISVerify#48/#49 — **Conformance#7** Scenario 3 |
| CC 5.3.2.1 holds_bytes 24h TTL | CCS | ⏳ | needs injectable clock → folded into CIRISPersist#125 |
| Identity-aware storage / per-actor eviction (scaling §9) | CCS | ⏳ | `list_holders` + evict-actor → **CIRISPersist#125** |
| Trust-recursion-depth admission (scaling §1.4) | CCS | ⏳ | depth-N graph walk → **CIRISNodeCore#21** |
| CC 3.2 steward-binding (node/agent) admission + resolution | CCS | ✅ | `test_360` — `steward_bind`/`is_steward_bound_json`/`steward_bindings_of_json` (persist 11.0.0, owner→steward reframe; un-stewarded community reject token `federation_unstewarded_community_member` via `test_340`) |
| CC 3.2 user-target steward binding — adult-target rejected | CCS | ✅ | `test_360` — `grant_delegation`/`steward_bind` onto a `user` target rejected (`federation_user_target_steward_binding_forbidden`), the adult-is-un-stewardable guarantee (persist 11.5.0) |
| CC 3.2 user-target admission — *conditional* minor-guardianship admit | CCS | ✅ | `test_360` — persist 13.0 ships `check_user_target_steward_binding_admission` (**CIRISPersist#367** closed): once the ages are established via the #368 witness-attests-subject path (`age_band(S)==adult`, `age_band(T)==minor`), `steward_bind`/`grant_delegation`(proven-adult → proven-minor) is **admitted**; a proven-adult OR unverified-age target is refused (`federation_user_target_steward_binding_forbidden` — presumption of sovereignty, *not* a wholesale block — the earlier xfail drove the wrong precondition) |
| CC 3.2 minor-stewardship liveness (steward-less minor fails secure) | CCS | ✅ | `test_361` — the adult→minor binding is now creatable (above), so its liveness is machine-checked: withdraw it (`revoke_delegation`) and `is_steward_bound(minor)` flips to `false` / `steward_bindings_of` empties — the steward-less-minor fail-secure posture, identical to the node/agent control |
| CC 3.4.11 age-assurance reservation (`age_assurance:*` witness-only) | CCS | ✅ | `test_350` — agent key refused (`federation_reserved_prefix_emitter_mismatch`); `identity_type="witness"` admitted; `age_self_declared:band:*` subject-signed admitted; `age_self_declared:level:*` refused (`federation_dimension_rejected`, persist 11.5.0 — closes CIRISPersist#307) |
| CC 3.4.13 one-way age ratchet + `age_band_json` + cross-subject witness | CCS | ✅ | `test_351` — `age_band_json` resolves the I1 band; a minor's `age_self_declared:band:adult` stays `"minor"` (self can only lower); **cross-subject witness graduation now real** (persist 13, **CIRISPersist#368**): a witness `emit_attestation(attested_key_id=subject, age_assurance:provider:adult)` graduates the *subject's* band (attest-about-subject; witness *self*-emission is now rejected `federation_age_assurance_self_emission_rejected`). Plus `age_band_fine_json` 4-band (`under_13`/`13_15`/`16_17`/`adult`) |
| CC 3.4.11 self-declared `{band}`-not-`{level}` rule | CCS | ⏳ | `test_350` xfail(strict) — `age_self_declared:level:*` is admitted but should be refused → **CIRISPersist#307** (filed) |
| CC 4.4.3.2.8 `affiliations` institutional cohort scope + tier | CCS | ✅ | `test_262` — `affiliations` admitted as a cohort scope; `cohort_scope_crypto_tier("affiliations") == "community_dek"` (persist 11.5.0, CIRISPersist#308 admission shipped) |
| CC 4.4.3.2.8 affiliations membership lifecycle | CCS | ✅ | `test_263` — 3-arg `cohort_add_member` add/idempotent/immediate-revoke; future-dated revoke correctly rejected (CommunityDek epoch bumps at write, SecReview F4) |
| CC 3.2/3.4.2 cohort membership-change quorum | CCS | ✅ | `test_264` — `cohort_verify_membership_quorum` verifies a real 2-of-3 / 3-of-3 hybrid-cosigned membership change, rejects 1-of-3 |
| CC 4.4.3.2.8 affiliations compartments / per-member exclusions / disclosure | CCS | 🦀 | declared-config limbs not on the Python wheel (no compartment-DEK / exclusion / disclosure surface) — Rust-lane / unexposed (**CIRISPersist#308** comment) |
| CC 4.5.4 moderator-existence admission gate (stewardless founder refused) | CCS | ✅ | `test_271` — `put_community_json` refuses a non-steward-bound founder (`federation_unstewarded_community_member`); `is_named_moderator_json`/`moderators_of_json` resolution primitives |
| CC 4.5.4 moderator-existence **federation-apply** gate | CCS | ✅ | `test_271` — persist 13 shipped `check_no_moderator_federate_json(community_id)` (the exact apply-step decision): a moderator-less known community → `{admitted:false, reason:"federation_community_no_moderator"}`, live-holder → admitted, unknown → fail-open (**CIRISPersist#369** closed). The §4.5.13 reverse-quorum recovery vote (48h/24h/live-majority) stays governance-tier, no byte-surface |
| CC 3.4.8 detection discriminator (`detection:*` → `lenscore_detector`) | CCP/CCS | ✅ | `test_550` — an agent key on `detection:*` (enumerated **and** novel `{newkind}:*` subkinds, via the prefix-wildcard shipped in persist 13.2.0, **CIRISPersist#379** closed) is refused (`federation_reserved_prefix_emitter_mismatch`); a `lenscore_detector`-in-`identity_type` key is admitted; `truth_grounding:detection:*` cross-attestations ride free |
| CC 3.2 single-owner — purpose-filtered `owner_of` resolver | CCS | ✅ | `test_551` — persist 13.2.0 shipped `owner_of_json` (part of **CIRISPersist#378** / delegation fixes #176): ownership resolves to ≤ 1 owner (no longer the purpose-conflating readers' cardinality-2) |
| CC 3.2 single-owner — reject-2nd-distinct-owner **admission** gate | CCS | ⏳ | `test_551` xfail(strict) — the resolver shipped but the admission half has NOT: no `delegation_purpose:owner_binding` arg on the delegation path, and a second distinct owner-binding is still admitted → **CIRISPersist#378** (admission leg) |
| CC 4.5.13 infohazard consent primitive + `content_class` reservation | CCS | ✅ | `test_272` — `consent:state:granted` + `consent:scope:view` admitted; `content_class:infohazard`/`reported` reserved to `substrate_persist` (all other identity types `federation_reserved_prefix_emitter_mismatch`) |
| CC 4.5.13 infohazard consent-gate **enforcement** (flagged read requires consent) | CCC | ⏳ | `test_272` xfail(strict) — no substrate view/reveal/gate-decision surface refusing a flagged read absent consent; interstitial enforcement is consumer/LensCore policy → **CIRISPersist#238** (tracked) |
| CC §5.4 scope-native privacy `record_id` golden vectors | CCS | ✅ | `test_500` — `ciris_verify.scope_privacy.derive_record_id` reproduces all three normative §5.4.1 vectors **byte-exact** (`K_record_id=0x11*32`; community/federation/self record-types; CBOR byte-string preimage); now Python-drivable via **verify 8.3.0** (was 🦀) |
| CC §5.4 scope-native privacy `symbol_key` / `witness_cover_leaf` construction | CCS | ✅ | `test_500` — `derive_symbol_key`/`witness_cover_leaf` gated by the construction properties the spec pins (determinism, salt/index/position/epoch diversification, 32-byte length, u16_be index sensitivity); spec ships no numeric output vectors for these |
| CC §5.4 / §11 fragmentation / welcome-wrap / announce suppression | CCS | 🦀 | the remaining scope-privacy wire limbs are not on the Python surface — substrate-internal; gated in the CIRISServer Rust lane |
| CC 4.4.3.1.1 sub-quorum fallback hard_case tokens | CCC | 🏛 | composition/policy tier, not a substrate call |
| CC 4.5.1.2 meta-amendment entrenchment | — | 🏛 | governance process (SemVer + 2-of-3 accord), not a wheel behavior |

As each ⏳ seam lands upstream, implement the corresponding test and move
the row to ✅; the `xfail`/`skip` markers are wired so they flip
automatically when the behavior appears.
