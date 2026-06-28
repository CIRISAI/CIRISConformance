# CIRIS Constitution conformance profiles in this harness

The **[CIRIS Constitution](../reference/CIRIS_Constitution/) `CC 0.6`** — the
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

## Why this harness can't yet cover all of CC 0.6

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
| Holder-scoped transport delivery (self/family/community/direct) | CCS | ⏳ | `test_340` xfail(strict) — **regression**: persist 11.5.0 deadlocks edge `init_edge_runtime(enable_transport=True)` Reticulum bring-up (A/B-confirmed: 11.0.0 works, 11.5.0 hangs, edge held constant) → no fabric node becomes ready → **CIRISPersist#320**. Was a real green gate on the CC 0.5.1 floor; flips back the moment the deadlock is fixed |
| R1/Q1 partition+heal merge contracts (Fed TM v1.1) | CCS | ⏳ | CIRISVerify#48/#49 — **Conformance#7** Scenario 3 |
| CC 5.3.2.1 holds_bytes 24h TTL | CCS | ⏳ | needs injectable clock → folded into CIRISPersist#125 |
| Identity-aware storage / per-actor eviction (scaling §9) | CCS | ⏳ | `list_holders` + evict-actor → **CIRISPersist#125** |
| Trust-recursion-depth admission (scaling §1.4) | CCS | ⏳ | depth-N graph walk → **CIRISNodeCore#21** |
| CC 3.2 steward-binding (node/agent) admission + resolution | CCS | ✅ | `test_360` — `steward_bind`/`is_steward_bound_json`/`steward_bindings_of_json` (persist 11.0.0, owner→steward reframe; un-stewarded community reject token `federation_unstewarded_community_member` via `test_340`) |
| CC 3.2 user-target steward binding — adult-target rejected | CCS | ✅ | `test_360` — `grant_delegation`/`steward_bind` onto a `user` target rejected (`federation_user_target_steward_binding_forbidden`), the adult-is-un-stewardable guarantee (persist 11.5.0) |
| CC 3.2 user-target admission — *conditional* minor-guardianship admit | CCS | ⏳ | `test_360` xfail(strict) — the forbid is *wholesale* (minor AND adult); the positive case (admit iff `age_band(T)==minor ∧ age_band(S)==adult ∧ S signed`) is not exposed over the FFI → **CIRISPersist#306/#309** (tracked) |
| CC 3.2 minor-stewardship liveness (steward-less minor fails secure) | CCS | ⏳ | `test_361` xfail(strict) — the legal adult→minor binding can't be created at all (wholesale forbid), so a withdrawn-binding fail-secure posture isn't machine-checkable → **CIRISPersist#306/#309** (tracked) |
| CC 3.4.11 age-assurance reservation (`age_assurance:*` witness-only) | CCS | ✅ | `test_350` — agent key refused (`federation_reserved_prefix_emitter_mismatch`); `identity_type="witness"` admitted; `age_self_declared:band:*` subject-signed admitted; `age_self_declared:level:*` refused (`federation_dimension_rejected`, persist 11.5.0 — closes CIRISPersist#307) |
| CC 3.4.13 one-way age ratchet + `age_band_json` resolution | CCS | ✅ | `test_351` — `age_band_json` resolves the I1 band; a minor's `age_self_declared:band:adult` emit is accepted but the resolved band stays `"minor"` (self can only lower); a self-bound witness `age_assurance:*` rung graduates its own band (read-union witness-outranks-self). xfail: cross-subject witness graduation (witness→other subject) not exposed → **CIRISPersist#309** |
| CC 3.4.11 self-declared `{band}`-not-`{level}` rule | CCS | ⏳ | `test_350` xfail(strict) — `age_self_declared:level:*` is admitted but should be refused → **CIRISPersist#307** (filed) |
| CC 4.4.3.2.8 `affiliations` institutional cohort scope + tier | CCS | ✅ | `test_262` — `affiliations` admitted as a cohort scope; `cohort_scope_crypto_tier("affiliations") == "community_dek"` (persist 11.5.0, CIRISPersist#308 admission shipped) |
| CC 4.4.3.2.8 affiliations membership lifecycle | CCS | ✅ | `test_263` — 3-arg `cohort_add_member` add/idempotent/immediate-revoke; future-dated revoke correctly rejected (CommunityDek epoch bumps at write, SecReview F4) |
| CC 3.2/3.4.2 cohort membership-change quorum | CCS | ✅ | `test_264` — `cohort_verify_membership_quorum` verifies a real 2-of-3 / 3-of-3 hybrid-cosigned membership change, rejects 1-of-3 |
| CC 4.4.3.2.8 affiliations compartments / per-member exclusions / disclosure | CCS | 🦀 | declared-config limbs not on the Python wheel (no compartment-DEK / exclusion / disclosure surface) — Rust-lane / unexposed (**CIRISPersist#308** comment) |
| CC 4.5.4 moderator-existence admission gate (stewardless founder refused) | CCS | ✅ | `test_271` — `put_community_json` refuses a non-steward-bound founder (`federation_unstewarded_community_member`); `is_named_moderator_json`/`moderators_of_json` resolution primitives |
| CC 4.5.4/4.5.13 moderator-existence **federation-apply** gate + reverse-quorum vote | CCS | ⏳ | `test_271` xfail(strict) — only the resolution primitive is exposed, no apply-step gate that consumes it / fails a moderator-less community secure; the 48h recovery / 24h candidacy / live-majority vote is time-governance with no surface → **CIRISPersist#238** (tracked) |
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
