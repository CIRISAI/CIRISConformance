# CEG conformance profiles in this harness

[CEG 0.1](https://github.com/CIRISAI/CIRISRegistry/tree/main/FSD/CEG) — the
CIRIS Epistemic Grammar — defines three normative conformance profiles in
§0.2. CIRISConformance adopts these as the **organizing principle** for
cross-artifact conformance tests, alongside the existing cohabitation
scenarios.

| Profile | Who | What it MUST do (§0.2) |
|---|---|---|
| **CCP** — CEG-Conforming Producer | emitters (Agent, Verify, LensCore, NodeCore, …) | emit well-formed envelopes (§4), sign per hybrid-sig, respect reserved-prefix rules (§7), declare `oversight_mode` + `witness_relation` (§4) |
| **CCC** — CEG-Conforming Consumer | composers (Agent, Verify, Portal) | verify hybrid signatures, enforce reserved-prefix at admission, implement ≥ Policy A (§8.1.1) + default aggregation (§8.2), honor `null` hardware-class rejection (§9.4) |
| **CCS** — CEG-Conforming Substrate | persist + edge + verify | storage/transport guarantees (§10.1/§10.3), idempotent replication, full-SHA blob verify before consumption (§10.1.1), witness-quorum admission (§10.3) |

Tests carry the `ceg` marker plus their profile marker (`ccp` / `ccc` /
`ccs`). Run a profile with `pytest -m ccc`.

## Reading discipline — §0.5 fractal-self

Per CEG's anti-Cartesian-default callout (§0.5 / README "Self is self,
fractally"): a conformant **substrate admits, it does not gate,
self-attestation**. A `witness_relation: self` row is accepted even with
zero prior cross-attestations, because the cross-attestation that
constitutes the self is *upstream* — there is no pre-relational atomic
entity available to do the admitting. This harness therefore tests that
substrates **accept** self-attestation, and treats a substrate that adds a
Cartesian admission gate on self-attestation as **non-conformant**. (Test
pending the `witness_relation` surface — see CIRISVerify#40 below.)

## Why this harness can't yet cover all of CEG 0.1

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

| CEG path | Profile | Status | Where / why |
|---|---|---|---|
| §0.2 profile organizing principle | — | ✅ | `ccp`/`ccc`/`ccs`/`ceg` markers; this doc |
| Hybrid-signature verify + policy matrix | CCC | ✅ | `test_100_ccc_hybrid_verify.py` (strict / ed25519_fallback / soft_freshness / directory) |
| §10.1.1 blob full-SHA integrity (reject mismatch) | CCS | ✅ | `test_110_ccs_blob_integrity.py` (`blob_hash_mismatch`) |
| §10.1.1 blob positive round-trip + holder attestation | CCS | ✅ | `test_110` via persist v3.3.0 `put_blob_signing` (CIRISPersist#124 shipped) |
| Canonical-bytes determinism + sign/verify round-trip | CCP | ✅ | `test_120_ccp_canonical_bytes.py` |
| §5.6.8.8.1.1 RNS destination-hash recompute (1.0-RC6) | CCS | ✅ | `test_150_rns_dest_hash.py` — executable golden vector of the pinned two-stage construction + the anti-flat-form regression (CIRISRegistry#80 / CIRISVerify#28). The wheel-recompute cross-check is now a **real gate** (`ciris_verify.rns_destination_hash`, exposed in **verify v7.3.0**); it skips only on a matrix pin < verify 7.3.0 |
| §6.1 concurrent-write precedence + dedup-on-triple | CCS | ⏳ | needs generic `put_attestation` schema (arbitrary dimension) → **CIRISPersist#124** |
| §7.0 reserved-prefix admission rejection | CCS | ✅ | `test_240` — `emit_attestation_self` refuses `accord:*`/`capacity:*`-self/`system:*` from an agent key (persist 10.4.0, CIRISPersist#288) |
| §0.5/§0.6/§0.7 canonicalization rejection | CCC | ✅ | `test_120` (timestamp/hex/future) + `test_240` (uppercase-hex `subject_key_ids`, persist 10.5.0 / CIRISPersist#293) |
| §4/§0.5 `witness_relation` + self-attestation | CCP/CCC | 🦀 | CIRISServer `tests/peer_replication.rs::peer_b_registered_admits_b_liveness_and_a_emits_directed_consent` asserts `witness_relation=="self"` + self-attestation admission / forged-peer rejection, vs the pinned triple. (`oversight_mode` itself is untested — see the Rust-harness gap below.) |
| §9.2.1 HUMANITY_ACCORD invocation anti-replay | CCC | 🦀 | CIRISServer `tests/accord.rs::register_holders_list_roster_and_verify_2_of_3_invocation` — cosigns `Invocation::canonical_bytes()`, asserts 2-of-3 verifies, 1-of-3 fails threshold, and a replayed `invocation_id` → 409 `duplicate_invocation` |
| §10.3.1 STH cosignature consistency-proof | CCS | ⏳🦀 | the proof lives in `ciris-persist::federation::stream_sth::consistency_proof`, but **no CIRISServer Rust test drives it** (gap). This is the substrate basis for compliance **D17 transparency_log**. Closed by the server Rust conformance harness (in progress). |
| §5.6.8 `key_grant` wrap (`x25519-aes256-gcm-hkdf-sha256`) | CCS | ⏳ | verify v4.4.0 multimedia tier (CIRISVerify#44) — wrap primitive not on the Python wheel surface |
| F-AV-RECONSIDER-DOS rate-limit / cumulative budget | CCC | ⏳ | verify v4.5.0 (CIRISVerify#46) — **Conformance#7** Scenario 1 |
| Hybrid KEX (X25519 + ML-KEM-768) | CCC | ◷🦀 | **bench-only** at the Rust layer — CIRISServer `benches/pqc_av_streaming.rs` runs the `ciris_edge::transport::federation_session` handshake for *timing*, but there is no correctness assertion (shared-secret agreement / fail-closed on tampered ciphertext). Correctness gate added by the server Rust conformance harness (in progress). |
| Realtime A/V mesh two-layer hybrid-PQC seal (CEG §10.5.8) | CCS | 🦀 | CIRISServer `tests/alm_chain.rs::inner_e2e_survives_relay_chain` (inner E2E plaintext recovered byte-identical through 1–5 relay reseal hops) + `::wrong_outer_key_at_a_hop_fails_closed` (outer AEAD fails closed), vs the pinned edge |
| R1/Q1 partition+heal merge contracts (Fed TM v1.1) | CCS | ⏳ | CIRISVerify#48/#49 — **Conformance#7** Scenario 3 |
| §10.1.2 holds_bytes 24h TTL | CCS | ⏳ | needs injectable clock → folded into CIRISPersist#125 |
| Identity-aware storage / per-actor eviction (scaling §9) | CCS | ⏳ | `list_holders` + evict-actor → **CIRISPersist#125** |
| Trust-recursion-depth admission (scaling §1.4) | CCS | ⏳ | depth-N graph walk → **CIRISNodeCore#21** |
| §8.1.5.1 sub-quorum fallback hard_case tokens | CCC | 🏛 | composition/policy tier, not a substrate call |
| §11.2.3 meta-amendment entrenchment | — | 🏛 | governance process (SemVer + 2-of-3 accord), not a wheel behavior |

As each ⏳ seam lands upstream, implement the corresponding test and move
the row to ✅; the `xfail`/`skip` markers are wired so they flip
automatically when the behavior appears.
