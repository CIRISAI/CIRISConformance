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

Status legend: ✅ implemented (real binary test) · ⏳ pending an upstream
seam · 🏛 governance/process tier (not a substrate behavior).

| CEG path | Profile | Status | Where / why |
|---|---|---|---|
| §0.2 profile organizing principle | — | ✅ | `ccp`/`ccc`/`ccs`/`ceg` markers; this doc |
| Hybrid-signature verify + policy matrix | CCC | ✅ | `test_100_ccc_hybrid_verify.py` (strict / ed25519_fallback / soft_freshness / directory) |
| §10.1.1 blob full-SHA integrity (reject mismatch) | CCS | ✅ | `test_110_ccs_blob_integrity.py` (`blob_hash_mismatch`) |
| §10.1.1 blob positive round-trip + holder attestation | CCS | ✅ | `test_110` via persist v3.3.0 `put_blob_signing` (CIRISPersist#124 shipped) |
| Canonical-bytes determinism + sign/verify round-trip | CCP | ✅ | `test_120_ccp_canonical_bytes.py` |
| §5.6.8.8.1.1 RNS destination-hash recompute (1.0-RC7) | CCS | ✅ | `test_150_rns_dest_hash.py` — executable golden vector of the pinned two-stage construction + the anti-flat-form regression (CIRISRegistry#80 / CIRISVerify#28). The wheel-recompute cross-check is `xfail` until the recompute is exposed on the Python surface. (Construction unchanged by RC7 — RC7 is no-wire-change.) |
| §10.1.5.1.1 PQC-mandatory-at-admission — reject classical-only at the federation gate (1.0-RC7) | CCS | ⏳ | New in CEG 1.0-RC7 (resolves CIRISRegistry#82 / Verify audit F1; satisfies the #57 "PQC-everywhere REQUIRED" gate). Every federation-tier / operational-authority admission gate (`operational_admit`, `transport_destination` binding, `partner_record` / founder-quorum) MUST verify **both** the Ed25519 half and the ML-DSA-65 half over `JCS(envelope) ‖ ed25519_sig`, and MUST **reject** a federation-tier Contribution carrying only the classical half — an immediate 1.0 requirement, no fleet-floor / no `require_hybrid: false` posture. Enforced by CIRISVerify#75 (hard-cut PQC); test pending the always-on hybrid-required check on the published Python wheel surface |
| §8.1.12.7.1 `infra:*` vs `agency:*` scope-split reject (1.0-RC7) | CCC | ⏳ | New in CEG 1.0-RC7 (resolves CIRISRegistry#83 §3; CIRISVerify#63). A `delegates_to` whose `attested_key_id` resolves to a `node`-only identity (no `agent`/brain) MUST carry **only** `infra:*` scopes; a verifier MUST **reject** an `infra`-only key presenting any `agency:*` scope — making §1.3 "infrastructure must not have agency" a wire-checkable invariant. Also pins the §8.1.12.7.1 canonical seven-member `consent:partnership_*:v1` set (resolves CIRISRegistry#81) so two impls converge on identical JCS bytes. Test pending the scope-resolver / partnership-envelope surface on the published Python wheel |
| §6.1 concurrent-write precedence + dedup-on-triple | CCS | ⏳ | needs generic `put_attestation` schema (arbitrary dimension) → **CIRISPersist#124** |
| §7.0 reserved-prefix admission rejection | CCS | ⏳ | needs generic `put_attestation` schema → **CIRISPersist#124** |
| §0.5/§0.6/§0.7 canonicalization rejection | CCC | ⏳ (xfail) | wheel accepts `+00:00`/uppercase hex/future ts → **CIRISPersist#126** |
| §4/§0.5 `witness_relation`/`oversight_mode` + self-attestation | CCP/CCC | ⏳ | shipped in the verify **Rust crate** (v4.2.0 `witness_relation.rs`, CIRISVerify#40 closed) but **not on the published Python wheel surface** — verified absent at verify 4.6.0 / persist 3.6.9, so not cross-wheel-drivable yet |
| §9.2.1 HUMANITY_ACCORD invocation anti-replay | CCC | ⏳ | shipped in the verify Rust crate (v4.2.0 `humanity_accord.rs`, CIRISVerify#41 closed) but **not on the published Python wheel surface** (no `invocation_canonical_bytes` on verify/persist) — not cross-wheel-drivable yet |
| §10.3.1 STH cosignature consistency-proof | CCS | ⏳ | shipped in the verify Rust crate (v4.2.0 `WitnessConsistencyProof::verify`, CIRISVerify#42 closed) but **not on the published Python wheel surface** (no `verify_sth_cosignature_consistency_proof`) — not cross-wheel-drivable yet |
| §5.6.8 `key_grant` wrap (`x25519-aes256-gcm-hkdf-sha256`) | CCS | ⏳ | verify v4.4.0 multimedia tier (CIRISVerify#44) — wrap primitive not on the Python wheel surface |
| F-AV-RECONSIDER-DOS rate-limit / cumulative budget | CCC | ⏳ | verify v4.5.0 (CIRISVerify#46) — **Conformance#7** Scenario 1 |
| Hybrid KEX (X25519 + ML-KEM-768) | CCC | ⏳ | verify v4.6.0 (CIRISVerify#47, `ml-kem` feature) — **Conformance#7** Scenario 2; not on the Python wheel surface. **Substrate now shipped** (edge v3.5.0 `transport::federation_session`) + **measured** by CIRISServer `pqc_av_streaming` (criterion; `benchmarks/reference.json` `av_kex_*`). Cross-wheel Python bench pending edge PyO3 exposure → **CIRISEdge#123** |
| Realtime A/V mesh two-layer hybrid-PQC seal (CEG §10.5.8) | CCS | ⏳ | edge v3.5.0 `transport::realtime_av` (CIRISEdge#62) shipped + **measured** by CIRISServer `pqc_av_streaming` (`reference.json` `av_frame_*` / `av_mesh_fanout_*`; ~2.3 GiB/s steady-state, PQC cost amortized at KEX). Rust-only today → cross-wheel Python bench pending **CIRISEdge#123** PyO3 exposure |
| R1/Q1 partition+heal merge contracts (Fed TM v1.1) | CCS | ⏳ | CIRISVerify#48/#49 — **Conformance#7** Scenario 3 |
| §10.1.2 holds_bytes 24h TTL | CCS | ⏳ | needs injectable clock → folded into CIRISPersist#125 |
| Identity-aware storage / per-actor eviction (scaling §9) | CCS | ⏳ | `list_holders` + evict-actor → **CIRISPersist#125** |
| Trust-recursion-depth admission (scaling §1.4) | CCS | ⏳ | depth-N graph walk → **CIRISNodeCore#21** |
| §8.1.5.1 sub-quorum fallback hard_case tokens | CCC | 🏛 | composition/policy tier, not a substrate call |
| §11.2.3 meta-amendment entrenchment | — | 🏛 | governance process (SemVer + 2-of-3 accord), not a wheel behavior |

As each ⏳ seam lands upstream, implement the corresponding test and move
the row to ✅; the `xfail`/`skip` markers are wired so they flip
automatically when the behavior appears.
