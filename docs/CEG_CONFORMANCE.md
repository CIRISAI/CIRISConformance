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
| Canonical-bytes determinism + sign/verify round-trip | CCP | ✅ | `test_120_ccp_canonical_bytes.py` |
| §10.1.1 blob positive round-trip | CCS | ⏳ | needs substrate-signed holder attestation → **CIRISPersist#124** |
| §6.1 concurrent-write precedence + dedup-on-triple | CCS | ⏳ | needs signed-attestation seam → **CIRISPersist#124** |
| §7.0 reserved-prefix admission rejection | CCS | ⏳ | needs signed-attestation seam → **CIRISPersist#124** |
| §0.5/§0.6/§0.7 canonicalization rejection | CCC | ⏳ (xfail) | wheel accepts `+00:00`/uppercase hex/future ts → **CIRISPersist#126** |
| §4/§0.5 `witness_relation`/`oversight_mode` + self-attestation | CCP/CCC | ⏳ | fields absent in Python surface → **CIRISVerify#40** |
| §9.2.1 HUMANITY_ACCORD invocation anti-replay | CCC | ⏳ | surface absent → **CIRISVerify#41** |
| §10.3.1 STH cosignature consistency-proof | CCS | ⏳ | HTTP-only, not cross-wheel → **CIRISVerify#42** |
| §10.1.2 holds_bytes 24h TTL | CCS | ⏳ | needs injectable clock → folded into CIRISPersist#125 |
| Identity-aware storage / per-actor eviction (scaling §9) | CCS | ⏳ | `list_holders` + evict-actor → **CIRISPersist#125** |
| Trust-recursion-depth admission (scaling §1.4) | CCS | ⏳ | depth-N graph walk → **CIRISNodeCore#21** |
| §8.1.5.1 sub-quorum fallback hard_case tokens | CCC | 🏛 | composition/policy tier, not a substrate call |
| §11.2.3 meta-amendment entrenchment | — | 🏛 | governance process (SemVer + 2-of-3 accord), not a wheel behavior |

As each ⏳ seam lands upstream, implement the corresponding test and move
the row to ✅; the `xfail`/`skip` markers are wired so they flip
automatically when the behavior appears.
