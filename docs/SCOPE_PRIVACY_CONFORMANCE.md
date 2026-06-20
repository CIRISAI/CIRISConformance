# SCOPE_PRIVACY §9 cross-artifact conformance

[CEWP `FSD/SCOPE_PRIVACY.md`](https://github.com/CIRISAI/CEWP/blob/main/FSD/SCOPE_PRIVACY.md)
is the construction realizing **CIRIS Constitution CC 1.13.3.4 — anonymity-by-default
at every scope below federation**, via substrate-tier configuration of primitives the
holonomic substrate already ships. §9 of the FSD lists five acceptance criteria — four
for the **substrate-tier ratification** that CIRISConformance owns, plus a fifth
benchmark criterion that lives in `CIRISEdge/benches/scope_privacy_steady_state.rs`.

This document maps each §9 bullet to the conformance file that ratifies it, lists the
substrate-side surface gaps the construction depends on, and explains the
simulator-vs-wheel-driven methodology split for the two statistical bullets.

## §9 acceptance matrix

| §9 bullet | Test file | What's checked | Status |
|---|---|---|---|
| 1. Forensic cold-state disk inspection recovers no publisher / community / record / member | [`tests/test_410_scope_privacy_forensic.py`](../tests/test_410_scope_privacy_forensic.py) | Persist v9.2.0 V088 `federation_scope_blobs` schema has only opaque columns (`record_id` HMAC, nonce, AEAD ciphertext, tag, group_dek_epoch, timestamps); the schema has NO column for publisher_key_id / community_id / plaintext / member_list / scope_label, by construction; a cold-state file carver finds NONE of six bait strings + the `community` scope label in the raw bytes; both indexes (on `admitted_at`, `last_accessed_at`) only mention opaque columns. | ✅ |
| 2. Cross-implementation `record_id` reproducibility on the RFC 8949 dCE CBOR profile | [`tests/test_400_scope_privacy_record_id.py`](../tests/test_400_scope_privacy_record_id.py) | Clean-room Python oracle reproduces verify v6.3.0's KAT vectors byte-for-byte: 3 record_id vectors (small uints, u16 epoch, u32 epoch), the §2.2 subkey KAT (bare HKDF-SHA256-Expand, NOT RFC 9420 `ExpandWithLabel`), §2.4 symbol_key (salt, ikm, info-suffix) sensitivity, §3.4 witness cover-leaf message layout, the CBOR inline-vs-extended boundary (`0x17` vs `0x18 0x18`), and the canonical key order `v < epc < iid < typ` (encoded-length-first then lexicographic). | ✅ |
| 3. Per-scope Poisson discipline + lifetime-average λ inequality, KS-test p > 0.01 over ≥24h | [`tests/test_420_scope_privacy_poisson.py`](../tests/test_420_scope_privacy_poisson.py) | FSD §3.1 first-principles Python simulator: 4 scopes (self/family/community/federation), each at a representative `λ_scope`; per-scope inter-emission interval distribution passes KS-vs-Exp(λ_scope) at p > 0.01; with real arrivals at `λ_real = 0.3 * λ_scope`, the 95th-percentile observed `λ_real/λ_cover` ratio stays ≤ 1.0 across 20 independent windows; adding real arrivals does not perturb the inter-emission distribution; a uniform-stream self-check confirms the KS test has discriminative power. **Methodology gap, see below.** | ✅ (simulator) / ⏳ (wheel-driven) |
| 4. 20-holder cross-fragment cluster-detection KS-test p > 0.01 | [`tests/test_430_scope_privacy_cluster_ks.py`](../tests/test_430_scope_privacy_cluster_ks.py) | n=20 holder fixture (FSD §2.4 default), K=6 reconstruction subset; the conformant jittered scheduler's per-holder arrival times pass KS-vs-Uniform(0, T) at p > 0.01; a clustered-attack pattern (3 cluster-widths: 5%, 10%, 15% of the window) is correctly REJECTED at p ≤ 0.01 (self-check / discriminative power); over 200 independent records the conformant pass rate stays ≥ 95%; every K-subset of size K_REPAIR within a conformant publication is also uniformly distributed (defense against an attacker who chooses which K to inspect). **Same methodology gap as bullet 3.** | ✅ (simulator) / ⏳ (wheel-driven) |
| 5. Bench: per-tier steady-state maintenance budget ~10–60 KB/s/peer | `CIRISEdge/benches/scope_privacy_steady_state.rs` (out of scope here) | The §2.6 budget anchor — bench tier lives in CIRISEdge per CIRISConformance#bench-policy | 🏛 |

## Substrate-side surface gaps (tracked upstream)

The §9 bullets above pass against the construction's mathematical contract today. Three
substrate-side PyO3 surfaces would let the conformance tests additionally drive the REAL
wheel implementations (not just the construction's math), closing the simulator-vs-wheel
gap. Each is tracked as a separate upstream issue.

| Gap | Repo/issue | Conformance impact |
|---|---|---|
| `put_scope_blob` / `get_scope_blob` PyO3 entry point | **CIRISPersist#236 (proposed)** — the schema ships in V088 + Rust `store/sqlite.rs::put_scope_blob` is implemented; FFI not yet wired. | `test_410` reaches the table via raw SQLite, populating one row with synthesized inputs. With the FFI, the test could drive a real persist Engine and assert the SAME opacity properties hold against bytes a CIRISEdge community publication actually lands. |
| `scope_privacy.derive_record_id` / `derive_symbol_key` PyO3 re-exports on `ciris_edge` | **CIRISEdge#236 (proposed)** — `src/scope_privacy.rs` re-exports verify v6.3.0's surface internally; not exposed on `ciris_edge.scope_privacy.*` to Python. | `test_400` runs a clean-room Python oracle (HMAC-SHA3, hand CBOR, hand HKDF-SHA3 — implementations independent of verify-rust and edge-rust). With the PyO3 export, an additional test could call into `ciris_edge.scope_privacy.derive_record_id(...)` and assert it produces the SAME bytes — making the conformance suite a TRUE third party between two language bindings of the same Rust impl. |
| Poisson `EmissionScheduler` PyO3 entry — `edge.send_community(...)` over a real scheduler | **CIRISEdge#237 (proposed)** — `src/emission/` scheduler is internal to the Rust send-path; no Python surface, and no accelerated-time mode for fast statistical convergence. | `test_420` + `test_430` simulate the FSD §3.1 / §7.5 construction in Python and verify the math. With the PyO3 surface + accelerated-time mode, additional tests could drive the REAL edge scheduler in a single-peer + 20-peer fixture and KS-test ITS observed inter-emission stream, closing the construction-vs-wheel gap. |

The simulator tests today are **mathematically equivalent to a wheel-driven test against
a §3.1-conforming scheduler** — a wheel that fails the simulator's gates necessarily
fails the wire-format contract. The wheel-driven variants land additional defense in
depth (they catch impl bugs *between* the spec and the running code, e.g. CSPRNG
misuse, queue-pop ordering bugs, timer-wheel quantization), not new spec coverage.

## §9 methodology — why first-principles simulators count

The pattern follows `tests/test_210_fabric_scaling_factors.py` precedent: when a
substrate model has a load-bearing mathematical contract (the FEDERATION_SCALING_MODEL
multiplier curve, the `k_eff` corridor, retention monotonicity) AND the wheel that
implements it is a single Rust source, the conformance suite pins **the contract itself**
as an executable artifact. A wheel that ships a non-conformant scheduler fails the same
KS-statistical bar a real-traffic capture would.

The two-test setup (positive: conformant scheduler passes the gate; negative: a
known-attack pattern is rejected at p ≤ 0.01) pins the test's **discriminative power** —
without the negative direction, a buggy KS implementation could silently pass every
input and the gate would degenerate to a tautology. Both `test_420` and `test_430` carry
the self-check; both use seeded RNGs under `CIRIS_CONFORMANCE_*_SEED` env vars for
deterministic CI while remaining unseeded under a local `pytest` so they exercise the
system CSPRNG production-shape distribution too.

## Cross-references

- **CEWP `FSD/SCOPE_PRIVACY.md` §9** — the acceptance criteria this suite ratifies.
- **CIRISRegistry CEG 1.0-RC29 §11** — the cross-artifact wire-format absorption. The
  KAT vectors in `test_400` ARE the §11 cross-impl ratification evidence.
- **CIRISVerify `docs/SCOPE_PRIVACY_NOTES.md`** — the implementer notes from the first
  conformant impl. Lists the three deliberate `MUST agree` flags (bare HKDF-Expand
  vs RFC 9420 ExpandWithLabel, the HPKE suite-id string, the RecordType integer
  encoding) — every flag is one of `test_400`'s asserted vectors.
- **CIRISConstitution CC 1.13.3.4** — the anonymity-by-default principle the
  construction realizes.
