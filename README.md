# CIRISConformance

Cross-artifact conformance harness for the CIRIS federation stack — the substrate and fabric of **CEWP**, the **CIRIS Epistemic Web Platform** (pronounced "soup"): [github.com/CIRISAI/CEWP](https://github.com/CIRISAI/CEWP) · [FSD](reference/CEWP.md). It doubles as the **CEWP reference**: the specs it conforms against are vendored under [`reference/`](reference/).

## Why this exists

The CIRIS stack ships as **separately-published PyO3 extension wheels** — storage, crypto, transport, node-serving — each built and released on its own cadence, but designed to run **together inside one Python process** (the CIRIS 3.0 cohabitation EPIC, [CIRISPersist#85](https://github.com/CIRISAI/CIRISPersist/issues/85)). That's how they run in production: one process, one persist `Engine`, one edge runtime, all sharing substrate handles.

Cohabitation has failure modes that **exist nowhere else** and that no single repo can test:

- **Cross-module type identity** — two wheels can each define what looks like "the same" type, but the interpreter treats them as distinct and rejects the hand-off.
- **Shared-substrate handles** — opaque capsules passed between wheels (an edge runtime built on a persist Engine) must agree on shape and lifetime.
- **Version skew** — wheel A pinned at one version must cohabit with wheel B at a different in-range version.
- **Wire-format agreement** — the canonical bytes one wheel signs must be byte-identical to what another wheel verifies.

Each wheel's own test suite compiles everything into a **single combined build**, where these cross-wheel problems vanish by construction. This harness installs the **real, separately-published wheels together** and drives them — the only place those bugs actually surface.

It does **not** test spec text or mocks. Every assertion calls a real published wheel and checks its behavior; where a wheel is missing a feature or has a bug, the harness files it upstream and marks the test an *expected failure* tied to that issue (never a skip, never a workaround — see ["expected failure" below](#why-tests-are-marked-expected-failure-instead-of-skipped)).

## What it tests — the wheels under test

| Wheel | Role |
|---|---|
| `ciris-persist` | substrate — federation-key directory, blob storage, audit chain, outbound queue, admission gates |
| `ciris-verify` (`ciris-keyring` + `ciris-crypto`) | crypto — hybrid Ed25519 + ML-DSA-65 sign/verify, Merkle transparency log, RNS dest-hash |
| `ciris-edge` | transport — federation wire dispatch, durable send, inbound trust gate |
| `ciris-server` | node-serving — absorbs lens-core (capacity scorer, detection, egress filter), reconsideration-DoS guard, audit-log client |

The exact versions under test are pinned in [`matrices/current.yaml`](matrices/current.yaml). `ciris-node-core` and `ciris-registry` join the matrix when they ship federation-relevant Python surfaces.

## Terminology

| Test class | Scope | Lives in |
|---|---|---|
| Unit | In-crate invariants | each crate |
| Integration | Crate against its dependencies, one binary | each crate |
| **Conformance** | **Artifacts (wheels) conforming to a cross-artifact contract** | **this repo** |

The name comes from the W3C / Khronos conformance-suite tradition: independent implementations of a contract are exercised against a separate, neutral suite that proves they conform to the contract.

## Two tiers: substrate + fabric

The suite is partitioned into two tiers (`pytest -m substrate` / `pytest -m fabric`):

- **Substrate** — the independently-built ciris-* wheels cohabit in one process, and each primitive conforms to the CEG contract (cohabitation scenarios + the CEG CCP/CCC/CCS profiles).
- **Fabric** — the *emergent* federation behaviour: the replication discipline (per-actor eviction, eviction sweeper, trust-threshold intake) and the scaling factors (`effective_trust_set_multiplier`, the `k_eff` corridor, retention) from [FEDERATION_SCALING_MODEL](https://github.com/CIRISAI/CIRISNodeCore/blob/main/FSD/FEDERATION_SCALING_MODEL.md) — how the CEWP "we don't need big tech" claim becomes a checked property.

See [`docs/FABRIC_CONFORMANCE.md`](docs/FABRIC_CONFORMANCE.md) for the tier coverage matrix.

## CEG conformance profiles

Beyond cohabitation, this harness verifies the three [CEG 0.1](https://github.com/CIRISAI/CIRISRegistry/tree/main/FSD/CEG) conformance profiles (§0.2) — **CCP** (producer), **CCC** (consumer), **CCS** (substrate). See [`docs/CEG_CONFORMANCE.md`](docs/CEG_CONFORMANCE.md) for the profile definitions, the §0.5 fractal-self reading discipline, and a coverage matrix tracking which CEG paths are tested today vs. pending an upstream surface. Profile tests carry the `ceg` marker plus `ccp`/`ccc`/`ccs`; run one with `pytest -m ccc`.

## Compliance controls

Several [CIRIS compliance controls](https://ciris.ai/compliance) reduce to a **substrate-enforced** mechanism — a behaviour a published wheel actually gates, not agent-side policy or governance. Those get a real conformance test driving the wheel: reconsideration anti-abuse (`test_220`, the F-AV-RECONSIDER-DOS guard), fail-secure peer-key enrollment (`test_310`), the §0.5–§0.7 canonical-bytes rejection rules (`test_120`), and the tamper-evident audit chain (`test_320`, D02/D23), and family cohort member add/remove (`test_260`, CEG #249 G1). Controls that live in the agent (conscience faculties, the WiseBus, the decision pipeline) are out of scope here — they're tested in CIRISAgent's own suite, not against the substrate wheels.

## How to run

```bash
pip install -e ".[dev]"                 # the harness + dev tooling
python tools/install_pins.py            # install the matrices/current.yaml wheels (with propagation-race retry)
pytest                                  # run everything (defaults to sqlite::memory:)

# Drive the postgres backend instead of sqlite (both must pass — full parity):
CIRIS_CONFORMANCE_DATABASE_URL="postgres://user:pw@localhost:5432/conformance" pytest

# A tier, a profile, or one scenario:
pytest -m substrate        # cohabitation + CEG profiles
pytest -m fabric           # replication discipline + scaling factors
pytest -m ccc              # one CEG profile (producer/consumer/substrate)
pytest -m version_skew     # the clean-venv version-skew lane (builds throwaway venvs; slow)
pytest tests/test_030_cohabitation_init.py -v
```

Each scenario runs in a **fresh Python subprocess**: PyO3 type registration is process-global, so once a wheel is imported you cannot rewind it — a test that imported a wheel would contaminate the next (mechanics in the first drop-down below). The same suite runs against **both** sqlite and postgres in CI; backend-agnostic invariants must hold identically on each.

## How this works

The CIRIS stack ships as several separate libraries (storage, crypto, networking) that are built and released independently but are meant to run **together inside one program**. This suite checks that they actually do. Expand a section for the details.

<details>
<summary><b>Why each test runs in its own fresh Python process</b></summary>

These libraries are compiled extensions (written in Rust). When Python imports one, the import permanently registers things into the running interpreter — there's no way to "un-import" it afterward. So a test that loaded one library would leave traces that contaminate the next test.

To keep every check clean, the harness launches a **brand-new Python process for each scenario**, hands it a short script, and reads the result back as JSON. The test runner file itself deliberately imports none of the CIRIS libraries, so nothing leaks in by accident.
</details>

<details>
<summary><b>What "cohabitation" means — and why the libraries' own tests miss these bugs</b></summary>

"Cohabitation" is just the situation where all these independently-shipped libraries run side by side in one process — which is exactly how they run in production.

That situation has its own failure modes that don't exist anywhere else: two libraries can each define what looks like "the same" type, but the program treats them as different and rejects the hand-off; they can fight over a shared resource; the order you load them in can matter. Each library's own test suite compiles everything into a **single combined build**, where these cross-library problems simply can't happen. This harness installs the **real, separately-published** libraries together — the only place those bugs actually surface.
</details>

<details>
<summary><b>The two kinds of checks: the building blocks vs. the whole network</b></summary>

Two test groups, selectable with `pytest -m substrate` or `pytest -m fabric`:

- **Substrate** — do the building-block libraries load and work together, and does each one correctly produce, read, and store the shared message format the components use to talk to each other?
- **Fabric** — does the network behave correctly *as a whole*: the rules for which data a node keeps, whose data it's allowed to delete, when it drops stale data, and the math behind the claim that this scales to internet size on ordinary hardware.

Detailed coverage tables: [`docs/CEG_CONFORMANCE.md`](docs/CEG_CONFORMANCE.md) (building blocks) and [`docs/FABRIC_CONFORMANCE.md`](docs/FABRIC_CONFORMANCE.md) (network).
</details>

<details>
<summary><b>What "conforming" means for each component (producer / consumer / storage)</b></summary>

The components talk to each other using a shared, signed message format — the **CEG** ("CIRIS Epistemic Grammar"; full spec under [`reference/CEG/`](reference/CEG/)). Every claim ("this content is genuine," "I trust this peer") is a signed message. A component can play three roles, and the spec says what *correct* means for each:

- **Producer** — writes well-formed messages and signs them properly.
- **Consumer** — checks those signatures and applies the agreed rules before acting on a message.
- **Storage** — keeps and forwards messages without corrupting them (verifies content against its hash, doesn't silently duplicate, etc.).

Signatures use both a standard algorithm and a post-quantum one, so they stay valid for decades.
</details>

<details>
<summary><b>How the tested versions are pinned</b></summary>

[`matrices/current.yaml`](matrices/current.yaml) lists the exact library versions expected to work together right now; CI installs precisely those into a clean environment. To move it forward: bump a version, run the tests, and update any test whose expected-failure now passes.
</details>

<details>
<summary><b>Why tests are marked "expected failure" instead of skipped</b></summary>

A *skipped* test silently hides untested code, which is easy to mistake for "it works." So this suite never skips to paper over a **missing feature or a bug** — a test either **passes** against the real wheel, or it's marked an **expected failure** linked to a specific upstream issue we've filed. The moment the upstream fix ships, that test automatically becomes a real, enforced check.

The only legitimate skip is a **hardware/environment precondition the wheel can't supply** — e.g. the HSM-contrast cell that needs a real TPM. That's not a hidden gap; it's "this host can't exercise this path," and it runs for real on a host that can.

The rule: when a wheel is missing a feature or has a bug, we **report it upstream and mark the test expected-to-fail** — never a workaround that tests something easier.
</details>

<details>
<summary><b>Running inside the phone app (the Android build)</b></summary>

The CIRIS agent packages three of these libraries into a single **Android app** and runs them on the phone. Android does this with a tool that bundles the compiled libraries directly and runs them on its own bundled Python — skipping the usual version checks. That only works because the libraries are built against Python's *stable* binary interface, so one build runs across Python versions.

These tests confirm that's actually true, that the libraries cope with the phone's secure-key hardware, and that startup produces a valid network identity. CI also runs on ARM chips (what phones use) and reproduces the Android bundling trick, so a break shows up before it reaches an app store.
</details>

<details>
<summary><b>The specs this suite checks against (the reference copies)</b></summary>

[`reference/`](reference/) holds copies of the specifications this suite verifies: the platform overview ([CEWP](reference/CEWP.md)), the [scaling model](reference/FEDERATION_SCALING_MODEL.md) and the small program that computes it, the [message-format spec](reference/CEG/), and the research paper behind the scaling claims. These are snapshots for convenience — [`reference/README.md`](reference/README.md) records exactly where each one came from.
</details>

## How sibling repos invoke this harness

Any CIRIS-stack repo can run this harness against its just-built artifact + the pinned sibling wheels:

```yaml
# In e.g. CIRISEdge/.github/workflows/ci.yml
jobs:
  conformance:
    needs: [pyo3-wheel]
    uses: CIRISAI/CIRISConformance/.github/workflows/run-against-wheels.yml@main
    with:
      under-test-wheel: ciris_edge-wheel-linux-x86_64  # the just-built artifact
      under-test-package: ciris-edge
      matrix: matrices/current.yaml                    # pinned siblings
```

The reusable workflow installs the under-test wheel + pinned siblings into a clean venv and runs `pytest`. A regression in the under-test repo fails its own CI before merge.

## Adding a new test case

1. Identify the cross-artifact invariant under test (e.g. "import order doesn't affect engine type identity").
2. Add a single Python file `tests/test_NNN_short_name.py` with one or more `pytest` functions.
3. If the case requires specific wheel versions, parametrize via the `wheels` fixture (`conftest.py`).
4. If the case is a known-failing regression seed (like persist#109 was for cohabitation init), mark it `@pytest.mark.xfail(strict=True, reason="...")` so the harness goes green once the upstream fix lands.

Each test file is self-contained — no shared imports between test files — so any failure reproduces in isolation and can be referenced verbatim in a bug report.

## Results

Against the current pinned matrix (persist 10.4.0 / verify 7.5.0 / edge 7.1.0 / server 0.5.51), the suite runs **green on both backends** — sqlite *and* postgres, in full parity — across py3.10 + py3.12 on x86_64 and aarch64:

**102 passed · 1 skipped · 2 expected-failures · 0 unexpected failures**

- The **1 skip** is the HSM hardware-contrast cell, which only runs on a host with a real TPM (not a wheel gate — environment-conditional, correct).
- The **2 expected-failures** are each blocked on a *filed* upstream issue and flip to a real enforced gate the moment that upstream ships:
  | xfail | Blocked on |
  |---|---|
  | `test_050` true loopback delivery | needs a 2-node transport fixture — [Conformance#4](https://github.com/CIRISAI/CIRISConformance/issues/4) |
  | `test_320` audit-chain accountability | `LensAudit.log_*` emits `sequence_number=0`, persist needs `≥1` — [CIRISServer#93](https://github.com/CIRISAI/CIRISServer/issues/93) |

The version-skew lane (`-m version_skew`, real installs into throwaway venvs) runs as its own CI job and is green.

## Test-case index

`✅` = real enforced gate · `⏳` = expected-failure tracked to a filed upstream issue.

| File | Tier | Verifies | Status |
|---|---|---|---|
| `test_010_solo_imports.py` | substrate | Each wheel (persist/verify/edge/server) imports cleanly alone | ✅ |
| `test_020_pairwise_imports.py` | substrate | Any two wheels coexist in one process (all pairs incl. `*-server`) | ✅ |
| `test_030_cohabitation_init.py` | substrate | `edge.init_edge_runtime(persist.Engine)` capsule handshake | ✅ |
| `test_040_pyclass_identity.py` | substrate | Cross-module PyClass identity invariants | ✅ |
| `test_050_send_receive.py` | substrate | Send/receive surface; durable send (sender FK after [edge#203](https://github.com/CIRISAI/CIRISEdge/issues/203)); loopback ⏳ [Conformance#4](https://github.com/CIRISAI/CIRISConformance/issues/4) | ✅ |
| `test_060_version_skew.py` | substrate | In-range cohabitation tolerance + below-floor pip refusal (clean-venv per case) | ✅ |
| `test_070_hsm_transport_identity.py` | substrate | `hardware_hsm_only` cohab init → 32-byte transport identity | ✅ |
| `test_080_mobile_target.py` | substrate | Android/Chaquopy bundling (abi3), keystore taxonomy, bring-up gate | ✅ |
| `test_100_ccc_hybrid_verify.py` | substrate (CCC) | Hybrid-signature verify policy matrix (strict / ed25519-fallback / soft-freshness) | ✅ |
| `test_110_ccs_blob_integrity.py` | substrate (CCS) | Blob full-SHA integrity + signed round-trip | ✅ |
| `test_120_ccp_canonical_bytes.py` | substrate (CCP) | Canonical-bytes determinism + §0.5/§0.6/§0.7 rejection (timestamp / hex / future) | ✅ |
| `test_130_multimedia.py` | substrate + fabric | CEG multimedia: media blob storage, perceptual-hash gate, takedown scheduling, key-grant retire, budget eviction | ✅ |
| `test_140_https_transport.py` | substrate | HTTPS transport stands up (mTLS + bearer config; clean refusal to unresolvable peer) | ✅ |
| `test_150_rns_dest_hash.py` | substrate | RNS destination-hash golden vectors + wheel-recompute cross-check ([verify#28](https://github.com/CIRISAI/CIRISVerify/issues/28)) | ✅ |
| `test_200_fabric_eviction.py` | fabric | Per-actor eviction + `withdraws`, eviction sweeper, trust-threshold setter | ✅ |
| `test_230_intake_gate.py` | fabric | Trust × capacity intake gate: low-trust sender refused at edge `dispatch_inbound` (`trust_short_circuited`) | ✅ |
| `test_210_fabric_scaling_factors.py` | fabric | Scaling-factor contract (multiplier curve, `k_eff` corridor, retention) | ✅ |
| `test_211_fav_cost_asymmetry.py` | fabric | F-AV cost-asymmetry contract (Sybil cost floors, dormant-vTPM, the 7-finding catalog) | ✅ |
| `test_220_reconsider_dos.py` | fabric | Reconsideration anti-abuse (F-AV-RECONSIDER-DOS): actor-budget + harassment-cluster gates | ✅ |
| `test_300_multinode_federation.py` | fabric | Multi-node over shared substrate: cross-node visibility, multi-holder discovery, per-operator eviction | ✅ |
| `test_310_peer_admission.py` | fabric | Fail-secure peer-key enrollment: tampered envelope / corrupted signature rejected before storage | ✅ |
| `test_320_audit_accountability.py` | fabric | Tamper-evident audit chain (compliance D02/D23): server writes → persist verifies | ✅ |
| `test_240_reserved_prefix_admission.py` | fabric | Namespace admission: non-member family-scope write refused; CC 3.4 reserved prefixes refused (persist 10.4.0); subject_key_ids lowercase-hex residual ⏳ [persist#293](https://github.com/CIRISAI/CIRISPersist/issues/293) | ✅ |
| `test_250_key_grant_pqc.py` | substrate | DEK-grant PQC wrap (CC 5.1): v2 is X25519+ML-KEM-768 hybrid, v1 classical-only, no cross-version downgrade | ✅ |
| `test_260_cohort_member_lifecycle.py` | fabric | Family cohort member add / remove (CEG #249 G1): idempotent add, immediate vs future-dated revoke, swap, member-side read | ✅ |
| `test_270_moderation_authority.py` | fabric | §11.10 moderation duty (CC 4.5.4): non-moderator refused at `file_moderation`; community authority files; appoint → `is_named_moderator` → remove revokes (persist 10.4.0) | ✅ |
| `test_280_blackhole_denylist.py` | substrate | Transport abuse-source blackhole (CC 4.5): 16-byte Reticulum identity-hash width gate + list round-trip | ✅ |
| `test_330_two_node_roundtrip.py` | fabric | Real two-node transport A→B inline-text round-trip (edge#217 abort + 30s timeout fixed; send returns 'sent' but B never receives) ⏳ [edge#220](https://github.com/CIRISAI/CIRISEdge/issues/220) | ⏳ |
| `test_900_bench_smoke.py` | — | Cross-wheel benchmark suite runs and reports (the benchmark tier's bit-rot gate) | ✅ |
| `test_912_install_pins_tool.py` | — | Unit pins for the propagation-race retry helper (`tools/install_pins.py`) | ✅ |

Two diagnostic tools live in [`tools/`](tools/): `hang_diagnose.py` (root-causes native-code hangs in cohabiting wheels — backtraces below the interpreter) and `install_pins.py` (retries the matrix install through PyPI propagation races, fails fast on real conflicts). See [`tools/README.md`](tools/README.md).

## Adding a new crate

When CIRISNodeCore / CIRISRegistry start shipping federation-relevant wheels (lens-core is already folded into `ciris-server`), add them to:

1. `matrices/current.yaml` — pin the version under `stack`
2. `conftest.py` — register in the wheel list driving the pairwise import test + the `requires_*` marker map
3. New test files for the crate-specific cohabitation invariants

The harness shape doesn't change.

## License

AGPL-3.0-or-later (matches the broader CIRIS stack).
