# CIRISConformance

Cross-artifact conformance harness for the CIRIS federation stack — the substrate and fabric of **CEWP**, the **CIRIS Epistemic Web Platform** (pronounced "soup"): [github.com/CIRISAI/CEWP](https://github.com/CIRISAI/CEWP) · [FSD](reference/CEWP.md). It tests the system's compliance with the **[CIRIS Constitution](reference/CIRIS_Constitution/) (`CC 0.4`)** — the ecosystem's **superalignment standard** — and doubles as the reference: the Constitution and the CEWP specs it conforms against are vendored under [`reference/`](reference/).

## What this is

**CEWP is a governable, post-quantum, decentralized mesh.** It's a peer-to-peer federation where every load-bearing claim — *"this content is genuine," "this peer is trusted," "defer this to a human"* — is a signed wire-format artifact; identity and content are protected by post-quantum-hybrid cryptography; messages cross a live encrypted mesh with no central server; and who may join, speak, and moderate is gated by the substrate and rooted in accountable humans. The full platform thesis is in [`reference/CEWP.md`](reference/CEWP.md).

Its conformance standard is the **[CIRIS Constitution](reference/CIRIS_Constitution/) (`CC 0.4`)** — a **superalignment standard** that treats alignment as cryptographic accountability and epistemic governance, not a training-time property (it superseded and absorbed the CEG wire-grammar; `CC N.x` lives in `part_N`). **This repo is the neutral suite that tests the CIRIS system's compliance with that standard.** It covers the **substrate's** compliance — proving the independently-published wheels enforce the Constitution *together*, not in a combined build where the cross-wheel seams vanish, but as the real, separately-shipped artifacts cohabiting in one process. The **agent's** compliance is tested in the [CIRISAgent](https://github.com/CIRISAI/CIRISAgent) suite + safety batteries; the two together are the system's constitutional-compliance claim (the [compliance coverage map](#compliance-coverage-map) tracks all 27 controls across both). Conformance runs in **two lanes** — Python cohabitation here, plus Rust feature-conformance in [CIRISServer](https://github.com/CIRISAI/CIRISServer) for substrate-internal behaviour the agent's brain never drives. Each property below is a behaviour a published wheel *gates*, driven by a real test (never spec text, never a mock):

- **Decentralized mesh** — messages cross a live transport node-to-node, no center. `test_340` drives A→B delivery across every holder mode over a 4-node / 3-owner fabric.
- **Post-quantum** — identity and the audit chain are Ed25519 + ML-DSA-65 hybrid; the content/DEK cascade is X25519 + ML-KEM-768 (`test_250`, `test_100`, `test_320`). The wire *session* keys are classical (Reticulum) — PQ protects the long-lived secrets, where harvest-now-decrypt-later actually bites.
- **Governable** — membership roots in an accountable human (`owner_bind`, CC 3.2), with delegated + revocable moderation authority and namespace admission (`test_270`, `test_240`, `test_260`), and a tamper-evident audit chain (`test_320`).
- **Scales without big tech** — the replication discipline + scaling factors that make internet-scale feasible on ordinary hardware are checked properties, not slides (`test_210`, `test_211`, `test_200`).

The grouped [test-case index](#test-case-index-by-property) below maps each property to the tests that enforce it and how.

## Where this fits — the CIRIS ecosystem CI

CIRISConformance is **not a deployable binary** — it's the **contract-governance stage** of the ecosystem CI/CD pipeline. It defines the reference matrices (`matrices/current.yaml`) and the integration boundaries every other project must satisfy *before any combination of wheels is allowed to boot*. The pipeline builds a verified [CIRISAgent](https://github.com/CIRISAI/CIRISAgent) 2.9.7+ image by evaluating the dependency chain **from the cryptographic foundation up**, running **16,000+ test functions** across the chain (measured — see the note below; executed cases run higher via parametrization) plus this suite's cross-artifact conformance gates:

```
            ┌──────────────── CIRISConformance ────────────────┐
            │  governs the matrix every combination must pass    │
            │  before it boots (this repo)                       │
            └───────────────────────┬───────────────────────────┘
                                     ▼  (matrix floors + cross-wheel gates)
 CIRISVerify ─▶ CIRISPersist ─▶ CIRISEdge ─▶ CIRISServer ─▶ CIRISAgent
   trust          state          mesh         headless        client
```

| Stage | Role | ~tests | CI |
|---|---|---|---|
| **[CIRISConformance](https://github.com/CIRISAI/CIRISConformance)** (this repo) | Ecosystem matrix & contract governance — adversarial fire-tests against the substrate data-access surfaces (caller-scope admission, hardware-backed attestation under duress) + matrix-alignment validation (PyO3/UniFFI init-skew floors) | cross-artifact gates | [reusable workflow](https://github.com/CIRISAI/CIRISConformance/blob/main/.github/workflows/run-against-wheels.yml) · [Actions](https://github.com/CIRISAI/CIRISConformance/actions) |
| **[CIRISVerify](https://github.com/CIRISAI/CIRISVerify)** | Cryptographic & trust foundation — key-gen, signature determinism, TPM2 mock; D27 AST pre-flight (runtime mustn't depend on `.md`); strict mypy; multi-arch FFI build | ~1,200\* | [Actions](https://github.com/CIRISAI/CIRISVerify/actions) |
| **[CIRISPersist](https://github.com/CIRISAI/CIRISPersist)** | Data & state — dual-backend (PostgreSQL + SQLite) parity sweep, upgrade-compat fixture capture, cross-platform serialization parity, ACID/locking/isolation | ~2,150\* | [Actions](https://github.com/CIRISAI/CIRISPersist/actions) |
| **[CIRISEdge](https://github.com/CIRISAI/CIRISEdge)** | Mesh networking & federation — Leviculum/Reticulum-rs vendor integration (TCP-loopback / LoRa / packet-radio), network-mesh simulation, latency/drain assertions, SAS verification, boundary fuzzing | ~990\* | [Actions](https://github.com/CIRISAI/CIRISEdge/actions) |
| **[CIRISServer](https://github.com/CIRISAI/CIRISServer)** | Headless operations — HTTP/REST + SSE surface (`/v1/federation/*`, `/a2a`), token-tier gating, PyInstaller headless binaries, signed multi-arch Docker images. Also hosts the **Rust conformance lane** (see [`docs/CC_CONFORMANCE.md`](docs/CC_CONFORMANCE.md)) | ~630\* | [Actions](https://github.com/CIRISAI/CIRISServer/actions) |
| **[CIRISAgent](https://github.com/CIRISAI/CIRISAgent)** | User-facing client (desktop/mobile) integrating all five layers — localization guard, staged QA, registry-signed build manifests, final cross-platform artifacts. Runs the **safety batteries** (below) | **~11,500**\* unit tests · 90+ QA-runner modules (8-way sharded) | [Actions](https://github.com/CIRISAI/CIRISAgent/actions) |

\* **Counts are measured, not estimated** — test-function definitions on each repo's `main` (`#[test]`/`#[tokio::test]`/`#[rstest]` for Rust, `def test_` for Python), via `grep`. *Executed* cases run higher (parametrized / table-driven / `rstest` cases), which is why a CI "test count" for a heavily-parametrized stage (e.g. Edge/Server integration) can exceed the function count shown. CIRISConformance itself contributes 124 Python cohabitation gates + the CIRISServer Rust conformance lane. Re-run the count anytime: `grep -rEc '^\s*(async )?def test_' tests/` (Python) / `grep -rE '#\[(tokio::)?test\]' src tests | wc -l` (Rust).

### CIRISAgent safety batteries (run + captured in CI)

The agent's compliance/safety tier is exercised in CI by the **[Safety Battery workflow](https://github.com/CIRISAI/CIRISAgent/blob/main/.github/workflows/safety-battery.yml)** — adversarial **mental-health safety batteries across 29 locales** ([`tests/safety/<lang>_mental_health/`](https://github.com/CIRISAI/CIRISAgent/tree/main/tests/safety)), driven through the **[`qa_runner`](https://github.com/CIRISAI/CIRISAgent/tree/main/tools/qa_runner)** harness ([`modules/safety_battery.py`](https://github.com/CIRISAI/CIRISAgent/blob/main/tools/qa_runner/modules/safety_battery.py) · [`safety_interpret.py`](https://github.com/CIRISAI/CIRISAgent/blob/main/tools/qa_runner/modules/safety_interpret.py)). **The results are in CI too** — each run publishes its capture as a `safety-battery-capture-*` workflow artifact (per language/domain), so the safety-interpretation sweeps are auditable run-over-run, not just pass/fail. Alongside it run the **[localization guard](https://github.com/CIRISAI/CIRISAgent/blob/main/tools/dev/check_localization_sync.py)** (29-locale mirror parity, stdlib-only) and the staged install-parity QA.

This is the agent half of the [compliance coverage map](#compliance-coverage-map): the controls marked *lane = agent* are the ones these batteries and the [CIRISAgent compliance map](https://github.com/CIRISAI/CIRISAgent/tree/main/compliance) own.

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

- **Substrate** — the independently-built ciris-* wheels cohabit in one process, and each primitive conforms to the CIRIS Constitution (cohabitation scenarios + the CC 2.2 CCP/CCC/CCS profiles).
- **Fabric** — the *emergent* federation behaviour: the replication discipline (per-actor eviction, eviction sweeper, trust-threshold intake) and the scaling factors (`effective_trust_set_multiplier`, the `k_eff` corridor, retention) from [FEDERATION_SCALING_MODEL](https://github.com/CIRISAI/CIRISNodeCore/blob/main/FSD/FEDERATION_SCALING_MODEL.md) — how the CEWP "we don't need big tech" claim becomes a checked property.

See [`docs/FABRIC_CONFORMANCE.md`](docs/FABRIC_CONFORMANCE.md) for the tier coverage matrix.

## CIRIS Constitution conformance profiles

Beyond cohabitation, this harness verifies the three [CIRIS Constitution](reference/CIRIS_Constitution/) `CC 0.4` conformance profiles (**CC 2.2** — these superseded the CEG §0.2 profiles, names retained) — **CCP** (producer), **CCC** (consumer), **CCS** (substrate). See [`docs/CC_CONFORMANCE.md`](docs/CC_CONFORMANCE.md) for the profile definitions, the self-as-subject reading discipline (CC 2.3.4 / part_1 anti-Cartesian), and a coverage matrix tracking which CC paths are tested today vs. pending an upstream surface. Profile tests carry the `ceg` marker plus `ccp`/`ccc`/`ccs`; run one with `pytest -m ccc`.

## Compliance coverage map

The [CIRIS compliance catalog](https://ciris.ai/compliance) defines 27 controls (D01–D27). **All 27 are addressed — none are uncovered.** The split is by *lane*: which controls this substrate conformance suite gates against the real wheels (`✅` Python lane · `🦀` Rust lane in CIRISServer), and which are owned by the **[CIRISAgent compliance map](https://github.com/CIRISAI/CIRISAgent/tree/main/compliance)** — the agent's conscience / H3ERE decision-pipeline / WiseBus tier, tracked dimension-by-dimension in `CIRISAgent/compliance/Dnn_*.md` (its own system of record, with a per-dimension known-gaps inventory). An agent-owned control is **coverage, not a gap**. (CIRISAgent#902 tracks crediting the substrate-gated facets back into the agent map.)

| Control | Lane | Addressed by | Status |
|---|---|---|---|
| D01 — non_maleficence | agent | CIRISAgent map · `non_maleficence:*` | ✅ |
| D02 — integrity | substrate | `test_320` (hash-chained hybrid-signed audit) | ✅ |
| D03 — justice | agent | CIRISAgent map · `justice:*` | ✅ |
| D04 — prohibited | agent | CIRISAgent map · `prohibited:*` | ✅ |
| D05 — detection | agent | CIRISAgent map · `detection:*` | ✅ |
| D06 — goal | agent | CIRISAgent map · `goal:*` | ✅ |
| D07 — locality_decision_scale | agent | CIRISAgent map · `locality:decision:{scale}` | ✅ |
| D08 — autonomy | agent | CIRISAgent map · `autonomy:*` | ✅ |
| D09 — fidelity | agent | CIRISAgent map · `fidelity:*` | ✅ |
| D10 — beneficence | agent | CIRISAgent map · `beneficence:*` | ✅ |
| D11 — multilateral_participation | agent | CIRISAgent map · `multilateral_participation:{forum}:{kind}` | ✅ |
| D12 — conscience | agent | CIRISAgent map · `conscience:*` | ✅ |
| D13 — testimonial_witness | agent | CIRISAgent map · `testimonial_witness:{kind}` | ✅ |
| D14 — witness_diversity | agent | CIRISAgent map · `witness_diversity:*` | ✅ |
| D15 — moderation | substrate | `test_270` (delegated, revocable moderation authority) | ✅ |
| D16 — method | agent | CIRISAgent map · `method:*` (the H3ERE pipeline) | ✅ |
| D17 — transparency_log | Rust | CIRISServer `tests/stream_sth_consistency.rs` (STH consistency-proof; PR #108) | 🦀 |
| D18 — attestation_l_3_5 | substrate + agent | `test_070`/`test_080` (L2 hardware-rooted) · CIRISAgent map (L1/L3/L4/L5 ladder) | ✅ |
| D19 — partner_role | agent | CIRISAgent map · `partner_role:*` (Registry taxonomy) | ✅ |
| D20 — approach | agent | CIRISAgent map · `approach:*` | ✅ |
| D21 — progress_measure | agent | CIRISAgent map · `progress_measure:*` | ✅ |
| D22 — expertise | agent | CIRISAgent map · `expertise:*` | ✅ |
| D23 — accountability | substrate + agent | `test_320` (tamper-evident log) · CIRISAgent map (named-accountability) | ✅ |
| D24 — reconsideration | substrate | `test_220` (anti-DoS / harassment-cluster admission) | ✅ |
| D25 — credits | agent | CIRISAgent map · `credits:*` | ✅ |
| D26 — key_boundary | substrate + agent | `test_070`/`test_080` + `test_250` (signer + storage-kind + PQC DEK wrap) · CIRISAgent map (`key_boundary:*` attestation) | ✅ |
| D27 — provenance | agent | CIRISAgent map · `provenance:*` | ✅ |

**How the substrate-gated controls are driven (the `✅` substrate / `🦀` Rust rows):**
- **D02 / D23 → `test_320`** — `ciris_server.LensAudit` writes entries; persist's `audit_verify_chain` walks the hash-chained, Ed25519 + ML-DSA-65–signed log and returns `ok`, with a typed break diagnostic on tamper. (D23 also carries a named-accountability / WiseAuthority facet owned by the agent map.)
- **D15 → `test_270`** — persist's `file_moderation` / `add_moderator` / `is_named_moderator`: a non-duty key is refused (`federation_delegated_scope_unauthorized`); appoint→verify→revoke walks the owner-bound scoped-delegation chain.
- **D17 → CIRISServer `tests/stream_sth_consistency.rs`** (Rust lane, PR #108) — `ciris-persist` builds an RFC 6962 STH consistency proof; the independently-published `ciris-verify-core` verifies it; forged root / tampered proof fail closed.
- **D18 → `test_070`/`test_080`** — the L2 hardware-rooted facet (recognized keystore kind; hardware-rooted signer → 32-byte transport identity). The L1/L3/L4/L5 ladder is consumer-side composition in the agent map.
- **D24 → `test_220`** — `ciris_server.ReconsiderDosGuard`: admits a fresh filing, refuses past the per-actor budget, refuses repeat same-pair filings as `HarassmentClusterDetected`.
- **D26 → `test_070`/`test_080` + `test_250`** — hardware-rooted signer + storage-kind taxonomy at cohab init, and the non-downgradable v2 X25519 + ML-KEM-768 DEK-grant wrap. The `no_seed_in_heap` self-attestation is owned by the agent map (`key_boundary:*`).

**Totals: all 27 green.** Substrate-gated here: **D02 · D15 · D24** (Python `✅`), **D17** (Rust `🦀`), with **D18 · D23 · D26** split substrate + agent. The remaining **20** are owned by the CIRISAgent compliance map (which tracks its own per-dimension implementation status). "Lane = agent" is where the control lives, not a gap in coverage.

## How to run

```bash
pip install -e ".[dev]"                 # the harness + dev tooling
python tools/install_pins.py            # install the matrices/current.yaml wheels (with propagation-race retry)
pytest                                  # run everything (defaults to sqlite::memory:)

# Drive the postgres backend instead of sqlite (both must pass — full parity):
CIRIS_CONFORMANCE_DATABASE_URL="postgres://user:pw@localhost:5432/conformance" pytest

# A tier, a profile, or one scenario:
pytest -m substrate        # cohabitation + Constitution profiles
pytest -m fabric           # replication discipline + scaling factors
pytest -m ccc              # one CC profile (producer/consumer/substrate)
pytest -m version_skew     # the clean-venv version-skew lane (builds throwaway venvs; slow)
pytest tests/test_030_cohabitation_init.py -v

# Emit a machine-readable certification artifact (for "does Implementation X conform?"):
pytest --conformance-report=conformance.json
```

`--conformance-report` writes a JSON report — the pinned matrix, a per-marker rollup (`substrate`/`fabric`/`ccp`/`ccc`/`ccs`/`requires_*`), every test's outcome, and a single top-level `passed_all_gates` boolean (false if anything failed, errored, or a strict-xfail unexpectedly passed). An implementer can certify against the suite by asserting `passed_all_gates` on the report instead of scraping pytest output.

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

Detailed coverage tables: [`docs/CC_CONFORMANCE.md`](docs/CC_CONFORMANCE.md) (building blocks) and [`docs/FABRIC_CONFORMANCE.md`](docs/FABRIC_CONFORMANCE.md) (network).
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

Against the current pinned matrix (persist 10.5.0 / verify 7.5.0 / edge 7.1.0 / server 0.5.51), the suite runs **green on both backends** — sqlite *and* postgres, in full parity — across py3.10 + py3.12 on x86_64 and aarch64:

**124 passed · 1 skipped · 0 expected-failures · 0 unexpected failures**

- The **1 skip** is the HSM hardware-contrast cell, which only runs on a host with a real TPM (not a wheel gate — environment-conditional, correct).
- **0 expected-failures** — the last one (`test_240` `subject_key_ids` lowercase-hex) flipped to a real gate when persist 10.5.0 closed [CIRISPersist#293](https://github.com/CIRISAI/CIRISPersist/issues/293). Every Python-lane assertion is now a real enforced gate. (Substrate-internal Rust-lane features — STH/D17, hybrid-KEX correctness — are tracked in [`docs/CC_CONFORMANCE.md`](docs/CC_CONFORMANCE.md) and gated in CIRISServer's Rust suite.)

The version-skew lane (`-m version_skew`, real installs into throwaway venvs) runs as its own CI job and is green.

## Test-case index (by property)

Grouped by the property each test enforces, and how it's driven. `✅` = real enforced gate · `⏳` = expected-failure tracked to a filed upstream issue. (Numeric file order is incidental; tests are listed under the property they primarily prove.)

### Cohabitation — the independently-shipped wheels actually run together

*How:* install the real, separately-published wheels into one clean env and import / cohabit / hand off shared handles in a single process — each scenario in a fresh subprocess so nothing leaks between cases. This is the harness's reason to exist: failure modes that vanish in any single combined build.

| File | Tier | Verifies | Status |
|---|---|---|---|
| `test_010_solo_imports.py` | substrate | Each wheel (persist/verify/edge/server) imports cleanly alone | ✅ |
| `test_020_pairwise_imports.py` | substrate | Any two wheels coexist in one process (all pairs incl. `*-server`) | ✅ |
| `test_030_cohabitation_init.py` | substrate | `edge.init_edge_runtime(persist.Engine)` capsule handshake | ✅ |
| `test_040_pyclass_identity.py` | substrate | Cross-module PyClass identity invariants | ✅ |
| `test_060_version_skew.py` | substrate | In-range cohabitation tolerance + below-floor pip refusal (clean-venv per case) | ✅ |
| `test_070_hsm_transport_identity.py` | substrate | `hardware_hsm_only` cohab init → 32-byte transport identity (skips without a real TPM) | ✅ |
| `test_080_mobile_target.py` | substrate | Android/Chaquopy bundling (abi3), keystore taxonomy, bring-up gate | ✅ |

### Post-quantum cryptographic accountability — every claim is hybrid-signed and tamper-evident

*How:* drive the real sign / verify / wrap surfaces and assert the post-quantum-hybrid shapes and the byte-exact canonicalization the signatures cover — Ed25519 + ML-DSA-65 identity, X25519 + ML-KEM-768 content/DEK, and a hash-chained, hybrid-signed audit log.

| File | Tier | Verifies | Status |
|---|---|---|---|
| `test_250_key_grant_pqc.py` | substrate | DEK-grant PQC wrap (CC 5.1): v2 is X25519 + ML-KEM-768 hybrid, v1 classical-only, no cross-version downgrade | ✅ |
| `test_100_ccc_hybrid_verify.py` | substrate (CCC) | Hybrid-signature verify policy matrix (strict / ed25519-fallback / soft-freshness) | ✅ |
| `test_120_ccp_canonical_bytes.py` | substrate (CCP) | Canonical-bytes determinism + CC 2.6.2/2.6.3/2.6.7 rejection (timestamp / hex / future) | ✅ |
| `test_110_ccs_blob_integrity.py` | substrate (CCS) | Blob full-SHA integrity + signed round-trip | ✅ |
| `test_320_audit_accountability.py` | fabric | Tamper-evident audit chain (compliance D02/D23): server writes → persist hash-chain verifies | ✅ |

### Decentralized mesh transport — messages cross live transports with no center

*How:* stand up real edge runtimes over Reticulum (and HTTPS), exchange identities, and deliver between *separate node processes* — asserting real receipt, not just a send that returns, and rejecting malformed peers before storage.

| File | Tier | Verifies | Status |
|---|---|---|---|
| `test_340_transport_delivery_modes.py` | fabric | Real multi-node A→B inline-text delivery across every holder mode — self / family / community / direct (= community of 2) — over a 4-node / 3-owner fabric (Conformance#4) | ✅ |
| `test_300_multinode_federation.py` | fabric | Multi-node over shared substrate: cross-node visibility, multi-holder discovery, per-operator eviction | ✅ |
| `test_310_peer_admission.py` | fabric | Fail-secure peer-key enrollment: tampered envelope / corrupted signature rejected before storage | ✅ |
| `test_050_send_receive.py` | substrate | Send/receive surface; durable send (sender FK after [edge#203](https://github.com/CIRISAI/CIRISEdge/issues/203)) | ✅ |
| `test_140_https_transport.py` | substrate | HTTPS transport stands up (mTLS + bearer config; clean refusal to unresolvable peer) | ✅ |
| `test_150_rns_dest_hash.py` | substrate | RNS destination-hash golden vectors + wheel-recompute cross-check ([verify#28](https://github.com/CIRISAI/CIRISVerify/issues/28)) | ✅ |

### Governance — who may join, speak, and moderate, rooted in accountable humans

*How:* drive the real admission / membership / moderation / safety surfaces and assert the gates — owner-binding to a human (`owner_bind`, CC 3.2), delegated + revocable authority, reserved-namespace refusal, content takedown, and abuse-source denial.

| File | Tier | Verifies | Status |
|---|---|---|---|
| `test_240_reserved_prefix_admission.py` | fabric | Namespace admission: non-member family-scope write refused; CC 3.4 reserved prefixes refused (persist 10.4.0); `subject_key_ids` lowercase-hex refused (persist 10.5.0, CC 2.6.3) | ✅ |
| `test_270_moderation_authority.py` | fabric | CC 4.5.4/4.5.5 moderation duty: non-moderator refused at `file_moderation`; community authority files; appoint → `is_named_moderator` → remove revokes (persist 10.4.0) | ✅ |
| `test_260_cohort_member_lifecycle.py` | fabric | Family cohort member add / remove (CC 3.3.4 / CC 4.4.3.4): idempotent add, immediate vs future-dated revoke, swap, member-side read | ✅ |
| `test_130_multimedia.py` | substrate + fabric | CIRIS Constitution multimedia (CC 3.3): media blob storage, perceptual-hash gate, takedown scheduling (CSAM/terrorist legal-basis), key-grant retire, budget eviction | ✅ |
| `test_280_blackhole_denylist.py` | substrate | Transport abuse-source blackhole (CC 4.5): 16-byte Reticulum identity-hash width gate + list round-trip | ✅ |
| `test_220_reconsider_dos.py` | fabric | Reconsideration anti-abuse (F-AV-RECONSIDER-DOS): actor-budget + harassment-cluster gates | ✅ |

### Scales without big tech — the fabric economics, as checked properties

*How:* drive the replication discipline and the scaling-factor contract from the [FEDERATION_SCALING_MODEL](reference/FEDERATION_SCALING_MODEL.md) — what a node keeps, whose data it may evict, when it sheds stale data, the intake throttle, and the adversarial cost floors that keep Sybil attacks expensive.

| File | Tier | Verifies | Status |
|---|---|---|---|
| `test_210_fabric_scaling_factors.py` | fabric | Scaling-factor contract (multiplier curve, `k_eff` corridor, retention) | ✅ |
| `test_211_fav_cost_asymmetry.py` | fabric | F-AV cost-asymmetry contract (Sybil cost floors, dormant-vTPM, the 7-finding catalog) | ✅ |
| `test_200_fabric_eviction.py` | fabric | Per-actor eviction + `withdraws`, eviction sweeper, trust-threshold setter | ✅ |
| `test_230_intake_gate.py` | fabric | Trust × capacity intake gate: low-trust sender refused at edge `dispatch_inbound` (`trust_short_circuited`) | ✅ |

### Packaging & tooling

| File | Tier | Verifies | Status |
|---|---|---|---|
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
