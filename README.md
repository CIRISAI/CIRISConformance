# CIRISConformance

Cross-artifact conformance harness for the CIRIS federation stack — the substrate and fabric of **CEWP**, the **CIRIS Epistemic Web Platform** (pronounced "soup"): [github.com/CIRISAI/CEWP](https://github.com/CIRISAI/CEWP) · [FSD](reference/CEWP.md). It doubles as the **CEWP reference**: the specs it conforms against are vendored under [`reference/`](reference/).

## What this tests

This repo verifies that **independently-distributed CIRIS wheels coexist correctly in a single Python process**. The CIRIS stack ships as five separate PyO3 extension modules:

- `ciris-persist` — substrate (federation_keys directory, outbound queue, etc.)
- `ciris-verify` (`ciris-keyring` + `ciris-crypto`) — hybrid Ed25519 + ML-DSA-65 signing
- `ciris-edge` — federation wire transport
- `ciris-node-core` (planned) — node-mode serving + WA UX
- `ciris-lens-core` (planned) — capacity-score + detector logic

These wheels are built independently but designed to **cohabit** in one Python interpreter — the CIRIS 3.0 cohabitation EPIC (CIRISPersist#85). Cohabitation is its own engineering surface: shared substrate handles, cross-module type identity, version-skew compatibility, import order. Per-crate unit tests and per-crate integration tests cannot cover this surface — they all run in single-binary test environments where cross-module problems vanish by construction.

This harness exists to close that test gap.

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

## How to run

```bash
# From a checkout of this repo:
pip install -e ".[dev]"
pytest

# Against a specific wheel matrix (CI default):
pytest --matrix matrices/current.yaml

# Single scenario:
pytest tests/test_030_cohabitation_init.py -v
```

Each scenario runs in a fresh Python subprocess because PyO3 type registration is process-global — once a module is imported, you cannot rewind it (the mechanics are in the first drop-down below).

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

A *skipped* test silently hides untested code, which is easy to mistake for "it works." This suite never skips. A test either **passes** against the real library, or it's marked an **expected failure** linked to a specific bug report we've filed upstream.

The rule: when a library is missing a feature or has a bug, we **report it upstream and mark the test expected-to-fail** — we don't paper over it with a workaround that tests something easier. The moment the upstream fix ships, that test automatically becomes a real, enforced check.
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

## Test-case index

| File | Tier | Verifies | Status |
|---|---|---|---|
| `test_010_solo_imports.py` | substrate | Each ciris-* wheel imports cleanly alone | ✅ |
| `test_020_pairwise_imports.py` | substrate | Any two ciris-* wheels coexist in one process | ✅ |
| `test_030_cohabitation_init.py` | substrate | `edge.init_edge_runtime(persist.Engine)` capsule handshake | ✅ |
| `test_040_pyclass_identity.py` | substrate | Cross-module PyClass identity invariants | ✅ |
| `test_050_send_receive.py` | substrate | Send/receive surface; ephemeral refuses cleanly; loopback + durable `xfail` ([edge#50](https://github.com/CIRISAI/CIRISEdge/issues/50)) | ✅ |
| `test_060_version_skew.py` | substrate | Compatible / incompatible version-pair matrix | `xfail` (needs clean-venv fixture) |
| `test_070_hsm_transport_identity.py` | substrate | `hardware_hsm_only` cohab init → 32-byte transport identity | ✅ |
| `test_080_mobile_target.py` | substrate | Android/Chaquopy bundling (abi3), keystore taxonomy, bring-up gate | ✅ |
| `test_100_ccc_hybrid_verify.py` | substrate (CCC) | Hybrid-signature verify policy matrix | ✅ |
| `test_110_ccs_blob_integrity.py` | substrate (CCS) | Blob full-SHA integrity + signed round-trip | ✅ |
| `test_120_ccp_canonical_bytes.py` | substrate (CCP) | Canonical-bytes determinism + sign/verify round-trip | ✅ (§0.5 reject `xfail` [persist#126](https://github.com/CIRISAI/CIRISPersist/issues/126)) |
| `test_200_fabric_eviction.py` | fabric | Per-actor eviction + `withdraws`, sweeper, trust threshold | ✅ (holders/gate `xfail` [persist#130](https://github.com/CIRISAI/CIRISPersist/issues/130)/[#129](https://github.com/CIRISAI/CIRISPersist/issues/129)) |
| `test_210_fabric_scaling_factors.py` | fabric | Scaling-factor contract (multiplier curve, `k_eff`, retention) | ✅ |

## Adding a new crate

When CIRISNodeCore / CIRISLensCore / CIRISRegistry start shipping wheels, add them to:

1. `matrices/current.yaml` — pin the version
2. `conftest.py::ALL_WHEELS` — register in the pairwise import test
3. New test files for the crate-specific cohabitation invariants

The harness shape doesn't change.

## License

AGPL-3.0-or-later (matches the broader CIRIS stack).
