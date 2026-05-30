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

The suite is small and opinionated. Expand the part you need — deepest mechanics first.

<details>
<summary><b>Why each scenario runs in its own subprocess</b></summary>

PyO3 `#[pyclass]` type registration is **process-global**. The moment `import ciris_persist` runs, the `Engine` `PyTypeInfo` is registered in the interpreter's type table for the life of the process — you cannot rewind it. A test that imports persist cannot be cleanly followed by one that must *not* see that registration. So every cohabitation scenario runs in a **fresh `subprocess`** — plain `subprocess` + an inline script, **not** `pytest-forked` (forked children inherit the parent's import state at fork time). `conftest.py` itself imports no `ciris-*` module at module level for the same reason; module names cross into the subprocess scripts as strings, and results come back over stdout as JSON.

An `Edge` holding a live Reticulum transport can panic on drop at interpreter teardown, so transport scripts `flush()` then `os._exit(0)` to land their JSON before the destructor runs.
</details>

<details>
<summary><b>What "cohabitation" means — and why per-crate tests can't catch these bugs</b></summary>

Each wheel ships its **own** compiled `.so` with its **own** embedded `PyTypeInfo`. When persist and edge are separate wheels, a naïve cross-module `isinstance(engine, Engine)` *fails* — the type ids don't match (the v0.9.1 production regression). The fix is the **PyCapsule** pattern: persist exposes opaque substrate handles (`federation_directory_capsule`, `keyring_signer_capsule`, `local_signer_capsule`, …) and edge extracts them by name tag rather than by type identity.

Per-crate unit and integration tests run in a **single binary**, where all that `.so` content is one module and these cross-module problems vanish by construction. This harness loads the real, independently-built wheels in one process — the only place the capsule extraction, the shared tokio runtime, and the cross-cdylib statics can actually break.
</details>

<details>
<summary><b>The two tiers: substrate vs fabric</b></summary>

`pytest -m substrate` / `pytest -m fabric` partition the suite (anything not marked `fabric` is auto-tagged `substrate`).

- **Substrate** (`test_0xx` / `test_1xx`) — the wheels cohabit and each primitive conforms to the [CEG wire spec](reference/CEG/): cohabitation init, cross-module PyClass identity, send/receive, the HSM transport-identity gate, and the CEG **CCP / CCC / CCS** profiles.
- **Fabric** (`test_2xx`) — the *emergent* federation: per-actor eviction + `withdraws`, the popularity×freshness eviction sweeper, the trust-threshold intake gate (replication discipline, [scaling model](reference/FEDERATION_SCALING_MODEL.md) §1/§9), and the scaling factors (`effective_trust_set_multiplier`, the `k_eff` corridor, retention) pinned as an executable contract.

Full coverage matrices: [`docs/FABRIC_CONFORMANCE.md`](docs/FABRIC_CONFORMANCE.md) and [`docs/CEG_CONFORMANCE.md`](docs/CEG_CONFORMANCE.md).
</details>

<details>
<summary><b>The CEG conformance profiles (CCP / CCC / CCS)</b></summary>

[CEG](reference/CEG/) §0.2 defines three normative profiles, adopted here as the substrate-tier organising principle (markers `ceg` + `ccp`/`ccc`/`ccs`):

- **CCP** — *Producer*: emits well-formed signed envelopes, respects reserved prefixes, declares `oversight_mode` + `witness_relation`.
- **CCC** — *Consumer*: verifies hybrid Ed25519 + ML-DSA-65 signatures, enforces reserved-prefix admission, applies the §8 composition policies.
- **CCS** — *Substrate*: storage/transport/crypto guarantees — full-SHA blob verify, idempotent replication, witness-quorum admission.

The §0.5 *fractal-self* reading discipline (a conformant substrate **admits**, never **gates**, self-attestation) is anchored in [`docs/CEG_CONFORMANCE.md`](docs/CEG_CONFORMANCE.md).
</details>

<details>
<summary><b>The wheel matrix + pin protocol</b></summary>

[`matrices/current.yaml`](matrices/current.yaml) is the canonical "what's expected to work together right now" — CI installs exactly these pins into a clean venv. Update protocol: bump the pin → run `pytest` locally → flip any `xfail` that now passes → PR. Downstream consumer repos pick up the new floor on their next merge via the reusable workflow (below).
</details>

<details>
<summary><b>Why <code>xfail</code>, never <code>skip</code> — and how a gap becomes an upstream issue</b></summary>

A `skip` green-washes untested code. This suite has **zero skips**: a test either passes (the behaviour works against the real wheel) or it is an **`xfail` pinned to a tracked upstream issue**. When a substrate surface is missing or broken, we **file upstream and `xfail`** — never route around it with a workaround (e.g. scraping `list_attestations` to fake a broken `list_holders`). The `xfail` flips to a passing gate automatically the moment the fix ships. Open seams are catalogued in the coverage-matrix docs.
</details>

<details>
<summary><b>The production mobile path (Android / Chaquopy / abi3)</b></summary>

CIRISAgent bundles persist + verify + edge into one Android process via **Chaquopy**, which runs its own Python 3.10 and bundles the wheels directly — bypassing pip's `Requires-Python` (edge floors at `>=3.11`). That is safe only because the extensions are CPython **abi3** (`*.abi3.so`) / a version-independent uniffi cdylib. `test_080_mobile_target.py` pins that ABI claim, the keystore storage-kind taxonomy (Android Keystore → `hardware_hsm_only`), and the 32-byte transport-identity bring-up gate. CI exercises an **aarch64** runner (the production architecture) and a **`chaquopy-bundle-py310`** job that reproduces the `--ignore-requires-python` bundle on py3.10.
</details>

<details>
<summary><b>The reference materials (this repo <em>as</em> the CEWP reference)</b></summary>

[`reference/`](reference/) vendors provenance-tagged snapshots of the specs the suite conforms against: the [CEWP FSD](reference/CEWP.md), the [scaling model](reference/FEDERATION_SCALING_MODEL.md) + its `scale_model.rs` toy, the 19-section [CEG wire spec](reference/CEG/), and the synthesis paper *Corridor Dynamics in Coordinated Systems*. Each is a snapshot, not the source of truth — [`reference/README.md`](reference/README.md) records the source repo + commit pin for every file.
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
