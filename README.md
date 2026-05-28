# CIRISConformance

Cross-artifact conformance harness for the CIRIS federation stack.

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

Each test runs in a fresh Python subprocess (via `pytest-forked`) because PyO3 type registration is process-global — once a module is imported, you cannot rewind it.

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

| File | Verifies | Status |
|---|---|---|
| `test_010_solo_imports.py` | Each ciris-* wheel imports cleanly alone | shipping |
| `test_020_pairwise_imports.py` | Any two ciris-* wheels coexist in one process | shipping |
| `test_030_cohabitation_init.py` | `edge.init_edge_runtime(persist.Engine)` succeeds | xfail — pending [persist#109](https://github.com/CIRISAI/CIRISPersist/issues/109) |
| `test_040_pyclass_identity.py` | Cross-module PyClass identity invariants | shipping (mostly xfail until persist#109) |
| `test_050_send_receive.py` | Full federation round-trip across cohabiting wheels | planned (after #109 ships) |
| `test_060_version_skew.py` | Compatible / incompatible version-pair matrix | planned |

## Adding a new crate

When CIRISNodeCore / CIRISLensCore / CIRISRegistry start shipping wheels, add them to:

1. `matrices/current.yaml` — pin the version
2. `conftest.py::ALL_WHEELS` — register in the pairwise import test
3. New test files for the crate-specific cohabitation invariants

The harness shape doesn't change.

## License

AGPL-3.0-or-later (matches the broader CIRIS stack).
