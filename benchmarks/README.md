# Cross-wheel substrate benchmarks

This is the **conformance benchmark tier**. It mirrors the discipline the
substrate sisters already use (criterion + a publish-only `bench.yml`,
**not** a pass/fail gate — shared CI runners are too noisy), and it builds
*on top of* their suites rather than duplicating them.

## What it does NOT measure

The per-operation costs are owned by the sisters' own criterion suites,
and those numbers calibrate the CEWP scaling model at
[ciris.ai/cewp](https://ciris.ai/cewp) (`src/app/cewp/lib/model.ts`):

| Op | Owner bench |
|---|---|
| `hybrid_sign` (Ed25519+ML-DSA-65), `hybrid_verify`, AES-256-GCM, HKDF | CIRISVerify `federation_crypto` |
| `canonicalize_python`, `ingest_pipeline`, `raw_sqlite_write`, `secrets_*`, `sign_*` | CIRISPersist `benches/` |
| `envelope_canonicalize`, `dispatch_inbound`, `inline_text_pipeline`, `content_fetch_roundtrip` | CIRISEdge `benches/` |

Those reference numbers are vendored in [`reference.json`](reference.json).

## What it DOES measure

The **cross-wheel, Python-boundary, cohabitation-inclusive** cost — what a
real caller pays when the independently-built wheels run together in one
Python process (the production shape: the Chaquopy/Android agent, the
cohabiting runtime). The per-crate criterion benches run in a single binary
and cannot see this. The gap between these numbers and the sister criterion
numbers is the **cohabitation + PyO3-FFI tax**.

Measured (see [`bench_substrate.py`](bench_substrate.py)):

- `ed25519_sign` / `hybrid_verify` — crypto cost through the persist Engine FFI
- `canonicalize` — `canonicalize_envelope` throughput (ns/byte) through FFI
- `put_blob_signing_composite` — the **headline** metric: canonicalize +
  sign + store + holder-attestation in one cross-wheel call. No per-crate
  bench measures this composite; it is far more than the sum of its parts.
- `cohab_init_edge_runtime` — the one-shot bootstrap cost

## Running

```bash
python3 benchmarks/bench_substrate.py                 # markdown summary to stdout
python3 benchmarks/bench_substrate.py --json out.json # + machine-readable report
python3 benchmarks/bench_substrate.py --quick         # fewer iters (the CI smoke gate)
```

The JSON report (`schema: ciris-conformance/bench/1`) carries the platform,
the exact wheel versions, the measured cross-wheel numbers, and the cited
sister references — the shape ciris.ai/cewp ingests for real, current
figures and drift detection.

`.github/workflows/bench.yml` runs it on every push to `main` (and manual
dispatch) and publishes the JSON + summary as artifacts. A fast bit-rot
gate (`tests/test_900_bench_smoke.py`, `--quick`) keeps the harness from
rotting on every PR.
