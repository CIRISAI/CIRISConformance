# Evidence registry — the `test:` tier

This directory publishes the machine-readable map from **CIRIS Constitution**
normative claims to the conformance tests / freeze-gate vectors that establish
them. It is the CIRISConformance half of the CC **evidence-tag** convention
(CIRISConstitution#17): the Constitution stops carrying all the evidentiary
weight and instead tags each load-bearing claim by the artifact that establishes
it — `impl` / `test` / `lean` / `bench`. **CIRISConformance owns the `test:`
tier.** Tracked in CIRISConformance#59.

The Constitution's `check_claims.py` pins this repo by commit and resolves every
`test:` pointer against [`cc_tests.tsv`](cc_tests.tsv).

## Files

| file | who maintains it | what it is |
|---|---|---|
| [`cc_tests.tsv`](cc_tests.tsv) | **generated — do not hand-edit** | the registry the Constitution resolves against |
| [`claim_map.tsv`](claim_map.tsv) | hand-maintained (editorial) | the CC-claim ↔ test association (no status) |
| [`gen_cc_tests.py`](gen_cc_tests.py) | — | the generator (merges the two, writes `cc_tests.tsv`) |
| [`_status_plugin.py`](_status_plugin.py) | — | the pytest plugin that reads each node's live outcome |
| [`floor_pins.txt`](floor_pins.txt) | bump on a floor move | the exact ciris-* triple the registry is derived against |

### `cc_tests.tsv` columns

```
cc_decimal_id   cc_claim_id   conformance_test_id(s)   freeze_gate_vector(s)   status
```

* `cc_decimal_id` — the CC clause (e.g. `6.1.2.3`).
* `cc_claim_id` — the stable claim slug the Constitution registry references.
* `conformance_test_id(s)` — pytest node id(s), comma-separated: a whole file
  (`tests/test_540_noise_floor.py`) when the file establishes one claim, or
  `file::function` granularity when a file spans several claims.
* `freeze_gate_vector(s)` — named frozen vector/shape(s) (the #57 freeze-gate
  family: `WholenessWitness`, `AggregationMetaV1`, `StorageBudgetV1`,
  `CorpusWantV1`; the §5.4.1 `record_id` vectors; the `WIRE_VOCABULARY.md`
  manifest), or `-`.
* `status ∈ {green, xfail}` — **auto-derived, never hand-edited** (see below).

Consumers MUST skip `#`-prefixed comment lines; the first non-comment line is
the header.

## How `status` is derived (never hardcoded)

`gen_cc_tests.py` runs the mapped tests on the CC-floor venv and reads each
node's real pytest outcome via `_status_plugin.py`:

* **green** — the test body ran and passed: a clean pass, a non-strict xpass, or
  a strict-xfail whose body now **passes** (`[XPASS(strict)]` — the surface
  shipped / the gate went live; the stale marker is the floor-bump effort's to
  remove, but the evidence already holds).
* **xfail** — the test did not pass on this floor: an explicit `xfail` marker, a
  genuine assertion failure, or a fixture error (a gate the floor does not yet
  pass — e.g. a test pending the `(R,ε)` noise-floor rework). It auto-flips to
  green the moment the test passes.
* a pure **environment skip** (a missing wheel or native lib) is a **hard error**
  — the floor host must run every mapped gate for real.

Because status is derived, the parallel floor-bump effort's xfail→green flips
land here for free, and any regression that turns a green claim xfail changes the
committed TSV — which the CI guard catches.

## Regenerate

```sh
# from the repo root, inside the CC-floor venv (persist/verify/edge per floor_pins.txt)
python evidence/gen_cc_tests.py
```

The output is sorted and deterministic (no timestamps): running it twice is a
no-op. CI regenerates it and fails on `git diff` (see the `evidence-registry`
job in `.github/workflows/conformance.yml`), so the map can never silently drift
from the suite. The CI job installs `floor_pins.txt` exactly, so its
regeneration matches a floor-generated commit.

## Stable-ID contract (breaking-change policy)

A Constitution `test:` pointer resolves to a **pytest node id** or a **freeze-gate
vector name** in this repo. Those identifiers are a **public API**:

* Renaming a `test_5xx_*` file / a mapped test function, or a freeze-gate vector
  (`WholenessWitness` / `AggregationMetaV1` / `StorageBudgetV1` / `CorpusWantV1`
  / a `record_id` vector), **is a breaking change** to a Constitution pointer.
* The generator hard-fails if `claim_map.tsv` references a test id the suite no
  longer runs — a rename cannot silently orphan a pointer.
* If you must rename, update `claim_map.tsv` in the same change, regenerate, and
  flag it in the PR so the Constitution registry re-pins.

## Bumping the floor

When the floor moves (e.g. CC 1.0-rc1), update `floor_pins.txt` to the new
ciris-* triple and regenerate. Status flips are expected and reviewable in the
`cc_tests.tsv` diff.
