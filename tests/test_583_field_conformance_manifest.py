"""
Substrate tier — CC 4.5.1.1 `axis` (`CLM-axis` / `CLM-ci-axis`): the manifest-driven
field-conformance harness runs clean on EVERY ratifying processor's live wheel, and
every wheel pins the byte-identical manifest cut (CIRISConformance#83).

CC 4.5.1.1 (part_4_composition_governance.md, "The axis-fusion gate (manifest
invariant, normative)"): `field_processor_matrix` records field → owner →
processor → enforcement point; an unclassified cross-axis field, or a field
"carried-but-unprocessed", is a generator error; and "the gate MUST run against
**every** ratifying processor's manifest render, not one repo's: a field whose
`typing` disagrees across repos, and a processor symbol appearing under two axes,
are mesh-wide defects that no single-repo check can see." #83 asked this suite to
host that cross-repo run against real wheels — the same table generating every
processor's property tests, so no repo can disagree about a field's meaning.

What is REAL on the floor (ciris-server 0.5.198 / persist v41.2.0 / edge v20.3.0),
driven end-to-end here:

- **`ciris_server.persist_field_conformance()`** (persist v21.7.0,
  CIRISPersist#519) — runs persist's `PERSIST_FIELD_CONFORMANCE` table against the
  live wheel (`cohort_scope` closed-set-processor totality, `fresh_as_of`
  merge = monotonic-max join semilattice, `transform` algebra strict totality,
  …) and returns the violations; the completeness gate inside it fails a
  persist-owned behavioural field with no check.
- **`ciris_server.edge_field_conformance()`** (CIRISEdge#411 §5) — the mirror
  over edge's routing processors, returning `"{field}: {reason}"` violations.
- **`namespace_manifest_version()` on BOTH wheels** (persist v21.7.0) — the
  vendored namespace-supersets manifest's `_meta.manifest_version`, so a
  cross-repo harness can assert every wheel pins the byte-identical cut. persist's
  own export and the server wheel's (which carries edge) must agree, or the two
  harnesses above are checking different tables.
- **`ciris_server.edge_evidence_rows()`** (CIRISEdge#410 §3) — the
  `cc_impl.tsv` lines generated from the live, tested `EDGE_FIELD_CONFORMANCE`
  table. Non-empty and well-formed (decimal, claim id, repo, `path#symbol`,
  `crate@version` naming the wheel under test) is what shows the edge table
  enumerated fields rather than returning an empty list from an empty table.

Real surface: `ciris_server.persist_field_conformance()`,
`ciris_server.edge_field_conformance()`, `ciris_server.namespace_manifest_version()`,
`ciris_persist.namespace_manifest_version()`, `ciris_server.edge_evidence_rows()`.
"""

from __future__ import annotations

import re

import pytest

from conftest import run_python_script

pytestmark = [pytest.mark.substrate, pytest.mark.ceg, pytest.mark.ccs, pytest.mark.cohabitation]

_BODY = r"""
import json, sys
try:
    import ciris_server as cs
    import ciris_persist as cp
except ImportError as exc:
    print(json.dumps({"_error": "import", "detail": str(exc)})); sys.exit(2)
for mod, name in ((cs, "persist_field_conformance"), (cs, "edge_field_conformance"),
                  (cs, "namespace_manifest_version"), (cp, "namespace_manifest_version"),
                  (cs, "edge_evidence_rows")):
    if not hasattr(mod, name):
        print(json.dumps({"_error": "absent", "surface": f"{mod.__name__}.{name}"})); sys.exit(2)
r = {
    "persist_violations": list(cs.persist_field_conformance()),
    "edge_violations": list(cs.edge_field_conformance()),
    "server_manifest_version": cs.namespace_manifest_version(),
    "persist_manifest_version": cp.namespace_manifest_version(),
    "edge_evidence_rows": list(cs.edge_evidence_rows()),
    "stage": "done",
}
print(json.dumps(r)); sys.stdout.flush(); sys.exit(0)
"""


@pytest.fixture(scope="module")
def manifest():
    payload = run_python_script(_BODY).parsed_stdout()
    if payload.get("_error") == "absent":
        pytest.fail(f"field-conformance surface missing on the wheel: {payload.get('surface')}")
    if payload.get("_error"):
        pytest.fail(f"probe failed: {payload}")
    assert payload.get("stage") == "done", payload
    return payload


@pytest.mark.requires_persist
def test_every_wheel_pins_the_same_manifest_cut(manifest):
    """CC 4.5.1.1: the gate runs against every ratifying processor's manifest render —
    which is only meaningful if they render the same manifest. persist's own export
    and the server wheel's (carrying edge) agree on `_meta.manifest_version`."""
    assert manifest["server_manifest_version"] == manifest["persist_manifest_version"], (
        f"the wheels pin different manifest cuts: server={manifest['server_manifest_version']!r} "
        f"persist={manifest['persist_manifest_version']!r} — the two field-conformance "
        f"harnesses are checking different tables")
    assert re.fullmatch(r"\d+\.\d+\.\d+", manifest["server_manifest_version"]), manifest


@pytest.mark.requires_persist
def test_persist_field_conformance_runs_clean_on_the_live_wheel(manifest):
    """CIRISConformance#83 / CC 4.5.1.1: persist's manifest-driven harness — every
    field persist is tagged to own, verified for the property the table declares,
    with the completeness gate for carried-but-unprocessed — reports no violation
    on the wheel under test."""
    assert manifest["persist_violations"] == [], (
        f"persist field-conformance violations on the live wheel: {manifest['persist_violations']}")


@pytest.mark.requires_persist
def test_edge_field_conformance_runs_clean_on_the_live_wheel(manifest):
    """CIRISConformance#83 / CIRISEdge#411 §5: edge's routing-processor harness over
    the same manifest reports no violation on the wheel under test."""
    assert manifest["edge_violations"] == [], (
        f"edge field-conformance violations on the live wheel: {manifest['edge_violations']}")


@pytest.mark.requires_persist
def test_edge_evidence_rows_name_the_wheel_under_test(manifest):
    """CIRISEdge#410 §3: the evidence rows are generated from the live, tested
    EDGE_FIELD_CONFORMANCE table — so a non-empty, well-formed set naming this
    wheel's crate@version is the witness that the table enumerated fields, rather
    than an empty harness returning an empty list."""
    rows = manifest["edge_evidence_rows"]
    assert rows and rows[0].split("\t") == ["decimal_id", "claim_id", "repo", "path#symbol", "crate@version"], rows[:1]
    body = [r.split("\t") for r in rows[1:]]
    assert body, "the edge evidence table is empty — no field enumerated"
    for cols in body:
        assert len(cols) == 5, cols
        decimal, claim, repo, sym, crate = cols
        assert re.fullmatch(r"\d+(\.\d+)*", decimal), cols
        assert claim.startswith("CLM-"), cols
        assert repo == "CIRISEdge", cols
        assert "#" in sym and sym.startswith("src/"), cols
        assert re.fullmatch(r"ciris-edge@v\d+\.\d+\.\d+", crate), cols
