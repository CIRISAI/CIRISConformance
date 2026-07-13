"""
Substrate tier — CC 2.6.1.2 per-field encoding catalog (`CLM-per-field`).

CC 2.6.1.2 (part_2_the_grammar.md §2.6.1.2, "`per-field` — Per-field encoding table")
catalogs every optional CC 2.1 envelope field and pins that each obeys the CC 2.6.1.1
omit-vs-materialize rule uniformly: **canonical when omitted → the member is absent**;
**canonical when explicit → the member is present** with its value — even when the
explicit value equals the field's documented default (an explicit `"epistemic_mode":
"direct"` is NOT the same canonical bytes as omitting it; defaults are
interpretation-time, never encoding-time). This is the rule §5.3.2.4.2 leans on when
it forbids re-defaulting at promote.

This test drives the FULL 16-row catalog (14 fields exercised — `family_id` /
`community_id` are conditional-required, gated by admission, and are covered by the
cohort family/community tests, not the omit-vs-materialize catalog) through TWO real
wheels at once — this is a genuine cohabitation property, not a single-wheel
tautology:

- **persist's production canonicalizer** — `Engine.canonicalize_envelope(...)`
  (`PythonJsonDumpsCanonicalizer`: sorted keys, no whitespace, ensure_ascii), the
  bytes the substrate signs; and
- **verify's JCS** — `ciris_verify.jcs_canonicalize(...)` (RFC 8785), the bytes a
  CIRISVerify consumer recomputes.

For every catalog field, all of the following hold, and persist's canonical bytes
equal verify's JCS bytes exactly:

- omitted → the `"field"` member is absent from the canonical bytes;
- explicit → the `"field"` member is present in the canonical bytes;
- explicit-at-default → the canonical bytes DIFFER from the omit-all bytes (no
  encoding-time defaulting);
- persist canonicalizer == verify JCS (cross-wheel byte agreement).

Real surface: `ciris_persist.Engine.canonicalize_envelope(envelope_json) -> bytes`,
`ciris_verify.jcs_canonicalize(bytes) -> bytes`. Both wheels are imported in the same
subprocess (the cohabitation the harness exists to test).
"""

from __future__ import annotations

import pytest

from conftest import get_database_url, run_python_script

pytestmark = [pytest.mark.ceg, pytest.mark.ccp, pytest.mark.cohabitation]

# The CC 2.6.1.2 catalog: (field, explicit value). SEVERAL values deliberately equal
# the field's documented default (epistemic_mode=direct, witness_relation=external,
# occurrence_count/… defaults, delivery_mode=pull-vs-push, history_on_join=from_join)
# — the point of the "no re-default" assertion is that writing the default is still
# distinct from omitting.
_CATALOG = [
    ("epistemic_mode", "direct"),
    ("witness_relation", "external"),
    ("oversight_mode", "HITL"),
    ("occurrence_id", "occurrence-1"),
    ("occurrence_count", 3),
    ("occurrence_role", "shared"),
    ("stake", "capital"),
    ("context", "free-form"),
    ("evidence_refs", ["ref-a", "ref-b"]),
    ("valid_until", "2026-12-31T00:00:00.000Z"),
    ("subject_key_ids", ["subject-key-0"]),
    ("delivery_mode", "push"),
    ("listed", "public"),
    ("history_on_join", "full"),
]

_BODY = r"""
import json, sys, os, tempfile, secrets

def report(obj):
    print(json.dumps(obj)); sys.stdout.flush(); os._exit(0)

try:
    import ciris_persist as cp
    import ciris_verify as cv
except ImportError as exc:
    print(json.dumps({"_error": "import", "detail": str(exc)})); sys.exit(2)

if INJECTED_URL.startswith("postgres"):
    DB_URL = INJECTED_URL
else:
    _dbf = os.path.join(tempfile.mkdtemp(), "f.db"); open(_dbf, "a").close()
    DB_URL = "sqlite:///" + _dbf

_d = tempfile.mkdtemp()
_s = os.path.join(_d, "s"); open(_s, "wb").write(secrets.token_bytes(32))
_p = os.path.join(_d, "p"); open(_p, "wb").write(secrets.token_bytes(32))
_k = "pf-" + secrets.token_hex(8)
cp.reset_engine()
E = cp.Engine(DB_URL, _k, local_key_id=_k, local_key_path=_s,
              local_pqc_key_id=_k + "-pqc", local_pqc_key_path=_p)

if not hasattr(E, "canonicalize_envelope") or not hasattr(cv, "jcs_canonicalize"):
    print(json.dumps({"_error": "absent",
                      "surface": "canonicalize_envelope/jcs_canonicalize"})); sys.exit(2)

BASE = {
    "attesting_key_id": _k, "attested_key_id": _k,
    "dimension": "observed:x", "score": 1.0,
    "asserted_at": "2026-05-28T14:00:00.000Z",
}


def _jcs(obj):
    b = cv.jcs_canonicalize(json.dumps(obj).encode())
    return b if isinstance(b, bytes) else b.encode()


r = {"fields": {}}
omit = E.canonicalize_envelope(json.dumps(BASE))
r["omit_persist_eq_verify"] = (omit == _jcs(BASE))

for field, value in CATALOG:
    obj = dict(BASE); obj[field] = value
    persist_bytes = E.canonicalize_envelope(json.dumps(obj))
    verify_bytes = _jcs(obj)
    member = ('"%s"' % field).encode()
    r["fields"][field] = {
        "omitted_absent": member not in omit,        # omit  -> member absent
        "explicit_present": member in persist_bytes, # write -> member materialized
        "no_redefault": persist_bytes != omit,       # even at the documented default
        "persist_eq_verify": persist_bytes == verify_bytes,  # cross-wheel agreement
    }

r["stage"] = "done"
report(r)
"""


@pytest.fixture(scope="module")
def catalog():
    script = (f"INJECTED_URL = {get_database_url()!r}\n"
              f"CATALOG = {_CATALOG!r}\n" + _BODY)
    payload = run_python_script(script).parsed_stdout()
    if payload.get("_error") == "absent":
        pytest.fail(f"canonicalization surface missing: {payload.get('surface')}")
    if payload.get("_error"):
        pytest.fail(f"probe failed: {payload}")
    assert payload.get("stage") == "done", payload
    return payload


@pytest.mark.requires_persist
@pytest.mark.requires_verify
def test_omission_canonicalizes_identically_across_wheels(catalog):
    """CC 2.6.1.2 baseline: the omit-all envelope canonicalizes to identical bytes
    under persist's canonicalizer and verify's JCS — the cross-wheel floor the
    per-field assertions build on.
    """
    assert catalog["omit_persist_eq_verify"] is True, (
        "persist canonicalize_envelope diverged from ciris_verify.jcs_canonicalize "
        "on the base envelope — the two wheels do not agree on canonical bytes")


@pytest.mark.requires_persist
@pytest.mark.requires_verify
@pytest.mark.parametrize("field", [f for f, _ in _CATALOG])
def test_per_field_omit_vs_materialize(catalog, field):
    """CC 2.6.1.2: each optional field obeys omit-vs-materialize AND canonicalizes
    identically across persist and verify.

    omitted → member absent; explicit → member present; explicit-at-default → bytes
    differ from omit-all (no encoding-time defaulting); persist bytes == verify JCS.
    """
    res = catalog["fields"][field]
    assert res["omitted_absent"], (
        f"{field}: member present in canonical bytes when the field was omitted "
        f"(CC 2.6.1.2: canonical-when-omitted is member-absent): {res}")
    assert res["explicit_present"], (
        f"{field}: member absent from canonical bytes when the field was explicit: {res}")
    assert res["no_redefault"], (
        f"{field}: writing the field produced the SAME canonical bytes as omitting it "
        f"— the canonicalizer defaulted at encoding time, which CC 2.6.1.2 forbids "
        f"(defaults are interpretation-time only): {res}")
    assert res["persist_eq_verify"], (
        f"{field}: persist canonicalize_envelope != ciris_verify.jcs_canonicalize — "
        f"the substrate's signing bytes diverge from what a verify consumer "
        f"recomputes: {res}")
