"""
Substrate tier — CC 2.6.1.3 canonical-bytes size bound (`CLM-envelope-size`):
the freeze-gate vector pair — an at-cap envelope ADMITS, a cap-plus-one envelope
is REFUSED with the stable token.

CC 2.6.1.3 (part_2_the_grammar.md, "Canonical-bytes size bound (normative)",
ratified in CC 1.0-rc3 resolving CIRISConstitution#38) pins: a CEG envelope's
canonical (JCS) bytes MUST NOT exceed **1 MiB (1 048 576 bytes)** — "the signed
thing is the sized thing, so the bound is on the bytes the signature covers,
never on a stored or transport-framed image of them". A CCP MUST NOT emit above
the cap; a CCS MUST reject one at admission — "at **every** write path, including
capsule/FFI and tier-ingest, not only an HTTP body gate" — with
`ENVELOPE_TOO_LARGE` (HTTP 413, CC 5.3.6.1). Above the cap the envelope carries
the manifest, not the bytes (the degradable fountain plane, CC 6.1.5). The text
mandates this exact pair (CIRISConformance#85).

What is REAL on the floor (persist v40.0.0), driven end-to-end here:

- **The gate is `check_envelope_size_admission`** (`MAX_ATTESTATION_ENVELOPE_BYTES`
  = 1024·1024), run FIRST at every attestation write chokepoint — all three
  backends' `put_attestation` and the local-tier write funnels — measuring the
  REAL JCS bytes via `ceg_produce_canonicalize`. Refusal kind:
  `federation_envelope_too_large`.
- **What is measured is what is stored.** persist stamps bytes of its own into
  the envelope before it lands (the typed-column mirror + bound instants —
  CIRISPersist#653: at the local door the gate runs twice, early on the
  producer's envelope and authoritatively after the stamp). So the boundary is
  the STORED canonical size, and this test derives the stamp's growth from a
  probe emit rather than hardcoding it — the growth depends on the key-id
  lengths inside the mirror, so a hardcoded delta would drift with the fixture.
- **Two doors, one boundary.** The federation-tier self emit
  (`emit_attestation_self`) and the local-tier funnel
  (`attestation_insert_local`) each admit at exactly 1 048 576 stored canonical
  bytes and refuse at 1 048 577 — the "every write path" clause, driven at the
  two paths the Python surface reaches.

Real surface: `Engine.emit_attestation_self(input_json)`,
`Engine.attestation_insert_local(input_json)`, `Engine.list_attestations_for(...)`
(read-back), `Engine.canonicalize_envelope(envelope_json)` (the produce-gate JCS
— the measuring stick is the substrate's own canonicalizer, not a re-spelling).
"""

from __future__ import annotations

import pytest

from conftest import get_database_url, run_python_script

pytestmark = [pytest.mark.substrate, pytest.mark.ceg, pytest.mark.ccs]

CAP = 1_048_576  # CC 2.6.1.3 — 1 MiB of canonical (JCS) bytes

_BODY = r"""
import json, sys, os, tempfile, secrets

def report(obj):
    print(json.dumps(obj)); sys.stdout.flush(); os._exit(0)

try:
    import ciris_persist as cp
except ImportError as exc:
    report({"_error": "import", "detail": str(exc)})

if INJECTED_URL.startswith("postgres"):
    DB_URL = INJECTED_URL
else:
    _dbf = os.path.join(tempfile.mkdtemp(), "f.db"); open(_dbf, "a").close()
    DB_URL = "sqlite:///" + _dbf

_d = tempfile.mkdtemp()
_s = os.path.join(_d, "s"); open(_s, "wb").write(secrets.token_bytes(32))
_p = os.path.join(_d, "p"); open(_p, "wb").write(secrets.token_bytes(32))
_k = "cap-" + secrets.token_hex(8)
cp.reset_engine()
engine = cp.Engine(DB_URL, _k, local_key_id=_k, local_key_path=_s,
                   local_pqc_key_id=_k + "-pqc", local_pqc_key_path=_p)
for surface in ("emit_attestation_self", "attestation_insert_local",
                "list_attestations_for", "canonicalize_envelope"):
    if not hasattr(engine, surface):
        report({"_error": "absent", "surface": surface})
kid = engine.register_self_federation_key("agent", "cap-ref", None, None, None)

r = {"kid": kid, "cap": CAP}


def _envelope(pad_len, atype, local):
    env = {"attesting_key_id": kid, "attested_key_id": kid, "dimension": atype,
           "score": 1.0, "asserted_at": "2026-05-28T14:00:00.000Z",
           "witness_relation": "self", "pad": "x" * pad_len}
    inp = {"attestation_type": atype, "attested_key_id": kid, "attestation_envelope": env}
    if local:
        env["cohort_scope"] = "self"
        inp.update({"attesting_key_id": kid, "dimension": atype,
                    "witness_relation": "self", "cohort_scope": "self"})
    return inp


def _emit(pad_len, atype, local):
    inp = _envelope(pad_len, atype, local)
    if local:
        return engine.attestation_insert_local(json.dumps(inp))
    return engine.emit_attestation_self(json.dumps(inp))


def _stored_canonical_len(aid):
    page = json.loads(engine.list_attestations_for(kid, None, 500, kid))
    items = page.get("items", page.get("attestations", []))
    row = next(x for x in items if x.get("attestation_id") == aid)
    se = row["attestation_envelope"]
    se = json.loads(se) if isinstance(se, str) else se
    return len(engine.canonicalize_envelope(json.dumps(se)))


def _attempt(label, fn):
    try:
        r[label] = {"outcome": "admitted", "value": fn()}
    except Exception as exc:
        r[label] = {"outcome": "refused", "token": str(exc)[:200]}


for door, local in (("federation_self_emit", False), ("local_tier_insert", True)):
    atype = "observed:size:" + door
    # Derive the stamp: what persist adds to the producer's envelope before it
    # lands. Two probes so the growth is shown to be pad-independent.
    probe = {}
    for pad in (1000, 2000):
        aid = _emit(pad, atype, local)
        probe[pad] = _stored_canonical_len(aid) - pad
    r[door + "_stamp_delta"] = probe
    delta = probe[2000]
    at_cap = CAP - delta
    _attempt(door + "_at_cap", lambda: _emit(at_cap, atype, local))
    if r[door + "_at_cap"]["outcome"] == "admitted":
        r[door + "_at_cap_stored_len"] = _stored_canonical_len(r[door + "_at_cap"]["value"])
    _attempt(door + "_cap_plus_one", lambda: _emit(at_cap + 1, atype, local))

r["stage"] = "done"
report(r)
"""


@pytest.fixture(scope="module")
def cap():
    script = f"INJECTED_URL = {get_database_url()!r}\nCAP = {CAP}\n" + _BODY
    payload = run_python_script(script).parsed_stdout()
    if payload.get("_error") == "absent":
        pytest.fail(f"persist surface missing: {payload.get('surface')}")
    if payload.get("_error"):
        pytest.fail(f"probe failed: {payload}")
    assert payload.get("stage") == "done", payload
    return payload


@pytest.mark.requires_persist
@pytest.mark.parametrize("door", ["federation_self_emit", "local_tier_insert"])
def test_stamp_growth_is_pad_independent(cap, door):
    """The bytes persist stamps into a landing envelope are a constant for a given
    signer — so the boundary below is derived, not guessed, and derived once."""
    probe = cap[door + "_stamp_delta"]
    assert probe["1000"] == probe["2000"], (
        f"the stored-envelope growth is not pad-independent on the {door} door: {probe}")


@pytest.mark.requires_persist
@pytest.mark.parametrize("door", ["federation_self_emit", "local_tier_insert"])
def test_at_cap_envelope_admits(cap, door):
    """CC 2.6.1.3 freeze-gate vector 1: an envelope whose STORED canonical bytes are
    exactly 1 048 576 is admitted — the cap is inclusive, and it is measured on the
    bytes the signature covers."""
    assert cap[door + "_at_cap"]["outcome"] == "admitted", (
        f"an at-cap envelope was refused on the {door} door: {cap[door + '_at_cap']}")
    assert cap[door + "_at_cap_stored_len"] == cap["cap"], (
        f"the admitted envelope did not land at exactly the cap on the {door} door: "
        f"stored={cap[door + '_at_cap_stored_len']} cap={cap['cap']}")


@pytest.mark.requires_persist
@pytest.mark.parametrize("door", ["federation_self_emit", "local_tier_insert"])
def test_cap_plus_one_envelope_is_refused_with_the_stable_token(cap, door):
    """CC 2.6.1.3 freeze-gate vector 2: one byte over the cap is refused at
    admission with the stable token — `ENVELOPE_TOO_LARGE` on the wire (413,
    CC 5.3.6.1), `federation_envelope_too_large` as persist's error kind — at
    every write path, here both the federation self-emit and the local-tier
    funnel."""
    got = cap[door + "_cap_plus_one"]
    assert got["outcome"] == "refused", (
        f"a cap-plus-one envelope was ADMITTED on the {door} door — the CC 2.6.1.3 "
        f"bound is not enforced at this write path: {got}")
    assert "envelope_too_large" in got["token"], (
        f"refused, but not with the size-bound token on the {door} door: {got}")
