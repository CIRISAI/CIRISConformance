"""
Substrate tier — CC 2.1.1 forward-compatibility (`CLM-forward-compatibility`).

CC 2.1.1 (part_2_the_grammar.md §2.1.1, "`forward-compatibility` —
Forward-compatibility rule") pins two rules that let the envelope grow without
breaking peers already speaking it:

- The **canonical-bytes contract** (per CC 2.6.1 / RFC 8785): a new field never
  silently changes what an old signature covers; the canonical bytes preserve
  member presence/absence exactly as the producer signed.
- The **unknown-field discipline**: a Conforming Consumer that receives an envelope
  carrying a field-name it does not recognize MUST (a) *not reject* the envelope on
  the basis of the unknown field alone, (b) *preserve* the unknown field on read
  (do not strip), and (c) *preserve* it on re-emission when the Consumer is also
  acting as a relaying Producer.

What is REAL on the floor (persist 16.1.1), driven end-to-end here — the substrate
round-trips an unknown future field through the full write → promote → read path:

- **NOT rejected on write.** An `attestation_envelope` carrying an unknown member
  (`zz_future_ceg_field`, a nested object) is admitted by
  `Engine.attestation_insert_local(input_json)` — the substrate does not reject on
  the unrecognized field.
- **Preserved on read, byte-identical.** After the write, the stored
  `attestation_envelope` read back via `list_attestations_for(...)` still carries
  `zz_future_ceg_field` with its exact nested value — the field is neither stripped
  nor mangled.
- **Preserved on re-emission (promotion).** `attestation_promote(id)` re-emits the
  row federation-tier — the "Consumer acting as a relaying Producer" case — and the
  unknown field survives that re-emission.
- **Inside the SIGNED canonical bytes.** `canonicalize_envelope(...)` over the
  stored envelope shows the unknown field is part of the canonical bytes the hybrid
  signature covers at promote — the CC 2.1.1 canonical-bytes contract: the
  unrecognized field rides the signature, not silently outside it.

Real surface: `Engine.attestation_insert_local(input_json)`,
`Engine.attestation_promote(attestation_id)`,
`Engine.list_attestations_for(target_key_id, cursor, limit, caller_occurrence)`,
`Engine.canonicalize_envelope(envelope_json)` (the production
`PythonJsonDumpsCanonicalizer` — sorted keys, no whitespace, ensure_ascii). The
engine carries a PQC identity so promotion's hybrid sign succeeds.
"""

from __future__ import annotations

import pytest

from conftest import get_database_url, run_python_script

pytestmark = [pytest.mark.ceg, pytest.mark.ccc]

# A single shared substrate (on-disk sqlite file, or the injected postgres URL) so
# the reconstructed engine sees the row it wrote. Only one Engine is live at a time;
# the identity is reconstructed on the shared substrate (stable kid) for each step.
_BODY = r"""
import json, sys, os, tempfile, secrets

def report(obj):
    print(json.dumps(obj)); sys.stdout.flush(); os._exit(0)

try:
    import ciris_persist as cp
except ImportError as exc:
    print(json.dumps({"_error": "import", "detail": str(exc)})); sys.exit(2)

if INJECTED_URL.startswith("postgres"):
    DB_URL = INJECTED_URL
else:
    _dbf = os.path.join(tempfile.mkdtemp(), "f.db"); open(_dbf, "a").close()
    DB_URL = "sqlite:///" + _dbf


class Ident:
    def __init__(self, prefix, itype, ref):
        d = tempfile.mkdtemp()
        self.s = os.path.join(d, "s"); open(self.s, "wb").write(secrets.token_bytes(32))
        self.p = os.path.join(d, "p"); open(self.p, "wb").write(secrets.token_bytes(32))
        self.k = prefix + "-" + secrets.token_hex(8)
        self.kid = self.engine().register_self_federation_key(itype, ref, None, None, None)

    def engine(self):
        cp.reset_engine()
        return cp.Engine(DB_URL, self.k, local_key_id=self.k, local_key_path=self.s,
                         local_pqc_key_id=self.k + "-pqc", local_pqc_key_path=self.p)


for surface in ("attestation_insert_local", "attestation_promote",
                "list_attestations_for", "canonicalize_envelope"):
    if not hasattr(Ident("probe", "agent", "probe").engine(), surface):
        print(json.dumps({"_error": "absent", "surface": surface})); sys.exit(2)

A = Ident("fc", "agent", "forward-compat")
r = {"A": A.kid}


def _attempt(label, fn):
    try:
        r[label] = {"outcome": "ok", "value": fn()}
    except Exception as exc:
        r[label] = {"outcome": "err", "token": str(exc)[:200]}


# The unknown future field — a nested object, so a naive "stringify scalars only"
# preservation would be observably wrong. The rest of the envelope is a well-formed
# CC 2.1 attestation.
UNKNOWN = {"nested": [1, 2, {"deep": "x"}], "flag": True}
_env = {
    "attesting_key_id": A.kid, "attested_key_id": A.kid,
    "dimension": "observed:x", "score": 1.0,
    "asserted_at": "2026-05-28T14:00:00.000Z", "witness_relation": "self",
    "zz_future_ceg_field": UNKNOWN,
}
_inp = {
    "attesting_key_id": A.kid, "attestation_type": "observed:x",
    "attested_key_id": A.kid, "dimension": "observed:x", "witness_relation": "self",
    "attestation_envelope": _env,
}

# (a) NOT rejected on write.
_attempt("insert_local", lambda: A.engine().attestation_insert_local(json.dumps(_inp)))
_aid = r["insert_local"].get("value")

# (c) preserved on re-emission (promotion = Consumer relaying as Producer).
_attempt("promote", lambda: A.engine().attestation_promote(_aid))


def _read_stored_envelope():
    page = json.loads(A.engine().list_attestations_for(A.kid, None, 50, A.kid))
    items = page.get("items", page.get("attestations", []))
    row = next(x for x in items if x.get("attestation_id") == _aid)
    se = row.get("attestation_envelope")
    return json.loads(se) if isinstance(se, str) else se


_attempt("stored_envelope", _read_stored_envelope)
_se = r["stored_envelope"].get("value") if r["stored_envelope"]["outcome"] == "ok" else None

# (b) preserved on read, byte-identical value.
r["preserved_on_read"] = bool(_se and _se.get("zz_future_ceg_field") == UNKNOWN)

# canonical-bytes contract: the unknown field is inside the bytes the sig covers.
if _se is not None:
    _attempt("canonical_bytes", lambda: A.engine().canonicalize_envelope(json.dumps(_se)).decode())
    r["in_signed_bytes"] = (r["canonical_bytes"]["outcome"] == "ok"
                            and "zz_future_ceg_field" in r["canonical_bytes"]["value"])
else:
    r["in_signed_bytes"] = False

r["stage"] = "done"
report(r)
"""


@pytest.fixture(scope="module")
def fc():
    script = f"INJECTED_URL = {get_database_url()!r}\n" + _BODY
    payload = run_python_script(script).parsed_stdout()
    if payload.get("_error") == "absent":
        pytest.fail(f"persist forward-compat surface missing: {payload.get('surface')}")
    if payload.get("_error"):
        pytest.fail(f"probe failed: {payload}")
    assert payload.get("stage") == "done", payload
    return payload


@pytest.mark.requires_persist
def test_unknown_field_is_not_rejected_on_write(fc):
    """CC 2.1.1: a Consumer MUST NOT reject an envelope merely for carrying a field
    it has not learned yet.

    `attestation_insert_local` admits an envelope carrying an unrecognized
    `zz_future_ceg_field` and returns its attestation id.
    """
    assert fc["insert_local"]["outcome"] == "ok", (
        f"the substrate rejected an envelope carrying an unknown field — CC 2.1.1 "
        f"forbids rejecting on the unknown field alone: {fc['insert_local']}")
    assert isinstance(fc["insert_local"]["value"], str) and fc["insert_local"]["value"], (
        f"insert_local did not return an attestation id: {fc['insert_local']}")


@pytest.mark.requires_persist
def test_unknown_field_is_preserved_on_read(fc):
    """CC 2.1.1: a Consumer MUST preserve the unknown field on read (do not strip).

    The stored envelope read back still carries `zz_future_ceg_field` with its exact
    nested value — neither stripped nor mangled.
    """
    assert fc["stored_envelope"]["outcome"] == "ok", (
        f"could not read the stored envelope back: {fc['stored_envelope']}")
    assert fc["preserved_on_read"] is True, (
        f"the unknown field was stripped or altered on read — CC 2.1.1 requires "
        f"byte-preservation: stored={fc['stored_envelope']['value']}")


@pytest.mark.requires_persist
def test_unknown_field_survives_re_emission(fc):
    """CC 2.1.1: a Consumer acting as a relaying Producer MUST preserve the unknown
    field on re-emission.

    `attestation_promote` re-emits the row federation-tier; the unknown field
    survives (asserted jointly with preservation-on-read, since the read happens
    after promotion).
    """
    assert fc["promote"]["outcome"] == "ok" and fc["promote"]["value"] is True, (
        f"promotion (the relay-as-Producer re-emission) did not succeed: {fc['promote']}")


@pytest.mark.requires_persist
def test_unknown_field_rides_the_signed_canonical_bytes(fc):
    """CC 2.1.1 canonical-bytes contract: the unknown field is part of the canonical
    bytes the signature covers, not silently outside it.

    `canonicalize_envelope` over the stored envelope contains `zz_future_ceg_field`
    — so the hybrid signature computed at promote covers it (a new field cannot
    silently change what an old signature covered).
    """
    assert fc["in_signed_bytes"] is True, (
        f"the unknown field is NOT inside the canonical signing bytes — the "
        f"canonical-bytes contract would let a new field ride outside the "
        f"signature: canonical={fc.get('canonical_bytes')}")
