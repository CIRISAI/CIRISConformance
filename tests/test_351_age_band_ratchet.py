"""
Fabric tier — CC §3.4.13 Q3 one-way age ratchet + `age_band_json` resolution.

CC §3.4.13 (part_3_the_namespace.md, "Q3 — Assurance rung: being a minor vs.
stewarding a minor") makes the age ladder a **strict one-way ratchet** over the
§3.4.11 self / witness rungs:

- **BE a minor (enter protection):** `age_self_declared:band:minor` SUFFICES. A
  self-declaration MAY only LOWER access / RAISE protection (the down-ratchet).
- **EXIT child protection (claim adult):** self-declaration is INSUFFICIENT — the
  claim MUST clear ≥ `age_assurance:provider:adult` (§3.4.11 "`self` is
  unfalsifiable"). A `self`-level row MUST NOT graduate a user UP a band
  (§3.4.13 line 1595); graduating up requires a witness-reserved
  `age_assurance:*` row. **All ambiguity resolves to `minor`.**

The resolved band is the **I1 age band**, read off the substrate via the real
`age_band_json(key_id)` surface. The read-union (§3.4.11) takes the HIGHEST level
on record across both prefixes, with a witness `age_assurance:*` OUTRANKING a
subject `age_self_declared:*`.

**Probed against persist 11.5.0 (venv /tmp/nf12):**

- `age_band_json(key_id)` is a one-arg surface. A key with no age row resolves to
  `"unknown"` (the protective-default sentinel — see the fail-secure note below).
- After a subject emits `age_self_declared:band:minor`, `age_band_json` resolves
  `"minor"`.
- **The load-bearing new gate (the ratchet):** after that same minor subject then
  emits `age_self_declared:band:adult`, the emit is ACCEPTED as a row, but
  `age_band_json` STILL resolves `"minor"` — self-declaration cannot graduate UP.
- **Witness outranks self (read-union, drivable on a self-bound witness key):** a
  key registered `identity_type="witness"` that self-declares minor and then
  emits a witness-reserved `age_assurance:provider:adult:v1` about its OWN key
  graduates to `"adult"` — the witness rung outranks the self rung on the same
  key. (Cross-subject witness graduation — a witness emitting `age_assurance:*`
  ABOUT a DIFFERENT subject's key — is NOT drivable over `emit_attestation_self`,
  which self-binds to the emitter's key; see the xfail at the end.)

Note on the `"unknown"` sentinel: §3.4.13 line 1595 says absence MUST resolve to
the most-protective band. The substrate exposes the absence as the literal
`"unknown"` (a raw sentinel), leaving the protective-default mapping
(unknown → most-protective) to the consumer. We assert the raw `age_band_json`
value here; the protective-default policy mapping is a consumer behavior, not an
`age_band_json` surface, so it is not gated in this file.
"""

from __future__ import annotations

import pytest

from conftest import get_database_url, run_python_script

pytestmark = pytest.mark.fabric

_BODY = r"""
import json, sys, os, tempfile, secrets
try:
    import ciris_persist as cp
except ImportError as exc:
    print(json.dumps({"_error": "import", "detail": str(exc)})); sys.exit(2)

# Shared substrate so every reconstructed engine sees the same federation_keys /
# attestations. The harness injects INJECTED_URL to honor the chosen backend
# (full sqlite+postgres parity): postgres is shared across subprocesses; the
# sqlite default needs an ON-DISK file (`:memory:` gives each Engine a private DB,
# so age rows would not be readable by a reconstructed engine).
if INJECTED_URL.startswith("postgres"):
    DB_URL = INJECTED_URL
else:
    _dbf = os.path.join(tempfile.mkdtemp(), "f.db"); open(_dbf, "a").close()
    DB_URL = "sqlite:///" + _dbf


# Only one Engine is live at a time (`reset_engine` closes the prior); each
# identity carries stable alias + key paths and is reconstructed to sign. The kid
# is stable across reconstructions (same alias + seed → same derived key_id).
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


# Sanity: both surfaces must exist.
for surface in ("emit_attestation_self", "age_band_json"):
    probe = Ident("probe", "agent", "probe")
    if not hasattr(probe.engine(), surface):
        print(json.dumps({"_error": "absent", "surface": surface})); sys.exit(2)


def emit(engine, atype):
    try:
        engine.emit_attestation_self(json.dumps(
            {"attestation_type": atype, "attestation_envelope": {}}))
        return "accepted"
    except Exception as exc:
        return str(exc)[:120]


def band(ident):
    # age_band_json returns a JSON string literal, e.g. "minor" → strip to value.
    return json.loads(ident.engine().age_band_json(ident.kid))


report = {}

# ── (a) pre-declaration band is the absence sentinel ──
S = Ident("subj", "agent", "subject")
report["S"] = S.kid
report["band_pre"] = band(S)

# ── (b) after age_self_declared:band:minor → "minor" ──
report["emit_minor"] = emit(S.engine(), "age_self_declared:band:minor")
report["band_after_minor"] = band(S)

# ── (c) ratchet: a subsequent self adult emit STAYS minor ──
report["emit_adult_self"] = emit(S.engine(), "age_self_declared:band:adult")
report["band_after_adult_self"] = band(S)

# ── (d) witness outranks self — graduate via a self-bound witness age_assurance ──
# A witness-type key declares minor, then emits a witness-reserved
# age_assurance:provider:adult:v1 about its OWN key. The read-union must take the
# higher (witness) rung → "adult".
W = Ident("witn", "witness", "witness")
report["W"] = W.kid
report["w_emit_minor"] = emit(W.engine(), "age_self_declared:band:minor")
report["w_band_after_minor"] = band(W)
report["w_emit_assurance_adult"] = emit(W.engine(), "age_assurance:provider:adult:v1")
report["w_band_after_assurance"] = band(W)

report["stage"] = "done"
print(json.dumps(report)); sys.stdout.flush(); os._exit(0)
"""


@pytest.fixture(scope="module")
def ratchet():
    script = f"INJECTED_URL = {get_database_url()!r}\n" + _BODY
    payload = run_python_script(script).parsed_stdout()
    if payload.get("_error") == "absent":
        pytest.fail(f"persist surface missing: {payload.get('surface')}")
    if payload.get("_error") == "import":
        pytest.fail(f"ciris_persist import failed: {payload.get('detail')}")
    assert payload.get("stage") == "done", payload
    return payload


@pytest.mark.requires_persist
def test_age_band_pre_declaration_is_unknown(ratchet):
    """CC §3.4.13: a key with no age row resolves to the absence sentinel.

    `age_band_json` on a freshly registered key (no `age_self_declared` /
    `age_assurance` row) resolves `"unknown"` on persist 11.5.0 — the raw
    absence sentinel the consumer must map protectively (§3.4.13 line 1595).
    """
    assert ratchet["band_pre"] == "unknown", (
        f"pre-declaration band was not the absence sentinel: {ratchet['band_pre']}")


@pytest.mark.requires_persist
def test_self_declared_minor_resolves_minor(ratchet):
    """CC §3.4.13 Q3 down-ratchet: age_self_declared:band:minor SUFFICES to BE a minor."""
    assert ratchet["emit_minor"] == "accepted", (
        f"a subject's self-declared minor band was refused: {ratchet['emit_minor']}")
    assert ratchet["band_after_minor"] == "minor", (
        f"age_band_json did not resolve minor after a self-declared minor band: "
        f"{ratchet['band_after_minor']}")


@pytest.mark.requires_persist
def test_self_declared_adult_cannot_graduate_a_minor(ratchet):
    """CC §3.4.13 Q3 / §3.4.11: the one-way ratchet — self-declaration cannot graduate UP.

    A minor emitting `age_self_declared:band:adult` is ACCEPTED as a row, but the
    resolved band STAYS `"minor"` — a `self` row MUST NOT graduate a user up a band
    (§3.4.13 line 1595: "`self` is unfalsifiable"; exit-to-adult requires a
    witness-reserved `age_assurance:*` rung). This is the load-bearing new gate
    that shipped in the CC 0.6 substrate (persist 11.5.0).
    """
    assert ratchet["emit_adult_self"] == "accepted", (
        f"the self adult emit was refused — the ratchet test needs the row to be "
        f"admitted so the resolution (not the admission) does the gating: "
        f"{ratchet['emit_adult_self']}")
    assert ratchet["band_after_adult_self"] == "minor", (
        f"a minor self-declared its way UP to adult — the §3.4.13 one-way ratchet "
        f"is broken (self may only lower access, never graduate up): "
        f"{ratchet['band_after_adult_self']}")


@pytest.mark.requires_persist
def test_witness_assurance_outranks_self(ratchet):
    """CC §3.4.11 read-union: a witness age_assurance:* rung OUTRANKS the self rung.

    The exit-to-adult path: a witness-reserved `age_assurance:provider:adult:v1`
    row graduates a key that previously self-declared minor up to `"adult"`. Driven
    on a self-bound witness key (the witness emits the assurance about its OWN key),
    which is what `emit_attestation_self` binds. This proves the read-union takes
    the HIGHEST level on record and that the witness rung outranks the self rung on
    the same key — the substantive half of the ratchet (you CAN graduate, but only
    with a witness rung). Probed real on persist 11.5.0.
    """
    assert ratchet["w_emit_minor"] == "accepted", ratchet["w_emit_minor"]
    assert ratchet["w_band_after_minor"] == "minor", (
        f"witness key did not resolve minor after self-declaring minor: "
        f"{ratchet['w_band_after_minor']}")
    assert ratchet["w_emit_assurance_adult"] == "accepted", (
        f"a witness-type key was refused on age_assurance:provider:adult:v1 — the "
        f"witness emitter gate is broken: {ratchet['w_emit_assurance_adult']}")
    assert ratchet["w_band_after_assurance"] == "adult", (
        f"a witness age_assurance:provider:adult rung did NOT outrank the self "
        f"minor rung on the same key — the §3.4.11 read-union (witness outranks "
        f"self) is broken: {ratchet['w_band_after_assurance']}")


@pytest.mark.requires_persist
@pytest.mark.xfail(strict=True, reason=(
    "Cross-subject witness graduation is undrivable over persist 11.5.0: "
    "emit_attestation_self self-binds the age row to the EMITTER's own key, so a "
    "witness emitting age_assurance:* ABOUT a DIFFERENT subject's key does not "
    "graduate that subject's age_band_json (it stays at the subject's self rung). "
    "The read-union witness-outranks-self is only drivable when the witness is the "
    "subject (self-bound, asserted green above). File upstream CIRISPersist: a "
    "witness-targets-subject age_assurance admission surface (carry the subject "
    "key_id in the attestation envelope) so a third-party verifier can graduate a "
    "subject's I1 band."))
def test_cross_subject_witness_graduation(ratchet):
    """CC §3.4.11: a witness graduating ANOTHER subject's band — not exposed over FFI.

    The drivable self-bound case is asserted green above. This xfail captures the
    cross-subject case (provider/government verifier attests a third party), which
    `emit_attestation_self` cannot express — it self-binds to the emitter's key.
    Flips to a real gate when persist exposes a witness-targets-subject age
    surface. Encoded as a missing signal the substrate does not provide today.
    """
    assert ratchet.get("cross_subject_graduation") is True, (
        "no witness-targets-subject age_assurance surface on persist 11.5.0; "
        f"emit_attestation_self self-binds to the emitter key: {ratchet.get('W')}")
