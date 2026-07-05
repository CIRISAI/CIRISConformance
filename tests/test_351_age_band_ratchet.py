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
  `age_assurance:*` row emitted ABOUT the subject by a witness. **All ambiguity
  resolves to `minor`.**

The resolved band is the **I1 age band**, read off the substrate via the real
`age_band_json(key_id)` surface (binary `minor` / `adult` / `unknown`), and the
finer four-band policy vocabulary via `age_band_fine_json(key_id)` (`under_13` /
`13_15` / `16_17` / `adult` / `unknown` — CIRISPersist#309, CC 3.4.13 Q1). The
read-union (§3.4.11) takes the HIGHEST level on record, with a witness
`age_assurance:*` OUTRANKING a subject `age_self_declared:*`.

**The persist 12.5 → 13.0.1 model change (CIRISPersist#368, CC 1.0-rc2):** the
witness rung is now **attest-about-subject**, not self-emission. A witness
graduates a subject by calling `emit_attestation` with `attested_key_id` naming
the SUBJECT's key (the cross-subject edge). A witness SELF-emitting
`age_assurance:*` is now rejected (`federation_age_assurance_self_emission_rejected`).

**Probed against persist 13.0.1 (venv /tmp/nf17):**

- `age_band_json(key_id)` on a key with no age row resolves `"unknown"`; the
  fine resolution is likewise `"unknown"` (the protective-default sentinel).
- After a subject emits `age_self_declared:band:minor`, `age_band_json` resolves
  `"minor"` and `age_band_fine_json` resolves `"under_13"` (the most-protective
  floor within the binary `minor` band — a self minor names no finer band).
- **The one-way ratchet:** after that same minor subject emits
  `age_self_declared:band:adult`, the row is ACCEPTED but `age_band_json` STILL
  resolves `"minor"` — self-declaration cannot graduate UP.
- **Cross-subject witness graduation (the #368 surface, now REAL):** a witness
  emits `age_assurance:provider:adult:v1` ABOUT a subject who previously
  self-declared minor → the SUBJECT's `age_band_json` graduates to `"adult"`, the
  witness rung outranking the self rung. A subsequent self `minor` from the
  subject does NOT pull it back down — the witness assurance holds.
- **Fine-band graduation:** a witness attesting `age_assurance:provider:16_17:v1`
  ABOUT a subject resolves `age_band_fine_json` → `"16_17"` while the binary
  `age_band_json` stays `"minor"` (the sub-18 fine bands are all `minor` on the
  binary wire predicate).

Note on the `"unknown"` sentinel: §3.4.13 line 1595 says absence MUST resolve to
the most-protective band. The substrate exposes the absence as the literal
`"unknown"`, leaving the protective-default mapping to the consumer. We assert the
raw values here; the protective-default policy mapping is a consumer behavior.
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
# attestations (a witness must be able to attest ABOUT a subject in the same
# table). postgres is shared across subprocesses; the sqlite default needs an
# ON-DISK file (`:memory:` gives each Engine a private DB, so age rows would not
# be readable by a reconstructed engine).
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


# Sanity: all three surfaces must exist.
for surface in ("emit_attestation_self", "emit_attestation", "age_band_json",
                "age_band_fine_json"):
    probe = Ident("probe", "agent", "probe")
    if not hasattr(probe.engine(), surface):
        print(json.dumps({"_error": "absent", "surface": surface})); sys.exit(2)


def emit_self(ident, atype):
    # Self-bound emit over the emitter's OWN key.
    try:
        ident.engine().emit_attestation_self(json.dumps(
            {"attestation_type": atype, "attestation_envelope": {}}))
        return "accepted"
    except Exception as exc:
        return str(exc)[:120]


def emit_about(witness, atype, subject_kid):
    # Cross-subject emit: `witness` attests `atype` ABOUT subject_kid (the #368
    # witness-targets-subject surface).
    try:
        witness.engine().emit_attestation(json.dumps(
            {"attestation_type": atype, "attestation_envelope": {},
             "attested_key_id": subject_kid}))
        return "accepted"
    except Exception as exc:
        return str(exc)[:120]


def band(ident):
    # age_band_json returns a JSON string literal, e.g. "minor" → strip to value.
    return json.loads(ident.engine().age_band_json(ident.kid))


def fine(ident):
    return json.loads(ident.engine().age_band_fine_json(ident.kid))


report = {}

# A single witness (provider/government verifier) attests about the subjects.
WIT = Ident("witn", "witness", "witness")
report["WIT"] = WIT.kid

# ── (a) pre-declaration band is the absence sentinel ──
S = Ident("subj", "agent", "subject")
report["S"] = S.kid
report["band_pre"] = band(S)
report["fine_pre"] = fine(S)

# ── (b) after age_self_declared:band:minor → "minor" / fine "under_13" ──
report["emit_minor"] = emit_self(S, "age_self_declared:band:minor")
report["band_after_minor"] = band(S)
report["fine_after_minor"] = fine(S)

# ── (c) ratchet: a subsequent self adult emit STAYS minor ──
report["emit_adult_self"] = emit_self(S, "age_self_declared:band:adult")
report["band_after_adult_self"] = band(S)

# ── (d) witness outranks self via the CROSS-SUBJECT #368 surface ──
# A fresh subject self-declares minor, then a witness attests
# age_assurance:provider:adult:v1 ABOUT that subject's key → the read-union takes
# the higher (witness) rung → "adult". A subsequent self minor from the subject
# must NOT pull it back down.
G = Ident("grad", "agent", "graduand")
report["G"] = G.kid
report["g_emit_minor"] = emit_self(G, "age_self_declared:band:minor")
report["g_band_after_minor"] = band(G)
report["g_witness_adult"] = emit_about(WIT, "age_assurance:provider:adult:v1", G.kid)
report["g_band_after_assurance"] = band(G)
report["g_fine_after_assurance"] = fine(G)
report["g_self_minor_again"] = emit_self(G, "age_self_declared:band:minor")
report["g_band_after_self_minor_again"] = band(G)

# A witness cannot SELF-graduate (self-emission rejected) — the cross-subject
# surface is the ONLY path to age_assurance:*.
report["witness_self_assurance"] = emit_self(WIT, "age_assurance:provider:adult:v1")

# ── (e) fine-band graduation: witness attests an intermediate 4-band rung ──
# age_assurance:provider:16_17:v1 → fine "16_17", binary stays "minor".
F = Ident("fine", "agent", "fineband")
report["F"] = F.kid
report["f_witness_16_17"] = emit_about(WIT, "age_assurance:provider:16_17:v1", F.kid)
report["f_band"] = band(F)
report["f_fine"] = fine(F)

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

    `age_band_json` / `age_band_fine_json` on a freshly registered key (no
    `age_self_declared` / `age_assurance` row) resolve `"unknown"` on persist
    13.0.1 — the raw absence sentinel the consumer must map protectively
    (§3.4.13 line 1595).
    """
    assert ratchet["band_pre"] == "unknown", (
        f"pre-declaration band was not the absence sentinel: {ratchet['band_pre']}")
    assert ratchet["fine_pre"] == "unknown", (
        f"pre-declaration fine band was not the absence sentinel: {ratchet['fine_pre']}")


@pytest.mark.requires_persist
def test_self_declared_minor_resolves_minor(ratchet):
    """CC §3.4.13 Q3 down-ratchet: age_self_declared:band:minor SUFFICES to BE a minor.

    The binary band resolves `"minor"`; the fine band floors to `"under_13"` —
    a self minor names no finer sub-band, so the fine resolution takes the
    most-protective floor within `minor` (CC 3.4.13 Q1 fail-secure).
    """
    assert ratchet["emit_minor"] == "accepted", (
        f"a subject's self-declared minor band was refused: {ratchet['emit_minor']}")
    assert ratchet["band_after_minor"] == "minor", (
        f"age_band_json did not resolve minor after a self-declared minor band: "
        f"{ratchet['band_after_minor']}")
    assert ratchet["fine_after_minor"] == "under_13", (
        f"age_band_fine_json did not floor a self minor to under_13: "
        f"{ratchet['fine_after_minor']}")


@pytest.mark.requires_persist
def test_self_declared_adult_cannot_graduate_a_minor(ratchet):
    """CC §3.4.13 Q3 / §3.4.11: the one-way ratchet — self-declaration cannot graduate UP.

    A minor emitting `age_self_declared:band:adult` is ACCEPTED as a row, but the
    resolved band STAYS `"minor"` — a `self` row MUST NOT graduate a user up a band
    (§3.4.13 line 1595: "`self` is unfalsifiable"; exit-to-adult requires a
    witness-reserved `age_assurance:*` rung).
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
    """CC §3.4.11 read-union: a witness age_assurance:* rung OUTRANKS the self rung (cross-subject).

    The exit-to-adult path, on the persist-13 attest-about-subject model: a
    witness emits `age_assurance:provider:adult:v1` ABOUT a subject who previously
    self-declared minor (via `emit_attestation` + `attested_key_id`), and the
    SUBJECT's `age_band_json` graduates to `"adult"`. This proves the read-union
    takes the HIGHEST level on record and that the witness rung outranks the self
    rung. The one-way ratchet holds in reverse too: a subsequent self `minor` from
    the subject does NOT pull the band back down — a witness assurance is not
    overridable by a later self-declaration. A witness cannot SELF-graduate
    (self-emission rejected), so the cross-subject surface is the only path.
    """
    assert ratchet["g_emit_minor"] == "accepted", ratchet["g_emit_minor"]
    assert ratchet["g_band_after_minor"] == "minor", (
        f"subject did not resolve minor after self-declaring minor: "
        f"{ratchet['g_band_after_minor']}")
    assert ratchet["g_witness_adult"] == "accepted", (
        f"a witness was refused emitting age_assurance:provider:adult:v1 ABOUT a "
        f"subject — the #368 cross-subject surface is broken: "
        f"{ratchet['g_witness_adult']}")
    assert ratchet["g_band_after_assurance"] == "adult", (
        f"a witness age_assurance:provider:adult rung did NOT outrank the subject's "
        f"self minor rung — the §3.4.11 read-union (witness outranks self) is "
        f"broken: {ratchet['g_band_after_assurance']}")
    assert ratchet["g_fine_after_assurance"] == "adult", (
        f"the fine band did not graduate to adult under a witness adult assurance: "
        f"{ratchet['g_fine_after_assurance']}")
    # The witness assurance is not overridable by a later self-declaration.
    assert ratchet["g_self_minor_again"] == "accepted", ratchet["g_self_minor_again"]
    assert ratchet["g_band_after_self_minor_again"] == "adult", (
        f"a later self minor pulled a witness-graduated adult back DOWN — the "
        f"witness rung must outrank a subsequent self rung: "
        f"{ratchet['g_band_after_self_minor_again']}")
    # A witness cannot self-mint its own age assurance (attest-about-subject only).
    assert "federation_age_assurance_self_emission_rejected" in ratchet["witness_self_assurance"], (
        f"a witness SELF-emitted age_assurance:* — persist 13 is attest-about-subject "
        f"only: {ratchet['witness_self_assurance']}")


@pytest.mark.requires_persist
def test_cross_subject_witness_graduation(ratchet):
    """CC §3.4.11 / CIRISPersist#368: a witness graduates ANOTHER subject's band — now REAL green.

    On persist 12.5 this was undrivable over FFI (`emit_attestation_self`
    self-bound the age row to the emitter's own key). Persist 13.0.1 ships the
    witness-targets-subject surface: `emit_attestation` carries an
    `attested_key_id` naming the SUBJECT, so a provider/government verifier
    graduates a THIRD party's I1 band. This is the substantive cross-subject case
    — the emitter and the graduated subject are distinct keys.
    """
    assert ratchet["WIT"] != ratchet["G"], (
        "cross-subject test needs distinct emitter and subject keys")
    assert ratchet["g_witness_adult"] == "accepted", (
        f"the cross-subject witness attestation was refused: {ratchet['g_witness_adult']}")
    assert ratchet["g_band_after_assurance"] == "adult", (
        f"a witness did not graduate a DISTINCT subject's band to adult — the "
        f"#368 cross-subject graduation surface is broken: "
        f"{ratchet['g_band_after_assurance']}")


@pytest.mark.requires_persist
def test_fine_band_witness_graduation(ratchet):
    """CC §3.4.13 Q1 / CIRISPersist#309: the four-band fine resolution graduates independently of the binary predicate.

    A witness attesting `age_assurance:provider:16_17:v1` ABOUT a subject resolves
    `age_band_fine_json` → `"16_17"` (the finer policy vocabulary), while the
    binary `age_band_json` stays `"minor"` — the three sub-18 fine bands are all
    `minor` on the binary wire predicate. This gates the four-band surface as a
    real ratchet leg, not just the binary one.
    """
    assert ratchet["f_witness_16_17"] == "accepted", (
        f"a witness was refused attesting age_assurance:provider:16_17:v1 ABOUT a "
        f"subject: {ratchet['f_witness_16_17']}")
    assert ratchet["f_fine"] == "16_17", (
        f"age_band_fine_json did not resolve the witness-attested 16_17 fine band: "
        f"{ratchet['f_fine']}")
    assert ratchet["f_band"] == "minor", (
        f"the binary age_band_json did not stay minor for a 16_17 fine band — the "
        f"sub-18 fine bands are all minor on the binary predicate: {ratchet['f_band']}")
