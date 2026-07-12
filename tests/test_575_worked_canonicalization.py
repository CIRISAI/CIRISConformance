"""
Fabric tier — CC 2.6.1.4 the worked canonicalization attack the rule closes
(`CLM-worked`).

CC 2.6.1.4 (part_2_the_grammar.md §2.6.1.4, "`worked` — Worked attack the rule
closes") gives the concrete failure the CC 2.6.1 omit-vs-materialize +
relay-preservation rule forecloses:

    > Alice's Producer signs an envelope OMITTING `epistemic_mode`. Bob's Relay
    > receives, materializes the default `"direct"`, re-serializes via JCS, and
    > forwards to Carol. Carol computes JCS, verifies signature → FAILS because
    > Alice signed over bytes without the `epistemic_mode` member. … The
    > attestation is lost in transit despite no party acting in bad faith.

The rule closes it: "Bob's relay MUST preserve member presence/absence exactly …
The semantic interpretation step (applying default `"direct"` to the absent
member) happens AFTER signature verification." (§2.6.1 canonical-bytes contract:
"defaults are interpretation-time, NOT encoding-time.")

The attack is fundamentally that **materializing an omitted default changes the
signed bytes**. Driven behaviorally here against the REAL canonicalizers — the
executable proof the rule closes the attack:

- **The canonicalizer preserves absence.** `ciris_verify.jcs_canonicalize(<omit
  form>)` does NOT emit `epistemic_mode` — it does not "helpfully" materialize the
  default at encoding-time. The materialize-form (default written in) DOES carry
  it.
- **Omit-form and materialize-form are byte-distinct.** The two canonicalizations
  differ, so a relay that materializes the default produces different signed bytes
  than the producer committed — exactly what makes a materializing relay's output
  fail Carol's verify, and exactly what the preserve-presence/absence rule
  forbids. (The two envelopes are semantically identical after interpretation-time
  defaulting — same meaning, different bytes.)
- **Both wheels agree byte-for-byte.** `Engine.canonicalize_envelope` (persist,
  the producer/relay path) and `ciris_verify.jcs_canonicalize` (verify, the
  consumer path) produce the IDENTICAL canonical bytes for the omit-form — so a
  producer and a verifier that both preserve absence agree, and the only divergence
  is the illegitimate materialization.

This is a pure-function canonicalization property (no signing, no attestation
admission) — the same discipline test_561 drives at the CC 6.1.3 boundary, here at
the CC 2.6.1 JCS boundary. `AggregationMetaV1` is not involved; this is the CC 2.1
1+4 envelope surface.

Real surface: `ciris_verify.jcs_canonicalize(value) -> bytes`,
`Engine.canonicalize_envelope(envelope_json) -> bytes` (cross-wheel agreement).
"""

from __future__ import annotations

import pytest

from conftest import get_database_url, run_python_script

pytestmark = pytest.mark.fabric

# The §2.6.1.4 worked-attack member: an optional field with a documented default
# that a relay might "helpfully" materialize. Omit-form signs without it; the
# materialize-form writes the default in. Any two producers must agree byte-for-byte
# on member presence/absence, so materializing MUST change the bytes.
_MEMBER = "epistemic_mode"


_BODY = r"""
import json, sys, os, tempfile, secrets

def report(obj):
    print(json.dumps(obj)); sys.stdout.flush(); os._exit(0)

try:
    import ciris_persist as cp
    import ciris_verify as cv
except ImportError as exc:
    report({"_error": "import", "detail": str(exc)})

if INJECTED_URL.startswith("postgres"):
    DB_URL = INJECTED_URL
else:
    _dbf = os.path.join(tempfile.mkdtemp(), "f.db"); open(_dbf, "a").close()
    DB_URL = "sqlite:///" + _dbf

# Alice's committed envelope OMITS epistemic_mode; the relay-materialized variant
# writes the default "direct" in. Same meaning after interpretation-time defaults.
omit_form = json.dumps({
    "attesting_key_id": "kA", "dimension": "identity:human", "score": 1.0})
materialize_form = json.dumps({
    "attesting_key_id": "kA", "dimension": "identity:human",
    "epistemic_mode": "direct", "score": 1.0})


def as_bytes(x):
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    if isinstance(x, str):
        return x.encode()
    return bytes(x)


if not hasattr(cv, "jcs_canonicalize"):
    report({"_error": "absent", "surface": "cv.jcs_canonicalize"})

r = {}

# ── verify canonicalizer: preserves absence + byte-distinct on materialization ──
jcs_omit = as_bytes(cv.jcs_canonicalize(omit_form))
jcs_mat = as_bytes(cv.jcs_canonicalize(materialize_form))
r["jcs_omit"] = jcs_omit.decode("utf-8", "replace")
r["jcs_mat"] = jcs_mat.decode("utf-8", "replace")
r["omit_lacks_member"] = b"epistemic_mode" not in jcs_omit
r["mat_has_member"] = b"epistemic_mode" in jcs_mat
r["jcs_byte_distinct"] = jcs_omit != jcs_mat

# ── cross-wheel agreement: persist's canonicalizer == verify's, byte-for-byte ──
cp.reset_engine()
_dir = tempfile.mkdtemp()
_seed = os.path.join(_dir, "s"); open(_seed, "wb").write(secrets.token_bytes(32))
_pqc = os.path.join(_dir, "p"); open(_pqc, "wb").write(secrets.token_bytes(32))
_k = "canon-probe-" + secrets.token_hex(8)
engine = cp.Engine(DB_URL, _k, local_key_id=_k, local_key_path=_seed,
                   local_pqc_key_id=_k + "-pqc", local_pqc_key_path=_pqc)

if hasattr(engine, "canonicalize_envelope"):
    r["has_engine_canon"] = True
    eng_omit = as_bytes(engine.canonicalize_envelope(omit_form))
    eng_mat = as_bytes(engine.canonicalize_envelope(materialize_form))
    r["engine_matches_verify_omit"] = eng_omit == jcs_omit
    r["engine_byte_distinct"] = eng_omit != eng_mat
    r["engine_omit_lacks_member"] = b"epistemic_mode" not in eng_omit
else:
    r["has_engine_canon"] = False

r["stage"] = "done"
report(r)
"""


@pytest.fixture(scope="module")
def canon():
    script = f"INJECTED_URL = {get_database_url()!r}\n" + _BODY
    payload = run_python_script(script).parsed_stdout()
    if payload.get("_error") == "absent":
        pytest.fail(f"canonicalizer surface missing: {payload.get('surface')}")
    if payload.get("_error"):
        pytest.fail(f"probe failed: {payload}")
    assert payload.get("stage") == "done", payload
    return payload


@pytest.mark.requires_verify
def test_jcs_preserves_absence_and_materialization_is_byte_distinct(canon):
    """CC 2.6.1.4: the JCS canonicalizer preserves member absence, and materializing
    the omitted default changes the bytes.

    `jcs_canonicalize(omit_form)` carries no `epistemic_mode` (absence preserved —
    the canonicalizer does not materialize the default at encoding-time), while the
    materialize-form does; the two are byte-distinct. That byte divergence is
    exactly what makes a materializing relay's output fail a downstream verify — the
    attack §2.6.1.4 closes by requiring presence/absence be preserved.
    """
    r = canon
    assert r["omit_lacks_member"], (
        f"the canonicalizer materialized the {_MEMBER} default at encoding-time — "
        f"the omit-vs-materialize rule is not honored: {r['jcs_omit']}")
    assert r["mat_has_member"], (
        f"the materialize-form lost its {_MEMBER} member: {r['jcs_mat']}")
    assert r["jcs_byte_distinct"], (
        f"omit-form and materialize-form canonicalized identically — materializing "
        f"a default did NOT change the signed bytes, so the worked attack would be "
        f"undetectable: {r['jcs_omit']!r} == {r['jcs_mat']!r}")


@pytest.mark.requires_verify
@pytest.mark.requires_persist
def test_persist_and_verify_canonicalizers_agree_byte_for_byte(canon):
    """CC 2.6.1.4: persist's producer/relay canonicalizer and verify's consumer
    canonicalizer agree byte-for-byte on the omit-form.

    `Engine.canonicalize_envelope` (persist) == `ciris_verify.jcs_canonicalize`
    (verify) for the same absence-preserving envelope — so an honest producer and an
    honest verifier compute the identical signed bytes, and the ONLY way the bytes
    diverge is an illegitimate default materialization (which persist also flags as
    byte-distinct). Cross-wheel agreement is what makes the rule enforceable across
    the producer/relay/consumer boundary.
    """
    r = canon
    assert r["has_engine_canon"], "Engine.canonicalize_envelope surface is absent"
    assert r["engine_omit_lacks_member"], (
        f"persist's canonicalizer materialized the {_MEMBER} default: it must "
        f"preserve absence exactly")
    assert r["engine_matches_verify_omit"], (
        "persist's Engine.canonicalize_envelope and verify's jcs_canonicalize "
        "disagree on the omit-form bytes — the cross-wheel canonical-bytes contract "
        "is broken")
    assert r["engine_byte_distinct"], (
        "persist's canonicalizer produced identical bytes for omit vs materialize — "
        "materializing a default did not change the signed bytes")
