"""
CEG grammar tier — CC 2.1 the 1+4 attestation surface is conformance-frozen
(`CLM-1plus4-frozen`): a wire-byte change is a defect.

CC 2.4 reduces the whole grammar to **five wire primitives — "1+4"**: one
workhorse claim primitive (`scores`, CC 2.4.2) plus four structural composers that
act on the attestation graph itself (`delegates_to` / `supersedes` / `withdraws` /
`recants`, CC 2.4.1). CC 2.1.1's **canonical-bytes contract** pins how that
envelope becomes signed bytes: *"the canonical-bytes encoding of this envelope for
signing follows CC 2.6.1 (JCS over the envelope object)."* CC 6.1.3 restates the
seam from the other side — every CC 6.1 substrate object is framing that *"never
enters CC 2.6.1 JCS canonicalization,"* precisely because the 1+4 attestation
surface is the frozen thing JCS protects.

This file is the executable freeze gate for that surface. It pins the **byte-exact
RFC 8785 (JCS) canonicalization** of one frozen envelope per 1+4 primitive against
a golden hex vector recomputed from the real wheel. A change to ANY expected hex —
a field reorder, a number-format drift (RFC 8785 renders the integer-valued float
`1.0` as `1`), a whitespace change — is a change to the CC 2.1 wire-signing
contract and MUST be a deliberate CEG bump, exactly the "wire-byte change is a
defect" property the claim asserts.

Two real wheel surfaces produce these bytes, and the gate proves they agree:

  • `ciris_verify.jcs_canonicalize(value)` — the CC 2.6.1 canonicalizer; its
    docstring pins it *"byte-identical to `ciris_verify_core::jcs::canonicalize`
    and therefore to what the Rust verifiers recompute."* This is the frozen
    reference the golden vectors are taken from.
  • `Engine.canonicalize_envelope(json)` — persist's independent envelope
    canonicalizer. The gate cross-checks it is **byte-identical** to verify's JCS
    for every primitive, so the 1+4 signing bytes are frozen AND reproduced the
    same across the persist and verify implementations (the CC 2.2 cross-impl
    determinism requirement).

The driver loads both wheels in one subprocess (cohabitation) and constructs a
persist `Engine` on the injected backend URL, so it runs identically under sqlite
and postgres (the canonicalizers are pure functions of the input — no DB rows are
written — so the golden hex is backend-independent).

Spec: reference/CIRIS_Constitution/part_2_the_grammar.md CC 2.1 / CC 2.1.1 /
CC 2.4 / CC 2.6.1; claim CLM-1plus4-frozen (2.1).
"""

from __future__ import annotations

import pytest

from conftest import get_database_url, run_python_script

pytestmark = pytest.mark.ceg

# ─── The five frozen 1+4 envelopes (one per primitive) ────────────────
# The score primitive carries score=1.0 to exercise RFC 8785 number
# canonicalization (1.0 -> "1"); the structural composers carry their CC 2.4.1
# envelope-shape fields. These literals MUST stay byte-identical to the driver's
# copy below, or the recomputed hex will not match the golden vectors.
_PRIMITIVES = (
    "scores",
    "delegates_to",
    "supersedes",
    "withdraws",
    "recants",
)

# ─── Golden JCS vectors (RFC 8785, recomputed from the wheel) ─────────
# Byte-exact canonicalization of each envelope. A wire-byte change flips these red.
_GOLDEN_JCS_HEX = {
    "scores": (
        "7b226174746573746174696f6e5f74797065223a2273636f726573222c2261747465737465"
        "645f6b65795f6964223a226b42222c22617474657374696e675f6b65795f6964223a226b41"
        "222c22636f6e666964656e6365223a302e392c22636f6e74657874223a22637478222c2264"
        "696d656e73696f6e223a226964656e746974793a68756d616e222c2273636f7265223a317d"
    ),
    "delegates_to": (
        "7b226174746573746174696f6e5f74797065223a2264656c6567617465735f746f222c2261"
        "747465737465645f6b65795f6964223a226b42222c22617474657374696e675f6b65795f69"
        "64223a226b41222c2264656c6567617465645f73636f7065223a5b22636f6e73656e745f72"
        "65766f636174696f6e225d2c2264656c65676174696f6e5f707572706f7365223a226f776e"
        "65725f62696e64696e67222c2264656c65676174696f6e5f76616c69645f66726f6d223a22"
        "323032362d30312d30315430303a30303a30305a222c2264656c65676174696f6e5f76616c"
        "69645f756e74696c223a22323032372d30312d30315430303a30303a30305a227d"
    ),
    "supersedes": (
        "7b226174746573746174696f6e5f74797065223a2273757065727365646573222c22617474"
        "657374696e675f6b65795f6964223a226b41222c22646966666572735f696e223a5b227363"
        "6f7065222c2265766964656e63655f72656673225d2c227265666572656e6365735f617474"
        "6573746174696f6e5f6964223a226174742d30303031222c22737570657273657373696f6e"
        "5f726561736f6e223a2273636f70652d657874656e64227d"
    ),
    "withdraws": (
        "7b226174746573746174696f6e5f74797065223a22776974686472617773222c2261747465"
        "7374696e675f6b65795f6964223a226b41222c227265666572656e6365735f617474657374"
        "6174696f6e5f6964223a226174742d30303031222c227769746864726177616c5f72656173"
        "6f6e223a22636f6e746578742d6368616e676564227d"
    ),
    "recants": (
        "7b226174746573746174696f6e5f74797065223a22726563616e7473222c22617474657374"
        "696e675f6b65795f6964223a226b41222c22726563616e746174696f6e5f726561736f6e22"
        "3a226572726f72222c227265666572656e6365735f6174746573746174696f6e5f6964223a"
        "226174742d30303031222c22776861745f7761735f66616c7365223a227468652d636c6169"
        "6d227d"
    ),
}


# ─── The cohabitation drive: canonicalize each envelope on both wheels ──
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


def as_bytes(x):
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    if isinstance(x, str):
        return x.encode("utf-8")
    raise TypeError(type(x))


# The five frozen 1+4 envelopes — byte-identical to the test module's copy.
VECS = {
    "scores": {"attestation_type": "scores", "attesting_key_id": "kA",
               "attested_key_id": "kB", "dimension": "identity:human",
               "score": 1.0, "confidence": 0.9, "context": "ctx"},
    "delegates_to": {"attestation_type": "delegates_to", "attesting_key_id": "kA",
                     "attested_key_id": "kB", "delegated_scope": ["consent_revocation"],
                     "delegation_purpose": "owner_binding",
                     "delegation_valid_from": "2026-01-01T00:00:00Z",
                     "delegation_valid_until": "2027-01-01T00:00:00Z"},
    "supersedes": {"attestation_type": "supersedes", "attesting_key_id": "kA",
                   "references_attestation_id": "att-0001",
                   "supersession_reason": "scope-extend",
                   "differs_in": ["scope", "evidence_refs"]},
    "withdraws": {"attestation_type": "withdraws", "attesting_key_id": "kA",
                  "references_attestation_id": "att-0001",
                  "withdrawal_reason": "context-changed"},
    "recants": {"attestation_type": "recants", "attesting_key_id": "kA",
                "references_attestation_id": "att-0001",
                "recantation_reason": "error", "what_was_false": "the-claim"},
}

# jcs_canonicalize + Engine both lazy-load a native shared lib; a host that can't
# load it is a provisioning gap, not a spec mismatch — surface it as a skip token.
try:
    _probe = cv.jcs_canonicalize({"a": 1})
except RuntimeError as exc:
    report({"_error": "verify_native", "detail": str(exc)})

_d = tempfile.mkdtemp()
_s = os.path.join(_d, "s"); open(_s, "wb").write(secrets.token_bytes(32))
_p = os.path.join(_d, "p"); open(_p, "wb").write(secrets.token_bytes(32))
cp.reset_engine()
_k = "node-" + secrets.token_hex(8)
eng = cp.Engine(DB_URL, _k, local_key_id=_k, local_key_path=_s,
                local_pqc_key_id=_k + "-pqc", local_pqc_key_path=_p)

out = {}
for name, env in VECS.items():
    jb = as_bytes(cv.jcs_canonicalize(env))
    pb = as_bytes(eng.canonicalize_envelope(json.dumps(env)))
    out[name] = {"jcs_hex": jb.hex(), "persist_hex": pb.hex(),
                 "cross": jb == pb, "first_byte": jb[0]}

report({"stage": "done", "out": out})
"""


def _script(url: str) -> str:
    return f"INJECTED_URL = {url!r}\n" + _BODY


@pytest.fixture(scope="module")
def canon():
    result = run_python_script(_script(get_database_url()), timeout=60.0)
    payload = result.parsed_stdout()
    if payload.get("_error") == "import":
        pytest.fail(f"driver could not import the wheels: {payload.get('detail')}")
    if payload.get("_error") == "verify_native":
        pytest.skip(f"ciris_verify JCS native lib can't load on this host: "
                    f"{payload.get('detail')}")
    assert payload.get("stage") == "done", payload
    return payload["out"]


# ─── The 1+4 freeze gate (byte-exact) ─────────────────────────────────


@pytest.mark.cohabitation
@pytest.mark.requires_verify
@pytest.mark.parametrize("prim", _PRIMITIVES)
def test_1plus4_canonical_bytes_are_frozen(canon, prim):
    """CC 2.1: the JCS canonicalization of each 1+4 envelope matches its golden
    vector byte-for-byte — a wire-byte change is a defect.

    The frozen bytes are RFC 8785 JCS over the envelope object (the CC 2.1.1
    canonical-bytes contract): keys sorted, minimal number encoding (so score=1.0
    renders `1`), no insignificant whitespace. A drift in any of these flips this
    red, which is exactly the conformance-frozen guarantee CLM-1plus4-frozen makes.
    """
    got = canon[prim]
    assert got["jcs_hex"] == _GOLDEN_JCS_HEX[prim], (
        f"{prim}: JCS bytes drifted from the frozen vector\n"
        f"  got   {got['jcs_hex']}\n  frozen {_GOLDEN_JCS_HEX[prim]}")
    # Structural anchor: JCS output is a JSON object (first byte '{').
    assert got["first_byte"] == 0x7B, got


@pytest.mark.cohabitation
@pytest.mark.requires_verify
def test_scores_number_canonicalization_is_pinned(canon):
    """CC 2.6.1 / RFC 8785: the integer-valued float `score: 1.0` canonicalizes to
    `"score":1` — the number-format rule a naive serializer silently breaks.

    This is the highest-value byte in the freeze vector: two implementations that
    disagree on whether `1.0` serializes as `1` or `1.0` produce different signing
    bytes for the same claim and fail to verify each other's attestations.
    """
    scores_hex = canon["scores"]["jcs_hex"]
    text = bytes.fromhex(scores_hex).decode("utf-8")
    assert '"score":1}' in text, text
    assert '"score":1.0' not in text, text


# ─── Cross-impl determinism: persist == verify ────────────────────────


@pytest.mark.cohabitation
@pytest.mark.requires_persist
@pytest.mark.requires_verify
@pytest.mark.parametrize("prim", _PRIMITIVES)
def test_persist_canonicalize_matches_verify_jcs(canon, prim):
    """CC 2.2 cross-impl determinism: `Engine.canonicalize_envelope` reproduces
    verify's `jcs_canonicalize` byte-for-byte for every 1+4 primitive.

    The 1+4 signing bytes are frozen AND identical across the persist and verify
    implementations — a producer canonicalizing on one wheel and a verifier
    canonicalizing on the other agree on the exact bytes under signature.
    """
    got = canon[prim]
    assert got["cross"] is True, (
        f"{prim}: persist canonicalize_envelope diverged from verify JCS\n"
        f"  verify  {got['jcs_hex']}\n  persist {got['persist_hex']}")
    # And both equal the frozen golden vector.
    assert got["persist_hex"] == _GOLDEN_JCS_HEX[prim], got
