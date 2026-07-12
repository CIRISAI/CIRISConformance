"""
Fabric tier — CC 6.1.3 the canonicalization boundary (`CLM-canonicalization-boundary`):
CC 6.1 objects use a binary, length-prefixed, big-endian, domain-separated signing
preimage — **never CC 2.6.1 JCS, never a 1+4 attestation**.

CC 6.1.3 is the seam that protects the frozen 1+4 attestation surface (CC 2.1):
every CC 6.1 substrate object is transport/substrate framing, so *"An implementer
MUST NOT apply JCS to a CC 6.1 object or its signatures will not verify
cross-impl."* Its signing preimage is the CC 6.1.3 binary discipline —
`domain_separator ‖ u32_be(version) ‖ lp(field)… ‖ raw_bytes`, with
`lp(x) = u32_be(len) ‖ utf8(x)` — bound-hybrid signed (Ed25519 over the preimage,
ML-DSA-65 over `preimage ‖ ed25519_sig`), verified at ingest and before
persistence.

This gate drives the boundary **behaviorally** through persist's §19.7.1
aggregation-admission surface `Engine.put_aggregated_tier(...)`, which runs
`verify_aggregation_meta` over the `AggregationMetaV1` preimage. It admits 3 signed
source fountains + a composite, then attempts to admit the SAME logical
`AggregationMetaV1` two ways:

  • signed over the correct CC 6.1.3 **binary** preimage
    (`b"AGG-META-v1\0\0\0\0\0"` ‖ length-prefixed fields ‖ raw 32-byte
    member_commitment ‖ `u32_be(n_eff)`) → **ADMITTED**;
  • signed over the **JCS canonicalization** of the very same verification object
    (`ciris_verify.jcs_canonicalize(...)`, a sorted JSON object, first byte `{`)
    → **REJECTED** `aggregation_meta_hybrid_required`, nothing written.

The two preimages are proven byte-distinct at their first byte: the binary
preimage begins with the exact 16-byte domain separator, the JCS preimage begins
with `0x7B` (`{`). Admitting the binary form while rejecting the JCS form is the
executable proof that the wheel's CC 6.1 preimage is binary/length-prefixed/
domain-separated and **not** JCS — the CLM-canonicalization-boundary property.
`AggregationMetaV1` is also *"a substrate wire shape, NOT a CC 2.1 attestation"*
(the "never 1+4" leg): it is admitted via `put_aggregated_tier`, never through the
attestation path.

The aggregation path uses only the `Engine` (no `init_edge_runtime`), so it is
postgres-safe; content ids are salted per subprocess so a shared backend never
sees a cross-run collision.

Spec: reference/CIRIS_Constitution/part_6_the_coherence_mathematics.md CC 6.1.3
(canonicalization-boundary) / CC 6.1.2.1; claim CLM-canonicalization-boundary (6.1.3);
verify `ciris-verify-core/src/holonomic/aggregation.rs::verify_aggregation_meta`.
"""

from __future__ import annotations

import pytest

from conftest import get_database_url, run_python_script

pytestmark = pytest.mark.fabric

# The CC 6.1.2.1 pinned 16-byte domain separator (exact) the binary preimage opens
# with — the anchor the boundary gate proves is present (and JCS is not).
DOMSEP_AGG_META = b"AGG-META-v1\x00\x00\x00\x00\x00"


_BODY = r"""
import json, sys, os, tempfile, secrets, base64, hashlib, struct

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
        return base64.b64decode(x)
    if isinstance(x, list):
        return bytes(x)
    raise TypeError(type(x))


def sha256(*parts):
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


# §19.1 WholenessWitness Merkle, reused verbatim by §19.7.1.1 member_commitment.
def member_commitment(content_ids):
    leaves = sorted(cid.encode("utf-8") for cid in content_ids)
    level = [sha256(b) for b in leaves]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(sha256(left, right))
        level = nxt
    return level[0]


# CC 6.1.3 binary signing preimage — v2 appends u32_be(n_eff).
DOMAIN_AGG_META = b"AGG-META-v1\0\0\0\0\0"
assert len(DOMAIN_AGG_META) == 16
def _u32(n):
    return struct.pack(">I", n)
def _lp(b):
    if isinstance(b, str):
        b = b.encode("utf-8")
    return _u32(len(b)) + b
def agg_meta_preimage(version, content_id, corpus_kind, tier, algo, source_count,
                      mc32, nfd, n_eff):
    return (DOMAIN_AGG_META + _u32(version) + _lp(content_id) + _lp(corpus_kind)
            + _u32(tier) + _lp(algo) + _u32(source_count) + mc32 + _lp(nfd)
            + _u32(n_eff))


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
ED_PUB = eng.local_public_key_b64()
PQC_PUB = eng.local_pqc_public_key_b64()
PQC_KEY_ID = eng.local_pqc_key_id()
NS = secrets.token_hex(6)

SYMBOL, N_SOURCE, K_REPAIR, MIN_VIABLE = 16, 10, 4, 3
TOTAL = N_SOURCE + K_REPAIR
AGG_CORPUS = "aggregate:trace"
V_VERSION, V_TIER, V_ALGO, V_NFD, V_N_EFF = 2, 1, "raptorq-pyramid-v1", "mean+stddev", 3


def sign_manifest(value):
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ed = as_bytes(eng.local_sign(canonical))
    pqc = as_bytes(eng.local_pqc_sign(canonical + ed))
    m = dict(value)
    m.update({"signature": base64.b64encode(ed).decode(),
              "signature_ml_dsa_65": base64.b64encode(pqc).decode(),
              "pqc_key_id": PQC_KEY_ID})
    return m


def build_content(cid, corpus):
    symbols, hashes = [], []
    for i in range(TOTAL):
        b = bytes((i * 31 + 7 + j) & 0xFF for j in range(SYMBOL))
        hashes.append(hashlib.sha256(b).hexdigest())
        symbols.append({"content_id": cid, "symbol_id": i,
                        "retention_priority": i, "symbol_bytes": list(b)})
    envelope = {"content_id": cid, "pubkey_ed25519": ED_PUB, "pubkey_ml_dsa_65": PQC_PUB}
    value = {"content_id": cid, "corpus_kind": corpus, "manifest_version": 1,
             "n_source": N_SOURCE, "k_repair": K_REPAIR, "symbol_size": SYMBOL,
             "original_content_length": N_SOURCE * SYMBOL, "min_viable_symbols": MIN_VIABLE,
             "symbol_hashes": hashes, "envelope": envelope}
    return sign_manifest(value), symbols


# ── admit 3 source fountains (the descent fan-in) ──
SOURCES = [(f"src-{i}-{NS}", "trace") for i in range(3)]
for cid, corpus in SOURCES:
    man, syms = build_content(cid, corpus)
    eng.put_fountain_content(json.dumps(man), json.dumps(syms))
member_ids = [cid for cid, _ in SOURCES]
mc32 = member_commitment(member_ids)
MC_HEX = mc32.hex()


def verification_object(cid):
    # The wire verification object, WITHOUT the two signature fields — this is what
    # a (wrong) implementer would feed to JCS.
    return {"version": V_VERSION, "content_id": cid, "corpus_kind": AGG_CORPUS,
            "tier": V_TIER, "aggregation_algorithm_id": V_ALGO,
            "source_count": len(member_ids), "n_eff": V_N_EFF,
            "member_commitment_hex": MC_HEX, "noise_floor_descriptor": V_NFD}


def agg_wire(cid, ed_sig, pqc_sig):
    ver = dict(verification_object(cid))
    ver["sig_ed25519_b64"] = base64.b64encode(ed_sig).decode()
    ver["sig_ml_dsa_65_b64"] = base64.b64encode(pqc_sig).decode()
    return {"aggregate_content_id": cid, "source_corpus_kind": "trace",
            "aggregation_level": 1, "fan_in": len(member_ids), "member_commitment": MC_HEX,
            "aggregation_meta": base64.b64encode(b"opaque").decode(), "verification": ver}


def try_admit(cid, preimage):
    comp_man, comp_syms = build_content(cid, AGG_CORPUS)
    ed_sig = as_bytes(eng.local_sign(preimage))
    pqc_sig = as_bytes(eng.local_pqc_sign(preimage + ed_sig))
    try:
        eng.put_aggregated_tier(json.dumps(comp_man), json.dumps(comp_syms),
                                json.dumps(agg_wire(cid, ed_sig, pqc_sig)), 1)
        return {"result": "admit", "observed": eng.get_aggregation(cid) is not None}
    except Exception as exc:
        return {"result": "reject", "token": str(exc),
                "nothing_written": eng.get_aggregation(cid) is None}


# (A) the correct CC 6.1.3 BINARY preimage → admit
CID_BIN = f"agg-bin-{NS}"
bin_pre = agg_meta_preimage(V_VERSION, CID_BIN, AGG_CORPUS, V_TIER, V_ALGO,
                            len(member_ids), mc32, V_NFD, V_N_EFF)
binary = try_admit(CID_BIN, bin_pre)

# (B) the SAME object canonicalized with JCS → reject (proves NOT JCS)
CID_JCS = f"agg-jcs-{NS}"
jcs_pre = as_bytes(cv.jcs_canonicalize(verification_object(CID_JCS)))
jcs = try_admit(CID_JCS, jcs_pre)

report({
    "stage": "done",
    "persist_version": getattr(cp, "__version__", "?"),
    "binary": binary,
    "jcs": jcs,
    "binary_preimage_first16": list(bin_pre[:16]),
    "binary_preimage_len": len(bin_pre),
    "jcs_preimage_first_byte": jcs_pre[0],
    "jcs_preimage_sample": jcs_pre[:48].decode("utf-8", "replace"),
})
"""


def _script(url: str) -> str:
    return f"INJECTED_URL = {url!r}\n" + _BODY


@pytest.fixture(scope="module")
def boundary():
    result = run_python_script(_script(get_database_url()), timeout=90.0)
    payload = result.parsed_stdout()
    if payload.get("_error") == "import":
        pytest.fail(f"driver could not import the wheels: {payload.get('detail')}")
    if payload.get("_error") == "verify_native":
        pytest.skip(f"ciris_verify JCS native lib can't load on this host: "
                    f"{payload.get('detail')}")
    assert payload.get("stage") == "done", payload
    return payload


# ─── The canonicalization boundary (behavioral) ───────────────────────


@pytest.mark.requires_persist
def test_binary_length_prefixed_preimage_is_admitted(boundary):
    """CC 6.1.3: an `AggregationMetaV1` signed over the binary, length-prefixed,
    domain-separated preimage is admitted — the CC 6.1 discipline verifies.

    The preimage opens with the exact 16-byte `AGG-META-v1\\0\\0\\0\\0\\0` domain
    separator (not a JSON object), and the bound-hybrid signature over it passes
    `verify_aggregation_meta` at `put_aggregated_tier`.
    """
    b = boundary["binary"]
    assert b["result"] == "admit", b
    assert b["observed"] is True, b
    assert bytes(boundary["binary_preimage_first16"]) == DOMSEP_AGG_META, boundary
    assert boundary["binary_preimage_first16"][0] != 0x7B, boundary  # not '{'


@pytest.mark.requires_verify
@pytest.mark.requires_persist
def test_jcs_signed_preimage_is_rejected(boundary):
    """CC 6.1.3: the SAME object signed over its JCS canonicalization is rejected —
    the wheel does NOT use CC 2.6.1 JCS for a CC 6.1 preimage.

    Signing `ciris_verify.jcs_canonicalize(verification_object)` (a sorted JSON
    object, first byte `{`) yields a signature the substrate cannot reconstruct
    against its binary preimage, so admission fails `aggregation_meta_hybrid_required`
    and nothing is written. This is the executable "never JCS" boundary.
    """
    j = boundary["jcs"]
    assert boundary["jcs_preimage_first_byte"] == 0x7B, boundary  # JCS is a JSON object
    assert j["result"] == "reject", j
    assert "aggregation_meta_hybrid_required" in j["token"], j
    assert j["nothing_written"] is True, j


@pytest.mark.requires_verify
@pytest.mark.requires_persist
def test_binary_and_jcs_preimages_are_byte_distinct(boundary):
    """CC 6.1.3: the binary preimage and the JCS preimage are not the same bytes —
    the boundary is a real byte-level fork, not a coincidental accept/reject.

    The binary preimage starts with the domain separator; the JCS preimage starts
    with `0x7B`. Admitting one while rejecting the other therefore proves the wheel
    selects the binary discipline, not JSON canonicalization.
    """
    assert boundary["binary_preimage_first16"][0] == DOMSEP_AGG_META[0]  # 'A'
    assert boundary["jcs_preimage_first_byte"] == 0x7B
    assert boundary["jcs_preimage_sample"].startswith("{"), boundary
