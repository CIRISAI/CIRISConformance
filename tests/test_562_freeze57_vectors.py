"""
Fabric tier — CC 6.1.4 the #57 freeze gate (`CLM-freeze-57`): byte-exact
conformance vectors for the CC 6.1 shapes.

CC 6.1.4 names the [CIRISRegistry #57] freeze gate: *"Conformance vectors generated
from the reference are the named #57 freeze gate."* CC 6.1.3 pins the byte layout
each CC 6.1 signed object hashes; CC 6.1.4 freezes concrete input→bytes vectors so
that a wire-byte change to any CC 6.1 shape is caught. This file is the executable
freeze gate for the two load-bearing CC 6.1.2 shapes:

  • **WholenessWitness member_commitment** (CC 6.1.1 / §19.1) — the Merkle root
    over the member content-ids: `leaf = SHA256(utf8(cid))`, RAW leaf bytes sorted
    lexicographically BEFORE hashing, `node = SHA256(l ‖ r)`, odd node duplicated,
    empty-set sentinel `SHA256(b"WW-v1-empty")`. Fully deterministic.
  • **AggregationMetaV1 v2 preimage** (CC 6.1.2.1 / §19.7.1) — the CC 6.1.3 binary
    preimage `b"AGG-META-v1\0\0\0\0\0" ‖ u32_be(version) ‖ lp(content_id) ‖
    lp(corpus_kind) ‖ u32_be(tier) ‖ lp(algorithm_id) ‖ u32_be(source_count) ‖
    member_commitment[32] ‖ lp(noise_floor_descriptor) ‖ u32_be(n_eff)`.

The gate has two legs that together freeze the wheel's bytes against the golden
vector:

  • **Vector leg (byte-exact golden).** For frozen inputs (member set
    `frozen-src-0..2`, `content_id=frozen-agg-root`, tier 1, `raptorq-pyramid-v1`,
    `mean+stddev`, `n_eff=3`), the recomputed `member_commitment`, the SHA-256 of
    the v2 preimage, and the WholenessWitness empty-sentinel root MUST match the
    frozen hex below. Any drift in the Merkle scheme, the domain separator, the
    length-prefix widths, the big-endian integers, or the v2 `n_eff` append is a
    change to the #57 vector family and MUST be a deliberate CC 6.1.4 re-cut.
  • **Wheel leg (admission byte-pins the substrate's preimage).** The engine
    ADMITS a bound-hybrid `AggregationMetaV1` whose Ed25519+ML-DSA-65 signatures
    cover exactly this preimage construction — `put_aggregated_tier` runs
    `verify_aggregation_meta`, reconstructing the preimage from the wire fields, so
    an admit proves the substrate's preimage is byte-identical to the frozen
    construction. A ONE-BYTE mutation of a signed field (without re-signing) is
    then REJECTED — the freeze-sensitivity proof: the substrate hashes exactly
    these bytes, not a byte more or less.

The wheel leg salts its content ids per subprocess (postgres-safe, no cross-run
collision); the vector leg's golden hex is input-fixed and backend-independent (a
pure hash of the pinned construction). The whole path is `Engine`-only
(no `init_edge_runtime`), so sqlite and postgres run identically.

Spec: reference/CIRIS_Constitution/part_6_the_coherence_mathematics.md CC 6.1.4
(conformance-freeze) / CC 6.1.1 / CC 6.1.2.1; claim CLM-freeze-57 (6.1.4);
verify `ciris-verify-core/src/holonomic/{wholeness_witness,aggregation}.rs`.
"""

from __future__ import annotations

import pytest

from conftest import get_database_url, run_python_script

pytestmark = pytest.mark.fabric

# ─── #57 golden vectors (recomputed from the frozen construction) ─────
# Frozen inputs: member set ["frozen-src-0","frozen-src-1","frozen-src-2"],
# content_id "frozen-agg-root", corpus "aggregate:trace", tier 1,
# algorithm "raptorq-pyramid-v1", noise_floor_descriptor "mean+stddev",
# version 2, source_count 3, n_eff 3.
GOLDEN_MEMBER_COMMITMENT = (
    "c58c80ff236115e1592afa943bcbd1b23098839f074b16f69aee7dd6e1090ae8"
)
GOLDEN_AGG_META_V2_PREIMAGE_SHA256 = (
    "7962b1ee05dfcbbfcf4c427ec8b0b99daa58f356820b52deebdcccd72e7294a6"
)
GOLDEN_WW_EMPTY_ROOT = (
    "2280d27f232100367e86211b5349fe0d6fbaee98e4c2b489a86008049563464f"
)
GOLDEN_PREIMAGE_LEN = 139

# The frozen construction inputs (mirrored in the driver's vector leg).
FROZEN_MEMBER_IDS = ["frozen-src-0", "frozen-src-1", "frozen-src-2"]
FROZEN_CONTENT_ID = "frozen-agg-root"


_BODY = r"""
import json, sys, os, tempfile, secrets, base64, hashlib, struct

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


WW_EMPTY = b"WW-v1-empty"
def member_commitment(content_ids):
    leaves = [cid.encode("utf-8") for cid in content_ids]
    if not leaves:
        return sha256(WW_EMPTY)
    leaves = sorted(leaves)
    level = [sha256(b) for b in leaves]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(sha256(left, right))
        level = nxt
    return level[0]


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


TIER, ALGO, NFD, VERSION = 1, "raptorq-pyramid-v1", "mean+stddev", 2

# ── Vector leg: the byte-exact #57 golden, recomputed from the frozen inputs ──
FROZEN_IDS = ["frozen-src-0", "frozen-src-1", "frozen-src-2"]
FROZEN_CID = "frozen-agg-root"
FROZEN_CORPUS = "aggregate:trace"
frozen_mc = member_commitment(FROZEN_IDS)
frozen_pre = agg_meta_preimage(VERSION, FROZEN_CID, FROZEN_CORPUS, TIER, ALGO,
                               len(FROZEN_IDS), frozen_mc, NFD, len(FROZEN_IDS))
vector = {
    "member_commitment": frozen_mc.hex(),
    "preimage_sha256": hashlib.sha256(frozen_pre).hexdigest(),
    "preimage_len": len(frozen_pre),
    "ww_empty_root": sha256(WW_EMPTY).hex(),
}

# ── Wheel leg: admit a bound-hybrid agg-meta over the binary preimage ──
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


SOURCES = [(f"src-{i}-{NS}", "trace") for i in range(3)]
for cid, corpus in SOURCES:
    man, syms = build_content(cid, corpus)
    eng.put_fountain_content(json.dumps(man), json.dumps(syms))
member_ids = [cid for cid, _ in SOURCES]
mc32 = member_commitment(member_ids)
MC_HEX = mc32.hex()
SRC_COUNT, N_EFF = len(member_ids), len(member_ids)


def agg_wire(cid, mc_hex, nfd, ed_sig, pqc_sig):
    ver = {"version": VERSION, "content_id": cid, "corpus_kind": AGG_CORPUS,
           "tier": TIER, "aggregation_algorithm_id": ALGO,
           "source_count": SRC_COUNT, "n_eff": N_EFF,
           "member_commitment_hex": mc_hex, "noise_floor_descriptor": nfd,
           "sig_ed25519_b64": base64.b64encode(ed_sig).decode(),
           "sig_ml_dsa_65_b64": base64.b64encode(pqc_sig).decode()}
    return {"aggregate_content_id": cid, "source_corpus_kind": "trace",
            "aggregation_level": 1, "fan_in": SRC_COUNT, "member_commitment": mc_hex,
            "aggregation_meta": base64.b64encode(b"opaque").decode(), "verification": ver}


# (1) admit over the exact binary preimage → the substrate reconstructs it byte-for-byte.
CID_OK = f"agg-frz-{NS}"
comp_man, comp_syms = build_content(CID_OK, AGG_CORPUS)
pre = agg_meta_preimage(VERSION, CID_OK, AGG_CORPUS, TIER, ALGO, SRC_COUNT, mc32,
                        NFD, N_EFF)
ed_sig = as_bytes(eng.local_sign(pre))
pqc_sig = as_bytes(eng.local_pqc_sign(pre + ed_sig))
try:
    eng.put_aggregated_tier(json.dumps(comp_man), json.dumps(comp_syms),
                            json.dumps(agg_wire(CID_OK, MC_HEX, NFD, ed_sig, pqc_sig)), 1)
    frozen_admit = {"result": "admit", "observed": eng.get_aggregation(CID_OK) is not None}
except Exception as exc:
    frozen_admit = {"result": "reject", "token": str(exc)}

# (2) mutate ONE signed field (noise_floor_descriptor) on the wire WITHOUT re-signing
#     → the substrate's reconstructed preimage differs by those bytes → reject.
CID_MUT = f"agg-mut-{NS}"
cm2, cs2 = build_content(CID_MUT, AGG_CORPUS)
pre2 = agg_meta_preimage(VERSION, CID_MUT, AGG_CORPUS, TIER, ALGO, SRC_COUNT, mc32,
                         NFD, N_EFF)
ed2 = as_bytes(eng.local_sign(pre2))
pqc2 = as_bytes(eng.local_pqc_sign(pre2 + ed2))
wire2 = agg_wire(CID_MUT, MC_HEX, "TAMPERED", ed2, pqc2)   # signed NFD, wire NFD differ
try:
    eng.put_aggregated_tier(json.dumps(cm2), json.dumps(cs2), json.dumps(wire2), 1)
    mutated = {"result": "admit"}
except Exception as exc:
    mutated = {"result": "reject", "token": str(exc),
               "nothing_written": eng.get_aggregation(CID_MUT) is None}

report({
    "stage": "done",
    "persist_version": getattr(cp, "__version__", "?"),
    "vector": vector,
    "frozen_admit": frozen_admit,
    "mutated": mutated,
})
"""


def _script(url: str) -> str:
    return f"INJECTED_URL = {url!r}\n" + _BODY


@pytest.fixture(scope="module")
def freeze():
    result = run_python_script(_script(get_database_url()), timeout=90.0)
    payload = result.parsed_stdout()
    if payload.get("_error") == "import":
        pytest.fail(f"driver could not import ciris_persist: {payload.get('detail')}")
    assert payload.get("stage") == "done", payload
    return payload


# ─── Vector leg — byte-exact golden #57 vectors ───────────────────────


@pytest.mark.requires_persist
def test_wholeness_witness_member_commitment_frozen(freeze):
    """CC 6.1.4 / CC 6.1.1: the WholenessWitness `member_commitment` Merkle root and
    the empty-set sentinel match their frozen #57 hex byte-for-byte.

    Pins the whole Merkle scheme: `SHA256(utf8(cid))` leaves, RAW-bytes lexical
    sort before hashing, `SHA256(l‖r)` nodes, and the `SHA256(b"WW-v1-empty")`
    empty sentinel. A change to any of these is a change to the federation's single
    Merkle scheme (shared by CC 6.1.1 witness leaves and CC 6.1.2 member commitments).
    """
    v = freeze["vector"]
    assert v["member_commitment"] == GOLDEN_MEMBER_COMMITMENT, v
    assert v["ww_empty_root"] == GOLDEN_WW_EMPTY_ROOT, v


@pytest.mark.requires_persist
def test_aggregation_meta_v2_preimage_frozen(freeze):
    """CC 6.1.4 / CC 6.1.2.1: the SHA-256 of the v2 `AggregationMetaV1` binary
    preimage matches its frozen #57 hex, at the frozen length.

    Freezes the CC 6.1.3 binary layout end to end: the 16-byte domain separator,
    the big-endian `u32` version/tier/source_count, the length-prefixed strings,
    the raw 32-byte member_commitment, and the appended v2 `u32_be(n_eff)`. A
    layout drift changes the preimage hash.
    """
    v = freeze["vector"]
    assert v["preimage_sha256"] == GOLDEN_AGG_META_V2_PREIMAGE_SHA256, v
    assert v["preimage_len"] == GOLDEN_PREIMAGE_LEN, v


# ─── Wheel leg — admission byte-pins the substrate's preimage ─────────


@pytest.mark.requires_persist
def test_wheel_admits_the_frozen_preimage_construction(freeze):
    """CC 6.1.4: the substrate ADMITS a bound-hybrid `AggregationMetaV1` signed over
    exactly the frozen preimage construction.

    `put_aggregated_tier` reconstructs the preimage from the wire fields and
    verifies the Ed25519+ML-DSA-65 halves against it; an admit proves the
    substrate's preimage bytes are byte-identical to the #57 construction the
    vector leg froze — the wheel side of the freeze gate.
    """
    fa = freeze["frozen_admit"]
    assert fa["result"] == "admit", fa
    assert fa["observed"] is True, fa


@pytest.mark.requires_persist
def test_one_byte_signed_field_mutation_breaks_admission(freeze):
    """CC 6.1.4: a one-byte change to a signed preimage field (without re-signing)
    is rejected — the freeze gate is byte-sensitive.

    The wire `noise_floor_descriptor` is changed after signing, so the substrate's
    reconstructed preimage differs from the signed bytes; admission fails
    `aggregation_meta_hybrid_required` and nothing is written. This proves the
    substrate hashes exactly the frozen bytes — a wire-byte change is a defect.
    """
    m = freeze["mutated"]
    assert m["result"] == "reject", m
    assert "aggregation_meta_hybrid_required" in m["token"], m
    assert m["nothing_written"] is True, m
