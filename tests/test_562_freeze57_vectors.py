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
  • **AggregationMetaV1 v3 preimage** (CC 6.1.2.1 / §19.7.1) — the CC 6.1.3 binary
    preimage `b"AGG-META-v1\0\0\0\0\0" ‖ u32_be(version) ‖ lp(content_id) ‖
    lp(corpus_kind) ‖ u32_be(tier) ‖ lp(algorithm_id) ‖ u32_be(source_count) ‖
    member_commitment[32] ‖ lp(noise_floor_descriptor) ‖ u32_be(n_eff) ‖
    u32_be(max_source_multiplicity) ‖ mass_commitment[32]`.

**The goldens were re-cut at v3 — deliberately, and that is the gate working.**
CIRISVerify#191 / CIRISEdge#328 bumped `AggregationMetaV1` v2 → v3, appending
`u32_be(max_source_multiplicity) ‖ mass_commitment[32]` to the preimage (persist ≥16
runs BOTH the dominance and the multiplicity gate, and **fail-closes any pre-v3
tier**). A freeze gate SHOULD resist *silent* drift, and it did: the v2 goldens broke
loudly the moment the layout moved. What lands here is the other half of that
contract — an **explicit, versioned re-freeze**: the frozen preimage is 175 bytes
(v2 was 139), its SHA-256 is a new golden, and a new golden pins the `mass_commitment`
root the v3 tail introduced. The `member_commitment` and empty-sentinel goldens are
UNCHANGED across the bump — the §19.1 Merkle scheme did not move, and the gate proves
it. A future change to any of these hexes must likewise be a deliberate CC 6.1.4 re-cut
with a version bump behind it, never a quiet edit.

The gate has two legs that together freeze the wheel's bytes against the golden
vector:

  • **Vector leg (byte-exact golden).** The vector is produced by **edge's §19.7.1.3
    producer** (`assemble_tier_meta_v3`) — not by a Python rebuild of the preimage, which
    would freeze our own re-derivation rather than the reference's bytes. It is made
    deterministic by pinning every input: member set `frozen-src-0..2`,
    `content_id=frozen-agg-root`, corpus `aggregate:trace`, tier 1,
    `raptorq-pyramid-v1`, `mean+stddev`, masses = equal thirds (→ `n_eff == 3`), and
    `max_source_multiplicity = 1`. (`content_multiplicity` is deliberately NOT called:
    it measures real payload similarity, and random payloads are not freezable.) The
    resulting `member_commitment`, `mass_commitment`, preimage SHA-256, preimage length,
    and the WholenessWitness empty-sentinel root MUST match the frozen hex below. Any
    drift in the Merkle scheme, the domain separator, the length-prefix widths, the
    big-endian integers, the mass fixed-point scale, or the v3 tail changes a golden.
  • **Wheel leg (admission byte-pins the substrate's preimage).** The engine
    ADMITS a bound-hybrid `AggregationMetaV1` whose Ed25519+ML-DSA-65 signatures
    cover exactly this v3 preimage construction — `put_aggregated_tier` runs
    `verify_aggregation_meta`, reconstructing the preimage from the wire fields, so
    an admit proves the substrate's preimage is byte-identical to the frozen
    construction. A ONE-BYTE mutation of a signed field (without re-signing) is
    then REJECTED — the freeze-sensitivity proof: the substrate hashes exactly
    these bytes, not a byte more or less.

The wheel leg salts its content ids per subprocess (postgres-safe, no cross-run
collision) while pinning every other input to the frozen construction; the vector leg's
golden hex is input-fixed and backend-independent (a pure hash of the pinned
construction). The persist path is `Engine`-only (no `init_edge_runtime`), so sqlite
and postgres run identically.

Spec: reference/CIRIS_Constitution/part_6_the_coherence_mathematics.md CC 6.1.4
(conformance-freeze) / CC 6.1.1 / CC 6.1.2.1; claim CLM-freeze-57 (6.1.4);
verify `ciris-verify-core/src/holonomic/{wholeness_witness,aggregation}.rs`.
"""

from __future__ import annotations

import pytest

from conftest import get_database_url, run_python_script

pytestmark = pytest.mark.fabric

# ─── #57 golden vectors, re-cut at AggregationMetaV1 v3 ───────────────
# Frozen inputs: member set ["frozen-src-0","frozen-src-1","frozen-src-2"],
# content_id "frozen-agg-root", corpus "aggregate:trace", tier 1,
# algorithm "raptorq-pyramid-v1", noise_floor_descriptor "mean+stddev",
# version 3, source_count 3, masses = equal thirds (n_eff 3),
# max_source_multiplicity 1.  Produced by ciris_edge.assemble_tier_meta_v3.
#
# UNCHANGED across the v2→v3 bump — the §19.1 Merkle scheme did not move:
GOLDEN_MEMBER_COMMITMENT = (
    "c58c80ff236115e1592afa943bcbd1b23098839f074b16f69aee7dd6e1090ae8"
)
GOLDEN_WW_EMPTY_ROOT = (
    "2280d27f232100367e86211b5349fe0d6fbaee98e4c2b489a86008049563464f"
)
# RE-CUT at v3 (CIRISVerify#191 / CIRISEdge#328) — the preimage gained
# u32_be(max_source_multiplicity) ‖ mass_commitment[32], so it grew 139 → 175 bytes
# and its hash moved; `mass_commitment` is a wholly new frozen shape:
GOLDEN_AGG_META_V3_PREIMAGE_SHA256 = (
    "d1e95da5b21962737b1fe41333d3bfbfa1de42f9b7be0a1d9877b0b573e6f368"
)
GOLDEN_MASS_COMMITMENT = (
    "a009bf9f4e19aa2e44a291aaa994097d567617a8bf03e60e42bde83d78256988"
)
GOLDEN_PREIMAGE_LEN = 175

# The frozen construction inputs (mirrored in the driver's vector leg).
FROZEN_MEMBER_IDS = ["frozen-src-0", "frozen-src-1", "frozen-src-2"]
FROZEN_CONTENT_ID = "frozen-agg-root"
FROZEN_VERSION = 3


_BODY = r"""
import json, sys, os, tempfile, secrets, base64, hashlib, struct

def report(obj):
    print(json.dumps(obj)); sys.stdout.flush(); os._exit(0)

try:
    import ciris_persist as cp
    # CIRISEdge#328 §19.7.1.3 producer. The freeze gate must freeze the REFERENCE's
    # bytes, so the vector leg takes its preimage / member_commitment / mass_commitment
    # from edge — a Python rebuild would only freeze our own re-derivation of them.
    from ciris_edge.ciris_edge import assemble_tier_meta_v3
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


# §19.1 WholenessWitness Merkle. Retained as the documented scheme + a CROSS-IMPL
# ORACLE against edge's signed `member_commitment` — and as the only way to state the
# empty-set sentinel, which has no member set for a producer to fold.
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


TIER, ALGO, NFD, VERSION = 1, "raptorq-pyramid-v1", "mean+stddev", 3
AGG_CORPUS = "aggregate:trace"

# The frozen mass vector. Equal thirds → Kish n_eff == 3 (edge DERIVES the signed n_eff
# from these), and a fixed max_source_multiplicity of 1 (1·n_min(2) ≤ 3 → admits).
# `content_multiplicity` is deliberately NOT called: it measures real payload
# similarity, and random payloads are not freezable.
FROZEN_MASSES = [1.0 / 3, 1.0 / 3, 1.0 / 3]
FROZEN_MULT = 1

# ── Vector leg: the byte-exact #57 golden, produced by edge from the frozen inputs ──
FROZEN_IDS = ["frozen-src-0", "frozen-src-1", "frozen-src-2"]
FROZEN_CID = "frozen-agg-root"
frozen_meta = assemble_tier_meta_v3(FROZEN_CID, AGG_CORPUS, TIER, ALGO, FROZEN_IDS,
                                    FROZEN_MASSES, FROZEN_MULT, NFD)
frozen_pre = bytes(frozen_meta["signing_preimage"])
vector = {
    "version": frozen_meta["version"],
    "member_commitment": frozen_meta["member_commitment"].hex(),
    "mass_commitment": frozen_meta["mass_commitment"].hex(),
    "source_count": frozen_meta["source_count"],
    "n_eff": frozen_meta["n_eff"],
    "max_source_multiplicity": frozen_meta["max_source_multiplicity"],
    "preimage_sha256": hashlib.sha256(frozen_pre).hexdigest(),
    "preimage_len": len(frozen_pre),
    "ww_empty_root": sha256(WW_EMPTY).hex(),
    # cross-impl oracle: the documented WW-Merkle == edge's signed member_commitment.
    "member_commitment_py_matches_edge": (
        member_commitment(FROZEN_IDS) == frozen_meta["member_commitment"]),
}

# ── Wheel leg: admit a bound-hybrid agg-meta over the v3 binary preimage ──
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


def wheel_meta(cid):
    # The frozen construction, salted only in the content ids (postgres-safe): same
    # corpus/tier/algo/nfd, same equal-thirds masses, same max_source_multiplicity.
    return assemble_tier_meta_v3(cid, AGG_CORPUS, TIER, ALGO, member_ids,
                                 FROZEN_MASSES, FROZEN_MULT, NFD)


def agg_wire(meta, nfd, ed_sig, pqc_sig):
    cid = meta["content_id"]
    mc_hex = meta["member_commitment"].hex()
    ver = {"version": meta["version"], "content_id": cid, "corpus_kind": AGG_CORPUS,
           "tier": meta["tier"], "aggregation_algorithm_id": ALGO,
           "source_count": meta["source_count"], "n_eff": meta["n_eff"],
           "max_source_multiplicity": meta["max_source_multiplicity"],
           "member_commitment_hex": mc_hex,
           "mass_commitment_hex": meta["mass_commitment"].hex(),
           "noise_floor_descriptor": nfd,
           "sig_ed25519_b64": base64.b64encode(ed_sig).decode(),
           "sig_ml_dsa_65_b64": base64.b64encode(pqc_sig).decode()}
    return {"aggregate_content_id": cid, "source_corpus_kind": "trace",
            "aggregation_level": 1, "fan_in": meta["source_count"],
            "member_commitment": mc_hex,
            "aggregation_meta": base64.b64encode(b"opaque").decode(), "verification": ver}


# (1) admit over the exact v3 binary preimage → the substrate reconstructs it byte-for-byte.
ok_meta = wheel_meta(f"agg-frz-{NS}")
comp_man, comp_syms = build_content(ok_meta["content_id"], AGG_CORPUS)
pre = bytes(ok_meta["signing_preimage"])
ed_sig = as_bytes(eng.local_sign(pre))
pqc_sig = as_bytes(eng.local_pqc_sign(pre + ed_sig))
try:
    eng.put_aggregated_tier(json.dumps(comp_man), json.dumps(comp_syms),
                            json.dumps(agg_wire(ok_meta, NFD, ed_sig, pqc_sig)), 1)
    frozen_admit = {"result": "admit",
                    "observed": eng.get_aggregation(ok_meta["content_id"]) is not None,
                    "preimage_len": len(pre), "version": ok_meta["version"],
                    "content_id": ok_meta["content_id"]}
except Exception as exc:
    frozen_admit = {"result": "reject", "token": str(exc)}

# (2) mutate ONE signed field (noise_floor_descriptor) on the wire WITHOUT re-signing
#     → the substrate's reconstructed preimage differs by those bytes → reject.
mut_meta = wheel_meta(f"agg-mut-{NS}")
cm2, cs2 = build_content(mut_meta["content_id"], AGG_CORPUS)
pre2 = bytes(mut_meta["signing_preimage"])
ed2 = as_bytes(eng.local_sign(pre2))
pqc2 = as_bytes(eng.local_pqc_sign(pre2 + ed2))
wire2 = agg_wire(mut_meta, "TAMPERED", ed2, pqc2)   # signed NFD, wire NFD differ
try:
    eng.put_aggregated_tier(json.dumps(cm2), json.dumps(cs2), json.dumps(wire2), 1)
    mutated = {"result": "admit"}
except Exception as exc:
    mutated = {"result": "reject", "token": str(exc),
               "nothing_written": eng.get_aggregation(mut_meta["content_id"]) is None}

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
        pytest.fail(f"driver could not import the wheels: {payload.get('detail')}")
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

    Both hexes are UNCHANGED across the v2→v3 `AggregationMetaV1` bump — the §19.7.1.3
    cut moved the preimage tail, not the §19.1 Merkle — and the golden here is edge's
    own signed root, cross-checked against the documented Python recompute.
    """
    v = freeze["vector"]
    assert v["member_commitment"] == GOLDEN_MEMBER_COMMITMENT, v
    assert v["ww_empty_root"] == GOLDEN_WW_EMPTY_ROOT, v
    assert v["member_commitment_py_matches_edge"] is True, v


@pytest.mark.requires_persist
def test_aggregation_meta_v3_preimage_frozen(freeze):
    """CC 6.1.4 / CC 6.1.2.1: the SHA-256 of the **v3** `AggregationMetaV1` binary
    preimage matches its frozen #57 hex, at the frozen length (175 bytes).

    Freezes the CC 6.1.3 binary layout end to end: the 16-byte domain separator, the
    big-endian `u32` version/tier/source_count, the length-prefixed strings, the raw
    32-byte member_commitment, the v2 `u32_be(n_eff)`, and the v3 tail
    `u32_be(max_source_multiplicity) ‖ mass_commitment[32]`. A layout drift changes the
    preimage hash.

    This golden is an **explicit versioned re-freeze**, not a repaired one: the v2
    golden (139 bytes, `7962b1ee…`) broke loudly when CIRISVerify#191 moved the layout,
    which is precisely what a freeze gate is for. The re-cut is licensed by the version
    bump the preimage itself carries — `version == 3` is asserted here, so this golden
    cannot silently absorb a *future* layout change at the same version.
    """
    v = freeze["vector"]
    assert v["version"] == FROZEN_VERSION == 3, v
    assert v["preimage_sha256"] == GOLDEN_AGG_META_V3_PREIMAGE_SHA256, v
    assert v["preimage_len"] == GOLDEN_PREIMAGE_LEN, v
    # the frozen fold's derived/pinned scalars are themselves part of the vector
    assert v["source_count"] == len(FROZEN_MEMBER_IDS) == 3, v
    assert v["n_eff"] == 3, v            # equal thirds → Kish n_eff == N
    assert v["max_source_multiplicity"] == 1, v


@pytest.mark.requires_persist
def test_mass_commitment_frozen(freeze):
    """CC 6.1.4 / CC 6.1.2.1.2: the v3 `mass_commitment` — the Merkle over the
    `(member_id, mass_to_fixed(mass))` pairs at the pinned 1e6 fixed-point scale —
    matches its frozen #57 hex.

    This is the shape the v3 bump ADDED, so it is a new #57 vector rather than a re-cut
    one. Freezing it pins the mass fixed-point scale and the pair-leaf encoding: a
    change to either (e.g. a different rounding or a different scale) moves this root
    and, through the preimage tail, every v3 signature in the federation.
    """
    v = freeze["vector"]
    assert v["mass_commitment"] == GOLDEN_MASS_COMMITMENT, v
    assert len(v["mass_commitment"]) == 64, v          # a 32-byte root, hex


# ─── Wheel leg — admission byte-pins the substrate's preimage ─────────


@pytest.mark.requires_persist
def test_wheel_admits_the_frozen_preimage_construction(freeze):
    """CC 6.1.4: the substrate ADMITS a bound-hybrid `AggregationMetaV1` signed over
    exactly the frozen v3 preimage construction.

    `put_aggregated_tier` reconstructs the preimage from the wire fields and verifies
    the Ed25519+ML-DSA-65 halves against it (and runs both the dominance and the
    multiplicity gate over the same signed fields); an admit proves the substrate's
    preimage bytes are byte-identical to the #57 construction the vector leg froze —
    the wheel side of the freeze gate. The construction is the frozen one in every
    input except the content ids, which are salted per subprocess so a shared postgres
    backend never sees a cross-run collision.
    """
    fa = freeze["frozen_admit"]
    assert fa["result"] == "admit", fa
    assert fa["observed"] is True, fa
    assert fa["version"] == FROZEN_VERSION == 3, fa
    # The admitted preimage differs from the 175-byte golden by EXACTLY the salt in the
    # length-prefixed content_id and nothing else — the member ids enter only through
    # their fixed-width 32-byte Merkle root, so no other field can move. This pins the
    # wheel leg to the frozen LAYOUT, not merely to "some v3 preimage".
    expected_len = GOLDEN_PREIMAGE_LEN - len(FROZEN_CONTENT_ID) + len(fa["content_id"])
    assert fa["preimage_len"] == expected_len, fa


@pytest.mark.requires_persist
def test_one_byte_signed_field_mutation_breaks_admission(freeze):
    """CC 6.1.4: a one-byte change to a signed preimage field (without re-signing)
    is rejected — the freeze gate is byte-sensitive.

    The wire `noise_floor_descriptor` is changed after signing, so the substrate's
    reconstructed preimage differs from the signed bytes; admission fails
    `aggregation_meta_hybrid_required` and nothing is written. This proves the
    substrate hashes exactly the frozen bytes — a wire-byte change is a defect. The
    signed fold is otherwise fully valid at v3 (it clears both admission gates), so the
    rejection isolates the byte-sensitivity of the preimage itself.
    """
    m = freeze["mutated"]
    assert m["result"] == "reject", m
    assert "aggregation_meta_hybrid_required" in m["token"], m
    assert m["nothing_written"] is True, m
