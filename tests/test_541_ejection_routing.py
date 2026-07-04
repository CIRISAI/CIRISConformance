"""
Fabric tier — CC 6.1.2.3 / §19.7.3 `EjectionVerdict` routing, driven behaviorally
through persist's §19.7 aggregation-descent surface (CIRISConformance#55 test #6).

CC 6.1.2.3 reframes revocation / retirement / capacity-eviction / aging as ONE
pressure-driven operator: a monotonic descent of an item's fidelity toward and
below the noise floor. The normative routing (verify `holonomic/aggregation.rs`
`ejection_verdict`) is:

  • `Withdrawn` (any pressure)          → `EjectHardDelete`  (fastest descent, NEVER tier-shed)
  • `Active` + capacity pressure        → `EjectToTier`      (one downward step, still recoverable)
  • `Active` + no pressure              → `Keep`             (retain at current fidelity)
  • plus the tier-granular             `EjectAggregatedTierOnly{tier}` (shed exactly one stratum)

There is NO `ejection_verdict` method on the Python surface — the verdict is a
verify-core pure function persist consumes internally. This gate drives it
**behaviorally** through persist 12.2.0's §19.7 aggregation-descent surface and
asserts the OBSERVED storage effect matches each verdict:

  • `descend_aggregated_sources(agg_cid, sources_json, consent, under_pressure, target_tier)`
    — §19.7.1.1 descent-integrity gated (the caller's source ids MUST re-derive
    the composite's stored `member_commitment`) then §19.7.3-routed;
  • `evict_aggregated_tier(agg_cid, tier)` — the `EjectAggregatedTierOnly` stratum-shed;
  • `get_aggregation` / `get_fountain_content` — observe the effect.

Probed signatures (persist 12.2.0):
  descend_aggregated_sources($self, aggregate_content_id, sources_json, consent,
                             under_capacity_pressure, target_tier=None) -> int
    - `consent`   : STRING enum, one of "active" | "withdrawn" | "unknown"
    - `pressure`  : BOOL (the §19.7.3 capacity-pressure flag)
    - `target_tier`: STRING "full"|"t2".."t5" or None (the tier used on a tier-shed)
    - returns the total source symbol rows evicted.
  evict_aggregated_tier($self, aggregate_content_id, tier:int) -> int  (rows shed)
  put_aggregated_tier($self, manifest_json, symbols_json, agg_json, aggregated_at_unix_ms)

The hard prerequisite — a signed §19.7.1 `AggregationMetaV1` — IS reproducible
byte-exact from Python (persist 12.2.0 runs the PQC-mandatory store-path gate at
admission; the stale v8.3.0 method docstring saying "NOT verified this cut" is
wrong — the source `AggregationMetaV1::verify_for_admission` runs
`verify_aggregation_meta`). The build:
  • `member_commitment` = the §19.1 WholenessWitness Merkle over the member
    content_ids: `leaf = SHA256(utf8(content_id))`, sort the RAW content-id bytes
    lexicographically BEFORE hashing, duplicate the last node on odd counts,
    empty-set sentinel `SHA256(b"WW-v1-empty")` (verify `holonomic/wholeness_witness.rs`
    `compute_merkle_root`, reused verbatim by `member_commitment`);
  • the agg-meta signing preimage is BINARY (verify `holonomic/aggregation.rs:73`):
    `b"AGG-META-v1\\0\\0\\0\\0\\0" ‖ u32_be(version) ‖ lp(content_id) ‖ lp(corpus_kind)
    ‖ u32_be(tier) ‖ lp(aggregation_algorithm_id) ‖ u32_be(source_count) ‖
    member_commitment[32] ‖ lp(noise_floor_descriptor) ‖ u32_be(n_eff)`,
    `lp(x)=u32_be(len)‖utf8(x)`. §19.7.1.2 (CC 6.1.2 G-B, CIRISVerify#167): verify
    8.7.0 **version-bumped `AggregationMetaV1` to v2** — the struct gained a signed
    `pub n_eff: u32` (the Kish effective-source count `(Σmᵢ)²/Σmᵢ²`) appended to the
    preimage, and admission now runs a **dominance gate**. A v1 tier (no signed
    n_eff) is ALWAYS rejected `aggregation_meta_dominated`; a v2 tier is admitted
    only when `2·n_eff ≥ source_count` (n_eff ≥ ⌈N/2⌉, the noise-floor ratio 0.5).
    A balanced fold signs `n_eff == source_count`;
  • signed bound-hybrid: `ed = local_sign(preimage)`, `pqc = local_pqc_sign(preimage ‖ ed)`,
    aggregator pubkeys resolved off the composite manifest envelope.

Composite content itself uses the fountain sign recipe: manifest canonical =
`json.dumps(value, sort_keys=True, separators=(",",":"))`, `ed=local_sign(canonical)`,
`pqc=local_pqc_sign(canonical+ed)`.

Real green gate (not xfail): the signed composite build succeeds and every verdict's
observed storage effect is asserted, including the two negative gates
(`aggregation_meta_member_commitment` for a forged member set, `aggregation_meta_hybrid_required`
for a tampered/classical-only agg-meta signature). The aggregation path uses only the
Engine (no `init_edge_runtime`), so it is postgres-safe.

Spec: reference §19.7.3 / CC 6.1.2.3; verify `ciris-verify-core/src/holonomic/aggregation.rs`.
"""

from __future__ import annotations

import pytest

from conftest import get_database_url, run_python_script


# ─── The full §19.7 descent drive, run once in an isolated subprocess ──
# Admits 3 source fountain contents + a signed composite (put_aggregated_tier),
# then drives descend_aggregated_sources across the whole §19.7.3 verdict matrix
# in monotonic-descent order (Keep → EjectToTier → EjectHardDelete), the
# EjectAggregatedTierOnly stratum-shed, and the two negative gates. Captures
# before/after storage observations so each test asserts an exact transition
# independent of the others.

_DRIVE_BODY = r"""
import json, sys, os, tempfile, secrets, base64, hashlib, struct

def report_error(stage, detail):
    print(json.dumps({"_error": stage, "detail": str(detail)})); sys.exit(2)

try:
    import ciris_persist as cp
except ImportError as exc:
    report_error("import", exc)


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


# §19.1 WholenessWitness Merkle, reused verbatim by §19.7.1.1 member_commitment
# (verify holonomic/wholeness_witness.rs::compute_merkle_root): sort the RAW leaf
# bytes lexicographically, THEN leaf = SHA256(bytes); node = SHA256(l ‖ r); odd
# node duplicates the last; empty set → SHA256(b"WW-v1-empty").
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


# §19.7.1 binary signing preimage (verify holonomic/aggregation.rs:73 +
# preimage.rs Preimage builder: u32-BE ints, u32-BE length-prefixed strings,
# fixed 32-byte member_commitment raw).
DOMAIN_AGG_META = b"AGG-META-v1\0\0\0\0\0"
assert len(DOMAIN_AGG_META) == 16
def _u32(n):
    return struct.pack(">I", n)
def _lp(b):
    if isinstance(b, str):
        b = b.encode("utf-8")
    return _u32(len(b)) + b
def agg_meta_preimage(version, content_id, corpus_kind, tier, algo, source_count, mc32, nfd, n_eff):
    # §19.7.1.2 (verify 8.7.0): AggregationMetaV1 v2 appends u32_be(n_eff) — the
    # signed Kish effective-source count — after the noise_floor_descriptor.
    return (DOMAIN_AGG_META + _u32(version) + _lp(content_id) + _lp(corpus_kind)
            + _u32(tier) + _lp(algo) + _u32(source_count) + mc32 + _lp(nfd) + _u32(n_eff))


# ── engine (bound-hybrid: agg-meta + composite manifest are both PQC-mandatory) ──
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

# Unique content-id namespace per subprocess so a shared (postgres) backend
# doesn't collide across the suite.
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


def fstate(cid, corpus):
    r = eng.get_fountain_content(cid, corpus)
    return json.loads(r) if r else None


# ── admit 3 source fountain contents (the descent fan-in) ──
SOURCES = [(f"src-a-{NS}", "trace"), (f"src-b-{NS}", "trace"), (f"src-c-{NS}", "trace")]
try:
    for cid, corpus in SOURCES:
        man, syms = build_content(cid, corpus)
        eng.put_fountain_content(json.dumps(man), json.dumps(syms))
except Exception as exc:
    report_error("source_admit", exc)

member_ids = [cid for cid, _ in SOURCES]
mc32 = member_commitment(member_ids)
MC_HEX = mc32.hex()

# ── build + admit the signed composite via put_aggregated_tier ──
AGG_CID = f"agg-root-{NS}"
AGG_LEVEL = 1
AGG_CORPUS = "aggregate:trace"            # aggregate_corpus_kind("trace")
V_VERSION, V_TIER, V_ALGO, V_NFD = 2, 1, "raptorq-pyramid-v1", "mean+stddev"
# §19.7.1.2 dominance gate: a balanced fold signs n_eff == source_count (uniform
# masses → Kish n_eff == N), which clears the noise-floor ratio (2·n_eff ≥ N).
V_N_EFF = len(member_ids)


def build_agg_json(agg_cid, member_commitment_hex, mc_bytes, *,
                   sig_content_id=None, blank_pqc=False):
    # A persist AggregationMetaV1 JSON with a real 19.7.1 bound-hybrid agg-meta
    # signature over the verify-core preimage. sig_content_id overrides the
    # signed/wire content_id (used to forge a mismatch); blank_pqc drops the
    # ML-DSA-65 half (the classical-only hard-cut signal).
    content_id = sig_content_id if sig_content_id is not None else agg_cid
    pre = agg_meta_preimage(V_VERSION, content_id, AGG_CORPUS, V_TIER, V_ALGO,
                            len(member_ids), mc_bytes, V_NFD, V_N_EFF)
    ed_sig = as_bytes(eng.local_sign(pre))
    pqc_sig = b"" if blank_pqc else as_bytes(eng.local_pqc_sign(pre + ed_sig))
    return {
        "aggregate_content_id": agg_cid,
        "source_corpus_kind": "trace",
        "aggregation_level": AGG_LEVEL,
        "fan_in": len(member_ids),
        "member_commitment": member_commitment_hex,
        "aggregation_meta": base64.b64encode(b"opaque-19.7-wire-payload").decode(),
        "verification": {
            "version": V_VERSION,
            "content_id": content_id,
            "corpus_kind": AGG_CORPUS,
            "tier": V_TIER,
            "aggregation_algorithm_id": V_ALGO,
            "source_count": len(member_ids),
            "n_eff": V_N_EFF,
            "member_commitment_hex": member_commitment_hex,
            "noise_floor_descriptor": V_NFD,
            "sig_ed25519_b64": base64.b64encode(ed_sig).decode(),
            "sig_ml_dsa_65_b64": ("" if blank_pqc else base64.b64encode(pqc_sig).decode()),
        },
    }


comp_man, comp_syms = build_content(AGG_CID, AGG_CORPUS)
agg = build_agg_json(AGG_CID, MC_HEX, mc32)
try:
    eng.put_aggregated_tier(json.dumps(comp_man), json.dumps(comp_syms),
                            json.dumps(agg), 1234567890)
    composite_admitted = True
except Exception as exc:
    report_error("composite_admit", exc)

rec = json.loads(eng.get_aggregation(AGG_CID))

sources_json = json.dumps([[cid, corpus] for cid, corpus in SOURCES])
SRC0, SRC0_CORPUS = SOURCES[0]


def src0_present():
    return fstate(SRC0, SRC0_CORPUS)["present"]


def src0_state():
    return fstate(SRC0, SRC0_CORPUS)["state"]


# ── drive the §19.7.3 verdict matrix in monotonic-descent order ──
report = {
    "stage": "done",
    "persist_version": getattr(cp, "__version__", "?"),
    "signed_composite_admitted": bool(composite_admitted),
    "agg_record": {k: rec[k] for k in
                   ("aggregate_content_id", "aggregation_level", "fan_in", "member_commitment")},
    "member_commitment_hex": MC_HEX,
    "agg_meta_version": V_VERSION,
    "n_eff_signed": V_N_EFF,
    "n_sources": len(SOURCES),
    "symbols_per_source": TOTAL,
    "consent_encoding": "string:active|withdrawn|unknown",
    "pressure_encoding": "bool",
    "target_tier_encoding": "string:full|t2..t5|None",
}

# (1) Active + no pressure → Keep (unchanged).
before = src0_present()
n = eng.descend_aggregated_sources(AGG_CID, sources_json, "active", False, None)
report["keep"] = {"evicted": n, "before": before,
                  "after": src0_present(), "state_after": src0_state()}

# (2) Active + capacity pressure + target t3 → EjectToTier (degraded, still present).
before = src0_present()
n = eng.descend_aggregated_sources(AGG_CID, sources_json, "active", True, "t3")
report["eject_to_tier"] = {"evicted": n, "before": before,
                           "after": src0_present(), "state_after": src0_state()}

# (3) Withdrawn → EjectHardDelete (purged below the floor, any pressure).
before = src0_present()
n = eng.descend_aggregated_sources(AGG_CID, sources_json, "withdrawn", False, None)
report["hard_delete"] = {"evicted": n, "before": before,
                         "after": src0_present(), "state_after": src0_state()}

# descend NEVER touches the composite (collective gist persists below the floor).
report["composite_untouched_by_descend"] = eng.get_aggregation(AGG_CID) is not None
comp_before = fstate(AGG_CID, AGG_CORPUS)
report["composite_present_before_shed"] = comp_before["present"]

# (4) EjectAggregatedTierOnly → shed exactly the tier-`level` composite stratum.
shed = eng.evict_aggregated_tier(AGG_CID, AGG_LEVEL)
comp_after = fstate(AGG_CID, AGG_CORPUS)
wrong = eng.evict_aggregated_tier(AGG_CID, AGG_LEVEL + 1)   # wrong stratum → no-op
report["stratum_shed"] = {
    "rows": shed,
    "present_after": comp_after["present"],
    "state_after": comp_after["state"],
    "record_survives": eng.get_aggregation(AGG_CID) is not None,
    "wrong_tier_rows": wrong,
}

# ── negative gates ──
# (N1) forged member set at descent → §19.7.1.1 descent-integrity reject.
forged = json.dumps([[f"EVIL-{NS}", "trace"], [SOURCES[1][0], "trace"], [SOURCES[2][0], "trace"]])
try:
    eng.descend_aggregated_sources(AGG_CID, forged, "active", True, "t3")
    report["neg_forged_member"] = {"rejected": False}
except Exception as exc:
    report["neg_forged_member"] = {"rejected": True, "token": str(exc)}

# (N2) tampered agg-meta signature at admission → PQC store-path reject, nothing written.
AGG2 = f"agg-tamper-{NS}"
cm2, cs2 = build_content(AGG2, AGG_CORPUS)
# Build a fully-valid signed agg for AGG2, then TAMPER a signed field
# (noise_floor_descriptor) WITHOUT re-signing → the reconstructed preimage no
# longer matches the ed/pqc signatures → verify_aggregation_meta fails.
bad = build_agg_json(AGG2, MC_HEX, mc32)
bad["verification"]["noise_floor_descriptor"] = "TAMPERED"
try:
    eng.put_aggregated_tier(json.dumps(cm2), json.dumps(cs2), json.dumps(bad), 1)
    report["neg_tampered_sig"] = {"rejected": False}
except Exception as exc:
    report["neg_tampered_sig"] = {"rejected": True, "token": str(exc),
                                  "nothing_written": eng.get_aggregation(AGG2) is None}

# (N3) classical-only agg-meta (empty ML-DSA-65 half) → PQC-mandatory reject.
AGG3 = f"agg-classical-{NS}"
cm3, cs3 = build_content(AGG3, AGG_CORPUS)
co = build_agg_json(AGG3, MC_HEX, mc32, blank_pqc=True)
try:
    eng.put_aggregated_tier(json.dumps(cm3), json.dumps(cs3), json.dumps(co), 1)
    report["neg_classical_only"] = {"rejected": False}
except Exception as exc:
    report["neg_classical_only"] = {"rejected": True, "token": str(exc),
                                    "nothing_written": eng.get_aggregation(AGG3) is None}

print(json.dumps(report)); sys.stdout.flush()
sys.exit(0)
"""


def _drive_script(database_url: str) -> str:
    return f"DB_URL = {database_url!r}\n" + _DRIVE_BODY


@pytest.fixture(scope="module")
def drive():
    result = run_python_script(_drive_script(get_database_url()), timeout=90.0)
    payload = result.parsed_stdout()
    if "_error" in payload:
        pytest.fail(
            f"§19.7 descent drive failed at stage {payload['_error']!r}: "
            f"{payload.get('detail')}\nSTDERR:\n{result.stderr}"
        )
    assert payload.get("stage") == "done", payload
    return payload


# ─── The signed §19.7.1 prerequisite ──────────────────────────────────


@pytest.mark.fabric
@pytest.mark.requires_persist
def test_signed_aggregation_meta_admitted(drive):
    """A byte-exact bound-hybrid `AggregationMetaV1` passes the PQC-mandatory
    store-path gate — the composite + its §19.7.1 provenance are admitted.

    This is the hard prerequisite: `put_aggregated_tier` runs
    `AggregationMetaV1::verify_for_admission` → `verify_aggregation_meta` over the
    §19.7.1 binary preimage (WholenessWitness member_commitment + AGG-META-v1
    domain), so a Python-built composite that admits proves the whole preimage +
    Merkle reconstruction is reproducible from the spec text alone.
    """
    assert drive["signed_composite_admitted"] is True
    rec = drive["agg_record"]
    assert rec["aggregate_content_id"].startswith("agg-root-")
    assert rec["aggregation_level"] == 1
    assert rec["fan_in"] == drive["n_sources"] == 3
    # The stored navigation commitment is the WholenessWitness Merkle we computed.
    assert rec["member_commitment"] == drive["member_commitment_hex"]
    assert len(drive["member_commitment_hex"]) == 64  # 32-byte root, hex
    # §19.7.1.2: the admitted composite is a v2 AggregationMetaV1 carrying a signed
    # n_eff == source_count (a balanced fold) — clears the dominance gate.
    assert drive["agg_meta_version"] == 2
    assert drive["n_eff_signed"] == drive["n_sources"] == 3


# ─── The §19.7.3 verdict routing (behavioral) ─────────────────────────


@pytest.mark.fabric
@pytest.mark.requires_persist
def test_active_no_pressure_keeps(drive):
    """`Active` + no pressure → `Keep`: descent is a no-op, sources unchanged."""
    keep = drive["keep"]
    assert keep["evicted"] == 0, keep
    assert keep["after"] == keep["before"] == drive["symbols_per_source"], keep
    assert keep["state_after"] == "full", keep


@pytest.mark.fabric
@pytest.mark.requires_persist
def test_active_pressure_ejects_to_tier(drive):
    """`Active` + capacity pressure + `target_tier` → `EjectToTier`: sources are
    degraded to the tier (still present, fewer symbols) — one downward step."""
    ejt = drive["eject_to_tier"]
    # A real number of symbol rows were evicted across the 3 sources...
    assert ejt["evicted"] > 0, ejt
    # ...and the observed source dropped to a strictly-lower present count but is
    # NOT purged (still recoverable — the descent-not-to-zero contract).
    assert 0 < ejt["after"] < ejt["before"], ejt
    assert ejt["state_after"] == "partial", ejt


@pytest.mark.fabric
@pytest.mark.requires_persist
def test_withdrawn_hard_deletes(drive):
    """`Withdrawn` → `EjectHardDelete`: sources purged below the floor (present=0,
    EnvelopeOnly). N5: revocation is the fastest descent, never a tier-shed."""
    hd = drive["hard_delete"]
    assert hd["evicted"] > 0, hd
    assert hd["after"] == 0, hd
    assert hd["state_after"] == "envelope_only", hd


@pytest.mark.fabric
@pytest.mark.requires_persist
def test_descend_never_touches_the_composite(drive):
    """Descent evicts SOURCES, never the composite (the collective gist persists
    below the floor forever — O(log T) memory). The aggregation record and the
    composite's own symbols survive the whole source-descent matrix."""
    assert drive["composite_untouched_by_descend"] is True
    # The composite's own fountain symbols are still fully present after every
    # source-level descent step ran.
    assert drive["composite_present_before_shed"] == drive["symbols_per_source"]


@pytest.mark.fabric
@pytest.mark.requires_persist
def test_evict_aggregated_tier_sheds_exactly_one_stratum(drive):
    """`EjectAggregatedTierOnly{tier}` → shed exactly the tier-`level` composite
    stratum: the composite's symbols are dropped (manifest survives as
    EnvelopeOnly provenance, the aggregation record survives), and a wrong-tier
    request is a no-op (never resurrects / never sheds the wrong stratum)."""
    shed = drive["stratum_shed"]
    assert shed["rows"] == drive["symbols_per_source"], shed
    assert shed["present_after"] == 0, shed
    assert shed["state_after"] == "envelope_only", shed
    assert shed["record_survives"] is True, shed
    assert shed["wrong_tier_rows"] == 0, shed


# ─── Negative gates ───────────────────────────────────────────────────


@pytest.mark.fabric
@pytest.mark.requires_persist
def test_forged_member_set_rejected_at_descent(drive):
    """§19.7.1.1 descent integrity: a source set that does NOT re-derive the
    stored `member_commitment` cannot drive eviction — rejected with the stable
    `aggregation_meta_member_commitment` token."""
    neg = drive["neg_forged_member"]
    assert neg["rejected"] is True, neg
    assert "aggregation_meta_member_commitment" in neg["token"], neg


@pytest.mark.fabric
@pytest.mark.requires_persist
def test_tampered_agg_meta_signature_rejected(drive):
    """PQC-mandatory store-path gate: an agg-meta whose signed preimage does not
    match its wire fields fails `verify_aggregation_meta` — rejected
    (`aggregation_meta_hybrid_required`) and NOTHING is written."""
    neg = drive["neg_tampered_sig"]
    assert neg["rejected"] is True, neg
    assert "aggregation_meta_hybrid_required" in neg["token"], neg
    assert neg["nothing_written"] is True, neg


@pytest.mark.fabric
@pytest.mark.requires_persist
def test_classical_only_agg_meta_rejected(drive):
    """§19.0 PQC-mandatory: an agg-meta with an empty ML-DSA-65 half is the
    classical-only hard-cut signal — rejected before persistence
    (`aggregation_meta_hybrid_required`), nothing written."""
    neg = drive["neg_classical_only"]
    assert neg["rejected"] is True, neg
    assert "aggregation_meta_hybrid_required" in neg["token"], neg
    assert neg["nothing_written"] is True, neg
