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
  • the agg-meta signing preimage is BINARY (verify `holonomic/aggregation.rs`), and as
    of **`AggregationMetaV1` v3** (§19.7.1.3, CIRISVerify#191 / CIRISEdge#328) it appends
    `u32_be(max_source_multiplicity) ‖ mass_commitment[32]` to the v2 layout. Admission on
    persist ≥16 runs **BOTH** gates:
      – **dominance** (v2, unchanged): `2·n_eff ≥ source_count` — the Kish effective-source
        count `(Σmᵢ)²/Σmᵢ²`; a balanced fold signs `n_eff == source_count`.
      – **multiplicity** (v3, NEW): `max_source_multiplicity · n_min ≤ source_count`, with
        `n_min` corpus-pinned persist-side (default 2). Rejects `aggregation_meta_multiplicity`.
    A pre-v3 tier **fail-closes** — the CIRISVerify#191 flag-day, no deprecation window.

    **This file does NOT hand-roll the v3 preimage** (CIRISConformance#76). `mass_commitment`
    is a Merkle over `(member_id, mass_to_fixed(mass))` at a pinned 1e6 scale — rebuilding a
    SIGNED field in Python is exactly how you silently fork it. We call edge's producer
    (`content_multiplicity` → `assemble_tier_meta_v3`) and sign the canonical
    `signing_preimage` it hands back. The WW-Merkle `member_commitment` is still recomputed
    here, but ONLY as a cross-impl oracle (python == edge); the bytes we sign are edge's.

    Member payloads are independent high-entropy content: the v3 producer measures content
    SIMILARITY, so identical/structured payloads would form one near-duplicate cluster and
    be rejected. `test_r9_near_duplicate_multiplicity_rejected` drives that case on purpose —
    the CC 6.1.2.1.2 **R9 residual**: 900 near-duplicates under distinct ids at equal mass
    carry an HONEST `n_eff == 1000` and the dominance gate alone ADMITS them; only the
    multiplicity gate closes it;
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
    # CIRISEdge#328 v3 PRODUCER. The v3 signing preimage and `mass_commitment`
    # (a Merkle over (member_id, mass_to_fixed(mass)) at a pinned 1e6 scale) are
    # SIGNED fields — re-deriving them in Python is exactly how you silently fork
    # a signed field, so we take them from edge rather than rebuilding them.
    from ciris_edge.ciris_edge import content_multiplicity, assemble_tier_meta_v3
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


# NOTE: this file used to HAND-ROLL the §19.7.1 v2 signing preimage here and sign
# `version = 2`. On persist ≥16 that fail-closes with `aggregation_meta_multiplicity`
# — the CIRISVerify#191 flag-day working as designed (no deprecation window). The v3
# preimage appends `u32_be(max_source_multiplicity) ‖ mass_commitment[32]`, and
# `mass_commitment` is a Merkle over (member_id, mass_to_fixed(mass)) at a pinned 1e6
# scale. We do NOT rebuild any of that: `assemble_tier_meta_v3` hands us the canonical
# `signing_preimage` and we sign exactly those bytes (CIRISConformance#76).
#
# The member_commitment Merkle IS still recomputed below — but only as a CROSS-IMPL
# ORACLE (python recompute == edge's bytes), never as the thing we submit. That is a
# conformance check, not a fork: the bytes we sign always come from edge.


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


def build_content(cid, corpus, payload=None):
    # payload: the member's CONTENT bytes. It matters now — the §19.7.1.3 producer
    # measures content SIMILARITY across members, and the old fixed byte-pattern gave
    # every source an IDENTICAL payload → one near-duplicate cluster of 3 →
    # max_source_multiplicity == 3 → `aggregation_meta_multiplicity` (3·n_min > 3).
    # Real members are independent high-entropy content, so each source gets its own.
    if payload is None:
        payload = secrets.token_bytes(TOTAL * SYMBOL)
    symbols, hashes = [], []
    for i in range(TOTAL):
        b = payload[i * SYMBOL:(i + 1) * SYMBOL].ljust(SYMBOL, b"\0")
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
# Independent high-entropy payloads: real members are not near-duplicates, so the
# §19.7.1.3 producer measures max_source_multiplicity == 1 and the fold admits.
SOURCES = [(f"src-a-{NS}", "trace"), (f"src-b-{NS}", "trace"), (f"src-c-{NS}", "trace")]
SRC_PAYLOADS = [secrets.token_bytes(TOTAL * SYMBOL) for _ in SOURCES]
try:
    for (cid, corpus), payload in zip(SOURCES, SRC_PAYLOADS):
        man, syms = build_content(cid, corpus, payload)
        eng.put_fountain_content(json.dumps(man), json.dumps(syms))
except Exception as exc:
    report_error("source_admit", exc)

member_ids = [cid for cid, _ in SOURCES]

# ── build + admit the signed composite via put_aggregated_tier (v3) ──
AGG_CID = f"agg-root-{NS}"
AGG_LEVEL = 1
AGG_CORPUS = "aggregate:trace"            # aggregate_corpus_kind("trace")
V_TIER, V_ALGO, V_NFD = 1, "raptorq-pyramid-v1", "mean+stddev"


def build_agg_json(agg_cid, mem_ids, payloads, *, sig_content_id=None, blank_pqc=False):
    # §19.7.1.3 v3: MEASURE at fold time (edge is the only point holding the member
    # payloads), ASSEMBLE the v3 meta, SIGN edge's canonical `signing_preimage`, ADMIT.
    # sig_content_id forges a signed/wire content_id mismatch; blank_pqc drops the
    # ML-DSA-65 half (the classical-only hard-cut signal).
    m = content_multiplicity(payloads, AGG_CORPUS)
    signed_cid = sig_content_id if sig_content_id is not None else agg_cid
    meta = assemble_tier_meta_v3(signed_cid, AGG_CORPUS, V_TIER, V_ALGO, mem_ids,
                                 m["member_masses"], m["max_source_multiplicity"], V_NFD)
    pre = meta["signing_preimage"]                      # edge's bytes — never rebuilt
    ed_sig = as_bytes(eng.local_sign(pre))
    pqc_sig = b"" if blank_pqc else as_bytes(eng.local_pqc_sign(pre + ed_sig))
    mc_hex = meta["member_commitment"].hex()
    agg = {
        "aggregate_content_id": agg_cid,
        "source_corpus_kind": "trace",
        "aggregation_level": AGG_LEVEL,
        "fan_in": len(mem_ids),
        "member_commitment": mc_hex,
        "aggregation_meta": base64.b64encode(b"opaque-19.7-wire-payload").decode(),
        "verification": {
            "version": meta["version"],                              # 3
            "content_id": signed_cid,
            "corpus_kind": AGG_CORPUS,
            "tier": meta["tier"],
            "aggregation_algorithm_id": V_ALGO,
            "source_count": meta["source_count"],
            "n_eff": meta["n_eff"],
            "max_source_multiplicity": meta["max_source_multiplicity"],   # NEW (v3)
            "member_commitment_hex": mc_hex,
            "mass_commitment_hex": meta["mass_commitment"].hex(),         # NEW (v3)
            "noise_floor_descriptor": V_NFD,
            "sig_ed25519_b64": base64.b64encode(ed_sig).decode(),
            "sig_ml_dsa_65_b64": ("" if blank_pqc else base64.b64encode(pqc_sig).decode()),
        },
    }
    return agg, meta


agg, AGG_META = build_agg_json(AGG_CID, member_ids, SRC_PAYLOADS)
mc32 = AGG_META["member_commitment"]
MC_HEX = mc32.hex()
# CROSS-IMPL ORACLE: our documented WW-Merkle recompute must equal edge's signed
# member_commitment. We SUBMIT edge's bytes; this only proves they agree.
MC_PY_MATCHES_EDGE = (member_commitment(member_ids) == mc32)

comp_man, comp_syms = build_content(AGG_CID, AGG_CORPUS)
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
    "agg_meta_version": AGG_META["version"],                       # 3
    "n_eff_signed": AGG_META["n_eff"],
    "max_source_multiplicity": AGG_META["max_source_multiplicity"],
    "mass_commitment_present": len(AGG_META["mass_commitment"]) == 32,
    "member_commitment_py_matches_edge": bool(MC_PY_MATCHES_EDGE),
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
bad, _ = build_agg_json(AGG2, member_ids, SRC_PAYLOADS)
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
co, _ = build_agg_json(AGG3, member_ids, SRC_PAYLOADS, blank_pqc=True)
try:
    eng.put_aggregated_tier(json.dumps(cm3), json.dumps(cs3), json.dumps(co), 1)
    report["neg_classical_only"] = {"rejected": False}
except Exception as exc:
    report["neg_classical_only"] = {"rejected": True, "token": str(exc),
                                    "nothing_written": eng.get_aggregation(AGG3) is None}

# (N4) THE R9 RESIDUAL (CC 6.1.2.1.2 / CIRISVerify#191 / CIRISConformance#71).
# 900 near-duplicate contents folded as 900 DISTINCT members at equal mass, plus 100
# genuinely-distinct members. The masses are honest and uniform, so the fold signs an
# HONEST n_eff == 1000 and the dominance gate ADMITS it (2·1000 ≥ 1000) — mass-dominance
# cannot see multiplicity collapse below member granularity. The v3 multiplicity gate is
# what catches it: max_source_multiplicity == 900, and 900·n_min(2) > 1000 → REJECTED
# `aggregation_meta_multiplicity`. This is the case the entire cut exists to close, and
# the one case where the dominance gate alone honestly admits.
AGG_R9 = f"agg-r9-{NS}"
_base = secrets.token_bytes(TOTAL * SYMBOL)
_near = [bytes([_base[0] ^ (i & 0xFF)]) + _base[1:] for i in range(900)]  # near-dups, distinct bytes
_dist = [secrets.token_bytes(TOTAL * SYMBOL) for _ in range(100)]
r9_payloads = _near + _dist
r9_ids = [f"r9-{i}-{NS}" for i in range(1000)]
r9_agg, r9_meta = build_agg_json(AGG_R9, r9_ids, r9_payloads)
cmr, csr = build_content(AGG_R9, AGG_CORPUS)
r9 = {
    "n_eff_signed": r9_meta["n_eff"],                                  # honest ≈1000
    "max_source_multiplicity": r9_meta["max_source_multiplicity"],     # ≈900
    "source_count": r9_meta["source_count"],                           # 1000
    # the dominance gate ALONE would admit this fold — that is the whole point
    "dominance_gate_alone_would_admit": 2 * r9_meta["n_eff"] >= r9_meta["source_count"],
}
try:
    eng.put_aggregated_tier(json.dumps(cmr), json.dumps(csr), json.dumps(r9_agg), 1)
    r9["rejected"] = False
except Exception as exc:
    r9["rejected"] = True
    r9["token"] = str(exc)
    r9["nothing_written"] = eng.get_aggregation(AGG_R9) is None
report["neg_r9_multiplicity"] = r9

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
    §19.7.1 binary preimage, and on persist ≥16 BOTH `passes_dominance_gate` AND
    `passes_multiplicity_gate` must clear (a pre-v3 tier fail-closes with
    `aggregation_meta_multiplicity` — the CIRISVerify#191 flag-day, no deprecation
    window). The composite is assembled by edge's §19.7.1.3 producer and signed over
    edge's canonical `signing_preimage` — we never rebuild the signed bytes.
    """
    assert drive["signed_composite_admitted"] is True
    rec = drive["agg_record"]
    assert rec["aggregate_content_id"].startswith("agg-root-")
    assert rec["aggregation_level"] == 1
    assert rec["fan_in"] == drive["n_sources"] == 3
    assert rec["member_commitment"] == drive["member_commitment_hex"]
    assert len(drive["member_commitment_hex"]) == 64  # 32-byte root, hex
    # §19.7.1.3: the admitted composite is a v3 AggregationMetaV1.
    assert drive["agg_meta_version"] == 3, "must sign v3 — v2 fail-closes on persist ≥16"
    # dominance: a balanced fold signs n_eff == source_count (2·n_eff ≥ N).
    assert drive["n_eff_signed"] == drive["n_sources"] == 3
    # multiplicity: independent high-entropy members are not near-duplicates, so the
    # largest similarity cluster is a single member (1·n_min(2) ≤ 3 → admits).
    assert drive["max_source_multiplicity"] == 1
    assert drive["mass_commitment_present"] is True   # the 32-byte v3 Merkle is carried
    # CROSS-IMPL ORACLE: our documented WW-Merkle recompute equals edge's SIGNED
    # member_commitment. We submit edge's bytes; this proves the two impls agree.
    assert drive["member_commitment_py_matches_edge"] is True


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


@pytest.mark.fabric
@pytest.mark.requires_persist
def test_r9_near_duplicate_multiplicity_rejected(drive):
    """CC 6.1.2.1.2 R9 — the residual the whole v3 cut exists to close.

    900 near-duplicate contents folded as 900 **distinct members at equal mass**, plus
    100 genuinely-distinct members (N=1000). The masses are *honest*: uniform mass over
    1000 distinct member ids yields a truthful Kish `n_eff == 1000`, so the **dominance
    gate alone ADMITS this fold** (`2·n_eff ≥ source_count`). That is CC 6.1.2.1.2's
    stated honest limit — "mass-dominance is not content-similarity": multiplicity
    collapse *below member granularity* is invisible to any mass-based count, and the
    aggregator is not even lying.

    The v3 **multiplicity gate** is what closes it: the §19.7.1.3 producer measures
    `max_source_multiplicity == 900` (the largest content-similarity cluster) and persist
    rejects with the stable token `aggregation_meta_multiplicity`, because
    `max_source_multiplicity · n_min ≤ source_count` fails (900·2 > 1000).

    This asserts BOTH halves — that the old gate would have let it through, and that the
    new one does not — so it stays honest if either gate ever changes. (CIRISConformance#71,
    CIRISVerify#191, CIRISEdge#328, CIRISPersist#435.)
    """
    r9 = drive["neg_r9_multiplicity"]
    # The fold is honest and the OLD gate would have admitted it — the R9 bet.
    assert r9["source_count"] == 1000, r9
    assert r9["n_eff_signed"] >= 900, (
        f"the near-duplicate fold must carry an HONEST high n_eff (uniform masses over "
        f"1000 distinct members) — that is what makes it invisible to the dominance "
        f"gate: {r9}")
    assert r9["dominance_gate_alone_would_admit"] is True, (
        f"if the dominance gate alone no longer admits this fold, the R9 residual has "
        f"changed shape and this fixture is no longer testing it: {r9}")
    # The NEW multiplicity gate closes it.
    assert r9["max_source_multiplicity"] >= 900, (
        f"the content-similarity producer must see the 900-member near-duplicate "
        f"cluster: {r9}")
    assert r9["rejected"] is True, (
        f"the 900-near-duplicate fold was ADMITTED — the CC 6.1.2.1.2 multiplicity gate "
        f"is not enforced and the R9 residual is OPEN: {r9}")
    assert "aggregation_meta_multiplicity" in r9["token"], r9
    assert r9["nothing_written"] is True, r9
