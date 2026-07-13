"""
Fabric tier — CC 6.1.2 G-B / §19.7.1.2 the **dominance gate**, driven behaviorally
through persist's §19.7.1 aggregation-admission surface (CIRISVerify#167).

CC 1.0-rc1 G-B (part_6 §6.1.2 / §19.7.1.2). The N5 "already-erased" shortcut — a
composite blur contains `< 1/N` of any one source — holds only for **independent,
non-dominated** sources and *fails for outliers*: a 900/1000-dominated fold **is**
its dominant subject, so the blur is not erasure. verify 8.7.0 closed this bet with
a signed diversity witness: `AggregationMetaV1` version-bumped to v2, gaining a
signed `pub n_eff: u32` — the **Kish effective-source count**
`n_eff = (Σmᵢ)² / Σmᵢ²` (a balanced fold of N equal masses → `n_eff == N`; a
900/1000-dominated fold → `n_eff → 1`). Admission runs `passes_dominance_gate` at
`put_aggregated_tier` and rejects a non-diverse (or n_eff-less) tier with the stable
token **`aggregation_meta_dominated`**.

verify 10.1.1 / edge 11.1.1 then bumped `AggregationMetaV1` **v2 → v3**
(CIRISVerify#191 / CIRISEdge#328): the preimage appends
`u32_be(max_source_multiplicity) ‖ mass_commitment[32]` after the v2 layout, and
admission now runs **BOTH** `passes_dominance_gate` AND `passes_multiplicity_gate`
(`max_source_multiplicity · n_min ≤ source_count`, `n_min` corpus-pinned persist-side,
default 2). A pre-v3 tier **fail-closes** — see `test_v2_tier_fail_closes_on_the_flag_day`.

Observed real behavior (persist 16.1.0 / verify 10.1.1, probed, not assumed):

  • **Floor** (pinned): a tier admits iff `2·n_eff ≥ source_count` (equivalently
    `n_eff ≥ ⌈N/2⌉`, the noise-floor ratio 0.5). Probed exactly across the whole
    sweep: N=2→n_eff≥1, N=3→≥2, N=4→≥2, N=5→≥3, N=10→≥5. Below the floor →
    `aggregation_meta_dominated`; at/above → admitted.
  • **v1 is always dominated**: a version-1 tier carries no signed n_eff, so it is
    unconditionally rejected `aggregation_meta_dominated`.
  • **v2 now fail-closes** `aggregation_meta_multiplicity` (the flag day, no
    deprecation window) — it carries no signed `max_source_multiplicity`, and the
    multiplicity gate cannot be satisfied by a field that is not there.
  • **The gate TRUSTS the signed n_eff — it does NOT recompute it.** This is the
    load-bearing R9 observation and it SURVIVES the v3 bump. `put_aggregated_tier`
    is passed no per-source masses (they are not a wire input at this surface), so
    a fold that LIES (dominated masses, but signs `n_eff == N`) is **admitted**.
    v3 does narrow the residual: `mass_commitment` is a Merkle over the *actual*
    `(member_id, mass)` pairs, so the lie is now **provable after the fact** — open
    the commitment and the dominated mass vector is bound to the same signature that
    claims `n_eff == N`. But it is still **NOT recomputable at admission**: the
    substrate holds only the 32-byte root and cannot invert a Merkle root to recover
    the masses. Diversity therefore remains a signed *claim*, bound (and now also
    *committed*) by the aggregator; the gate enforces only the floor on the signed
    value. The CC 8.3.1 R9 limit — "the gate trusts the signed n_eff" — still holds;
    what changed is that it is now non-repudiable, not that it is checked.

**Adversarial hand-roll (deliberate).** Unlike test_541 — which drives edge's honest
v3 producer end-to-end — this file must sweep `(version, source_count, signed n_eff)`
*independently*, including signing a fold whose masses are dominated while claiming
`n_eff == N`. An honest producer REFUSES to lie: `assemble_tier_meta_v3` DERIVES
`n_eff` from the masses it is handed, so the lie case is unreachable through it. So
we hand-roll the preimage **LAYOUT** only (v3 = the v2 bytes ‖ `u32_be(max_source_multiplicity)`
‖ `mass_commitment[32]`, byte-verified against edge's `signing_preimage` as a
cross-impl oracle in `test_handrolled_v3_layout_matches_edge`) and take both signed
Merkle roots — `member_commitment` AND `mass_commitment` — **from edge**. We never
re-derive a Merkle in Python: rebuilding a signed field is exactly how you silently
fork it. The lie is constructed by signing edge's `mass_commitment` **over the
dominated masses** while the preimage carries `n_eff == N` — the sharpest possible
form of the R9 residual.

Every dominance case signs `max_source_multiplicity == 1` so the multiplicity gate
passes cleanly and the **dominance** gate is what is under test.

The path is Engine-only (no `init_edge_runtime`), so it is postgres-safe.

Spec: reference §6.1.2 (G-B / R,ε non-dominated-composite caveat) / §19.7.1.2 / §19.7.1.3;
verify `ciris-verify-core/src/holonomic/aggregation.rs::{passes_dominance_gate,
passes_multiplicity_gate}`.
"""

from __future__ import annotations

import pytest

from conftest import get_database_url, run_python_script


# ─── The dominance-gate drive, run once in an isolated subprocess ──────
# Admits N source fountain contents, then hammers put_aggregated_tier with a
# matrix of (version, source_count, signed n_eff, mass-honesty) AggregationMetaV1
# composites and records the exact admit/reject token for each — so every test
# below asserts one observed transition independently.

_DRIVE_BODY = r"""
import json, sys, os, tempfile, secrets, base64, hashlib, struct, math

def report_error(stage, detail):
    print(json.dumps({"_error": stage, "detail": str(detail)})); sys.exit(2)

try:
    import ciris_persist as cp
    # CIRISEdge#328 v3 producer. We call it ONLY to obtain the two SIGNED Merkle
    # roots (`member_commitment` over the member ids, `mass_commitment` over the
    # (member_id, mass_to_fixed(mass)) pairs at a pinned 1e6 scale). Re-deriving a
    # signed Merkle in Python is exactly how you silently fork it — so we don't.
    # The PREIMAGE LAYOUT is hand-rolled below, on purpose: this file has to sign a
    # LIE (dominated masses, n_eff == N) and an honest producer refuses to lie.
    from ciris_edge.ciris_edge import assemble_tier_meta_v3
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


# §19.7.1 binary signing preimage. v2 appends u32_be(n_eff); **v3** (CIRISVerify#191)
# further appends u32_be(max_source_multiplicity) ‖ mass_commitment[32]. Only the
# LAYOUT is rebuilt here — every byte of `mc32` / `mass32` comes from edge, and the
# whole construction is byte-checked against edge's own `signing_preimage` below.
DOMAIN_AGG_META = b"AGG-META-v1\0\0\0\0\0"
assert len(DOMAIN_AGG_META) == 16
def _u32(n):
    return struct.pack(">I", n)
def _lp(b):
    if isinstance(b, str):
        b = b.encode("utf-8")
    return _u32(len(b)) + b
def agg_meta_preimage(version, content_id, corpus_kind, tier, algo, source_count,
                      mc32, nfd, n_eff, max_mult, mass32):
    pre = (DOMAIN_AGG_META + _u32(version) + _lp(content_id) + _lp(corpus_kind)
           + _u32(tier) + _lp(algo) + _u32(source_count) + mc32 + _lp(nfd))
    if version >= 2:            # v1 has no n_eff slot (unconditionally dominated)
        pre += _u32(n_eff)
    if version >= 3:            # v3 tail: the CIRISVerify#191 multiplicity witness
        pre += _u32(max_mult) + mass32
    return pre


# The Kish effective-source count n_eff = (Σmᵢ)² / Σmᵢ²; floor to a u32 for signing.
# (Documents the math the gate witnesses; edge derives the signed value identically.)
def effective_source_count(masses):
    s1 = sum(masses)
    s2 = sum(m * m for m in masses)
    return (s1 * s1) / s2


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
V_TIER, V_ALGO, V_NFD = 1, "raptorq-pyramid-v1", "mean+stddev"
V3, V2, V1 = 3, 2, 1


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


def make_sources(n):
    src = [(f"s{i}-{NS}-{secrets.token_hex(3)}", "trace") for i in range(n)]
    for cid, corpus in src:
        man, syms = build_content(cid, corpus)
        eng.put_fountain_content(json.dumps(man), json.dumps(syms))
    return [c for c, _ in src]


def edge_commitments(member_ids, masses):
    # The two SIGNED Merkle roots, straight from edge's v3 producer. Neither depends
    # on the composite's content_id (it is a separate preimage field), so one call
    # serves every admit attempt over the same (members, masses). We also keep edge's
    # DERIVED n_eff and its canonical `signing_preimage` — the latter is the oracle
    # our hand-rolled LAYOUT is byte-compared against.
    meta = assemble_tier_meta_v3(ORACLE_CID, AGG_CORPUS, V_TIER, V_ALGO, member_ids,
                                 masses, 1, V_NFD)
    return {"mc32": meta["member_commitment"], "mass32": meta["mass_commitment"],
            "n_eff": meta["n_eff"], "source_count": meta["source_count"],
            "preimage": bytes(meta["signing_preimage"])}


ORACLE_CID = f"agg-oracle-{NS}"


def try_admit(mc32, mass32, source_count, n_eff, *, version=V3, max_mult=1):
    # Build + attempt to admit a v(version) AggregationMetaV1 signing the given
    # n_eff / max_source_multiplicity; return {"result": "admit"|"reject", "token": ...}.
    agg_cid = f"agg-{secrets.token_hex(4)}-{NS}"
    comp_man, comp_syms = build_content(agg_cid, AGG_CORPUS)
    mc_hex = mc32.hex()
    pre = agg_meta_preimage(version, agg_cid, AGG_CORPUS, V_TIER, V_ALGO,
                            source_count, mc32, V_NFD, n_eff, max_mult, mass32)
    ed_sig = as_bytes(eng.local_sign(pre))
    pqc_sig = as_bytes(eng.local_pqc_sign(pre + ed_sig))
    ver = {"version": version, "content_id": agg_cid, "corpus_kind": AGG_CORPUS,
           "tier": V_TIER, "aggregation_algorithm_id": V_ALGO,
           "source_count": source_count, "member_commitment_hex": mc_hex,
           "noise_floor_descriptor": V_NFD,
           "sig_ed25519_b64": base64.b64encode(ed_sig).decode(),
           "sig_ml_dsa_65_b64": base64.b64encode(pqc_sig).decode()}
    if version >= V2:
        ver["n_eff"] = n_eff
    if version >= V3:
        ver["max_source_multiplicity"] = max_mult
        ver["mass_commitment_hex"] = mass32.hex()
    agg = {"aggregate_content_id": agg_cid, "source_corpus_kind": "trace",
           "aggregation_level": 1, "fan_in": source_count, "member_commitment": mc_hex,
           "aggregation_meta": base64.b64encode(b"opaque").decode(), "verification": ver}
    try:
        eng.put_aggregated_tier(json.dumps(comp_man), json.dumps(comp_syms),
                                json.dumps(agg), 1)
        # Admission implies the composite is retrievable — confirm the observed effect.
        admitted = eng.get_aggregation(agg_cid) is not None
        return {"result": "admit", "token": None, "observed": admitted}
    except Exception as exc:
        return {"result": "reject", "token": str(exc),
                "nothing_written": eng.get_aggregation(agg_cid) is None}


# ── build one N=10 source set reused across the diversity cases ──
N = 10
try:
    ids = make_sources(N)
except Exception as exc:
    report_error("source_admit", exc)
FLOOR = -(-N // 2)                              # ⌈N/2⌉ = 5

# The two folds' masses. `balanced` is what an honest producer would fold; `dominated`
# is the §6.1.2 outlier. edge derives the SIGNED n_eff from each (Kish), and commits to
# each mass vector in its own `mass_commitment` — so the LIE case below signs the
# *dominated* mass commitment while claiming the *balanced* n_eff.
balanced_masses = [1.0] * N                     # uniform → n_eff == N
dominated_masses = [900.0] + [100.0 / 9] * 9    # 900/1000 → n_eff ≈ 1.23
n_eff_balanced = effective_source_count(balanced_masses)
n_eff_dominated = effective_source_count(dominated_masses)
n_eff_dominated_u32 = int(math.floor(n_eff_dominated))

try:
    BAL = edge_commitments(ids, balanced_masses)
    DOM = edge_commitments(ids, dominated_masses)
except Exception as exc:
    report_error("edge_commitments", exc)

# CROSS-IMPL ORACLE: our hand-rolled v3 LAYOUT must reproduce edge's own canonical
# `signing_preimage` byte-for-byte (same members, masses, multiplicity, content_id).
# That is what licenses the adversarial hand-roll below: we vary only the fields under
# test, on a layout the producer itself agrees with.
oracle_pre = agg_meta_preimage(V3, ORACLE_CID, AGG_CORPUS, V_TIER, V_ALGO,
                               BAL["source_count"], BAL["mc32"], V_NFD,
                               BAL["n_eff"], 1, BAL["mass32"])
LAYOUT_MATCHES_EDGE = (oracle_pre == BAL["preimage"])

report = {
    "stage": "done",
    "persist_version": getattr(cp, "__version__", "?"),
    "N": N,
    "floor_n_eff": FLOOR,
    "n_eff_balanced": n_eff_balanced,
    "n_eff_dominated": n_eff_dominated,
    "n_eff_dominated_u32": n_eff_dominated_u32,
    # edge's own DERIVED n_eff for each mass vector — the honest producer's answer.
    "edge_n_eff_balanced": BAL["n_eff"],
    "edge_n_eff_dominated": DOM["n_eff"],
    # the v3 layout oracle
    "handrolled_layout_matches_edge": bool(LAYOUT_MATCHES_EDGE),
    "handrolled_preimage_len": len(oracle_pre),
    "edge_preimage_len": len(BAL["preimage"]),
    "mass_commitments_differ_by_masses": BAL["mass32"] != DOM["mass32"],
}

# (1) Balanced fold: signed n_eff == N → admitted.
report["balanced"] = try_admit(BAL["mc32"], BAL["mass32"], N, N)

# (2) Dominated fold, TRUTHFUL low n_eff (edge derives ⌊1.23⌋ = 1) → dominated reject.
report["dominated_truthful"] = try_admit(DOM["mc32"], DOM["mass32"], N, DOM["n_eff"])

# (3) Dominated masses (edge's mass_commitment over THEM) but a LYING signed
#     n_eff == N → admitted. The gate trusts the signed value; put_aggregated_tier
#     gets no masses, and it cannot invert the 32-byte mass_commitment to find them.
report["dominated_lie"] = try_admit(DOM["mc32"], DOM["mass32"], N, N)

# (4) Floor boundary swept across the whole probed family: at ⌈N/2⌉ admits, one
#     below rejects. max_source_multiplicity is 1 throughout, so the multiplicity
#     gate (1·n_min(2) ≤ N) passes and DOMINANCE is what is under test.
sweep = {}
for n in (2, 3, 4, 5, 10):
    try:
        sids = make_sources(n)
    except Exception as exc:
        report_error("source_admit", exc)
    sc = edge_commitments(sids, [1.0 / n] * n)
    floor = -(-n // 2)
    sweep[str(n)] = {
        "floor": floor,
        "at_floor": try_admit(sc["mc32"], sc["mass32"], n, floor),
        "below_floor": try_admit(sc["mc32"], sc["mass32"], n, floor - 1),
    }
report["floor_sweep"] = sweep
report["at_floor"] = sweep["10"]["at_floor"]
report["below_floor"] = sweep["10"]["below_floor"]

# (5) A v1 tier (no signed n_eff) is unconditionally dominated.
report["v1_no_n_eff"] = try_admit(BAL["mc32"], BAL["mass32"], N, N, version=V1)

# (6) THE FLAG DAY (CIRISVerify#191): a v2 tier — a perfectly-formed, correctly-signed,
#     non-dominated v2 AggregationMetaV1 that admitted cleanly on persist 15 — now
#     FAIL-CLOSES `aggregation_meta_multiplicity`. It carries no signed
#     max_source_multiplicity, so the multiplicity gate cannot be satisfied. No
#     deprecation window: the same bytes that were valid yesterday are rejected today.
report["v2_flag_day"] = try_admit(BAL["mc32"], BAL["mass32"], N, N, version=V2)

print(json.dumps(report)); sys.stdout.flush()
sys.exit(0)
"""


def _drive_script(database_url: str) -> str:
    return f"DB_URL = {database_url!r}\n" + _DRIVE_BODY


@pytest.fixture(scope="module")
def drive():
    result = run_python_script(_drive_script(get_database_url()), timeout=120.0)
    payload = result.parsed_stdout()
    if "_error" in payload:
        pytest.fail(
            f"dominance-gate drive failed at stage {payload['_error']!r}: "
            f"{payload.get('detail')}\nSTDERR:\n{result.stderr}"
        )
    assert payload.get("stage") == "done", payload
    return payload


# ─── The math the gate witnesses ──────────────────────────────────────


@pytest.mark.fabric
@pytest.mark.requires_persist
def test_kish_effective_source_count(drive):
    """The Kish participation ratio `n_eff = (Σmᵢ)²/Σmᵢ²` folds N equal masses to
    exactly N, and collapses the 900/1000 outlier fold to ≈1.23 (⌊⌋ = 1) — the
    §6.1.2 outlier that the naive `< 1/N` erasure shortcut fails on.

    Cross-checked against edge's v3 producer, which DERIVES the signed n_eff from the
    masses it is handed: it independently reports N for the balanced fold and 1 for
    the dominated one.
    """
    assert drive["n_eff_balanced"] == drive["N"] == 10
    assert 1.2 < drive["n_eff_dominated"] < 1.3
    assert drive["n_eff_dominated_u32"] == 1
    # the honest producer agrees, from the masses alone
    assert drive["edge_n_eff_balanced"] == 10, drive
    assert drive["edge_n_eff_dominated"] == 1, drive


@pytest.mark.fabric
@pytest.mark.requires_persist
def test_handrolled_v3_layout_matches_edge(drive):
    """The oracle that licenses this file's adversarial hand-roll: the v3 preimage
    LAYOUT rebuilt here — the v2 bytes ‖ `u32_be(max_source_multiplicity)` ‖
    `mass_commitment[32]` — reproduces edge's own canonical `signing_preimage`
    byte-for-byte for the same (content_id, members, masses, multiplicity).

    This file must vary `version` / `source_count` / signed `n_eff` independently, and
    must sign a fold that LIES about its own diversity — neither is reachable through
    `assemble_tier_meta_v3`, which derives n_eff from the masses and refuses to lie. So
    the layout is hand-rolled, but the two SIGNED Merkle roots (`member_commitment`,
    `mass_commitment`) are always edge's bytes, never re-derived here. This test proves
    the hand-roll is a faithful re-serialization and not a private fork of the format.
    """
    assert drive["handrolled_layout_matches_edge"] is True, drive
    assert drive["handrolled_preimage_len"] == drive["edge_preimage_len"], drive
    # the v3 tail is real: mass_commitment is a function OF the masses, so the balanced
    # and dominated folds commit to different roots over the same member set.
    assert drive["mass_commitments_differ_by_masses"] is True, drive


# ─── The dominance gate (behavioral, at put_aggregated_tier) ──────────


@pytest.mark.fabric
@pytest.mark.requires_persist
def test_balanced_fold_admitted(drive):
    """A balanced fold (`n_eff == N`, uniform masses, `max_source_multiplicity == 1`)
    clears BOTH gates — `put_aggregated_tier` succeeds and the composite is
    retrievable."""
    b = drive["balanced"]
    assert b["result"] == "admit", b
    assert b["observed"] is True, b


@pytest.mark.fabric
@pytest.mark.requires_persist
def test_dominated_fold_rejected(drive):
    """A dominated fold (900/1000) with a TRUTHFULLY-low signed `n_eff` (⌊1.23⌋=1,
    far below the ⌈N/2⌉=5 floor) is rejected `aggregation_meta_dominated`, and
    nothing is written — the CC 6.1.2 G-B non-dominated-composite gate.

    `max_source_multiplicity == 1` here, so the multiplicity gate passes and the
    rejection is unambiguously the DOMINANCE gate."""
    d = drive["dominated_truthful"]
    assert d["result"] == "reject", d
    assert "aggregation_meta_dominated" in d["token"], d
    assert d["nothing_written"] is True, d


@pytest.mark.fabric
@pytest.mark.requires_persist
def test_gate_trusts_signed_n_eff_not_recomputed(drive):
    """The R9 residual, re-pinned at v3: the gate TRUSTS the signed n_eff — it does
    NOT recompute it. A fold whose `mass_commitment` commits to *dominated* masses
    while its preimage claims `n_eff == N` is **admitted**.

    Be precise about what v3 changed here. The v3 preimage now appends
    `mass_commitment` — a Merkle over the actual `(member_id, mass_to_fixed(mass))`
    pairs — so the aggregator's mass vector is *bound to the very signature that
    claims `n_eff == N`*. The lie is therefore **provable after the fact**: open the
    commitment (the aggregator, or anyone holding the masses, can) and the dominated
    vector is non-repudiably attached to the diversity claim it contradicts.

    What v3 did NOT do is make the lie **recomputable at admission**. `put_aggregated_tier`
    receives no per-source masses — only the 32-byte root — and a Merkle root cannot be
    inverted. The substrate literally has nothing to cross-check `n_eff` against. So
    diversity remains a signed aggregator *claim*, and the gate enforces only the floor
    on that claim: the CC 8.3.1 R9 limit is narrowed from "undetectable" to
    "non-repudiable but undetected-at-admission", not closed. This pins the REAL
    observed behavior, exactly as it behaves.
    """
    lie = drive["dominated_lie"]
    assert lie["result"] == "admit", lie
    assert lie["observed"] is True, lie
    # the lie is a real lie: the SIGNED mass_commitment is the one over the dominated
    # masses (from which edge itself derives n_eff == 1), yet n_eff == 10 was admitted.
    assert drive["edge_n_eff_dominated"] == 1, drive
    assert drive["mass_commitments_differ_by_masses"] is True, drive


@pytest.mark.fabric
@pytest.mark.requires_persist
def test_dominance_floor_is_half_the_source_count(drive):
    """The pinned threshold, swept across the whole probed family: a tier admits iff
    `2·n_eff ≥ source_count` (`n_eff ≥ ⌈N/2⌉`, the noise-floor ratio 0.5).

    Probed exactly at N=2→n_eff≥1, N=3→≥2, N=4→≥2, N=5→≥3, N=10→≥5. At the floor it
    admits; exactly one below it rejects `aggregation_meta_dominated` and nothing is
    written. `max_source_multiplicity == 1` throughout, so the multiplicity gate is
    satisfied (1·n_min(2) ≤ N for every N in the sweep) and only the dominance floor
    can move the verdict.
    """
    assert drive["floor_n_eff"] == 5  # ⌈10/2⌉
    expected_floor = {"2": 1, "3": 2, "4": 2, "5": 3, "10": 5}
    sweep = drive["floor_sweep"]
    assert set(sweep) == set(expected_floor), sweep
    for n, floor in expected_floor.items():
        case = sweep[n]
        assert case["floor"] == floor, (n, case)
        at, below = case["at_floor"], case["below_floor"]
        assert at["result"] == "admit", (n, at)
        assert at["observed"] is True, (n, at)
        assert below["result"] == "reject", (n, below)
        assert "aggregation_meta_dominated" in below["token"], (n, below)
        assert below["nothing_written"] is True, (n, below)


@pytest.mark.fabric
@pytest.mark.requires_persist
def test_version_1_tier_has_no_signed_n_eff(drive):
    """A version-1 `AggregationMetaV1` carries no signed n_eff slot, so it is
    unconditionally rejected `aggregation_meta_dominated` — the dominance gate has
    no signed value to enforce its floor against."""
    v1 = drive["v1_no_n_eff"]
    assert v1["result"] == "reject", v1
    assert "aggregation_meta_dominated" in v1["token"], v1
    assert v1["nothing_written"] is True, v1


@pytest.mark.fabric
@pytest.mark.requires_persist
def test_v2_tier_fail_closes_on_the_flag_day(drive):
    """CIRISVerify#191 / CIRISEdge#328 — the v2→v3 **flag day**, with no deprecation
    window.

    The tier admitted here is a perfectly-formed v2 `AggregationMetaV1`: correctly
    signed over the v2 binary preimage, carrying an honest non-dominated
    `n_eff == N == source_count`, over a real member set. It cleared admission on
    persist 15 (it IS the shape the rest of this file used to sign). On persist 16.1.0
    it **fail-closes** with `aggregation_meta_multiplicity` and nothing is written —
    it carries no signed `max_source_multiplicity`, and `passes_multiplicity_gate`
    cannot be satisfied by a field that does not exist in the preimage.

    That is the whole point of a flag day: the dominance gate would have admitted this
    tier (2·10 ≥ 10), and it is rejected anyway. Only v3 is admissible.
    """
    v2 = drive["v2_flag_day"]
    assert v2["result"] == "reject", v2
    assert "aggregation_meta_multiplicity" in v2["token"], v2
    assert v2["nothing_written"] is True, v2
    # the same (n_eff, source_count) at v3 admits — so version, not diversity, is the
    # thing that closed the door.
    assert drive["balanced"]["result"] == "admit", drive
