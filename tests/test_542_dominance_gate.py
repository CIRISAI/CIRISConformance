"""
Fabric tier — CC 6.1.2 G-B / §19.7.1.2 the **dominance gate**, driven behaviorally
through persist's §19.7.1 aggregation-admission surface (CIRISVerify#167).

CC 1.0-rc1 G-B (part_6 §6.1.2 / §19.7.1.2). The N5 "already-erased" shortcut — a
composite blur contains `< 1/N` of any one source — holds only for **independent,
non-dominated** sources and *fails for outliers*: a 900/1000-dominated fold **is**
its dominant subject, so the blur is not erasure. verify 8.7.0 closed this bet with
a signed diversity witness: `AggregationMetaV1` **version-bumped to v2**, gaining a
signed `pub n_eff: u32` — the **Kish effective-source count**
`n_eff = (Σmᵢ)² / Σmᵢ²` (a balanced fold of N equal masses → `n_eff == N`; a
900/1000-dominated fold → `n_eff → 1`). Admission now runs `passes_dominance_gate`
at `put_aggregated_tier` and rejects a non-diverse (or n_eff-less) tier with the
stable token **`aggregation_meta_dominated`**.

This gate was the Rust-lane gap our earlier work pinned (verify exposes the pure
`EjectionVerdict`/diversity math; the enforcement point lives in the substrate) —
now enforced AND Python-drivable through `put_aggregated_tier`.

Observed real behavior (verify-core 8.7.0, probed, not assumed):

  • **Floor** (pinned): a v2 tier admits iff `2·n_eff ≥ source_count`
    (equivalently `n_eff ≥ ⌈N/2⌉`, the noise-floor ratio 0.5). Probed exactly:
    N=2→n_eff≥1, N=3→≥2, N=4→≥2, N=5→≥3, N=10→≥5. Below the floor →
    `aggregation_meta_dominated`; at/above → admitted.
  • **v1 is always dominated**: a version-1 tier carries no signed n_eff, so it is
    unconditionally rejected `aggregation_meta_dominated` ("a version-1 tier with no
    signed n_eff").
  • **The gate TRUSTS the signed n_eff** — it does NOT recompute it. `put_aggregated_tier`
    is passed no per-source masses (they are not a wire input at this surface), so the
    substrate cannot cross-check n_eff against a mass vector. A fold that LIES (masses
    dominated, but signs `n_eff == N`) is therefore **admitted**. Diversity is a
    signed *claim* by the aggregator, bound by the v2 preimage + bound-hybrid
    signature; the gate enforces only the floor on that signed value. (This is the
    CC 8.3.1 R9 acknowledged bet: member_commitment counts *which* members, n_eff is
    a signed count of *effective* members — neither is recomputed from raw content at
    the substrate.)

The signed §19.7.1 prerequisite is byte-identical to test_541's (WholenessWitness
member_commitment + AGG-META-v1 v2 preimage with u32_be(n_eff) appended); this file
reuses those helpers and varies only `source_count` / signed `n_eff`. The path is
Engine-only (no `init_edge_runtime`), so it is postgres-safe.

Spec: reference §6.1.2 (G-B / R,ε non-dominated-composite caveat) / §19.7.1.2;
verify `ciris-verify-core/src/holonomic/aggregation.rs::passes_dominance_gate`.
"""

from __future__ import annotations

import pytest

from conftest import get_database_url, run_python_script


# ─── The dominance-gate drive, run once in an isolated subprocess ──────
# Admits N source fountain contents, then hammers put_aggregated_tier with a
# matrix of (version, source_count, signed n_eff, mass-honesty) v2 AggregationMetaV1
# composites and records the exact admit/reject token for each — so every test
# below asserts one observed transition independently.

_DRIVE_BODY = r"""
import json, sys, os, tempfile, secrets, base64, hashlib, struct, math

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


# §19.1 WholenessWitness Merkle, reused verbatim by §19.7.1.1 member_commitment.
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


# §19.7.1.2 binary signing preimage — v2 appends u32_be(n_eff).
DOMAIN_AGG_META = b"AGG-META-v1\0\0\0\0\0"
assert len(DOMAIN_AGG_META) == 16
def _u32(n):
    return struct.pack(">I", n)
def _lp(b):
    if isinstance(b, str):
        b = b.encode("utf-8")
    return _u32(len(b)) + b
def agg_meta_preimage(version, content_id, corpus_kind, tier, algo, source_count,
                      mc32, nfd, n_eff, append_n_eff=True):
    pre = (DOMAIN_AGG_META + _u32(version) + _lp(content_id) + _lp(corpus_kind)
           + _u32(tier) + _lp(algo) + _u32(source_count) + mc32 + _lp(nfd))
    if append_n_eff:            # v1 has no n_eff slot (unconditionally dominated)
        pre += _u32(n_eff)
    return pre


# The Kish effective-source count n_eff = (Σmᵢ)² / Σmᵢ²; floor to a u32 for signing.
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
    return src


def try_admit(source_ids, mc32, source_count, n_eff, *, version=2, append_n_eff=True):
    # Build + attempt to admit a v(version) AggregationMetaV1 signing the given
    # n_eff; return {"result": "admit"|"reject", "token": ...}.
    agg_cid = f"agg-{secrets.token_hex(4)}-{NS}"
    comp_man, comp_syms = build_content(agg_cid, AGG_CORPUS)
    mc_hex = mc32.hex()
    pre = agg_meta_preimage(version, agg_cid, AGG_CORPUS, V_TIER, V_ALGO,
                            source_count, mc32, V_NFD, n_eff, append_n_eff=append_n_eff)
    ed_sig = as_bytes(eng.local_sign(pre))
    pqc_sig = as_bytes(eng.local_pqc_sign(pre + ed_sig))
    ver = {"version": version, "content_id": agg_cid, "corpus_kind": AGG_CORPUS,
           "tier": V_TIER, "aggregation_algorithm_id": V_ALGO,
           "source_count": source_count, "member_commitment_hex": mc_hex,
           "noise_floor_descriptor": V_NFD,
           "sig_ed25519_b64": base64.b64encode(ed_sig).decode(),
           "sig_ml_dsa_65_b64": base64.b64encode(pqc_sig).decode()}
    if append_n_eff:
        ver["n_eff"] = n_eff
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
    src = make_sources(N)
except Exception as exc:
    report_error("source_admit", exc)
ids = [c for c, _ in src]
mc32 = member_commitment(ids)
FLOOR = -(-N // 2)                              # ⌈N/2⌉ = 5

# The two folds' Kish n_eff (documents the math; floor→u32 is what gets signed).
balanced_masses = [1.0] * N                     # uniform → n_eff == N
dominated_masses = [900.0] + [100.0 / 9] * 9    # 900/1000 → n_eff ≈ 1.23
n_eff_balanced = effective_source_count(balanced_masses)
n_eff_dominated = effective_source_count(dominated_masses)
n_eff_dominated_u32 = int(math.floor(n_eff_dominated))

report = {
    "stage": "done",
    "persist_version": getattr(cp, "__version__", "?"),
    "N": N,
    "floor_n_eff": FLOOR,
    "n_eff_balanced": n_eff_balanced,
    "n_eff_dominated": n_eff_dominated,
    "n_eff_dominated_u32": n_eff_dominated_u32,
}

# (1) Balanced fold: signed n_eff == N → admitted.
report["balanced"] = try_admit(ids, mc32, N, N)

# (2) Dominated fold, TRUTHFUL low n_eff (⌊1.23⌋ = 1) → dominated reject.
report["dominated_truthful"] = try_admit(ids, mc32, N, n_eff_dominated_u32)

# (3) Dominated masses but a LYING signed n_eff == N → admitted (gate trusts the
#     signed value; put_aggregated_tier gets no masses to cross-check).
report["dominated_lie"] = try_admit(ids, mc32, N, N)

# (4) Floor boundary: exactly ⌈N/2⌉ admits, one below rejects.
report["at_floor"] = try_admit(ids, mc32, N, FLOOR)
report["below_floor"] = try_admit(ids, mc32, N, FLOOR - 1)

# (5) A v1 tier (no signed n_eff) is unconditionally dominated.
report["v1_no_n_eff"] = try_admit(ids, mc32, N, N, version=1, append_n_eff=False)

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
    §6.1.2 outlier that the naive `< 1/N` erasure shortcut fails on."""
    assert drive["n_eff_balanced"] == drive["N"] == 10
    assert 1.2 < drive["n_eff_dominated"] < 1.3
    assert drive["n_eff_dominated_u32"] == 1


# ─── The dominance gate (behavioral, at put_aggregated_tier) ──────────


@pytest.mark.fabric
@pytest.mark.requires_persist
def test_balanced_fold_admitted(drive):
    """A balanced fold (`n_eff == N`, uniform masses) clears the dominance gate —
    `put_aggregated_tier` succeeds and the composite is retrievable."""
    b = drive["balanced"]
    assert b["result"] == "admit", b
    assert b["observed"] is True, b


@pytest.mark.fabric
@pytest.mark.requires_persist
def test_dominated_fold_rejected(drive):
    """A dominated fold (900/1000) with a TRUTHFULLY-low signed `n_eff` (⌊1.23⌋=1,
    far below the ⌈N/2⌉=5 floor) is rejected `aggregation_meta_dominated`, and
    nothing is written — the CC 6.1.2 G-B non-dominated-composite gate."""
    d = drive["dominated_truthful"]
    assert d["result"] == "reject", d
    assert "aggregation_meta_dominated" in d["token"], d
    assert d["nothing_written"] is True, d


@pytest.mark.fabric
@pytest.mark.requires_persist
def test_gate_trusts_signed_n_eff_not_recomputed(drive):
    """The gate TRUSTS the signed n_eff — it does NOT recompute it. `put_aggregated_tier`
    is passed no per-source masses, so a fold with dominated masses that signs a
    LYING `n_eff == N` is admitted. Diversity is a signed aggregator *claim* bound by
    the v2 preimage; the substrate enforces only the floor on that signed value
    (the CC 8.3.1 R9 acknowledged bet). This pins the REAL observed behavior."""
    lie = drive["dominated_lie"]
    assert lie["result"] == "admit", lie
    assert lie["observed"] is True, lie


@pytest.mark.fabric
@pytest.mark.requires_persist
def test_dominance_floor_is_half_the_source_count(drive):
    """The pinned threshold: a v2 tier admits iff `2·n_eff ≥ source_count`
    (`n_eff ≥ ⌈N/2⌉`, the noise-floor ratio 0.5). At the floor (`n_eff == ⌈N/2⌉`)
    it admits; exactly one below rejects `aggregation_meta_dominated`."""
    assert drive["floor_n_eff"] == 5  # ⌈10/2⌉
    at = drive["at_floor"]
    below = drive["below_floor"]
    assert at["result"] == "admit", at
    assert below["result"] == "reject", below
    assert "aggregation_meta_dominated" in below["token"], below


@pytest.mark.fabric
@pytest.mark.requires_persist
def test_version_1_tier_has_no_signed_n_eff(drive):
    """A version-1 `AggregationMetaV1` carries no signed n_eff slot, so it is
    unconditionally rejected `aggregation_meta_dominated` — v2 (with the appended
    signed n_eff) is the only admissible shape under the dominance gate."""
    v1 = drive["v1_no_n_eff"]
    assert v1["result"] == "reject", v1
    assert "aggregation_meta_dominated" in v1["token"], v1
    assert v1["nothing_written"] is True, v1
