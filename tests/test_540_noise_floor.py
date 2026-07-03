"""
Fabric tier — CC 6.1.2 noise floor: Full / Partial / EnvelopeOnly classification
and N5 revocation → below-floor descent (CIRISConformance#55 tests #1 + #2).

CC 6.1 gives content a *fountain* shape: a bound-hybrid-signed manifest
(Ed25519 + ML-DSA-65, verified at ingest) plus `n_source + k_repair` erasure
symbols. The **noise floor** is the classification of how much of that content is
still recoverable from the symbols currently held:

  • **Full**       — enough symbols to reconstruct the original (all `n_source`
                     source symbols recoverable).
  • **Partial**    — some symbols remain but fewer than `n_source`; still at or
                     above `min_viable_symbols`, so partial recovery is possible.
  • **EnvelopeOnly** — symbols have fallen *below* `min_viable_symbols`; nothing
                     is reconstructable, but the signed manifest (the envelope)
                     survives. This is the noise floor: provenance is retained
                     even when payload is gone — descent NEVER goes to zero.

This is drivable end-to-end on the Python wheel (persist 12.2.0) via the real
fountain surface: `Engine.put_fountain_content(manifest_json, symbols_json)`
admits a signed fountain; `Engine.get_fountain_content(cid, corpus)` returns
`{"state": "full"|"partial"|"envelope_only", "present": <int>, "manifest": ...}`
— that IS the classification surface. Two eviction verbs drive descent:
`evict_fountain_content_to_tier(cid, corpus, tier)` (capacity-pressure descent
down a retention ladder) and `evict_fountain_content_hard_delete(cid, corpus)`
(N5 revocation — purge every symbol regardless of retention priority).

────────────────────────────────────────────────────────────────────────────
OBSERVED tier → present → state mapping (persist 12.2.0, fresh engine per tier,
n_source=10, k_repair=4, symbol_size=16, min_viable=3, total=14 symbols admitted):

    admit         present=14   state=full           (all present)
    tier "t2"     present=10   state=full           (drops k_repair; keeps n_source)
    tier "t3"     present= 7   state=partial        (min_viable ≤ present < n_source)
    tier "t4"     present= 3   state=partial        (present == min_viable, still partial)
    tier "t5"     present= 0   state=envelope_only  (present < min_viable → floor)
    hard_delete   present= 0   state=envelope_only  (dropped == 14; manifest survives)

The valid tier vocabulary is exactly `full | t2 | t3 | t4 | t5` (any other tier
name is rejected `unknown fountain tier`). The classification crossings observed
are consistent with `FountainContent::classify(present, n_source, min_viable)`
being pinned in parallel on the CIRISServer Rust lane: Full = all source
symbols present (present ≥ n_source), Partial = min_viable ≤ present < n_source,
EnvelopeOnly = present < min_viable. The manifest is present in EVERY state,
including envelope_only — the floor is envelope-only provenance, never nothing.

Backend parity: the fountain path uses only the Engine (never init_edge_runtime),
so both sqlite and postgres are exercised without the CIRISPersist#354 edge-runtime
abort. Each content id is salted with a per-subprocess token so a shared postgres
database never sees a cross-run cid collision.

Spec: reference/CIRIS_Constitution/part_6_the_coherence_mathematics.md §6.1.2 (CC 6.1).
"""

from __future__ import annotations

import pytest

from conftest import get_database_url, run_python_script

pytestmark = pytest.mark.fabric

# The fountain geometry these gates pin their crossings against.
N_SOURCE, K_REPAIR, SYMBOL_SIZE, MIN_VIABLE = 10, 4, 16, 3
TOTAL_SYMBOLS = N_SOURCE + K_REPAIR  # 14

# The observed tier → (present, state) descent ladder. Pinned from a real
# discovery pass (see module docstring); flips RED if persist changes the ladder.
EXPECTED_TIER_LADDER = {
    "t2": (10, "full"),           # sheds k_repair; all n_source still present
    "t3": (7, "partial"),         # min_viable ≤ present < n_source
    "t4": (3, "partial"),         # present == min_viable (boundary is partial)
    "t5": (0, "envelope_only"),   # present < min_viable → noise floor
}

# The valid tier vocabulary persist accepts (from the rejection message).
VALID_TIERS = ("full", "t2", "t3", "t4", "t5")


# ─── Real fountain admit-and-observe driver ───────────────────────────
# One subprocess admits several independent signed fountains and drives the
# real eviction verbs, returning a structured report the tests assert on. The
# signing recipe is the proven bound-hybrid one: canonical manifest JSON signed
# Ed25519, then ML-DSA-65 over (canonical || ed_sig), verified at ingest.

_DRIVER_BODY = r"""
import json, sys, os, tempfile, secrets, base64, hashlib
try:
    import ciris_persist as cp
except ImportError as exc:
    print(json.dumps({"_error": "import", "detail": str(exc)})); sys.exit(2)

N_SOURCE, K_REPAIR, SYMBOL, MIN_VIABLE = 10, 4, 16, 3
TOTAL = N_SOURCE + K_REPAIR
CORPUS = "trace"
SALT = secrets.token_hex(6)  # per-subprocess cid salt → no postgres cross-run collision

_d = tempfile.mkdtemp()
_s = os.path.join(_d, "s"); open(_s, "wb").write(secrets.token_bytes(32))
_p = os.path.join(_d, "p"); open(_p, "wb").write(secrets.token_bytes(32))
cp.reset_engine()
_k = "node-" + secrets.token_hex(8)
engine = cp.Engine(DB_URL, _k, local_key_id=_k, local_key_path=_s,
                   local_pqc_key_id=_k + "-pqc", local_pqc_key_path=_p)

for _name in ("put_fountain_content", "get_fountain_content",
              "evict_fountain_content_to_tier", "evict_fountain_content_hard_delete"):
    if not hasattr(engine, _name):
        print(json.dumps({"_error": "absent", "missing": _name})); sys.exit(2)

def as_bytes(x):
    if isinstance(x, (bytes, bytearray)): return bytes(x)
    if isinstance(x, str): return base64.b64decode(x)
    if isinstance(x, list): return bytes(x)
    raise TypeError(type(x))

def admit(cid, *, top_priority_symbol=None):
    ed_pub = engine.local_public_key_b64()
    pqc_pub = engine.local_pqc_public_key_b64()
    pqc_kid = engine.local_pqc_key_id()
    symbols, symbol_hashes = [], []
    for i in range(TOTAL):
        b = bytes((i*31 + 7 + j) & 0xFF for j in range(SYMBOL))
        symbol_hashes.append(hashlib.sha256(b).hexdigest())
        # retention_priority normally == symbol_id; optionally spike one symbol's
        # priority to prove rarity can't resurrect it past a hard delete.
        prio = i if top_priority_symbol is None else (
            255 if i == top_priority_symbol else i)  # retention_priority is a u8
        symbols.append({"content_id": cid, "symbol_id": i,
                        "retention_priority": prio, "symbol_bytes": list(b)})
    envelope = {"content_id": cid, "pubkey_ed25519": ed_pub, "pubkey_ml_dsa_65": pqc_pub}
    cv = {"content_id": cid, "corpus_kind": CORPUS, "manifest_version": 1,
          "n_source": N_SOURCE, "k_repair": K_REPAIR, "symbol_size": SYMBOL,
          "original_content_length": N_SOURCE*SYMBOL, "min_viable_symbols": MIN_VIABLE,
          "symbol_hashes": symbol_hashes, "envelope": envelope}
    canonical = json.dumps(cv, sort_keys=True, separators=(",", ":")).encode()
    ed_sig = as_bytes(engine.local_sign(canonical))
    pqc_sig = as_bytes(engine.local_pqc_sign(canonical + ed_sig))
    manifest = dict(cv)
    manifest.update({"signature": base64.b64encode(ed_sig).decode(),
                     "signature_ml_dsa_65": base64.b64encode(pqc_sig).decode(),
                     "pqc_key_id": pqc_kid})
    engine.put_fountain_content(json.dumps(manifest), json.dumps(symbols))

def observe(cid):
    r = engine.get_fountain_content(cid, CORPUS)
    if not r:
        return {"present": None, "state": None, "has_manifest": False,
                "manifest_content_id": None}
    obj = json.loads(r)
    man = obj.get("manifest")
    return {"present": obj.get("present"), "state": obj.get("state"),
            "has_manifest": man is not None,
            "manifest_content_id": (man or {}).get("content_id")}

report = {"n_source": N_SOURCE, "k_repair": K_REPAIR, "min_viable": MIN_VIABLE,
          "total": TOTAL}

# Baseline: a freshly admitted fountain is Full with every symbol present.
_base_cid = f"nf-base-{SALT}"
admit(_base_cid)
report["baseline"] = observe(_base_cid)

# Gate #1 — per-tier capacity descent. Fresh content per tier so each crossing is
# measured from Full, isolating the tier → present → state mapping.
tiers = {}
for tier in ("t2", "t3", "t4", "t5"):
    cid = f"nf-{tier}-{SALT}"
    admit(cid)
    before = observe(cid)
    dropped = engine.evict_fountain_content_to_tier(cid, CORPUS, tier)
    after = observe(cid)
    tiers[tier] = {"before": before, "dropped": dropped, "after": after}
report["tiers"] = tiers

# The tier vocabulary: an unknown tier name must be rejected (pins the ladder set).
_voc_cid = f"nf-voc-{SALT}"
admit(_voc_cid)
try:
    engine.evict_fountain_content_to_tier(_voc_cid, CORPUS, "t9-not-a-tier")
    report["unknown_tier"] = "accepted"
except Exception as exc:
    report["unknown_tier"] = str(exc)[:120]

# Gate #2 — N5 revocation hard delete. Spike symbol 0's retention_priority so we
# prove rarity/priority can't hold it above the floor against revocation.
_hd_cid = f"nf-hd-{SALT}"
admit(_hd_cid, top_priority_symbol=0)
report["hd_before"] = observe(_hd_cid)
report["hd_dropped"] = engine.evict_fountain_content_hard_delete(_hd_cid, CORPUS)
report["hd_after"] = observe(_hd_cid)
report["hd_cid"] = _hd_cid

report["stage"] = "done"
print(json.dumps(report)); sys.stdout.flush()
sys.exit(0)
"""


def _driver_script(database_url: str) -> str:
    return f"DB_URL = {database_url!r}\n" + _DRIVER_BODY


@pytest.fixture(scope="module")
def floor():
    result = run_python_script(_driver_script(get_database_url()))
    payload = result.parsed_stdout()
    if payload.get("_error") == "import":
        pytest.fail(f"driver could not import ciris_persist: {payload.get('detail')}")
    if payload.get("_error") == "absent":
        pytest.fail("fountain surface missing on the wheel: "
                    f"{payload.get('missing')} is not on Engine")
    assert payload.get("stage") == "done", payload
    # Guard: a freshly admitted fountain MUST classify Full with every symbol
    # present, else the descent crossings below would pass for the wrong reason.
    base = payload["baseline"]
    assert base["state"] == "full" and base["present"] == TOTAL_SYMBOLS, payload
    return payload


# ─── Gate #1 — below-floor classification (behavioral) ────────────────


@pytest.mark.requires_persist
def test_tier_descent_crosses_full_partial_envelope(floor):
    """CC 6.1.2 #1: capacity-pressure descent crosses Full → Partial → EnvelopeOnly.

    Driving `evict_fountain_content_to_tier` down the real retention ladder
    reproduces the pinned tier → present → state mapping: t2 keeps all n_source
    symbols (Full), t3/t4 land in the Partial band (min_viable ≤ present <
    n_source), and t5 drops below min_viable → EnvelopeOnly (the noise floor).
    The signed manifest is retained in every state — descent never zeroes.
    """
    tiers = floor["tiers"]
    for tier, (exp_present, exp_state) in EXPECTED_TIER_LADDER.items():
        after = tiers[tier]["after"]
        assert after["present"] == exp_present, (
            f"tier {tier}: present={after['present']}, expected {exp_present}; "
            f"full ladder={tiers}")
        assert after["state"] == exp_state, (
            f"tier {tier}: state={after['state']!r}, expected {exp_state!r}; "
            f"full ladder={tiers}")
        # Provenance survives at every rung, including the floor.
        assert after["has_manifest"], (
            f"tier {tier}: manifest lost at present={after['present']} — the "
            f"envelope must survive at every rung; full={tiers}")


@pytest.mark.requires_persist
def test_classification_boundaries_are_consistent(floor):
    """CC 6.1.2 #1: the observed states honor the classify(present,n_source,min_viable) boundaries.

    Cross-checks the crossings against the boundary predicate the CIRISServer
    Rust lane pins in parallel — Full ⇔ present ≥ n_source, Partial ⇔ min_viable
    ≤ present < n_source, EnvelopeOnly ⇔ present < min_viable — over every
    (present, state) pair the descent produced (baseline + all four tiers).
    """
    n_source, min_viable = floor["n_source"], floor["min_viable"]
    samples = [(floor["baseline"]["present"], floor["baseline"]["state"])]
    for tier in ("t2", "t3", "t4", "t5"):
        after = floor["tiers"][tier]["after"]
        samples.append((after["present"], after["state"]))

    for present, state in samples:
        if present >= n_source:
            expected = "full"
        elif present >= min_viable:
            expected = "partial"
        else:
            expected = "envelope_only"
        assert state == expected, (
            f"present={present} classified {state!r}, but the "
            f"classify(present,n_source={n_source},min_viable={min_viable}) "
            f"boundary predicts {expected!r}")

    # Pin the exact boundary rows the discovery pass observed, so a silent
    # off-by-one in either direction of the crossing turns this RED.
    t2, t4, t5 = (floor["tiers"][t]["after"] for t in ("t2", "t4", "t5"))
    assert (t2["present"], t2["state"]) == (n_source, "full"), floor["tiers"]
    assert (t4["present"], t4["state"]) == (min_viable, "partial"), floor["tiers"]
    assert (t5["present"], t5["state"]) == (0, "envelope_only"), floor["tiers"]


@pytest.mark.requires_persist
def test_unknown_tier_is_rejected(floor):
    """CC 6.1.2 #1: the retention ladder is a fixed vocabulary — an unknown tier is refused.

    Pins the tier set (`full|t2|t3|t4|t5`): an out-of-vocabulary tier name is
    rejected rather than silently accepted, so the crossings above are measured
    against a closed ladder.
    """
    assert floor["unknown_tier"] != "accepted", (
        "an unknown fountain tier was accepted — the ladder vocabulary is not closed")
    assert "unknown fountain tier" in floor["unknown_tier"], floor["unknown_tier"]


# ─── Gate #2 — N5 revocation → below floor ────────────────────────────


@pytest.mark.requires_persist
def test_hard_delete_drops_to_envelope_only(floor):
    """CC 6.1.2 #2 / N5: revocation purges every symbol → EnvelopeOnly, present=0.

    `evict_fountain_content_hard_delete` is the revocation path: it drops ALL
    symbols (dropped == total admitted), driving the content to `present == 0`
    and `state == "envelope_only"`. This is unconditional descent to the noise
    floor — the strongest below-floor classification the surface expresses.
    """
    before = floor["hd_before"]
    after = floor["hd_after"]
    assert before["state"] == "full" and before["present"] == TOTAL_SYMBOLS, before
    assert floor["hd_dropped"] == TOTAL_SYMBOLS, (
        f"hard delete dropped {floor['hd_dropped']}, expected all {TOTAL_SYMBOLS} symbols")
    assert after["present"] == 0, f"present={after['present']} after hard delete, expected 0"
    assert after["state"] == "envelope_only", (
        f"state={after['state']!r} after hard delete, expected 'envelope_only'")


@pytest.mark.requires_persist
def test_hard_delete_ignores_retention_priority(floor):
    """CC 6.1.2 #2: rarity/retention priority cannot resurrect content past revocation.

    The hard-deleted content had symbol 0 spiked to a retention priority far
    above every other symbol. Revocation still purged all `total` symbols
    (dropped == total, present == 0) — a high retention priority holds content
    above the floor against *capacity* pressure, never against *revocation*.
    """
    # All symbols dropped despite one carrying an outsized retention priority.
    assert floor["hd_dropped"] == TOTAL_SYMBOLS, (
        f"only {floor['hd_dropped']} of {TOTAL_SYMBOLS} purged — a high "
        "retention_priority survived revocation")
    assert floor["hd_after"]["present"] == 0, floor["hd_after"]


@pytest.mark.requires_persist
def test_signed_manifest_survives_revocation(floor):
    """CC 6.1.2 #2: the signed manifest survives hard delete — provenance never goes to zero.

    Even at the noise floor (present == 0, EnvelopeOnly), `get_fountain_content`
    still returns the signed manifest for the revoked content: the envelope is
    retained as provenance. Descent below the floor is envelope-only, never a
    total erasure of the record that the content existed.
    """
    after = floor["hd_after"]
    assert after["has_manifest"], (
        "the signed manifest was erased by hard delete — envelope-only provenance "
        "must survive revocation (descent is never to zero)")
    assert after["manifest_content_id"] == floor["hd_cid"], (
        f"surviving manifest content_id={after['manifest_content_id']!r} != "
        f"revoked cid {floor['hd_cid']!r}")
