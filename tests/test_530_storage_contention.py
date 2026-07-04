"""
Substrate tier — CC 0.9 CEG replication storage-contention axis (CC 6.1.5.2 §Q).

CC 0.9 closes the last replication gap before mesh seed: replication was
specified by wire type (CC 5.3.2.3), membership (`cohort_scope`), and consent
(`consent:replication`) — but had **no rule for storage contention on an owned
node**. CC 6.1.5.2 adds the missing 4th axis (the IPFS-pinning model) with two
new CC 6.1 substrate shapes (16-byte domain separators, hybrid Ed25519+ML-DSA-65,
verify-at-ingest — NOT CC 2.1 attestations, so the 1+4 surface is untouched):

  • **`StorageBudgetV1`** — the owner's per-`cohort_scope` allotment: a
    `budget_bytes` ceiling + a `pin_reserve_bytes` floor (MUST be ≤ budget_bytes),
    a `pinned_class` set (the corpus `subject_kind`s the owner elects to pin), and
    a monotonic `revision`. `self`/`family` scopes are suppressed from the wire
    (CC 5.2 structural invisibility). Supersedable by monotonic `revision`: a
    higher revision from the same `node_id` supersedes; a lower one MUST be
    rejected (anti-rollback). Signing preimage domain separator: `b"CIRIS-STG-BUDGET"`.
  • **`CorpusWantV1`** — the B4 want/have advertisement: a peer advertises exactly
    the corpus CIDs it will accept + a per-object `size_cap_bytes`; a producer
    pulls only against it (wanted-then-pulled, never unsolicited-pushed). Domain
    separator: `b"CIRIS-WANT-HAVE\0"`.

And the invariant this section is the positive inverse of: **a pin never defeats
revocation** — an active `withdraws` / `consent:state:revoked` forces immediate
descent below the noise floor regardless of pin state (CC 6.1.5 N5 / B6). A pin
holds content above the floor against *capacity* pressure only, never against
*revocation*.

STATUS ON THE CC 1.0-rc1 FLOOR (persist 12.5.0 / edge 8.7.2 / verify 8.7.0): the
CC 0.9 shapes **now ship on the Engine** (CIRISPersist#356, CLOSED) as six
bound-hybrid builder/verify/predicate methods —
`build_storage_budget_v1` / `verify_storage_budget_v1` / `storage_budget_supersedes`
and `build_corpus_want_v1` / `verify_corpus_want_v1` / `corpus_want_admits`. Each
`build_*` signs the CC 6.1.3 length-prefixed domain-separated preimage with the
engine's Ed25519+ML-DSA-65 key halves and returns the wire JSON; `verify_*` checks
both signature halves + structural validity at ingest; the validation rules
(pin_reserve ≤ budget, self/family suppression, lexicographic sort+dedup) are
enforced at build time (raising `ciris_persist.LensQueryError`). So the first two
gates are now **real behavioral drives** (round-trip, anti-rollback, admission).

The pin-never-defeats-revocation leg (B6/N5) is **still one leg short**: the §Q
shapes are wire-negotiation objects only — there is **no pin-install surface**
(no `put_storage_budget_v1` / `install_storage_budget`; `build_storage_budget_v1`
returns a signed wire object that does NOT govern fountain eviction). The
revocation half IS drivable and works (`evict_fountain_content_hard_delete` purges
admitted fountain content — confirmed in the driver), but "a pin holds content
above the floor under capacity pressure" cannot be STAGED, so the invariant "the
pin does not survive revocation" cannot be exercised. That leg stays
`xfail(strict=True)` with a precise reason until a pin-install surface that
governs eviction ships.

Spec: reference/CIRIS_Constitution/part_6_the_coherence_mathematics.md §6.1.5.2 (CC 0.9).
"""

from __future__ import annotations

import pytest

from conftest import get_database_url, run_python_script

# CC 6.1.5.2 pinned 16-byte domain separators (the in-spec preimage anchors —
# enforced inside the Rust builder; the Python surface returns wire JSON, not the
# raw preimage, so these are documented here rather than byte-checked from Python).
DOMSEP_STORAGE_BUDGET = b"CIRIS-STG-BUDGET"
DOMSEP_CORPUS_WANT = b"CIRIS-WANT-HAVE\x00"


# ─── Behavioral driver ────────────────────────────────────────────────
# Drive the six §Q Engine methods end-to-end in one hybrid-signing subprocess and
# report every outcome as a boolean the tests assert on. Build/verify signs with
# the engine's Ed25519+ML-DSA-65 halves; validation rejections surface as a
# `ciris_persist.LensQueryError` at build time (captured via `raised(...)`).
_DRIVE_BODY = r"""
import json, sys, os, tempfile, secrets, base64, hashlib

def report_error(detail):
    print(json.dumps({"_error": "import", "detail": detail})); sys.exit(2)

try:
    import ciris_persist as cp
except ImportError as exc:
    report_error(str(exc))

_d = tempfile.mkdtemp()
_s = os.path.join(_d, "s"); open(_s, "wb").write(secrets.token_bytes(32))
_p = os.path.join(_d, "p"); open(_p, "wb").write(secrets.token_bytes(32))
cp.reset_engine()
NODE = "node-" + secrets.token_hex(8)
# Hybrid engine — StorageBudgetV1/CorpusWantV1 are bound-hybrid (Ed25519+ML-DSA-65)
# verified-at-ingest, so a real driver needs both key halves present.
eng = cp.Engine(DB_URL, NODE, local_key_id=NODE, local_key_path=_s,
                local_pqc_key_id=NODE + "-pqc", local_pqc_key_path=_p)
ed = eng.local_public_key_b64()
pqc = eng.local_pqc_public_key_b64()


def raised(fn):
    "True iff the builder rejected the payload with a LensQueryError (a real reject)."
    try:
        fn(); return False
    except cp.LensQueryError:
        return True


# ── StorageBudgetV1: round-trip, anti-rollback, validation (CC 6.1.5.2 B3) ──
def sb(payload):
    return eng.build_storage_budget_v1(json.dumps(payload))

BASE = {"node_id": NODE, "epoch_id": "ep-1", "revision": 5,
        "scopes": [{"cohort_scope": "community:aaa", "budget_bytes": 1000, "pin_reserve_bytes": 500},
                   {"cohort_scope": "community:bbb", "budget_bytes": 2000, "pin_reserve_bytes": 100}],
        "pinned_class": ["trace", "xtrace"]}
w5 = sb(BASE)                                   # the reference revision
w9 = sb(dict(BASE, revision=9))                 # same node, higher revision
w3 = sb(dict(BASE, revision=3))                 # same node, lower revision (rollback)
wx = sb(dict(BASE, node_id="other-node", revision=99))  # different node, higher rev

sb_report = {
    "verify_valid": eng.verify_storage_budget_v1(w5, ed, pqc),
    "verify_swapped_pub": eng.verify_storage_budget_v1(w5, pqc, ed),   # must be False
    "higher_supersedes": eng.storage_budget_supersedes(w9, w5),        # True
    "lower_supersedes": eng.storage_budget_supersedes(w3, w5),         # False (anti-rollback)
    "equal_supersedes": eng.storage_budget_supersedes(w5, w5),         # False
    "cross_node_supersedes": eng.storage_budget_supersedes(wx, w5),    # False (diff node_id)
    "reject_pin_gt_budget": raised(lambda: sb(dict(BASE,
        scopes=[{"cohort_scope": "community:a", "budget_bytes": 100, "pin_reserve_bytes": 500}]))),
    "reject_self_scope": raised(lambda: sb(dict(BASE,
        scopes=[{"cohort_scope": "self", "budget_bytes": 100, "pin_reserve_bytes": 10}]))),
    "reject_family_scope": raised(lambda: sb(dict(BASE,
        scopes=[{"cohort_scope": "family", "budget_bytes": 100, "pin_reserve_bytes": 10}]))),
    "reject_unsorted_scopes": raised(lambda: sb(dict(BASE,
        scopes=[{"cohort_scope": "community:z", "budget_bytes": 100, "pin_reserve_bytes": 10},
                {"cohort_scope": "community:a", "budget_bytes": 100, "pin_reserve_bytes": 10}]))),
    "reject_dup_scopes": raised(lambda: sb(dict(BASE,
        scopes=[{"cohort_scope": "community:a", "budget_bytes": 100, "pin_reserve_bytes": 10},
                {"cohort_scope": "community:a", "budget_bytes": 100, "pin_reserve_bytes": 10}]))),
    "reject_unsorted_pinned_class": raised(lambda: sb(dict(BASE, pinned_class=["zzz", "aaa"]))),
    "reject_dup_pinned_class": raised(lambda: sb(dict(BASE, pinned_class=["aaa", "aaa"]))),
}

# ── CorpusWantV1: round-trip + admission + validation (CC 6.1.5.2 B4) ──
def cw(payload):
    return eng.build_corpus_want_v1(json.dumps(payload))

WBASE = {"node_id": NODE, "epoch_id": "ep-1", "cohort_scope": "community:aaa",
         "size_cap_bytes": 1000, "remaining_budget_bytes": 5000,
         "want": ["cid-aaa", "cid-bbb", "cid-ccc"]}
cwire = cw(WBASE)
cw_report = {
    "verify_valid": eng.verify_corpus_want_v1(cwire, ed, pqc),
    "verify_swapped_pub": eng.verify_corpus_want_v1(cwire, pqc, ed),   # False
    "admits_wanted_undercap": eng.corpus_want_admits(cwire, "cid-aaa", 500),   # True
    "admits_wanted_atcap": eng.corpus_want_admits(cwire, "cid-aaa", 1000),     # True (== cap)
    "admits_wanted_overcap": eng.corpus_want_admits(cwire, "cid-aaa", 1001),   # False (> cap)
    "admits_absent_cid": eng.corpus_want_admits(cwire, "cid-zzz", 10),         # False (not wanted)
    "reject_self_scope": raised(lambda: cw(dict(WBASE, cohort_scope="self"))),
    "reject_family_scope": raised(lambda: cw(dict(WBASE, cohort_scope="family"))),
    "reject_unsorted_want": raised(lambda: cw(dict(WBASE, want=["z", "a"]))),
    "reject_dup_want": raised(lambda: cw(dict(WBASE, want=["a", "a"]))),
}

# ── pin-vs-revocation (CC 6.1.5.2 B6 / N5): revocation leg + pin-install probe ──
# The revocation half — evict_fountain_content_hard_delete — is drivable: admit a
# signed fountain manifest, confirm it is present, hard-delete it, confirm it is
# gone. The pin half is NOT installable: enumerate any surface that would install
# a StorageBudgetV1 as an eviction-governing pin (absent → the invariant can't be
# staged; that leg xfails).
pin_install_surface = [n for n in dir(eng) if n in (
    "put_storage_budget_v1", "install_storage_budget",
    "apply_storage_budget", "set_storage_budget_v1")]

def _as_bytes(x):
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    if isinstance(x, str):
        return base64.b64decode(x)
    if isinstance(x, list):
        return bytes(x)
    raise TypeError(type(x))

N, K, SYM, MV = 10, 4, 16, 3
TOTAL = N + K
cid, corpus = "py-nf-1", "trace"
sym_hashes, symbols = [], []
for i in range(TOTAL):
    b = bytes((i * 31 + 7 + j) & 0xFF for j in range(SYM))
    sym_hashes.append(hashlib.sha256(b).hexdigest())
    symbols.append({"content_id": cid, "symbol_id": i, "retention_priority": i,
                    "symbol_bytes": list(b)})
canonical_value = {"content_id": cid, "corpus_kind": corpus, "manifest_version": 1,
                   "n_source": N, "k_repair": K, "symbol_size": SYM,
                   "original_content_length": N * SYM, "min_viable_symbols": MV,
                   "symbol_hashes": sym_hashes,
                   "envelope": {"content_id": cid, "pubkey_ed25519": ed, "pubkey_ml_dsa_65": pqc}}
canon = json.dumps(canonical_value, sort_keys=True, separators=(",", ":")).encode()
ed_sig = _as_bytes(eng.local_sign(canon))
pqc_sig = _as_bytes(eng.local_pqc_sign(canon + ed_sig))
manifest = dict(canonical_value)
manifest.update({"signature": base64.b64encode(ed_sig).decode(),
                 "signature_ml_dsa_65": base64.b64encode(pqc_sig).decode(),
                 "pqc_key_id": eng.local_pqc_key_id()})
eng.put_fountain_content(json.dumps(manifest), json.dumps(symbols))
before = json.loads(eng.get_fountain_content(cid, corpus))
eng.evict_fountain_content_hard_delete(cid, corpus)   # the revocation descent
after = eng.get_fountain_content(cid, corpus)
after = json.loads(after) if after else None
revocation_report = {
    "present_before": bool(before.get("present")),
    "gone_after_hard_delete": (after is None) or (not after.get("present")),
    "pin_install_surface": pin_install_surface,
}

print(json.dumps({"stage": "done", "storage_budget": sb_report,
                  "corpus_want": cw_report, "revocation": revocation_report}))
sys.stdout.flush()
sys.exit(0)
"""


def _drive_script(database_url: str) -> str:
    return f"DB_URL = {database_url!r}\n" + _DRIVE_BODY


@pytest.fixture(scope="module")
def contention():
    result = run_python_script(_drive_script(get_database_url()), timeout=90)
    payload = result.parsed_stdout()
    if payload.get("_error") == "import":
        pytest.fail(f"driver could not import the wheels: {payload.get('detail')}")
    assert payload.get("stage") == "done", payload
    return payload


@pytest.mark.cohabitation
@pytest.mark.requires_persist
def test_storage_budget_v1_signed_and_anti_rollback(contention):
    """CC 6.1.5.2 B3: a signed `StorageBudgetV1` verifies and monotonic-`revision` anti-rollback holds.

    A bound-hybrid `StorageBudgetV1` verifies at ingest (both signature halves)
    and fails under a swapped pubkey; a higher `revision` from the same `node_id`
    supersedes, a lower one is REJECTED (anti-rollback), an equal one does not
    supersede, and a higher `revision` from a *different* `node_id` does not
    supersede (single-owner self-declaration). The validation rules are enforced
    at build: `pin_reserve_bytes > budget_bytes`, a `self`/`family` scope entry,
    and unsorted/duplicated scope or `pinned_class` lists are all rejected.
    """
    sb = contention["storage_budget"]
    # round-trip + tamper
    assert sb["verify_valid"] is True, sb
    assert sb["verify_swapped_pub"] is False, sb
    # anti-rollback (B3)
    assert sb["higher_supersedes"] is True, sb
    assert sb["lower_supersedes"] is False, sb
    assert sb["equal_supersedes"] is False, sb
    assert sb["cross_node_supersedes"] is False, sb
    # structural validation
    assert sb["reject_pin_gt_budget"] is True, sb
    assert sb["reject_self_scope"] is True, sb
    assert sb["reject_family_scope"] is True, sb
    assert sb["reject_unsorted_scopes"] is True, sb
    assert sb["reject_dup_scopes"] is True, sb
    assert sb["reject_unsorted_pinned_class"] is True, sb
    assert sb["reject_dup_pinned_class"] is True, sb


@pytest.mark.cohabitation
@pytest.mark.requires_persist
def test_corpus_want_v1_roundtrips(contention):
    """CC 6.1.5.2 B4: a signed `CorpusWantV1` round-trips and `size_cap`/CID admission holds.

    A bound-hybrid `CorpusWantV1` verifies at ingest and fails under a swapped
    pubkey; `corpus_want_admits` admits a wanted CID at or below `size_cap_bytes`
    but REFUSES an over-cap object or an absent (not-wanted) CID
    (wanted-then-pulled, never unsolicited-pushed). A `self`/`family`
    `cohort_scope` and unsorted/duplicated `want` lists are rejected at build.
    """
    cw = contention["corpus_want"]
    assert cw["verify_valid"] is True, cw
    assert cw["verify_swapped_pub"] is False, cw
    # wanted-then-pulled admission (B4)
    assert cw["admits_wanted_undercap"] is True, cw
    assert cw["admits_wanted_atcap"] is True, cw
    assert cw["admits_wanted_overcap"] is False, cw
    assert cw["admits_absent_cid"] is False, cw
    # structural validation
    assert cw["reject_self_scope"] is True, cw
    assert cw["reject_family_scope"] is True, cw
    assert cw["reject_unsorted_want"] is True, cw
    assert cw["reject_dup_want"] is True, cw


@pytest.mark.cohabitation
@pytest.mark.requires_persist
@pytest.mark.xfail(
    strict=True,
    reason="CC 0.9 pin-never-defeats-revocation (B6/N5) is one leg short on persist "
           "12.5.0: the §Q shapes are wire-negotiation objects only — there is NO "
           "pin-install surface (no put_storage_budget_v1 / install_storage_budget; "
           "build_storage_budget_v1 returns a signed wire object that does not govern "
           "fountain eviction). The revocation half (evict_fountain_content_hard_delete) "
           "IS drivable and works, but 'a pin holds content above the floor under "
           "capacity pressure' cannot be STAGED, so 'the pin does not survive revocation' "
           "cannot be exercised. Flip to a real pinned-then-revoked descent drive when a "
           "pin-install surface that governs eviction ships (CIRISPersist#356 follow-up).",
)
def test_pin_never_defeats_revocation(contention):
    """CC 6.1.5.2 B6 / CC 6.1.5 N5: revocation forces descent below the floor regardless of pin.

    The revocation half is real: admitted fountain content is present, and
    `evict_fountain_content_hard_delete` purges it (asserted below as a
    precondition — it passes). The invariant itself needs the pin half too: a
    surface that installs a satisfied `StorageBudgetV1` as an eviction-governing
    pin, so the content can be shown held above the floor under *capacity* pressure
    yet still purged by *revocation*. No such install surface exists on this floor,
    so this leg xfails on the missing precondition.
    """
    rev = contention["revocation"]
    # revocation half is genuinely drivable and correct
    assert rev["present_before"] is True, rev
    assert rev["gone_after_hard_delete"] is True, rev
    # ...but the pin half (an eviction-governing StorageBudgetV1 install) is absent,
    # so the pin-never-defeats-revocation invariant cannot be staged. This
    # assertion is the still-missing leg → xfail(strict).
    assert rev["pin_install_surface"], (
        "no pin-install surface that governs fountain eviction "
        f"(build_storage_budget_v1 is wire-only); surface probe={rev['pin_install_surface']}")
