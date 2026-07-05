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

STATUS ON THE CC 1.0-rc2 FLOOR (persist 13.0.1 / edge 9.1.0 / verify 8.7.0): the
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

The pin-never-defeats-revocation leg (B6/N5) is now a **real green drive** on
persist 13.0.1 (CIRISPersist#370), which ships the missing pin-INSTALL surface:
`install_storage_budget_v1(wire, ed_pub, ml_dsa_pub)` verifies the bound-hybrid
signature at the gate, enforces §Q B3 anti-rollback, and persists a
`StorageBudgetV1` that GOVERNS fountain eviction (its `pinned_class` /
`pin_reserve_bytes` drive the B5 cache-before-pinned sweep); returning the
accepted `revision`. `get_installed_storage_budget_json(node_id)` reads it back
verbatim. The driver installs a budget pinning the `trace` corpus class, admits
`trace` fountain content held under that pin, then revokes it
(`evict_fountain_content_hard_delete`) and asserts the pin does **not** save it:
the symbols are purged and the manifest descends to `EnvelopeOnly`, while the pin
itself stays installed — revocation is **pin-blind** (§Q B6). A pin holds content
above the floor against *capacity* pressure only, never against *revocation*.

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

# ── pin-vs-revocation (CC 6.1.5.2 B6 / N5): install a pin, then revoke past it ──
# persist 13 (CIRISPersist#370) ships the pin-INSTALL surface:
#   install_storage_budget_v1(wire, ed_pub, ml_dsa_pub) verifies the bound-hybrid
#     signature at the gate, enforces §Q B3 anti-rollback, then persists a
#     StorageBudgetV1 that GOVERNS eviction (its pinned_class / pin_reserve drive
#     the B5 CACHE-BEFORE-PINNED sweep), returning the accepted revision;
#   get_installed_storage_budget_json(node_id) reads it back VERBATIM (re-verifiable).
# Install a budget that PINS the `trace` corpus class, admit trace fountain
# content, confirm it is held under the pin, then revoke it
# (evict_fountain_content_hard_delete) and assert the pin does NOT save it: N5/B6 —
# revocation is pin-blind and forces descent below the floor (symbols purged, the
# manifest left EnvelopeOnly) regardless of the pin, which itself stays installed.

def _as_bytes(x):
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    if isinstance(x, str):
        return base64.b64decode(x)
    if isinstance(x, list):
        return bytes(x)
    raise TypeError(type(x))

def install_raises(fn):
    "True iff install rejected the payload with a ValueError (anti-rollback etc.)."
    try:
        fn(); return False
    except ValueError:
        return True

cid, corpus = "py-nf-1", "trace"

# Install an eviction-governing budget whose pinned_class covers `trace` (the
# corpus_kind of the content admitted below), with headroom so it is not evicted
# by capacity pressure — only revocation can force it out.
PIN_BUDGET = {"node_id": NODE, "epoch_id": "ep-1", "revision": 5,
              "scopes": [{"cohort_scope": "community:aaa", "budget_bytes": 100000,
                          "pin_reserve_bytes": 50000}],
              "pinned_class": ["trace", "xtrace"]}
pin_wire = eng.build_storage_budget_v1(json.dumps(PIN_BUDGET))
install_revision = eng.install_storage_budget_v1(pin_wire, ed, pqc)
installed_wire = eng.get_installed_storage_budget_json(NODE)
pin_report = {
    "install_revision": install_revision,
    "installed_present": installed_wire is not None,
    "installed_reverifies": bool(installed_wire)
        and eng.verify_storage_budget_v1(installed_wire, ed, pqc),
    # §Q B3 anti-rollback holds at the INSTALL gate: a lower revision is rejected.
    "install_rollback_rejected": install_raises(lambda: eng.install_storage_budget_v1(
        eng.build_storage_budget_v1(json.dumps(dict(PIN_BUDGET, revision=3))), ed, pqc)),
    # a swapped-pubkey install MUST fail signature verification at the gate.
    "install_bad_sig_rejected": install_raises(
        lambda: eng.install_storage_budget_v1(pin_wire, pqc, ed)),
}

N, K, SYM, MV = 10, 4, 16, 3
TOTAL = N + K
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
    # the pin is still installed — it just does NOT save the content (pin-blind
    # revocation, §Q B6); the content descends to EnvelopeOnly regardless.
    "pin_survives_revocation": eng.get_installed_storage_budget_json(NODE) is not None,
    "state_after": (after or {}).get("state"),
}

print(json.dumps({"stage": "done", "storage_budget": sb_report,
                  "corpus_want": cw_report, "pin": pin_report,
                  "revocation": revocation_report}))
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
def test_pin_never_defeats_revocation(contention):
    """CC 6.1.5.2 B6 / CC 6.1.5 N5: revocation forces descent below the floor regardless of pin.

    Now a real end-to-end drive on persist 13 (CIRISPersist#370): an
    eviction-governing `StorageBudgetV1` pinning the `trace` corpus class is
    installed (`install_storage_budget_v1` — bound-hybrid verified at the gate,
    §Q B3 anti-rollback enforced, re-readable verbatim via
    `get_installed_storage_budget_json`); `trace` fountain content is admitted and
    held under that pin. Then the content is revoked
    (`evict_fountain_content_hard_delete`) and the pin does **NOT** save it: the
    symbols are purged and the manifest descends to `EnvelopeOnly`, while the pin
    itself stays installed — revocation is **pin-blind** and forces immediate
    descent below the noise floor regardless of pin state. §Q is the positive
    inverse of N5 and is bounded by it: a pin holds content above the floor
    against *capacity* pressure only, never against *revocation*.
    """
    pin = contention["pin"]
    rev = contention["revocation"]
    # the pin was really INSTALLED as an eviction-governing budget, verified at the
    # gate, and anti-rollback / bad-signature installs are rejected (B3 / CC 6.1.3).
    assert pin["installed_present"] is True, pin
    assert pin["installed_reverifies"] is True, pin
    assert pin["install_revision"] == 5, pin
    assert pin["install_rollback_rejected"] is True, pin
    assert pin["install_bad_sig_rejected"] is True, pin
    # content is held under the pin, then revocation purges it anyway (N5/B6)...
    assert rev["present_before"] is True, rev
    assert rev["gone_after_hard_delete"] is True, rev
    # ...descending to EnvelopeOnly (symbols purged below the floor)...
    assert rev["state_after"] == "envelope_only", rev
    # ...while the pin itself is untouched — revocation is pin-blind, not a
    # budget teardown: the pin survives, the pinned content does not.
    assert rev["pin_survives_revocation"] is True, rev
