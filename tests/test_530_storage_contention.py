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

STATUS ON THE FLOOR WHEEL (persist 12.2.0 / edge 8.6.1 / verify 8.5.0): the CC 0.9
shapes are **not yet on the Python surface**. Probed exhaustively —
`ciris_persist` (module + Engine), `ciris_edge.ciris_edge`, and `ciris_verify`
carry **no** `StorageBudgetV1` / `CorpusWantV1` builder or verifier, and neither
`.so` contains the `CIRIS-STG-BUDGET` / `CIRIS-WANT-HAVE` domain separators. The
pre-0.9 surface that DOES exist — `Engine.set_storage_budget_bytes` (CIRISPersist#123)
and `Engine.cache_budget_bytes` (CIRISPersist#148) — is the *old scalar per-node
byte budget driving reactive eviction*, i.e. exactly the "no owner budget, only
reactive eviction after content landed" gap CC 0.9 was written to close. It is
NOT the signed per-`cohort_scope` `StorageBudgetV1` shape, so it does not satisfy
this gate.

Therefore this is an **`xfail(strict=True)`** gate, not a fabricated green one:
each test probes for the specific missing builder/verify surface (across every
plausible name, mirroring how the sibling CC 6.1 shape `FountainContent` surfaces
as `Engine.put_fountain_content` / `get_fountain_content`) and asserts it is
present + drivable. While the surface is absent the assertion fails → xfailed;
the day persist/edge ships `StorageBudgetV1` / `CorpusWantV1` the probe finds it,
the test xpasses, and `strict=True` turns that xpass RED — forcing this gate to
be flipped to a real behavioral assertion (monotonic-revision anti-rollback,
want/have round-trip, pin-never-defeats-revocation) at that time.

Upstream: file against CIRISPersist (the `put_fountain_content` sibling owner) to
add `put_storage_budget_v1` / `verify_storage_budget_v1` / `put_corpus_want_v1`
with the CC 6.1.3 binary preimage + #57 freeze-gate vectors.

Spec: reference/CIRIS_Constitution/part_6_the_coherence_mathematics.md §6.1.5.2 (CC 0.9).
"""

from __future__ import annotations

import pytest

from conftest import get_database_url, run_python_script

# CC 6.1.5.2 pinned 16-byte domain separators (verify byte-exact once the shape
# ships — the sole in-spec anchor a builder's preimage must begin with).
DOMSEP_STORAGE_BUDGET = b"CIRIS-STG-BUDGET"
DOMSEP_CORPUS_WANT = b"CIRIS-WANT-HAVE\x00"


# ─── Surface probe ────────────────────────────────────────────────────
# Enumerate the CC 6.1 shape surface across every namespace + naming form that
# persist/edge/verify could plausibly ship it under, so this gate flips the day
# it lands regardless of the exact symbol chosen. A name is a hit only if it
# names the SHAPE (storage_budget / corpus_want / the domain-sep slugs) AND a
# build/put/verify/sign verb — the pre-0.9 scalar `set_storage_budget_bytes` /
# `cache_budget_bytes` are deliberately NOT matched (they carry no shape verb and
# are the reactive-eviction budget CC 0.9 supersedes).

_PROBE_BODY = r"""
import json, sys, os, tempfile, secrets

def report_error(detail):
    print(json.dumps({"_error": "import", "detail": detail})); sys.exit(2)

try:
    import ciris_persist as cp
except ImportError as exc:
    report_error(str(exc))
try:
    from ciris_edge import ciris_edge as cei
except Exception:
    cei = None
try:
    import ciris_verify as cv
except Exception:
    cv = None

_d = tempfile.mkdtemp()
_s = os.path.join(_d, "s"); open(_s, "wb").write(secrets.token_bytes(32))
_p = os.path.join(_d, "p"); open(_p, "wb").write(secrets.token_bytes(32))
cp.reset_engine()
k = "node-" + secrets.token_hex(8)
# Hybrid engine — StorageBudgetV1/CorpusWantV1 are bound-hybrid (Ed25519+ML-DSA-65)
# verified-at-ingest, so a real driver needs both key halves present.
engine = cp.Engine(DB_URL, k, local_key_id=k, local_key_path=_s,
                   local_pqc_key_id=k + "-pqc", local_pqc_key_path=_p)

SHAPE_TOKENS = ("storage_budget", "corpus_want", "stg_budget", "want_have")
# Verb as a full `_`-delimited segment (persist is `put_*` / `verify_*` / …), so
# the pre-0.9 scalar `set_storage_budget_bytes` is NOT matched — its segments are
# {set, storage, budget, bytes}, none a shape verb (and "budget" contains "get"
# only as a substring, which segment-matching correctly rejects).
VERB_TOKENS = frozenset(("put", "verify", "build", "sign", "emit", "ingest", "get"))

def shape_verb_hits(names):
    hits = []
    for n in names:
        low = n.lower()
        segments = set(low.split("_"))
        if any(t in low for t in SHAPE_TOKENS) and (segments & VERB_TOKENS):
            hits.append(n)
    return sorted(hits)

namespaces = {
    "ciris_persist.module": dir(cp),
    "ciris_persist.Engine": dir(engine),
    "ciris_edge.ciris_edge": dir(cei) if cei is not None else [],
    "ciris_verify": dir(cv) if cv is not None else [],
}
found = {ns: shape_verb_hits(names) for ns, names in namespaces.items()}

report = {
    "storage_budget_surface": sorted(
        h for ns in found.values() for h in ns
        if "storage_budget" in h.lower() or "stg_budget" in h.lower()),
    "corpus_want_surface": sorted(
        h for ns in found.values() for h in ns
        if "corpus_want" in h.lower() or "want_have" in h.lower()),
    "found_by_namespace": found,
    # The pre-0.9 scalar budget that exists but does NOT satisfy CC 0.9.
    "legacy_scalar_budget_present": bool(
        hasattr(engine, "set_storage_budget_bytes") or hasattr(engine, "cache_budget_bytes")),
    "stage": "done",
}
print(json.dumps(report)); sys.stdout.flush()
sys.exit(0)
"""


def _probe_script(database_url: str) -> str:
    return f"DB_URL = {database_url!r}\n" + _PROBE_BODY


@pytest.fixture(scope="module")
def contention():
    result = run_python_script(_probe_script(get_database_url()))
    payload = result.parsed_stdout()
    if payload.get("_error") == "import":
        pytest.fail(f"probe could not import the wheels: {payload.get('detail')}")
    assert payload.get("stage") == "done", payload
    return payload


@pytest.mark.cohabitation
@pytest.mark.requires_persist
@pytest.mark.xfail(
    strict=True,
    reason="CC 0.9 StorageBudgetV1 not on the Python wheel (persist 12.2.0): no "
           "put_storage_budget_v1 / verify_storage_budget_v1 on ciris_persist "
           "(module or Engine), ciris_edge, or ciris_verify, and no b'CIRIS-STG-BUDGET' "
           "domain separator in any .so. The existing scalar set_storage_budget_bytes / "
           "cache_budget_bytes is the pre-0.9 reactive-eviction budget, not the signed "
           "per-cohort_scope shape. Flip to a real anti-rollback drive when persist ships it (CIRISPersist#356).",
)
def test_storage_budget_v1_signed_and_anti_rollback(contention):
    """CC 6.1.5.2 B3: a signed `StorageBudgetV1` verifies and monotonic `revision` supersede holds.

    Once the surface exists this MUST assert: a bound-hybrid `StorageBudgetV1`
    whose preimage begins `b"CIRIS-STG-BUDGET"` verifies at ingest; a higher
    `revision` from the same `node_id` supersedes; a lower `revision` is REJECTED
    (anti-rollback); and a `self`/`family` scope entry or `pin_reserve_bytes >
    budget_bytes` is rejected. Until the builder/verifier lands there is no shape
    to sign, so this expected-fails.
    """
    assert contention["storage_budget_surface"], (
        "no StorageBudgetV1 build/verify surface found; scalar-budget-present="
        f"{contention['legacy_scalar_budget_present']}, "
        f"namespaces={contention['found_by_namespace']}")


@pytest.mark.cohabitation
@pytest.mark.requires_persist
@pytest.mark.xfail(
    strict=True,
    reason="CC 0.9 CorpusWantV1 not on the Python wheel (persist 12.2.0): no "
           "put_corpus_want_v1 / verify_corpus_want_v1 on ciris_persist, ciris_edge, "
           "or ciris_verify, and no b'CIRIS-WANT-HAVE\\0' domain separator in any .so. "
           "Flip to a real want/have round-trip when persist ships it (CIRISPersist#356).",
)
def test_corpus_want_v1_roundtrips(contention):
    """CC 6.1.5.2 B4: a signed `CorpusWantV1` round-trips (build → verify).

    Once the surface exists this MUST assert: a bound-hybrid `CorpusWantV1` whose
    preimage begins `b"CIRIS-WANT-HAVE\\0"` carries `content_id` (CID) + `size_cap_bytes`
    + `remaining_budget_bytes`, verifies, and rejects a `self`/`family` cohort_scope.
    Until the builder lands there is no shape to round-trip.
    """
    assert contention["corpus_want_surface"], (
        "no CorpusWantV1 build/verify surface found; "
        f"namespaces={contention['found_by_namespace']}")


@pytest.mark.cohabitation
@pytest.mark.requires_persist
@pytest.mark.xfail(
    strict=True,
    reason="CC 0.9 pin-never-defeats-revocation (B6/N5) is undrivable: it needs the "
           "StorageBudgetV1 pin surface (absent — see test_storage_budget_v1_signed_and_anti_rollback) "
           "composed with the existing evict_fountain_content_hard_delete revocation path. "
           "Flip to a real pinned-then-revoked descent drive when StorageBudgetV1 ships (CIRISPersist#356).",
)
def test_pin_never_defeats_revocation(contention):
    """CC 6.1.5.2 B6 / CC 6.1.5 N5: revocation forces descent below the floor regardless of pin.

    Once the pin surface exists this MUST assert: content pinned via a satisfied
    `StorageBudgetV1` + `consent:replication` grant is held above the floor under
    capacity pressure, but an active `withdraws` / `consent:state:revoked` still
    drives `evict_fountain_content_hard_delete` on it (pin holds against capacity,
    never against revocation). Undrivable until the pin half (StorageBudgetV1) lands.
    """
    assert contention["storage_budget_surface"], (
        "pin-vs-revocation invariant needs the StorageBudgetV1 pin surface, which is "
        f"absent; namespaces={contention['found_by_namespace']}")
