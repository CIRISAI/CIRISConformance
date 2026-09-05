"""
Fabric tier — CC 6.1.1 WholenessWitness Merkle construction (`CLM-wholeness-witness`,
the construction + leaf-order half): the root the substrate computes is the ratified
scheme, byte-for-byte against an independent second implementation.

CC 6.1.1 (part_6_the_coherence_mathematics.md) pins the WholenessWitness root as
`leaf = SHA-256(leaf_bytes)`, `node = SHA-256(left ‖ right)`, odd-node duplication,
`b"WW-v1-empty"` empty sentinel — "the construction the reference shipped and a
second implementation proved cross-impl" — with **leaf order MUST be lexicographic
over leaf bytes** (the CC 2.6.1.1.1 set-semantics rule): "any 'either order as
long as both peers agree' convention is non-conformant — it is the CC 2.6.1-class
divergence hazard". CEG deliberately does NOT adopt the RFC 6962 `0x00`/`0x01`
leaf/node prefix (rationale in-clause; every root is mandatorily hybrid-signed).
"Changing this scheme is a vector-invalidating wire change."

What is REAL on the floor (persist v40.0.0), driven end-to-end here:

- **`Engine.wholeness_witness_root_hex(leaf_bytes_b64_json)`** — the pure §19.1
  root builder (CIRISPersist#431). This file is the SECOND implementation: a
  from-the-clause Python Merkle over the same leaves must agree with the wheel on
  every vector — empty (the sentinel), one leaf (root == SHA-256(leaf)), an even
  set, two odd sets (the duplication rule at two depths), and duplicate leaf
  bytes (two equal leaves are two leaves, not one).
- **Leaf order is the wheel's, not the caller's.** The same leaf set presented in
  three orders yields one root, and that root is the LEXICOGRAPHIC construction —
  the insertion-order Merkle over the same leaves differs, which is exactly the
  "both peers agree" convention the clause rules non-conformant.
- **No RFC 6962 domain prefix.** The 6962-prefixed construction over the same
  leaves differs from the wheel's root; the two schemes MUST NOT be cross-verified.

NOT DRIVEN HERE (the other half of `CLM-wholeness-witness`): N3 (hybrid PQC
verification before persistence to the witness corpus) and N4 (non-repudiable
equivocation surfaced as a hard case). `put_wholeness_witness_json` takes the
witness's Ed25519 + ML-DSA-65 signatures as arguments and the Python surface
exposes no hybrid signer, so a downstream cannot mint a witness to ingest —
tracked as a substrate ask (CIRISPersist#812).

Real surface: `Engine.wholeness_witness_root_hex(leaf_bytes_b64_json)`.
"""

from __future__ import annotations

import base64
import hashlib
import json

import pytest

from conftest import run_python_script

pytestmark = [pytest.mark.fabric, pytest.mark.ceg, pytest.mark.ccs]

# The ratified scheme, written from the clause — the second implementation.
_EMPTY_SENTINEL = b"WW-v1-empty"


def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def ww_root(leaves: list[bytes]) -> str:
    """CC 6.1.1: lexicographic leaf order, SHA-256 leaves, SHA-256(left‖right)
    nodes, odd-node duplication, empty sentinel. No 6962 prefixes."""
    if not leaves:
        return _sha256(_EMPTY_SENTINEL).hex()
    level = [_sha256(x) for x in sorted(leaves)]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [_sha256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0].hex()


def _insertion_order_root(leaves: list[bytes]) -> str:
    # The non-conformant "either order as long as both peers agree" construction.
    level = [_sha256(x) for x in leaves]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [_sha256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0].hex()


def _rfc6962_root(leaves: list[bytes]) -> str:
    # RFC 6962 §2.1: leaf = SHA-256(0x00 ‖ d), node = SHA-256(0x01 ‖ l ‖ r), and a
    # lone node promotes rather than duplicates. CEG explicitly does NOT use it.
    if not leaves:
        return _sha256(b"").hex()
    level = [_sha256(b"\x00" + x) for x in sorted(leaves)]
    while len(level) > 1:
        nxt = [_sha256(b"\x01" + level[i] + level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0].hex()


VECTORS: dict[str, list[bytes]] = {
    "empty": [],
    "single": [b"alpha"],
    "even_two": [b"beta", b"alpha"],
    "odd_three": [b"gamma", b"alpha", b"beta"],
    "odd_five": [b"epsilon", b"delta", b"gamma", b"beta", b"alpha"],
    "duplicate_leaves": [b"alpha", b"alpha", b"beta"],
    "binary_leaves": [bytes(range(32)), bytes(range(255, 223, -1)), b"\x00", b"\xff"],
}
ORDER_SET = [b"zeta", b"alpha", b"mid", b"beta"]

_BODY = r"""
import json, sys, os, tempfile, secrets, base64
try:
    import ciris_persist as cp
except ImportError as exc:
    print(json.dumps({"_error": "import", "detail": str(exc)})); sys.exit(2)
_d = tempfile.mkdtemp()
_s = os.path.join(_d, "s"); open(_s, "wb").write(secrets.token_bytes(32))
_p = os.path.join(_d, "p"); open(_p, "wb").write(secrets.token_bytes(32))
_k = "ww-" + secrets.token_hex(8)
cp.reset_engine()
engine = cp.Engine("sqlite::memory:", _k, local_key_id=_k, local_key_path=_s,
                   local_pqc_key_id=_k + "-pqc", local_pqc_key_path=_p)
if not hasattr(engine, "wholeness_witness_root_hex"):
    print(json.dumps({"_error": "absent", "surface": "wholeness_witness_root_hex"})); sys.exit(2)

def root(leaves_b64):
    return engine.wholeness_witness_root_hex(json.dumps(leaves_b64))

r = {"vectors": {name: root(lv) for name, lv in VECTORS.items()}}
r["order"] = [root(o) for o in ORDERINGS]
r["stage"] = "done"
print(json.dumps(r)); sys.stdout.flush(); sys.exit(0)
"""


@pytest.fixture(scope="module")
def roots():
    b64 = lambda lv: [base64.b64encode(x).decode() for x in lv]
    orderings = [ORDER_SET, list(reversed(ORDER_SET)), sorted(ORDER_SET)]
    script = (f"VECTORS = {json.dumps({n: b64(lv) for n, lv in VECTORS.items()})}\n"
              f"ORDERINGS = {json.dumps([b64(o) for o in orderings])}\n" + _BODY)
    payload = run_python_script(script).parsed_stdout()
    if payload.get("_error") == "absent":
        pytest.fail("persist wholeness_witness_root_hex is missing — the CC 6.1.1 "
                    "root builder is not on the wheel (CIRISPersist#431)")
    if payload.get("_error"):
        pytest.fail(f"probe failed: {payload}")
    assert payload.get("stage") == "done", payload
    return payload


@pytest.mark.requires_persist
@pytest.mark.parametrize("name", list(VECTORS))
def test_root_matches_the_ratified_construction(roots, name):
    """CC 6.1.1: the wheel's root equals an independent implementation of the
    ratified scheme on every vector — the sentinel, the single leaf, even and
    odd sets (duplication at two depths), duplicate leaf bytes, binary leaves."""
    assert roots["vectors"][name] == ww_root(VECTORS[name]), (
        f"vector {name!r}: wheel root {roots['vectors'][name]} != ratified "
        f"construction {ww_root(VECTORS[name])}")


@pytest.mark.requires_persist
def test_empty_root_is_the_sentinel_and_single_root_is_the_leaf_hash(roots):
    """CC 6.1.1 pins the two degenerate cases explicitly: `b"WW-v1-empty"` for no
    leaves, and a lone leaf's root is SHA-256(leaf) (odd duplication is not
    applied to a one-node tree)."""
    assert roots["vectors"]["empty"] == _sha256(_EMPTY_SENTINEL).hex()
    assert roots["vectors"]["single"] == _sha256(b"alpha").hex()


@pytest.mark.requires_persist
def test_leaf_order_is_lexicographic_not_the_callers(roots):
    """CC 6.1.1 / CC 2.6.1.1.1: leaf order MUST be lexicographic over leaf bytes.

    The same leaf set in three presentation orders yields one root, equal to the
    lexicographic construction — and NOT equal to the insertion-order Merkle over
    the un-sorted presentation, which is the "either order as long as both peers
    agree" convention the clause names as the CC 2.6.1-class divergence hazard.
    """
    assert len(set(roots["order"])) == 1, (
        f"the root depends on the caller's leaf order: {roots['order']}")
    assert roots["order"][0] == ww_root(ORDER_SET)
    assert roots["order"][0] != _insertion_order_root(ORDER_SET), (
        "the wheel computes the insertion-order root — leaf order is the caller's, "
        "not lexicographic (non-conformant per CC 6.1.1)")


@pytest.mark.requires_persist
def test_no_rfc6962_domain_prefix(roots):
    """CC 6.1.1: CEG does NOT adopt the RFC 6962 `0x00`/`0x01` leaf/node prefix;
    the two constructions MUST NOT be cross-verified. On a set where they would
    differ, the wheel's root is the CEG one."""
    for name in ("odd_three", "odd_five", "binary_leaves"):
        assert roots["vectors"][name] != _rfc6962_root(VECTORS[name]), (
            f"vector {name!r}: the wheel's root equals the RFC 6962 construction")
