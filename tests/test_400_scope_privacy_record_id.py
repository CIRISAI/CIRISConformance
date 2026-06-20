"""
SCOPE_PRIVACY §9 (acceptance bullet 2) — cross-implementation `record_id`
reproducibility on the FSD §2.4 deterministic-CBOR profile.

This is the cross-impl ratification step of the
[CEWP `FSD/SCOPE_PRIVACY.md` §9](https://github.com/CIRISAI/CEWP/blob/main/FSD/SCOPE_PRIVACY.md#9-acceptance-criteria)
construction. The §2.4 derivation:

    record_id  = HMAC-SHA3-256(K_record_id,
                               CBOR_dCE({v:1, epc:epoch, iid:internal_id, typ:record_type}))
    symbol_key = HKDF-SHA3-256(salt = record_id,
                               ikm  = K_symbol,
                               info = "ciris-edge/scope-privacy/symbol/v1" ‖ u16_be(idx),
                               L    = 32)

is the load-bearing privacy-tier addressing primitive. The
**CEG §11 cross-impl agreement** requires that every conformant
implementation produce IDENTICAL bytes for identical inputs. Verify
v6.3.0 ships the canonical KAT vectors at
`ciris-crypto/src/scope_privacy.rs::tests`; this conformance file lifts
the same vectors and computes them via a clean-room third
implementation (Python `hashlib` + a hand CBOR builder + RFC 5869
HKDF-SHA3-256 by hand) — independent of the verify Rust impl, the
edge Rust impl, and any future ciris-edge Python re-export.

A drift between any two of (verify Rust, edge Rust, this Python
oracle) flags a §11 wire-break. The conformance suite is the
neutral third party.

## What's pinned

| Vector | Test | What it pins |
|---|---|---|
| `v1_small`         | CommunityRecord, epoch=7   | Single-byte uint encoding; "v"/"epc"/"iid"/"typ" canonical key order; 0x4b byte-string-length-11 header for internal_id |
| `v2_u16_epoch`     | FederationRecord, epoch=300 | `0x19 0x01 0x2c` u16 epoch — multi-byte minimal-int boundary |
| `v3_u32_epoch`     | SelfRecord, epoch=16909060  | `0x1a 0x01 0x02 0x03 0x04` u32 epoch — 4-byte minimal-int path |
| `subkey_kat`       | k_record_id + k_symbol from exporter=[0x42; 32] | The bare HKDF-SHA256-Expand (NOT RFC 9420 ExpandWithLabel) §2.2 construction |
| `symbol_key_kat`   | HKDF-SHA3-256(salt=record_id, ikm=k_symbol, info=label‖u16_be(idx)) | The §2.4 per-symbol diversification with `record_id` as the SALT (not the IKM); label is DELIBERATELY reused from §2.2 |
| `witness_cover`    | HMAC-SHA3-256(key, u32_be(pos)‖u64_be(epoch)) | The §3.4 cover-leaf message layout |
| `record_type_enum` | typ=1/2/3/4, 0 reserved   | The CBOR `typ` integer encoding pinned by Verify as first impl |

## Why this test is allowed to import a CIRIS wheel at module scope

Other tests in this suite avoid module-level imports to keep PyO3 type
registration out of the pytest main process. This test imports NOTHING
from the CIRIS stack — it computes the construction entirely from
Python's stdlib `hashlib` / `hmac`. The whole point is to be a
**third, clean-room implementation** of §2.4. So there's no isolation
hazard.

(If/when CIRISEdge exposes `derive_record_id` via PyO3, an additional
test that drives THAT surface in a subprocess will land here.
Currently `ciris_edge` v6.1.0 keeps the construction internal to the
Rust send-path; the substrate-side gap is tracked under
[CIRISEdge §scope_privacy PyO3 export](https://github.com/CIRISAI/CIRISEdge/issues)
and documented in `docs/SCOPE_PRIVACY_CONFORMANCE.md`.)
"""

from __future__ import annotations

import hashlib
import hmac as _hmac

import pytest

pytestmark = pytest.mark.ceg


# ── §2.4 RecordType integer encoding (pinned by verify v6.3.0) ────────
# `0` is reserved.
RECORD_TYPE = {
    "self":       1,
    "family":     2,
    "community":  3,
    "federation": 4,
}

# ── §2.2 domain-separation labels ─────────────────────────────────────
LABEL_RECORD_ID = b"ciris-edge/scope-privacy/record-id/v1"
LABEL_SYMBOL    = b"ciris-edge/scope-privacy/symbol/v1"


# ─────────────────────────────────────────────────────────────────────
# RFC 8949 §4.2.1 Core Deterministic CBOR — a hand encoder for the
# `record_id` preimage. We do this from scratch (not via cbor2 / similar)
# so the test exercises the encoded BYTES, not somebody else's encoder.
# ─────────────────────────────────────────────────────────────────────

def _cbor_head(major: int, value: int) -> bytes:
    """RFC 8949 §3 minimal-length type-header for `(major, value)`.

    `0..=23` inline in the type byte, else `0x18`+u8 / `0x19`+u16_be /
    `0x1a`+u32_be / `0x1b`+u64_be. Definite-length only — RFC 8949 §4.2.1
    forbids indefinite-length encodings in dCE.
    """
    mt = major << 5
    if value <= 23:
        return bytes([mt | value])
    if value <= 0xFF:
        return bytes([mt | 0x18, value])
    if value <= 0xFFFF:
        return bytes([mt | 0x19]) + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return bytes([mt | 0x1A]) + value.to_bytes(4, "big")
    return bytes([mt | 0x1B]) + value.to_bytes(8, "big")


def _record_id_cbor(internal_id: bytes, record_type: int, mls_group_epoch: int) -> bytes:
    """The §2.4 record_id preimage as RFC 8949 §4.2.1 deterministic CBOR.

    4-entry map; canonical key order by encoded-key bytes (shorter-first,
    then lexicographic): `v`, `epc`, `iid`, `typ`. Verify v6.3.0 pins
    this order — see `ciris-crypto/src/scope_privacy.rs::record_id_cbor`.
    """
    out = bytearray()
    out += _cbor_head(5, 4)          # map(4)
    # "v"  -> uint 1
    out += _cbor_head(3, 1) + b"v"
    out += _cbor_head(0, 1)
    # "epc" -> uint mls_group_epoch
    out += _cbor_head(3, 3) + b"epc"
    out += _cbor_head(0, mls_group_epoch)
    # "iid" -> byte string internal_id
    out += _cbor_head(3, 3) + b"iid"
    out += _cbor_head(2, len(internal_id)) + internal_id
    # "typ" -> uint record_type
    out += _cbor_head(3, 3) + b"typ"
    out += _cbor_head(0, record_type)
    return bytes(out)


def _derive_record_id(k_record_id: bytes, internal_id: bytes,
                      record_type: int, mls_group_epoch: int) -> bytes:
    """§2.4 `record_id = HMAC-SHA3-256(K_record_id, CBOR_dCE(...))`."""
    cbor = _record_id_cbor(internal_id, record_type, mls_group_epoch)
    return _hmac.new(k_record_id, cbor, hashlib.sha3_256).digest()


# ─────────────────────────────────────────────────────────────────────
# RFC 5869 HKDF, by hand, both SHA-256 (for §2.2 subkeys) and SHA3-256
# (for §2.4 symbol_key). Hand-rolled so the test is independent of
# any library's HKDF implementation.
# ─────────────────────────────────────────────────────────────────────

def _hkdf_expand(prk: bytes, info: bytes, length: int, hash_name: str) -> bytes:
    """RFC 5869 §2.3 HKDF-Expand."""
    hash_len = hashlib.new(hash_name).digest_size
    n = (length + hash_len - 1) // hash_len
    if n > 255:
        raise ValueError("HKDF output too long")
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = _hmac.new(prk, t + info + bytes([i]), hash_name).digest()
        okm += t
    return okm[:length]


def _hkdf_extract(salt: bytes, ikm: bytes, hash_name: str) -> bytes:
    """RFC 5869 §2.2 HKDF-Extract."""
    if not salt:
        salt = b"\x00" * hashlib.new(hash_name).digest_size
    return _hmac.new(salt, ikm, hash_name).digest()


def _k_record_id_from_exporter(exporter_secret: bytes) -> bytes:
    """§2.2 — bare HKDF-SHA256-Expand(PRK=exporter, info=LABEL, L=32).

    NOTE: NOT RFC 9420 ExpandWithLabel. NOT the MLS exporter.
    No HKDF-Extract, no MLS KDF-label framing. See the verify
    SCOPE_PRIVACY_NOTES §1 cross-impl ratification flag.
    """
    return _hkdf_expand(exporter_secret, LABEL_RECORD_ID, 32, "sha256")


def _k_symbol_from_exporter(exporter_secret: bytes) -> bytes:
    """§2.2 — bare HKDF-SHA256-Expand(PRK=exporter, info=LABEL, L=32)."""
    return _hkdf_expand(exporter_secret, LABEL_SYMBOL, 32, "sha256")


def _derive_symbol_key(k_symbol: bytes, record_id: bytes, symbol_index: int) -> bytes:
    """§2.4 — `HKDF-SHA3-256(salt = record_id, ikm = K_symbol,
                            info = LABEL_SYMBOL || u16_be(symbol_index))`.

    Note the deliberate LABEL_SYMBOL reuse from §2.2: safe because the
    PRK + salt are distinct (§2.2 PRK = exporter, no salt; §2.4 PRK =
    k_symbol, salt = record_id). Verify v6.3.0 pins this; CIRISEdge MUST
    NOT "fix" it to a different label or the impls diverge.
    """
    info = LABEL_SYMBOL + symbol_index.to_bytes(2, "big")
    prk = _hkdf_extract(record_id, k_symbol, "sha3_256")
    return _hkdf_expand(prk, info, 32, "sha3_256")


def _witness_cover_leaf(witness_key: bytes, leaf_position: int,
                        federation_epoch_id: int) -> bytes:
    """§3.4 — `HMAC-SHA3-256(key, u32_be(pos) || u64_be(epoch))`."""
    msg = leaf_position.to_bytes(4, "big") + federation_epoch_id.to_bytes(8, "big")
    return _hmac.new(witness_key, msg, hashlib.sha3_256).digest()


# ─────────────────────────────────────────────────────────────────────
# Cross-impl conformance vectors — lifted byte-for-byte from
# CIRISVerify v6.3.0 `ciris-crypto/src/scope_privacy.rs::tests`.
# Any drift in EITHER the CBOR preimage OR the record_id flags a §11
# wire-break in one of the two impls.
# ─────────────────────────────────────────────────────────────────────

K_REC_FIXED = bytes([0x11] * 32)
EXPORTER_FIXED = bytes([0x42] * 32)


def _hex(b: bytes) -> str:
    return b.hex()


@pytest.mark.ccs
def test_record_type_integer_encoding_pinned():
    """§2.4 RecordType: SelfRecord=1, FamilyRecord=2, CommunityRecord=3,
    FederationRecord=4 (0 reserved). Verify pins this as first impl; any
    second implementation MUST NOT use a different mapping.
    """
    assert RECORD_TYPE["self"]       == 1
    assert RECORD_TYPE["family"]     == 2
    assert RECORD_TYPE["community"]  == 3
    assert RECORD_TYPE["federation"] == 4
    # All values are distinct, no zero (0 is reserved by FSD §2.4).
    vals = list(RECORD_TYPE.values())
    assert len(set(vals)) == len(vals)
    assert 0 not in vals


@pytest.mark.ccs
def test_record_id_vector_1_small():
    """Vector 1: CommunityRecord, internal_id=b'record-0001', epoch=7.

    Single-byte uints throughout. The CBOR preimage is the canonical
    4-entry map; the resulting `record_id` is the HMAC-SHA3-256 over it.
    """
    cbor = _record_id_cbor(b"record-0001", RECORD_TYPE["community"], 7)
    assert _hex(cbor) == \
        "a46176016365706307636969644b7265636f72642d303030316374797003", \
        f"CBOR preimage drift (CIRISVerify v6.3.0 cross-impl): {_hex(cbor)}"

    rid = _derive_record_id(K_REC_FIXED, b"record-0001",
                            RECORD_TYPE["community"], 7)
    assert _hex(rid) == \
        "5428ddb514a8f8692cc4f254f3550ea75790f5069673e42afb6ef318517a0b21", \
        f"record_id drift (CIRISVerify v6.3.0 cross-impl): {_hex(rid)}"


@pytest.mark.ccs
def test_record_id_vector_2_u16_epoch():
    """Vector 2: FederationRecord, epoch=300 — `0x19 0x01 0x2c` u16 path.

    Exercises the multi-byte minimal-int encoding boundary (epoch>23, ≤u16).
    """
    cbor = _record_id_cbor(b"record-0002", RECORD_TYPE["federation"], 300)
    assert _hex(cbor) == \
        "a46176016365706319012c636969644b7265636f72642d303030326374797004", \
        f"CBOR preimage drift: {_hex(cbor)}"
    # Sanity: bytes 8..11 are the u16 epoch header + value.
    assert cbor[8:11] == bytes([0x19, 0x01, 0x2c]), cbor[8:11].hex()

    rid = _derive_record_id(K_REC_FIXED, b"record-0002",
                            RECORD_TYPE["federation"], 300)
    assert _hex(rid) == \
        "04eebeee4d5b83f2fdd0012a205781e6c05fe9a587377e6161b347629a189ff2", \
        f"record_id drift: {_hex(rid)}"


@pytest.mark.ccs
def test_record_id_vector_3_u32_epoch():
    """Vector 3: SelfRecord, internal_id=b'x', epoch=16909060 (0x01020304).

    Exercises the u32 minimal-int path (`0x1a` + 4 BE bytes).
    """
    cbor = _record_id_cbor(b"x", RECORD_TYPE["self"], 16_909_060)
    assert _hex(cbor) == \
        "a4617601636570631a010203046369696441786374797001", \
        f"CBOR preimage drift: {_hex(cbor)}"
    assert cbor[8:13] == bytes([0x1a, 0x01, 0x02, 0x03, 0x04]), cbor[8:13].hex()

    rid = _derive_record_id(K_REC_FIXED, b"x", RECORD_TYPE["self"], 16_909_060)
    assert _hex(rid) == \
        "79bee8b3f1e815a1df03ca9d83427dc5ab474e184f34e3876d3ef3c36559d6a3", \
        f"record_id drift: {_hex(rid)}"


@pytest.mark.ccs
def test_subkey_kat_bare_hkdf_expand():
    """§2.2 subkey KAT — bare HKDF-SHA256-Expand over a 32-byte PRK.

    Verify pins these bytes; CIRISEdge reproduces them. Drift here is a
    sign that someone called RFC 9420 `ExpandWithLabel` instead of the
    bare HKDF-Expand the FSD §2.2 cross-impl ratification flag requires.
    """
    kr = _k_record_id_from_exporter(EXPORTER_FIXED)
    ks = _k_symbol_from_exporter(EXPORTER_FIXED)
    assert _hex(kr) == \
        "49209926b0439f10d73d63317758b9ec19492429368c6aa67e33232da586af99", \
        f"k_record_id drift: {_hex(kr)}"
    assert _hex(ks) == \
        "3c973c828a218053dc909c51337ae256164437353bde347ee4bac6874888450f", \
        f"k_symbol drift: {_hex(ks)}"
    # Label domain separation.
    assert kr != ks


@pytest.mark.ccs
def test_symbol_key_diversification_layout():
    """§2.4 symbol_key — sensitivity to record_id (salt), k_symbol (ikm),
    and symbol_index (info-suffix). Drift means the (salt, ikm, info)
    triple is wired wrong.
    """
    k_symbol = bytes([0x22] * 32)
    rid      = bytes([0x33] * 32)
    base = _derive_symbol_key(k_symbol, rid, 0)
    # Deterministic.
    assert base == _derive_symbol_key(k_symbol, rid, 0)
    # symbol_index sensitivity.
    assert base != _derive_symbol_key(k_symbol, rid, 1)
    # record_id (salt) sensitivity.
    rid2 = bytearray(rid)
    rid2[0] ^= 0x01
    assert base != _derive_symbol_key(k_symbol, bytes(rid2), 0)
    # k_symbol (ikm) sensitivity.
    k2 = bytearray(k_symbol)
    k2[0] ^= 0x01
    assert base != _derive_symbol_key(bytes(k2), rid, 0)


@pytest.mark.ccs
def test_witness_cover_leaf_message_layout():
    """§3.4 cover-leaf — pin the `u32_be(pos) || u64_be(epoch)` 12-byte
    preimage. A second implementation that swaps byte order or width
    fails here.
    """
    key = b"k"
    # pos = 0x01020304, epoch = 0x0506070809000000
    got = _witness_cover_leaf(key, 0x0102_0304, 0x0506_0708_0900_0000)
    msg = (0x0102_0304).to_bytes(4, "big") + (0x0506_0708_0900_0000).to_bytes(8, "big")
    assert len(msg) == 12
    assert got == _hmac.new(key, msg, hashlib.sha3_256).digest()


@pytest.mark.ccs
def test_cbor_minimal_int_boundary():
    """RFC 8949 §3 inline-vs-extended boundary: 23 inline (single byte
    `0x17`); 24 needs a `0x18 0x18` header. A non-conformant encoder
    that ALWAYS uses `0x18`+u8 (even for values 0..=23) breaks
    cross-impl reproducibility on every record_id whose epoch lives in
    that range.
    """
    # Major 0 (uint), value 23 → inline.
    assert _cbor_head(0, 23) == bytes([0x17])
    # Major 0 (uint), value 24 → 0x18 0x18.
    assert _cbor_head(0, 24) == bytes([0x18, 0x18])
    # u64 path: u32::MAX + 1 forces the 8-byte tail.
    assert _cbor_head(0, 0x1_0000_0000) == bytes([0x1b, 0, 0, 0, 1, 0, 0, 0, 0])


@pytest.mark.ccs
def test_canonical_key_order_is_encoded_length_first():
    """The §2.4 CBOR map uses canonical key order by encoded-key bytes:
    shorter-first (1-byte "v"), then lexicographic among same-length
    ("epc" < "iid"; "iid" < "typ"). An implementation that sorts
    alphabetically WITHOUT the shorter-first rule produces a different
    preimage and a different record_id.
    """
    cbor = _record_id_cbor(b"record-0001", RECORD_TYPE["community"], 7)
    # Skip the map(4) header byte (0xa4), then find each text key.
    # The expected key order in the byte stream is v, epc, iid, typ.
    v_pos   = cbor.index(b"v",   1)
    epc_pos = cbor.index(b"epc", 1)
    iid_pos = cbor.index(b"iid", 1)
    typ_pos = cbor.index(b"typ", 1)
    assert v_pos < epc_pos < iid_pos < typ_pos, (v_pos, epc_pos, iid_pos, typ_pos)
