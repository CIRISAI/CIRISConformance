"""Scope-native privacy derivation conformance (CC 5.4 / CEG §11).

CC 5.4 absorbs the CEWP `SCOPE_PRIVACY.md` FSD (§2.2/§2.4/§3.4; CIRISRegistry#107)
into the wire layer: the deterministic, byte-pinned primitives a conformant
substrate uses to make real and cover traffic indistinguishable below the cohort
boundary — HMAC-opaque `record_id` addressing, per-symbol AEAD key diversification,
and the witness cover-leaf. These derivations MUST be byte-identical across
producer, substrate, and every consumer: any disagreement on CBOR byte order,
integer minimal-encoding, major-type selection, or HKDF/HMAC suite yields a
different tag and silently partitions holders of the same record.

This was a Rust-lane-only feature until **ciris-verify 8.3.0** exposed
`ciris_crypto::scope_privacy` on the Python wheel (CIRISVerify#82) over the FFI
symbol `ciris_verify_scope_privacy_derive`, as the `ciris_verify.scope_privacy`
namespace: `k_record_id`, `k_symbol`, `derive_record_id`, `derive_symbol_key`,
`witness_cover_leaf`. A Python consumer can now reproduce a `record_id` /
`symbol_key` / witness cover-leaf byte-identically to the Rust verifiers.

This file is the **executable golden-vector gate** for the §5.4.1 `record_id`
construction:

    record_id_input = CBOR_dCE({"v":1, "epc":epoch, "iid":internal_id(bytes), "typ":RecordType})
    record_id       = HMAC-SHA3-256(K_record_id, record_id_input)

The three normative vectors below (CC 5.4.1, "Conformance vectors (normative)")
are frozen with `K_record_id = 0x11` * 32. The wheel's recompute MUST match them
byte-for-byte; a change to ANY expected hex is a change to the wire-verification
contract and MUST be a deliberate CEG bump. This follows the
`tests/test_150_rns_dest_hash.py` model: frozen golden vector against the wheel
recompute, plus anti-regression cross-properties the construction guarantees
(major-type pinning, RecordType-integer pinning, salt/index/key diversification).

The spec carries explicit byte vectors only for `record_id`. For `symbol_key`
(§5.4.2 HKDF-SHA3-256) and `witness_cover_leaf` (§5.4.4 HMAC-SHA3-256) the spec
pins the *construction* (label bytes, BE width, salt = record_id) but no numeric
output vector — so those are gated by the cross-properties the construction
guarantees (determinism, salt/index/position/epoch diversification, key length),
not a fabricated byte vector.

Spec: reference/CIRIS_Constitution/part_5_transport_substrate.md CC 5.4.1–5.4.4
(vendored; CEWP SCOPE_PRIVACY §2.2/§2.4/§3.4, CIRISRegistry#107).
"""

from __future__ import annotations

import pytest

# scope_privacy loads its native lib via ctypes (NOT PyO3), so it's safe to
# import + drive in-process — same as test_150's wheel recompute leg. We import
# lazily inside each test so collection never fails when the wheel is older than
# verify 8.3.0 (the symbol is absent → clean skip, never a collection error).


# ─── §5.4.1 RecordType integer encoding (pinned; CC 5.4.1 table) ───────
# | Type             | int |  → the `record_type` string the FFI accepts maps
# | reserved         | 0   |    to this integer in the CBOR `typ` value.
# | SelfRecord       | 1   |    "self"=1, "family"=2, "community"=3, "federation"=4
# | FamilyRecord     | 2   |
# | CommunityRecord  | 3   |
# | FederationRecord | 4   |
_RECORD_TYPE_INTS = {"self": 1, "family": 2, "community": 3, "federation": 4}

# K_record_id used by the normative vector block.
_K_RECORD_ID = bytes([0x11]) * 32

# ─── Golden vectors (CC 5.4.1, normative) ─────────────────────────────
# Each tuple: (internal_id, record_type, epoch, expected_cbor_preimage_hex,
#              expected_record_id_hex). typ-int is implied by record_type.
#   v1 → typ=3 (community), v2 → typ=4 (federation), v3 → typ=1 (self).
# The `iid` value is a CBOR byte string (major type 2): the preimages carry
# 0x4b / 0x41 (major-2 length headers), NOT 0x6b / 0x61 (major-3 text) — that
# major-type choice is the silent-partition hazard the vectors pin.
_VECTORS = [
    (
        b"record-0001",
        "community",
        7,  # epc=0x07 in the preimage (…657063 07…)
        "a46176016365706307636969644b7265636f72642d303030316374797003",
        "5428ddb514a8f8692cc4f254f3550ea75790f5069673e42afb6ef318517a0b21",
    ),
    (
        b"record-0002",
        "federation",
        300,
        "a46176016365706319012c636969644b7265636f72642d303030326374797004",
        "04eebeee4d5b83f2fdd0012a205781e6c05fe9a587377e6161b347629a189ff2",
    ),
    (
        b"x",
        "self",
        0x01020304,
        "a4617601636570631a010203046369696441786374797001",
        "79bee8b3f1e815a1df03ca9d83427dc5ab474e184f34e3876d3ef3c36559d6a3",
    ),
]

# The pinned info label for the §5.4.2 symbol_key HKDF (and K_symbol derivation).
_LABEL_SYMBOL = b"ciris-edge/scope-privacy/symbol/v1"


def _scope_privacy_or_skip():
    """Return ciris_verify.scope_privacy, or skip if the surface predates verify 8.3.0.

    The native lib lazy-loads on first derive call (it's a ctypes CDLL, like
    test_150's rns recompute). A missing/old library surfaces as RuntimeError on
    first use — a host-provisioning gap, not a spec mismatch — so we skip, never
    red, mirroring test_150's libtss2 handling.
    """
    import ciris_verify

    sp = getattr(ciris_verify, "scope_privacy", None)
    if sp is None or not hasattr(sp, "derive_record_id"):
        pytest.skip(
            "ciris_verify.scope_privacy requires ciris-verify >= 8.3.0 "
            "(the CIRISVerify#82 wheel lift); current matrix pin predates it"
        )
    return sp


def _derive_or_skip(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except RuntimeError as exc:
        # The Python symbol exists even when the native CIRISVerify shared lib
        # can't load on this host (FFI lazy-loads on first call). That's a
        # provisioning gap, not a spec mismatch — skip, like test_150.
        if "could not load" in str(exc) or "library" in str(exc).lower():
            pytest.skip(
                f"scope_privacy present but its native lib can't load on this host: {exc}"
            )
        raise


# ─── record_id golden-vector gate ─────────────────────────────────────
@pytest.mark.ceg
@pytest.mark.ccs
@pytest.mark.requires_verify
@pytest.mark.parametrize("iid,record_type,epoch,preimage_hex,record_id_hex", _VECTORS)
def test_record_id_golden_vector(iid, record_type, epoch, preimage_hex, record_id_hex):
    """CC 5.4.1: the wheel's record_id MUST match the normative vector byte-for-byte.

    `preimage_hex` is documented here as the contract's CBOR preimage (the
    major-type-pinned `record_id_input`); the wheel only exposes the final tag,
    so the byte-exact assertion is on `record_id`. A mismatch is a wire-contract
    break (CBOR order / minimal-int / major-type / HMAC-suite drift).
    """
    sp = _scope_privacy_or_skip()
    got = _derive_or_skip(sp.derive_record_id, _K_RECORD_ID, iid, record_type, epoch)
    assert bytes(got).hex() == record_id_hex, bytes(got).hex()
    assert len(bytes(got)) == 32  # HMAC-SHA3-256 → 32-byte tag


@pytest.mark.ceg
@pytest.mark.ccs
@pytest.mark.requires_verify
def test_record_id_is_deterministic():
    """Same inputs → same record_id (pure function; the ALM 'directory' is deterministic)."""
    sp = _scope_privacy_or_skip()
    a = _derive_or_skip(sp.derive_record_id, _K_RECORD_ID, b"record-0001", "community", 1)
    b = sp.derive_record_id(_K_RECORD_ID, b"record-0001", "community", 1)
    assert bytes(a) == bytes(b)


@pytest.mark.ceg
@pytest.mark.ccs
@pytest.mark.requires_verify
def test_record_id_record_type_int_is_pinned():
    """The four RecordType ints are distinct and pinned: distinct typ → distinct record_id.

    Anti-regression for the CC 5.4.1 RecordType table — if two types ever
    collapsed to the same integer they'd produce the same record_id, cross-linking
    scopes that MUST stay unlinkable.
    """
    sp = _scope_privacy_or_skip()
    ids = {}
    for rt in _RECORD_TYPE_INTS:
        rid = bytes(_derive_or_skip(sp.derive_record_id, _K_RECORD_ID, b"same-iid", rt, 7))
        ids[rt] = rid
    assert len({v for v in ids.values()}) == len(_RECORD_TYPE_INTS), ids


@pytest.mark.ceg
@pytest.mark.ccs
@pytest.mark.requires_verify
def test_record_id_distinct_scopes_unlinkable():
    """Distinct internal_id / epoch → distinct record_id (the unlinkability argument)."""
    sp = _scope_privacy_or_skip()
    base = bytes(_derive_or_skip(sp.derive_record_id, _K_RECORD_ID, b"rec-A", "community", 1))
    diff_iid = bytes(sp.derive_record_id(_K_RECORD_ID, b"rec-B", "community", 1))
    diff_epoch = bytes(sp.derive_record_id(_K_RECORD_ID, b"rec-A", "community", 2))
    assert base != diff_iid, "different internal_id must yield a different record_id"
    assert base != diff_epoch, "epoch rebind (MLS Add/Remove) must yield a different record_id"


@pytest.mark.ceg
@pytest.mark.ccs
@pytest.mark.requires_verify
def test_record_id_unknown_type_rejected():
    """An unknown record_type is rejected (would otherwise pick an unpinned typ int)."""
    sp = _scope_privacy_or_skip()
    _scope_privacy_or_skip()  # ensure surface present before asserting the raise
    with pytest.raises(ValueError):
        sp.derive_record_id(_K_RECORD_ID, b"x", "bogus", 1)


# ─── K_record_id / K_symbol from the MLS exporter secret (§5.4 / §2.2) ─
@pytest.mark.ceg
@pytest.mark.ccs
@pytest.mark.requires_verify
def test_exporter_subkeys_shape_and_separation():
    """§2.2: K_record_id and K_symbol are 32-byte HKDF-Expand subkeys of one exporter, and differ.

    They share the raw `exporter_secret` ikm but use distinct labels, so they MUST
    be 32 bytes each and MUST NOT be equal — a collision would let `record_id`
    addressing and symbol-AEAD keying share entropy.
    """
    sp = _scope_privacy_or_skip()
    exporter = bytes(range(32))
    krid = bytes(_derive_or_skip(sp.k_record_id, exporter))
    ksym = bytes(sp.k_symbol(exporter))
    assert len(krid) == 32 and len(ksym) == 32
    assert krid != ksym, "K_record_id and K_symbol must be domain-separated"
    # Deterministic in the exporter secret.
    assert bytes(sp.k_record_id(exporter)) == krid
    # A different exporter (new MLS epoch) rebinds both.
    other = bytes([0xAB]) * 32
    assert bytes(sp.k_record_id(other)) != krid


# ─── §5.4.2 symbol_key — construction cross-properties (no numeric vector) ──
@pytest.mark.ceg
@pytest.mark.ccs
@pytest.mark.requires_verify
def test_symbol_key_diversification():
    """§5.4.2: symbol_key = HKDF-SHA3-256(salt=record_id, ikm=K_symbol, info=label‖u16_be(idx)).

    Spec pins the construction but ships no numeric vector, so we assert the
    cross-properties the construction guarantees: 32-byte output, deterministic,
    and diversified by BOTH the salt (record_id) and the symbol_index. A u16_be /
    u16_le drift on the index, or losing the salt binding, would collapse these.
    """
    sp = _scope_privacy_or_skip()
    exporter = bytes(range(32))
    ksym = bytes(_derive_or_skip(sp.k_symbol, exporter))
    rid_a = bytes(sp.derive_record_id(_K_RECORD_ID, b"rec-A", "community", 1))
    rid_b = bytes(sp.derive_record_id(_K_RECORD_ID, b"rec-B", "community", 1))

    sk0 = bytes(sp.derive_symbol_key(ksym, rid_a, 0))
    sk1 = bytes(sp.derive_symbol_key(ksym, rid_a, 1))
    sk0_other_record = bytes(sp.derive_symbol_key(ksym, rid_b, 0))

    assert len(sk0) == 32
    assert sk0 == bytes(sp.derive_symbol_key(ksym, rid_a, 0)), "must be deterministic"
    assert sk0 != sk1, "distinct symbol_index must yield a distinct symbol_key"
    assert sk0 != sk0_other_record, "salt=record_id must diversify across records"


@pytest.mark.ceg
@pytest.mark.ccs
@pytest.mark.requires_verify
def test_symbol_key_index_is_big_endian_sensitive():
    """The u16_be(symbol_index) framing means index 1 and index 256 must differ.

    1 == 0x0001 and 256 == 0x0100 — under a correct u16_be these are distinct
    info preimages; a byte-swapped or width-confused encoding could collide them.
    """
    sp = _scope_privacy_or_skip()
    ksym = bytes(_derive_or_skip(sp.k_symbol, bytes(range(32))))
    rid = bytes(sp.derive_record_id(_K_RECORD_ID, b"rec", "community", 1))
    assert bytes(sp.derive_symbol_key(ksym, rid, 1)) != bytes(sp.derive_symbol_key(ksym, rid, 256))


# ─── §5.4.4 witness cover-leaf — construction cross-properties ─────────
@pytest.mark.ceg
@pytest.mark.ccs
@pytest.mark.requires_verify
def test_witness_cover_leaf_diversification():
    """§5.4.4: witness_cover_leaf = HMAC-SHA3-256(key, u32_be(pos) ‖ u64_be(epoch)).

    Under the IND of HMAC-SHA3 a cover leaf is indistinguishable from a real
    federation-scope record_id commitment. Spec pins the construction but no
    numeric vector — assert 32-byte output, determinism, and diversification by
    both leaf_position (u32_be) and federation_epoch_id (u64_be).
    """
    sp = _scope_privacy_or_skip()
    key = bytes([0x22]) * 32
    leaf = bytes(_derive_or_skip(sp.witness_cover_leaf, key, 0, 0))
    assert len(leaf) == 32
    assert leaf == bytes(sp.witness_cover_leaf(key, 0, 0)), "must be deterministic"
    assert leaf != bytes(sp.witness_cover_leaf(key, 1, 0)), "leaf_position must diversify"
    assert leaf != bytes(sp.witness_cover_leaf(key, 0, 1)), "federation_epoch_id must diversify"
    assert leaf != bytes(sp.witness_cover_leaf(bytes([0x33]) * 32, 0, 0)), "key must diversify"
