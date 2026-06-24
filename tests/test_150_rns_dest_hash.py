"""
RNS destination-hash recompute conformance (CEG 1.0-RC6 §5.6.8.8.1.1).

RC6 pins the RNS destination-hash construction in-spec so a conformant
verifier can recompute `destination_hash` from the spec alone — closing the
gap that made CIRISVerify ship `DestinationHashCheck::Unsupported` (the AV-42
destination-authenticity recompute was the one unverifiable step). Resolves
CIRISRegistry#80 / CIRISVerify#28.

The construction is **two-stage** — NOT a flat single SHA-256 over
`x25519 ‖ ed25519 ‖ app_name ‖ aspects` (the flat form the ≤RC5 "per the RNS
rule" wording implied yields a *different, wrong* value):

    name_hash        = SHA256(app_name + "." + ".".join(aspects))[:10]
    identity_hash    = SHA256(x25519_pub ‖ ed25519_pub)[:16]
    destination_hash = SHA256(name_hash ‖ identity_hash)[:16]

This file is the **executable spec** of that algorithm: a CCS golden-vector
test that any conformant verifier's recompute must match, plus the
anti-regression assertion that the naive flat form is rejected. The
cross-check against a *wheel's* recompute is `xfail` until the recompute is
exposed on the Python surface (CIRISVerify#28 lift / CIRISEdge PyO3 ask) —
realtime-transport surfaces (federation_session KEX, realtime_av) are Rust-only
today, so the dest-hash recompute follows the same exposure path.

Spec: reference/CEG/05_namespace.md §5.6.8.8.1.1 (vendored, 1.0-RC6).
"""

from __future__ import annotations

import hashlib

import pytest

# Pinned constants (CEG §5.6.8.8.1.1; RNS origin in comments).
NAME_HASH_LEN = 10   # Identity.NAME_HASH_LENGTH = 80 bits
DEST_HASH_LEN = 16   # Reticulum.TRUNCATED_HASHLENGTH = 128 bits


def ceg_destination_hash(
    app_name: str,
    aspects: list[str],
    x25519_pub: bytes,
    ed25519_pub: bytes,
) -> bytes:
    """Reference implementation of CEG §5.6.8.8.1.1, by the book.

    This IS the closed conformance source — it does not call Reticulum; a
    verifier that reproduces these four steps has performed the AV-42 check.
    """
    expanded_name = app_name
    for aspect in aspects:
        if "." in aspect:
            raise ValueError(f"aspect must not contain '.': {aspect!r}")
        expanded_name += "." + aspect
    name_hash = hashlib.sha256(expanded_name.encode("utf-8")).digest()[:NAME_HASH_LEN]
    identity_hash = hashlib.sha256(x25519_pub + ed25519_pub).digest()[:DEST_HASH_LEN]
    return hashlib.sha256(name_hash + identity_hash).digest()[:DEST_HASH_LEN]


# ─── Golden vector ────────────────────────────────────────────────────
# Deterministic inputs; the expected values are computed by the four pinned
# steps above and frozen here. A change to ANY of these expected strings is a
# change to the wire-verification contract and MUST be a deliberate CEG bump.
_X25519_PUB = bytes(range(0, 32))    # 00 01 .. 1f
_ED25519_PUB = bytes(range(32, 64))  # 20 21 .. 3f
_APP_NAME = "ciris.federation"
_ASPECTS = ["transport"]

_EXPECTED_NAME_HASH = "79c70d101a377a525aed"
_EXPECTED_IDENTITY_HASH = "fdeab9acf3710362bd2658cdc9a29e8f"
_EXPECTED_DEST_HASH = "98baa5d17abd7d940741d2f7b850577c"


@pytest.mark.ceg
@pytest.mark.ccs
def test_dest_hash_golden_vector():
    """§5.6.8.8.1.1: the two-stage construction matches the frozen golden vector."""
    expanded = _APP_NAME + "." + ".".join(_ASPECTS)
    name_hash = hashlib.sha256(expanded.encode()).digest()[:NAME_HASH_LEN]
    identity_hash = hashlib.sha256(_X25519_PUB + _ED25519_PUB).digest()[:DEST_HASH_LEN]
    dest_hash = ceg_destination_hash(_APP_NAME, _ASPECTS, _X25519_PUB, _ED25519_PUB)

    assert name_hash.hex() == _EXPECTED_NAME_HASH, name_hash.hex()
    assert identity_hash.hex() == _EXPECTED_IDENTITY_HASH, identity_hash.hex()
    assert dest_hash.hex() == _EXPECTED_DEST_HASH, dest_hash.hex()
    assert len(name_hash) == NAME_HASH_LEN
    assert len(dest_hash) == DEST_HASH_LEN


@pytest.mark.ceg
@pytest.mark.ccs
def test_dest_hash_is_two_stage_not_flat():
    """The flat single-concat SHA-256 (the ≤RC5 under-spec) yields a DIFFERENT value.

    This is the anti-regression the RC6 pin exists for: a verifier that
    naively hashed `x25519 ‖ ed25519 ‖ app_name ‖ aspects` flat would compute
    the wrong destination_hash and silently fail the AV-42 check.
    """
    two_stage = ceg_destination_hash(_APP_NAME, _ASPECTS, _X25519_PUB, _ED25519_PUB)
    flat = hashlib.sha256(
        _X25519_PUB + _ED25519_PUB + _APP_NAME.encode() + b"".join(a.encode() for a in _ASPECTS)
    ).digest()[:DEST_HASH_LEN]
    assert two_stage != flat, "two-stage and flat must differ — the RC6 latent-under-spec catch"


@pytest.mark.ceg
@pytest.mark.ccs
def test_dest_hash_key_order_matters():
    """Key order is x25519 THEN ed25519 (RNS get_public_key = pub ‖ sig_pub)."""
    correct = ceg_destination_hash(_APP_NAME, _ASPECTS, _X25519_PUB, _ED25519_PUB)
    swapped = ceg_destination_hash(_APP_NAME, _ASPECTS, _ED25519_PUB, _X25519_PUB)
    assert correct != swapped, "swapping the two pubkeys must change the hash"


@pytest.mark.ceg
@pytest.mark.ccs
def test_dest_hash_aspect_rejects_dot():
    """An aspect containing '.' is illegal (it would alter the name preimage split)."""
    with pytest.raises(ValueError):
        ceg_destination_hash(_APP_NAME, ["bad.aspect"], _X25519_PUB, _ED25519_PUB)


# ─── Cross-check against the wheel's recompute (LIVE as of verify v7.3.0) ──
# CIRISVerify shipped DestinationHashCheck::Unsupported, lifted it to a real
# recompute (v5.6.0), and exposed it on the Python wheel as
# `ciris_verify.rns_destination_hash` in **v7.3.0** (CIRISVerify#28 — the
# verify-side remainder of the transport-binding waterfall). This is now a REAL
# gate, not an xfail: where the symbol is present (matrix pin >= verify 7.3.0)
# the wheel recompute MUST match the pinned algorithm byte-for-byte; on an older
# pin (symbol absent) it skips cleanly until the matrix bumps. The remaining #28
# leg — the fleet Advisory→RequireTransportBinding enforcement flip — is consumer
# work (CIRISEdge#205), not the dest-hash recompute this asserts.
@pytest.mark.ceg
@pytest.mark.ccc
@pytest.mark.requires_verify
def test_wheel_recomputes_dest_hash_per_spec():
    """verify's wheel recompute MUST match §5.6.8.8.1.1 byte-for-byte (CIRISVerify#28, v7.3.0)."""
    import ciris_verify  # noqa: F401

    recompute = getattr(ciris_verify, "rns_destination_hash", None)
    if recompute is None:
        pytest.skip(
            "ciris_verify.rns_destination_hash requires ciris-verify >= 7.3.0 "
            "(the CIRISVerify#28 wheel lift); current matrix pin predates it"
        )
    got = recompute(_APP_NAME, _ASPECTS, _X25519_PUB, _ED25519_PUB)
    assert bytes(got) == bytes.fromhex(_EXPECTED_DEST_HASH)
