"""
RNS destination-hash recompute conformance (CEG 1.0-RC7 §5.6.8.8.1.1).

The §5.6.8.8.1.1 RNS destination-hash construction (pinned in 1.0-RC6,
unchanged through the 1.0-RC7 re-vendor — RC7 is no-wire-change) is in-spec
so a conformant
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

Spec: reference/CEG/05_namespace.md §5.6.8.8.1.1 (vendored, 1.0-RC7).
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

    This is the anti-regression the §5.6.8.8.1.1 pin exists for (pinned in
    RC6, carried unchanged into the vendored 1.0-RC7 spec): a verifier that
    naively hashed `x25519 ‖ ed25519 ‖ app_name ‖ aspects` flat would compute
    the wrong destination_hash and silently fail the AV-42 check.
    """
    two_stage = ceg_destination_hash(_APP_NAME, _ASPECTS, _X25519_PUB, _ED25519_PUB)
    flat = hashlib.sha256(
        _X25519_PUB + _ED25519_PUB + _APP_NAME.encode() + b"".join(a.encode() for a in _ASPECTS)
    ).digest()[:DEST_HASH_LEN]
    assert two_stage != flat, "two-stage and flat must differ — the ≤RC5 latent-under-spec catch"


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


# ─── Cross-check against the wheel's recompute (pending Python exposure) ──
# CIRISVerify shipped DestinationHashCheck::Unsupported; the §5.6.8.8.1.1 pin
# (RC6, vendored here at 1.0-RC7) unblocks lifting
# that stub to a real recompute. When the recompute (or the transport-identity
# pubkeys + dest-hash) is exposed on the Python wheel surface, this flips to a
# green gate asserting the wheel matches the pinned algorithm above. Today the
# transport/dest-hash surfaces are Rust-only (federation_session + realtime_av
# are not on the PyO3 wheel; PyEdge.reticulum_dest_hash_hex() returns the local
# node's hash but takes no inputs to recompute an arbitrary peer's).
@pytest.mark.ceg
@pytest.mark.ccc
@pytest.mark.requires_verify
@pytest.mark.xfail(
    strict=False,
    reason="CIRISVerify#28 — dest-hash recompute not yet on the Python wheel surface "
    "(transport KEX/realtime_av are Rust-only); flips to a real gate when exposed.",
)
def test_wheel_recomputes_dest_hash_per_spec():
    """When verify exposes the recompute, it MUST match §5.6.8.8.1.1 byte-for-byte."""
    import ciris_verify  # noqa: F401

    recompute = getattr(ciris_verify, "rns_destination_hash", None)
    if recompute is None:
        pytest.xfail("ciris_verify.rns_destination_hash not exposed yet (CIRISVerify#28)")
    got = recompute(_APP_NAME, _ASPECTS, _X25519_PUB, _ED25519_PUB)
    assert bytes(got) == bytes.fromhex(_EXPECTED_DEST_HASH)
