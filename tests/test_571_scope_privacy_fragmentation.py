"""
Substrate tier — CC 5.4.3 content-fragmentation wire discipline (scope-privacy
transport): the wire-exact per-symbol key derivation.

CC 5.4.3 (part_5_transport_substrate.md §5.4.3, "`fragmentation` — Uniform-envelope
fragmentation & reassembly") and its companion §5.4.2 (`symbol` — Uniform symbol
AEAD framing) define how a record's bytes are fountain-coded (RaptorQ) and each
symbol sealed under its OWN AEAD key, so a holder lacking the keys holds bytes
indistinguishable from random. The whole discipline hangs on one wire-exact
primitive, and the spec explicitly names CIRISConformance as its checker:

    symbol_key = HKDF-SHA3-256(salt=record_id, ikm=K_symbol,
                               info="ciris-edge/scope-privacy/symbol/v1"
                                    || u16_be(symbol_index), len=32)

"This matches `ciris_crypto::scope_privacy::derive_symbol_key` and the pinned
`LABEL_SYMBOL` constant; CIRISConformance asserts byte-for-byte reproducibility."
Any BE/LE disagreement on `symbol_index`, or any drift in the label bytes, yields a
different `symbol_key` → AEAD authentication failure on reassembly.

**The real wheel surface (server 0.5.102 + verify 9.0.0) — two independent
implementations.** The derivation chain is exposed by TWO separately-built wheels,
which is what makes "byte-for-byte reproducibility" checkable rather than
tautological:

- `ciris_server.k_symbol / derive_record_id / derive_symbol_key` — native `_native`
  (CIRISEdge#193 §2.2/§2.4). `derive_record_id` takes the pinned record-type INT
  (1=self, 2=family, 3=community, 4=federation).
- `ciris_verify.scope_privacy.k_symbol / k_record_id / derive_record_id /
  derive_symbol_key` — ctypes over `libciris_verify_ffi`, same sections;
  `derive_record_id` takes the record-type STR ("self"/"family"/"community"/
  "federation"). Docstring: "Reproduces verify v6.3.0's §9 KAT vectors byte-for-byte."

**Why the assertion is deterministic / robust.** Pure keyed-hash functions — no
Engine, no database, no Reticulum transport, no timing. Three independent oracles
must agree byte-for-byte on the 32-byte `symbol_key`: (1) the `ciris_server` native
impl, (2) the `ciris_verify` ctypes impl, and (3) an in-test pure-Python RFC-5869
HKDF-SHA3-256 recomputation of the exact §5.4.3 formula. It further pins the
index-diversification (idx N ≠ idx N+1), determinism (same inputs → same key), and
the `u16_be` index binding (a symbol index > 65535 raises `OverflowError` at
conversion — the BE/LE-sensitive 2-byte encoding). Backend-agnostic; identical
under sqlite and postgres. Loading both wheels in one subprocess is exactly the
`cohabitation` property. Nothing touches the scope-disable hook.
"""

from __future__ import annotations

import pytest

from conftest import run_python_script

# Both scope-privacy wheels cohabit one subprocess; a pure-Python RFC-5869
# HKDF-SHA3-256 recomputes the wire-exact §5.4.3 formula as a third oracle.
_BODY = r"""
import json, sys, hashlib, hmac
try:
    import ciris_server as srv
    from ciris_verify import scope_privacy as vfy
except ImportError as exc:
    print(json.dumps({"_error": "import", "detail": str(exc)})); sys.exit(2)

LABEL = b"ciris-edge/scope-privacy/symbol/v1"  # the pinned LABEL_SYMBOL constant


def hkdf_sha3_256(salt, ikm, info, length=32):
    # RFC 5869 HKDF instantiated with HMAC-SHA3-256 (the HNDL-discipline hash the
    # per-symbol layer mandates, distinct from the SHA-256 key-schedule one layer up).
    prk = hmac.new(salt, ikm, hashlib.sha3_256).digest()
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha3_256).digest()
        okm += block; counter += 1
    return okm[:length]


exporter = bytes(range(32))  # a fixed 32-byte MLS exporter_secret
ks_srv, ks_vfy = srv.k_symbol(exporter), vfy.k_symbol(exporter)
rid_srv = srv.derive_record_id(srv.k_record_id(exporter), b"internal-id", 2, 7)     # 2 == "family"
rid_vfy = vfy.derive_record_id(vfy.k_record_id(exporter), b"internal-id", "family", 7)

report = {
    "k_symbol_agree": ks_srv == ks_vfy,
    "record_id_agree": rid_srv == rid_vfy,
    "record_id_len": len(rid_srv),
    "per_index": {},
}
for idx in (0, 5, 65535):
    sk_srv = srv.derive_symbol_key(ks_srv, rid_srv, idx)
    sk_vfy = vfy.derive_symbol_key(ks_vfy, rid_vfy, idx)
    sk_ref = hkdf_sha3_256(salt=rid_srv, ikm=ks_srv, info=LABEL + idx.to_bytes(2, "big"))
    report["per_index"][idx] = {
        "server_eq_verify": sk_srv == sk_vfy,
        "server_eq_spec_formula": sk_srv == sk_ref,
        "len": len(sk_srv),
    }

report["index_diversified"] = (
    srv.derive_symbol_key(ks_srv, rid_srv, 5) != srv.derive_symbol_key(ks_srv, rid_srv, 6))
report["deterministic"] = (
    srv.derive_symbol_key(ks_srv, rid_srv, 5) == srv.derive_symbol_key(ks_srv, rid_srv, 5))
try:
    srv.derive_symbol_key(ks_srv, rid_srv, 70000)  # > u16::MAX
    report["u16_index_binding"] = "not_enforced"
except OverflowError:
    report["u16_index_binding"] = "overflow"
except Exception as exc:  # any conversion refusal still binds the index width
    report["u16_index_binding"] = type(exc).__name__

report["stage"] = "done"
print(json.dumps(report)); sys.stdout.flush()
import os; os._exit(0)
"""


@pytest.fixture(scope="module")
def symbol_kdf():
    payload = run_python_script(_BODY).parsed_stdout()
    if payload.get("_error") == "import":
        pytest.fail(f"scope-privacy wheel import failed: {payload.get('detail')}")
    assert payload.get("stage") == "done", payload
    return payload


@pytest.mark.cohabitation
@pytest.mark.requires_verify
@pytest.mark.requires_lens  # ciris_server
@pytest.mark.ccs
def test_symbol_key_matches_across_wheels_and_spec_formula(symbol_kdf):
    """CC 5.4.3 / 5.4.2: the per-symbol `symbol_key` is derived byte-for-byte
    identically by two independent wheels AND by the wire-exact spec formula.

    `ciris_server` (native) and `ciris_verify.scope_privacy` (ctypes) both compute
    `symbol_key = HKDF-SHA3-256(salt=record_id, ikm=K_symbol,
    info="ciris-edge/scope-privacy/symbol/v1" || u16_be(symbol_index))`, and both
    match an in-test pure-Python RFC-5869 HKDF-SHA3-256 recomputation across
    several symbol indices. Three independent oracles agreeing to the byte is the
    reproducibility guarantee §5.4.3 pins on CIRISConformance — the structural
    basis for a holder's truthful cold-state-ignorance claim.
    """
    assert symbol_kdf["k_symbol_agree"], "K_symbol subkey disagreed across wheels"
    assert symbol_kdf["record_id_agree"], "record_id disagreed across wheels"
    assert symbol_kdf["record_id_len"] == 32, symbol_kdf
    for idx, r in symbol_kdf["per_index"].items():
        assert r["len"] == 32, (idx, r)
        assert r["server_eq_verify"], (
            f"symbol_key(idx={idx}) differs between ciris_server and ciris_verify")
        assert r["server_eq_spec_formula"], (
            f"symbol_key(idx={idx}) does not match the HKDF-SHA3-256 §5.4.3 formula")


@pytest.mark.cohabitation
@pytest.mark.requires_verify
@pytest.mark.requires_lens  # ciris_server
@pytest.mark.ccs
def test_symbol_key_is_index_bound_and_deterministic(symbol_kdf):
    """CC 5.4.3: the derivation is deterministic, per-index diversified, and binds
    a `u16_be` symbol index.

    Same inputs → same key (a failed reproduction would break reassembly); index N
    and N+1 yield different keys (each RaptorQ symbol seals under its own key); and a
    symbol index beyond `u16::MAX` is refused at conversion — pinning the 2-byte
    big-endian `symbol_index` encoding whose BE/LE agreement §5.4.3 makes normative.
    """
    assert symbol_kdf["deterministic"], "symbol_key derivation is not deterministic"
    assert symbol_kdf["index_diversified"], (
        "symbol_key did not diversify by symbol_index (idx 5 == idx 6)")
    assert symbol_kdf["u16_index_binding"] == "overflow", (
        f"a symbol_index > u16::MAX was not refused — the u16_be index binding is "
        f"not enforced: {symbol_kdf['u16_index_binding']}")
