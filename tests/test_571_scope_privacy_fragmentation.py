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

**The real wheel surface — `ciris_verify.scope_privacy` (the same ctypes surface
test_500 drives for §5.4.1/§5.4.2).** `k_symbol / k_record_id / derive_record_id /
derive_symbol_key` load their native lib via `libciris_verify_ffi`; this is the
surface installed by the evidence-registry floor venv (persist/verify/edge), so the
registry can derive this claim's status without a host-provisioning skip. The
load-bearing oracle is verify's compiled derivation vs an in-test pure-Python
RFC-5869 HKDF-SHA3-256 recomputation of the exact §5.4.3 formula — a byte-for-byte
match rules out a BE/LE index bug, a label-constant drift, or the wrong hash.

**A second independent implementation cross-checks when present.** `ciris_server`
exposes the SAME derivation natively (`k_symbol / derive_record_id /
derive_symbol_key`, CIRISEdge#193 §2.2/§2.4, record-type INT 1=self/2=family/…). The
full cohabitation suite loads it and asserts server ≡ verify byte-for-byte — but
`ciris_server` is not part of the registry floor triple (and its native path needs
libtss2), so that leg is OPTIONAL: it runs when the wheel is importable and is
skipped in-script otherwise, never gating the load-bearing verify-vs-spec assertion.

**Why the assertion is deterministic / robust.** Pure keyed-hash functions — no
Engine, no database, no Reticulum transport, no timing. It pins the byte-exact
derivation, the index-diversification (idx N ≠ idx N+1), determinism (same inputs →
same key), and the `u16_be` index binding (a symbol index > 65535 raises
`OverflowError` at conversion — the BE/LE-sensitive 2-byte encoding). Backend-
agnostic; identical under sqlite and postgres. Nothing touches the scope-disable hook.
"""

from __future__ import annotations

import pytest

from conftest import run_python_script

# ciris_verify.scope_privacy (guaranteed, registry-floor surface) + a pure-Python
# RFC-5869 HKDF-SHA3-256 recompute of the wire-exact §5.4.3 formula. ciris_server,
# when importable, is a third oracle cross-checked byte-for-byte.
_BODY = r"""
import json, sys, hashlib, hmac
try:
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
# ── the load-bearing path: verify's compiled derivation vs the spec formula ──
try:
    ks_vfy = vfy.k_symbol(exporter)
    rid_vfy = vfy.derive_record_id(vfy.k_record_id(exporter), b"internal-id", "family", 7)
except OSError as exc:
    # scope_privacy present but its native lib can't load — same host-provisioning
    # signature test_500 documents; surface it as an error so the registry fails
    # loudly (a provisioning gap) rather than silently skipping.
    print(json.dumps({"_error": "native_lib", "detail": str(exc)[:200]})); sys.exit(2)

report = {"record_id_len": len(rid_vfy), "per_index": {}}
for idx in (0, 5, 65535):
    sk_vfy = vfy.derive_symbol_key(ks_vfy, rid_vfy, idx)
    sk_ref = hkdf_sha3_256(salt=rid_vfy, ikm=ks_vfy, info=LABEL + idx.to_bytes(2, "big"))
    report["per_index"][idx] = {"verify_eq_spec_formula": sk_vfy == sk_ref, "len": len(sk_vfy)}

report["index_diversified"] = (
    vfy.derive_symbol_key(ks_vfy, rid_vfy, 5) != vfy.derive_symbol_key(ks_vfy, rid_vfy, 6))
report["deterministic"] = (
    vfy.derive_symbol_key(ks_vfy, rid_vfy, 5) == vfy.derive_symbol_key(ks_vfy, rid_vfy, 5))
try:
    vfy.derive_symbol_key(ks_vfy, rid_vfy, 70000)  # > u16::MAX
    report["u16_index_binding"] = "not_enforced"
except OverflowError:
    report["u16_index_binding"] = "overflow"
except Exception as exc:  # any conversion refusal still binds the index width
    report["u16_index_binding"] = type(exc).__name__

# ── optional second oracle: ciris_server (not in the registry floor triple) ──
report["server_present"] = False
report["server_eq_verify"] = None
try:
    import ciris_server as srv
    ks_srv = srv.k_symbol(exporter)
    rid_srv = srv.derive_record_id(srv.k_record_id(exporter), b"internal-id", 2, 7)  # 2 == "family"
    report["server_present"] = True
    report["server_eq_verify"] = (
        ks_srv == ks_vfy and rid_srv == rid_vfy
        and all(srv.derive_symbol_key(ks_srv, rid_srv, i) == vfy.derive_symbol_key(ks_vfy, rid_vfy, i)
                for i in (0, 5, 65535)))
except Exception:
    pass  # server not installed / native lib absent — verify-vs-spec still stands

report["stage"] = "done"
print(json.dumps(report)); sys.stdout.flush()
import os; os._exit(0)
"""


@pytest.fixture(scope="module")
def symbol_kdf():
    payload = run_python_script(_BODY).parsed_stdout()
    if payload.get("_error") == "import":
        pytest.fail(f"ciris_verify.scope_privacy import failed: {payload.get('detail')}")
    if payload.get("_error") == "native_lib":
        pytest.fail(
            f"ciris_verify.scope_privacy native lib can't load on this host "
            f"(provisioning gap, not a spec mismatch): {payload.get('detail')}")
    assert payload.get("stage") == "done", payload
    return payload


@pytest.mark.ceg
@pytest.mark.requires_verify
@pytest.mark.ccs
def test_symbol_key_matches_spec_formula(symbol_kdf):
    """CC 5.4.3 / 5.4.2: the per-symbol `symbol_key` matches the wire-exact spec
    formula byte-for-byte.

    `ciris_verify.scope_privacy` computes `symbol_key = HKDF-SHA3-256(salt=record_id,
    ikm=K_symbol, info="ciris-edge/scope-privacy/symbol/v1" || u16_be(symbol_index))`,
    and it matches an in-test pure-Python RFC-5869 HKDF-SHA3-256 recomputation across
    several symbol indices — the reproducibility guarantee §5.4.3 pins on
    CIRISConformance (the structural basis for a holder's truthful cold-state-
    ignorance claim). When `ciris_server` is also importable, its independent native
    derivation is cross-checked byte-for-byte as a second oracle.
    """
    assert symbol_kdf["record_id_len"] == 32, symbol_kdf
    for idx, r in symbol_kdf["per_index"].items():
        assert r["len"] == 32, (idx, r)
        assert r["verify_eq_spec_formula"], (
            f"symbol_key(idx={idx}) does not match the HKDF-SHA3-256 §5.4.3 formula")
    # Optional cross-wheel oracle — only asserted when ciris_server is present.
    if symbol_kdf["server_present"]:
        assert symbol_kdf["server_eq_verify"], (
            "ciris_server and ciris_verify disagree on the scope-privacy derivation")


@pytest.mark.ceg
@pytest.mark.requires_verify
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
    # A symbol_index beyond u16::MAX MUST be refused at conversion (it cannot be
    # encoded in the 2-byte u16_be field). Both impls refuse it, with different
    # exception types — verify's ctypes surface raises ValueError, the ciris_server
    # native path raises OverflowError; either is a valid width-binding refusal.
    # "not_enforced" (the call returned a key) is the only failure.
    assert symbol_kdf["u16_index_binding"] != "not_enforced", (
        f"a symbol_index > u16::MAX was NOT refused — the u16_be index binding is "
        f"not enforced (derivation returned a key): {symbol_kdf['u16_index_binding']}")
