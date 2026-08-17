"""
Substrate tier — CC 0.7 hash-pinned two-tier wire vocabulary (§2.6.4 + manifests/WIRE_VOCABULARY.md).

CC 0.7 promotes the set of message types the substrate recognizes from "whatever
`CIRISEdge::MessageType` happens to hold" into a **ratified, hash-pinned
contract**: `manifests/WIRE_VOCABULARY.md`. It is governed in two tiers (the
RFC 8126 registration-policy discipline):

- **Tier 1 — closed, CC-ratified `MessageType` variants.** 25 variants whose
  canonicalization is load-bearing to an ethical primitive (attestations, votes,
  moderation/slashing, deferral, steward directives, key registration, the
  humanity-accord path, `Withdraws`, goals, build provenance, content/blob
  fetch). Adding/removing/re-semanticizing one is a wire break riding the CC
  §4.5.1 "Standards Action" amendment path.
- **Tier 2 — three opaque channels** (`OpaqueRequest` / `OpaqueResponse` /
  `OpaqueEvent`) carrying a `kind: u32` from a per-repo range (RFC 8126 "Private
  Use"); Edge treats `payload` as opaque bytes.

Plus `DSARRequest` / `DSARResponse`, which §3.3 keeps **Tier-1** (rights-bearing +
Durable/requires_ack, which the opaque model can't express) — so the wheel's
closed `MessageType` enum is exactly **25 Tier-1 + 3 opaque + 2 DSAR = 30**.

This is the executable form of the pin. The wheel exposes the closed enum through
`Edge.build_signed_inbound_envelope(...)` (CIRISEdge#211): a valid wire-string
`message_type` builds; an unknown/retired one is refused *at parse* with a serde
`unknown variant` error that enumerates the whole accepted set. This test:

  (a) drives every variant the manifest names Tier-1 (incl. opaque + DSAR) through
      `build_signed_inbound_envelope` and asserts it is accepted;
  (b) asserts the three §3.3 migrants that CC 0.7 **removes** from Tier-1
      (`InlineText`, `AccordEventsBatch`, `FederationKeyDirectoryQuery`) are now
      rejected with `unknown variant` — the retired-variant catch;
  (c) pins the module constants `CODEC_OPAQUE == 255` (the Tier-2 opaque codec)
      and `SUPPORTED_SCHEMA_VERSIONS == ['1.0.0']` (the envelope `SchemaVersion`,
      orthogonal to the vocabulary version per manifest §1); and
  (d) **cross-checks the wheel's accepted set against the manifest byte-for-name**
      — the accepted enum MUST equal the manifest-derived Tier-1 ∪ opaque ∪ DSAR
      set exactly, so the test goes red if the wheel and the manifest drift in
      *either* direction (a wheel variant not in the manifest, or a manifest
      variant the wheel dropped).

The manifest itself carries **no concrete hash value** — its `WIRE_VOCABULARY_HASH`
is the placeholder `hex!("…")` (the artifact is DRAFT for the coordinated v8.0.0
cut, hash "computed at build time") — and neither edge nor verify exposes a
recompute/verify-hash surface on the Python wheel. So there is no byte-exact
hash-pin to gate à la `tests/test_150_rns_dest_hash.py`; this gates the
accept/reject membership behavior the hash pin will (eventually) protect.

Spec: reference/CIRIS_Constitution/part_2_the_grammar.md §2.6.4 +
reference/CIRIS_Constitution/WIRE_VOCABULARY.md (CC 0.7, vocabulary v1.0.1).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from conftest import REPO_ROOT, get_database_url, run_python_script

MANIFEST_PATH = REPO_ROOT / "reference" / "CIRIS_Constitution" / "WIRE_VOCABULARY.md"


# ─── Manifest-derived expectation (the drift anchor) ──────────────────
# Parse the ratified artifact so the test's expectation IS the manifest, not a
# second hand-copied list. A change to the manifest's Tier-1 table, opaque
# block, or DSAR disposition changes what this test demands of the wheel.


def _table_col1_variants(section: str) -> list[str]:
    """First-column backticked `Variant` tokens of a markdown table."""
    return [m.group(1) for m in re.finditer(r"^\|\s`([A-Za-z][A-Za-z0-9]+)`\s\|", section, re.M)]


def _manifest_sets() -> dict[str, set[str]]:
    txt = MANIFEST_PATH.read_text()
    sec2 = txt[txt.index("## 2. Tier 1"):txt.index("## 3. Tier 2")]
    sec3 = txt[txt.index("## 3. Tier 2"):]

    tier1 = set(_table_col1_variants(sec2))          # 25 closed Tier-1 variants

    # The three opaque channels — parsed from the §3 ```rust``` block, not
    # hand-listed, so a manifest that changes the opaque set changes the gate.
    opaque = set(re.findall(r"\b(Opaque(?:Request|Response|Event))\b", sec3))

    # DSAR kept Tier-1 (§3.3 "stay Tier-1"); guard the disposition text so a
    # future migration of DSAR is caught rather than silently mis-expected.
    dsar = {"DSARRequest", "DSARResponse"}
    dsar_kept = "stay Tier-1" in sec3 and all(d in txt for d in dsar)

    # §3.3 migrants CC 0.7 removes from Tier-1 → the wheel MUST reject these.
    migrants = set(_table_col1_variants(sec3))

    return {
        "tier1": tier1,
        "opaque": opaque,
        "dsar": dsar if dsar_kept else set(),
        "migrants": migrants,
    }


_SETS = _manifest_sets()
# The full closed enum the wheel must recognize = Tier-1 ∪ opaque ∪ DSAR.
_EXPECTED_ACCEPT = _SETS["tier1"] | _SETS["opaque"] | _SETS["dsar"]
_MIGRANTS = _SETS["migrants"]


# ─── Wheel probe ──────────────────────────────────────────────────────
# Build a real Edge and, for every candidate wire-string, actually call
# `build_signed_inbound_envelope` — a variant that builds is accepted; one that
# raises `unknown variant` at parse is rejected. Also harvest the wheel's OWN
# enumeration of the accepted set from the serde error (the drift cross-check).

_PROBE_BODY = r"""
import json, sys, os, re, tempfile, secrets
try:
    import ciris_persist as cp
    from ciris_edge import ciris_edge as cei
    from ciris_edge.ciris_edge import init_edge_runtime
except ImportError as exc:
    print(json.dumps({"_error": "import", "detail": str(exc)})); sys.exit(2)

_seed = secrets.token_bytes(32)
_d = tempfile.mkdtemp()
_sp = os.path.join(_d, "s"); open(_sp, "wb").write(_seed)
_idp = os.path.join(_d, "t.id"); open(_idp, "wb").write(b"\x00" * 64)
cp.reset_engine()
k = "node-" + secrets.token_hex(8)
# Ed25519-only engine + ed25519_fallback edge — the documented pairing for
# build_signed_inbound_envelope (it emits no PQC half).
engine = cp.Engine(DB_URL, k, local_key_id=k, local_key_path=_sp)
kid = engine.register_self_federation_key("agent", "wire-ref", None, None, None)
# HTTPS-only keeps the engine Ed25519-only — the documented pairing this test
# is about. edge v17 (CIRISEdge#458) refuses to stand up the RETICULUM
# transport without an ML-DSA-65 half; provisioning one would make
# register_self publish a PQC pubkey and the key would stop being
# hybrid-pending, which is the state `ed25519_fallback` exists to accept.
# `disable_reticulum=True` requires an https_listen_addr in exchange (an edge
# with no transports at all is refused). The wire vocabulary is a
# codec/variant question, not a transport one.
edge = init_edge_runtime(engine, _idp, hybrid_policy="ed25519_fallback",
                         disable_reticulum=True,
                         https_listen_addr="127.0.0.1:0",
                         https_dev_self_signed=True)
if not hasattr(edge, "build_signed_inbound_envelope"):
    print(json.dumps({"_error": "absent"})); sys.exit(2)
dest = edge.signer_key_id()

def build(mt):
    try:
        edge.build_signed_inbound_envelope(kid, _seed, dest, mt, "{}")
        return "accepted"
    except Exception as exc:
        return str(exc)

report = {}
# (1) Try each candidate the manifest names; record accept vs the error text.
report["accept"] = {mt: build(mt) for mt in ACCEPT_CANDIDATES}
# (2) Try each retired/migrant variant; record the rejection text.
report["migrants"] = {mt: build(mt) for mt in MIGRANT_CANDIDATES}
# (3) Harvest the wheel's own accepted-set enumeration from a deliberately
#     bogus variant's serde error ("... expected one of `A`, `B`, ...").
err = build("__DEFINITELY_NOT_A_VARIANT__")
idx = err.find("expected one of")
report["wheel_accept_set"] = re.findall(r"`([A-Za-z0-9_]+)`", err[idx:]) if idx >= 0 else []
# (4) The two Tier-2 / envelope-schema module constants.
report["CODEC_OPAQUE"] = getattr(cei, "CODEC_OPAQUE", None)
report["SUPPORTED_SCHEMA_VERSIONS"] = list(getattr(cei, "SUPPORTED_SCHEMA_VERSIONS", []) or [])

report["stage"] = "done"
print(json.dumps(report)); sys.stdout.flush()
sys.exit(0)
"""


def _probe_script(database_url: str) -> str:
    header = (
        f"DB_URL = {database_url!r}\n"
        f"ACCEPT_CANDIDATES = {sorted(_EXPECTED_ACCEPT)!r}\n"
        f"MIGRANT_CANDIDATES = {sorted(_MIGRANTS)!r}\n"
    )
    return header + _PROBE_BODY


@pytest.fixture(scope="module")
def wire():
    result = run_python_script(_probe_script(get_database_url()))
    payload = result.parsed_stdout()
    if payload.get("_error") == "absent":
        pytest.fail("edge.build_signed_inbound_envelope is missing — the wire-vocabulary "
                    "gate needs CIRISEdge#211 (edge >= 7.0.10)")
    assert payload.get("stage") == "done", payload
    return payload


@pytest.mark.cohabitation
@pytest.mark.requires_persist
@pytest.mark.requires_edge
def test_tier1_and_opaque_variants_accepted(wire):
    """CC 0.7 §2/§3: every manifest-named Tier-1 / opaque / DSAR variant builds.

    Drives each accepted wire-string through the real `build_signed_inbound_envelope`
    — a full build+sign, not a lookup — and asserts none is refused. This is the
    positive half of the closed-vocabulary contract.
    """
    assert _EXPECTED_ACCEPT, "manifest parse yielded no accepted variants"
    refused = {mt: r for mt, r in wire["accept"].items() if r != "accepted"}
    assert not refused, (
        f"manifest-ratified variants refused by the wheel: {refused}")


@pytest.mark.cohabitation
@pytest.mark.requires_persist
@pytest.mark.requires_edge
def test_retired_variants_rejected_unknown_variant(wire):
    """CC 0.7 §3.3: the migrated-out variants are refused with `unknown variant`.

    `InlineText`, `AccordEventsBatch`, `FederationKeyDirectoryQuery` are the three
    variants CC 0.7 removes from Tier-1 (they move to Tier-2 opaque channels owned
    by their range stewards). The retired-variant catch: each MUST now be rejected
    at parse — the same way `tests/test_230_intake_gate.py` once built `InlineText`
    and no longer can.
    """
    assert _MIGRANTS, "manifest parse yielded no migrants to assert rejection of"
    for mt, res in wire["migrants"].items():
        assert res != "accepted", f"retired variant {mt!r} is still accepted by the wheel"
        assert "unknown variant" in res, (
            f"{mt!r} rejected, but not with the serde `unknown variant` signal: {res}")


@pytest.mark.cohabitation
@pytest.mark.requires_edge
def test_codec_opaque_and_schema_version_pins(wire):
    """CC 0.7 §3 / manifest §1: `CODEC_OPAQUE == 255` and the envelope schema pin.

    `CODEC_OPAQUE` is the Tier-2 opaque-payload codec; `SUPPORTED_SCHEMA_VERSIONS`
    is the `EdgeEnvelope` `SchemaVersion` set, orthogonal to the vocabulary version
    (manifest §1). Both are wire-contract constants — a change is a substrate cut.
    """
    assert wire["CODEC_OPAQUE"] == 255, wire["CODEC_OPAQUE"]
    assert wire["SUPPORTED_SCHEMA_VERSIONS"] == ["1.0.0"], wire["SUPPORTED_SCHEMA_VERSIONS"]


@pytest.mark.cohabitation
@pytest.mark.requires_persist
@pytest.mark.requires_edge
def test_wheel_accept_set_matches_manifest_no_drift(wire):
    """CC 0.7 §4: the wheel's closed enum equals the manifest set exactly.

    The load-bearing anti-drift assertion the hash pin exists to enforce. The set
    the wheel recognizes (harvested from its own serde enumeration) MUST equal the
    manifest-derived Tier-1 ∪ opaque ∪ DSAR set — no extra variant the manifest
    doesn't ratify, and no ratified variant the wheel dropped. Either direction is
    a substrate-tier build failure once the vocabulary hash is committed (manifest
    §4); here it is a red gate.
    """
    wheel = set(wire["wheel_accept_set"])
    assert wheel, "could not harvest the wheel's accepted-variant enumeration"
    missing = _EXPECTED_ACCEPT - wheel   # ratified by manifest, absent on wheel
    extra = wheel - _EXPECTED_ACCEPT     # on wheel, not ratified by manifest
    assert not missing and not extra, (
        f"wheel/manifest wire-vocabulary drift — "
        f"manifest-only (wheel dropped): {sorted(missing)}; "
        f"wheel-only (not in manifest): {sorted(extra)}")
