"""
Substrate tier — CC 3.1.2.1 provenance primitives (`CLM-provenance`),
per-locale Merkle composition leg.

CC 3.1.2.1 (part_3_the_namespace.md §3.1.2.1, "`provenance` — Canonical-bytes
contracts for provenance primitives") pins the exact bytes a producer signs and a
consumer recomputes for provenance primitives, including the per-locale Merkle
composition (RFC 6962-style):

    leaf_hash[lang]  = sha256( 0x00 || JCS(locale_manifest_object) )   # leaf domain
    parent_hash(l,r) = sha256( 0x01 || l || r )                       # parent domain

DELIBERATE SCOPE CAVEAT — assert the COMPOSITION, not the CC-pinned leaf preimage.
CC 3.1.2.1 pins the leaf-manifest domain literal `ciris.locale_manifest.v2` and a
field named `locale`. The SHIPPED floor (ciris_verify 10.1.1, embedded in the
persist wheel's locale surface) carries domain `ciris.locale_manifest.v1` and names
the field `lang_code` — the `LocaleLeaf` struct rejects `locale` with
`missing field 'lang_code'`, and the wheel's leaf hash does NOT reproduce from
`sha256(0x00 || JCS({...,"domain":"ciris.locale_manifest.v2","locale":...}))`. That
is a CC-vs-impl drift (CC says v2/`locale`; the floor ships v1/`lang_code`), filed
upstream (CIRISVerify/CIRISPersist locale-manifest domain drift).

So this test asserts ONLY what is genuinely green: the RFC 6962 COMPOSITION and its
domain separation, which the floor reproduces byte-exactly, plus tamper-rejection.
It does NOT assert the CC-pinned leaf preimage (blocked by the drift above).

What is REAL on the floor (persist 16.1.1), driven end-to-end here:

- **Parent composition is exactly RFC 6962.** `locale_merkle_root_hex([en, fr])`
  over two leaves equals `sha256(0x01 || leaf_en || leaf_fr)` — the CC 3.1.2.1
  parent-domain rule, byte-exact (leaves are computed by the wheel via
  `locale_leaf_hash_hex`, so the leaf preimage is treated as an opaque wheel
  primitive and never re-derived here).
- **Leaves are distinct per locale.** Changing only `lang_code` en→fr yields a
  different leaf hash (the leaf binds the locale).
- **Valid inclusion verifies.** `verify_locale_inclusion_json(leaf, proof, root)`
  returns `{"valid": true, ...}` for a correct inclusion proof, at both leaf indices.
- **Three distinct tamper modes reject** with distinct named tokens: wrong expected
  root, tampered sibling hash (both → "reconstructed root != expected parent root"),
  and a leaf_hash that does not match the sub-manifest (→ "leaf_hash != computed
  leaf hash from sub-manifest").

Real surface: `Engine.locale_leaf_hash_hex(leaf_json) -> hex`,
`Engine.locale_merkle_root_hex(leaves_json) -> hex`,
`Engine.verify_locale_inclusion_json(leaf_json, proof_json, expected_root_hex)`.
Real (discovered, NOT CC-pinned) shapes: `LocaleLeaf = {target, lang_code,
files_root, build_id, signer_identity}`; `LocaleInclusionProof = {leaf_hash,
lang_code, sibling_hashes, leaf_index, tree_size}`.
"""

from __future__ import annotations

import pytest

from conftest import get_database_url, run_python_script

pytestmark = [pytest.mark.ceg, pytest.mark.ccc]

_BODY = r"""
import json, sys, os, tempfile, secrets, hashlib

def report(obj):
    print(json.dumps(obj)); sys.stdout.flush(); os._exit(0)

try:
    import ciris_persist as cp
except ImportError as exc:
    print(json.dumps({"_error": "import", "detail": str(exc)})); sys.exit(2)

if INJECTED_URL.startswith("postgres"):
    DB_URL = INJECTED_URL
else:
    _dbf = os.path.join(tempfile.mkdtemp(), "f.db"); open(_dbf, "a").close()
    DB_URL = "sqlite:///" + _dbf

_d = tempfile.mkdtemp()
_s = os.path.join(_d, "s"); open(_s, "wb").write(secrets.token_bytes(32))
_p = os.path.join(_d, "p"); open(_p, "wb").write(secrets.token_bytes(32))
_k = "lp-" + secrets.token_hex(8)
cp.reset_engine()
E = cp.Engine(DB_URL, _k, local_key_id=_k, local_key_path=_s,
              local_pqc_key_id=_k + "-pqc", local_pqc_key_path=_p)
kid = E.register_self_federation_key("agent", "locale-provenance", None, None, None)

for surface in ("locale_leaf_hash_hex", "locale_merkle_root_hex",
                "verify_locale_inclusion_json"):
    if not hasattr(E, surface):
        print(json.dumps({"_error": "absent", "surface": surface})); sys.exit(2)

# Two per-locale leaves differing only in lang_code (the floor's field name).
EN = {"target": "linux-x64", "lang_code": "en", "files_root": "aa" * 32,
      "build_id": "b1", "signer_identity": kid}
FR = dict(EN, lang_code="fr")

h_en = E.locale_leaf_hash_hex(json.dumps(EN))
h_fr = E.locale_leaf_hash_hex(json.dumps(FR))
root = E.locale_merkle_root_hex(json.dumps([EN, FR]))

r = {
    "leaves_distinct": h_en != h_fr,
    # RFC 6962 parent domain separation: sha256(0x01 || left || right).
    "rfc6962_parent": root == hashlib.sha256(
        b"\x01" + bytes.fromhex(h_en) + bytes.fromhex(h_fr)).hexdigest(),
}


def _proof(leaf_hash, lang_code, siblings, index):
    return json.dumps({"leaf_hash": leaf_hash, "lang_code": lang_code,
                       "sibling_hashes": siblings, "leaf_index": index, "tree_size": 2})


def _inc(label, leaf, proof_json, expected_root):
    try:
        r[label] = {"outcome": "ok", "value": json.loads(
            E.verify_locale_inclusion_json(leaf, proof_json, expected_root))}
    except Exception as exc:
        r[label] = {"outcome": "err", "token": str(exc)[:180]}


# Valid inclusion at both indices.
_inc("valid_en", json.dumps(EN), _proof(h_en, "en", [h_fr], 0), root)
_inc("valid_fr", json.dumps(FR), _proof(h_fr, "fr", [h_en], 1), root)
# Tamper mode 1: wrong expected root.
_inc("wrong_root", json.dumps(EN), _proof(h_en, "en", [h_fr], 0), "ff" * 32)
# Tamper mode 2: tampered sibling hash.
_inc("tampered_sibling", json.dumps(EN), _proof(h_en, "en", ["00" * 32], 0), root)
# Tamper mode 3: leaf_hash does not match the presented sub-manifest.
_inc("leaf_mismatch", json.dumps(EN), _proof(h_fr, "en", [h_fr], 0), root)

r["stage"] = "done"
report(r)
"""


@pytest.fixture(scope="module")
def locale():
    script = f"INJECTED_URL = {get_database_url()!r}\n" + _BODY
    payload = run_python_script(script).parsed_stdout()
    if payload.get("_error") == "absent":
        pytest.fail(f"persist locale-merkle surface missing: {payload.get('surface')}")
    if payload.get("_error"):
        pytest.fail(f"probe failed: {payload}")
    assert payload.get("stage") == "done", payload
    return payload


@pytest.mark.requires_persist
def test_parent_composition_is_rfc6962_domain_separated(locale):
    """CC 3.1.2.1: `parent_hash(l, r) = sha256(0x01 || l || r)`.

    The wheel's Merkle root over two leaves equals the RFC 6962 parent hash with the
    0x01 parent-domain prefix — byte-exact. (Leaves are the wheel's own
    `locale_leaf_hash_hex` outputs, so the 0x00 leaf-domain separation is exercised
    transitively; the CC-pinned leaf PREIMAGE is not asserted — see the module
    docstring's drift caveat.)
    """
    assert locale["rfc6962_parent"] is True, (
        "locale_merkle_root_hex did not equal sha256(0x01 || leaf_en || leaf_fr) — "
        "the parent composition is not RFC 6962 domain-separated as CC 3.1.2.1 pins")


@pytest.mark.requires_persist
def test_leaves_are_distinct_per_locale(locale):
    """CC 3.1.2.1: the per-locale leaf binds the locale — two leaves differing only
    in `lang_code` hash differently.
    """
    assert locale["leaves_distinct"] is True, (
        "en and fr leaves hashed identically — the leaf does not bind the locale")


@pytest.mark.requires_persist
@pytest.mark.parametrize("leaf_key", ["valid_en", "valid_fr"])
def test_valid_inclusion_verifies(locale, leaf_key):
    """CC 3.1.2.1: a correct inclusion proof verifies against the per-target root, at
    each leaf index.
    """
    res = locale[leaf_key]
    assert res["outcome"] == "ok", f"valid inclusion proof errored: {res}"
    assert res["value"].get("valid") is True, (
        f"a correct inclusion proof did not verify: {res}")


@pytest.mark.requires_persist
@pytest.mark.parametrize("mode,token", [
    ("wrong_root", "reconstructed root"),
    ("tampered_sibling", "reconstructed root"),
    ("leaf_mismatch", "leaf_hash"),
])
def test_tampered_inclusion_rejects(locale, mode, token):
    """CC 3.1.2.1: a provenance claim is only as trustworthy as its bytes — three
    distinct tamper modes reject with distinct, stable reason tokens.

    wrong expected root and a tampered sibling both fail root reconstruction; a
    leaf_hash that does not match the presented sub-manifest fails the leaf check.
    """
    res = locale[mode]
    assert res["outcome"] == "err", (
        f"tamper mode {mode!r} was ACCEPTED — the inclusion verifier does not "
        f"reject it: {res}")
    assert token in res["token"], (
        f"tamper mode {mode!r} rejected but with an unexpected token (wanted "
        f"{token!r}): {res['token']}")
