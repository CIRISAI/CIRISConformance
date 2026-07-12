"""
Substrate tier — CC 5.2 structural invisibility (the CEWP "the wire format can't
carry them" privacy promise).

CC 5.2 (part_5_transport_substrate.md §5.2, "`family` — Structural invisibility —
`holds_bytes:sha256:*` suppression for `cohort_scope: self | family`") codifies a
NORMATIVE substrate discipline, not an operator policy:

- When a Contribution carries `cohort_scope: self` OR `cohort_scope: family`, the
  substrate **MUST NOT** emit a corresponding `holds_bytes:sha256:{prefix}`
  holder-directory attestation (CC 3.1.9.1). The bytes are held locally and
  delivered to admitted self-collective / family members via the at-rest flow,
  never via the public holder-discovery directory — so "a non-member peer cannot
  even *discover* the bytes exist." This is the UNCONDITIONAL layer (§5.2 (1)),
  holding even when the at-rest bytes are plaintext.
- `cohort_scope: community | affiliations | federation` content emits
  `holds_bytes:sha256:*` per status-quo behavior (§5.2 "Interaction with existing
  behavior"); only the self/family path is suppressed.

**The real wheel surface (persist 15.1.0) — fully drivable, no transport needed.**
The presence/absence of the `holds_bytes` directory attestation IS the structural
property, and persist exposes both emission paths plus the scope→tier resolver on
one Engine:

- `cohort_scope_crypto_tier(token)` (CC 4.4.3.2.8 / CIRISPersist#308) — a closed-set
  negative-default resolver: `self`/`family` → `"invisible_encrypted"`,
  `community`/`affiliations` → `"community_dek"`, Commons/unknown → `"plaintext"`.
- `store_blob_local_json(payload)` (CIRISPersist#153, CEG 0.7 §10.1.4) — the
  self/family primitive: stores the bytes locally (readable via `get_blob_json`)
  WITHOUT emitting a `holds_bytes` attestation — "no `holds_bytes` row, so
  non-member peers cannot discover the bytes exist."
- `put_blob_signing(...)` (CIRISPersist#121) — the community/federation primitive:
  writes the blob WITH holder-attestation emission (persist owns the envelope
  construction + hybrid signing internally).
- `list_local_holders_json(sha256)` / `list_holders_json(sha256)` — the holder
  directory: the `attesting_key_id`s of every `holds_bytes` attestation for a blob.

**Why the assertion is deterministic / robust.** One persist Engine, one process,
no Reticulum transport, no timing — a pure storage-semantics gate. The SAME node
stores the SAME shape of content two ways differing ONLY in cohort scope; the
self/family path yields an empty holder directory while the community path names
the local key. This is the wire-format-level closure of the structural-invisibility
claim, asserted at the exact `holds_bytes`-suppression seam §5.2 makes normative.
It runs under BOTH sqlite and postgres via the injected database URL. The
scope-disable hook (`cohort_scope_enforcement=Off`) is NOT touched — suppression is
the substrate's unconditional default, exercised through the ordinary blob surface.
"""

from __future__ import annotations

import pytest

from conftest import get_database_url, run_python_script

_BODY = r"""
import json, sys, os, tempfile, secrets, hashlib, base64, uuid
try:
    import ciris_persist as cp
except ImportError as exc:
    print(json.dumps({"_error": "import", "detail": str(exc)})); sys.exit(2)

if INJECTED_URL.startswith("postgres"):
    DB_URL = INJECTED_URL
else:
    _dbf = os.path.join(tempfile.mkdtemp(), "f.db"); open(_dbf, "a").close()
    DB_URL = "sqlite:///" + _dbf

d = tempfile.mkdtemp()
s = os.path.join(d, "s"); open(s, "wb").write(secrets.token_bytes(32))
p = os.path.join(d, "p"); open(p, "wb").write(secrets.token_bytes(32))
k = "inv-" + secrets.token_hex(8)
cp.reset_engine()
eng = cp.Engine(DB_URL, k, local_key_id=k, local_key_path=s,
                local_pqc_key_id=k + "-pqc", local_pqc_key_path=p)
for surface in ("cohort_scope_crypto_tier", "store_blob_local_json",
                "put_blob_signing", "list_local_holders_json", "get_blob_json"):
    if not hasattr(eng, surface):
        print(json.dumps({"_error": "absent", "surface": surface})); sys.exit(2)

kid = eng.register_self_federation_key("agent", "invisibility-node", None, None, None)
report = {"kid": kid}

# The scope→at-rest-tier resolver: the self/family (invisible) vs community
# (discoverable) split, at the closed-set dispatch that governs suppression.
report["tiers"] = {t: eng.cohort_scope_crypto_tier(t)
                   for t in ("self", "family", "community", "affiliations", "federation")}

# self/family path: bytes held locally, NO holds_bytes directory attestation.
b_self = b"family-photo-" + secrets.token_hex(4).encode()
sha_self = hashlib.sha256(b_self).hexdigest()
eng.store_blob_local_json(json.dumps({"sha256": sha_self,
    "body": {"inline": base64.b64encode(b_self).decode()}, "media_type": "image/jpeg"}))
report["self"] = {
    "readable": eng.get_blob_json(sha_self) is not None,
    "local_holders": json.loads(eng.list_local_holders_json(sha_self)),
    "fed_holders": json.loads(eng.list_holders_json(sha_self)),
}

# community/federation path: bytes held locally AND a holds_bytes attestation emitted.
b_comm = b"community-post-" + secrets.token_hex(4).encode()
sha_comm = hashlib.sha256(b_comm).hexdigest()
eng.put_blob_signing(sha_comm, base64.b64encode(b_comm).decode(), None, "text/plain",
                     kid, "2026-07-12T00:00:00.000Z", str(uuid.uuid4()))
report["community"] = {
    "readable": eng.get_blob_json(sha_comm) is not None,
    "local_holders": json.loads(eng.list_local_holders_json(sha_comm)),
}

report["stage"] = "done"
print(json.dumps(report)); sys.stdout.flush(); os._exit(0)
"""


@pytest.fixture(scope="module")
def invisibility():
    script = f"INJECTED_URL = {get_database_url()!r}\n" + _BODY
    payload = run_python_script(script).parsed_stdout()
    if payload.get("_error") == "absent":
        pytest.fail(f"persist structural-invisibility surface missing: {payload.get('surface')}")
    if payload.get("_error") == "import":
        pytest.fail(f"ciris_persist import failed: {payload.get('detail')}")
    assert payload.get("stage") == "done", payload
    return payload


@pytest.mark.requires_persist
@pytest.mark.ccs
def test_cohort_scope_crypto_tier_splits_invisible_from_discoverable(invisibility):
    """CC 5.2: the scope→at-rest-tier resolver puts self/family in the
    invisible-encrypted tier and community/affiliations in the discoverable tier.

    This is the closed-set dispatch (`cohort_scope_crypto_tier`, CC 4.4.3.2.8) that
    governs which content is `holds_bytes`-suppressed. `self`/`family` resolve to
    `invisible_encrypted` (no holder-directory attestation), `community`/
    `affiliations` to `community_dek` (holder-inspectable), and `federation` to
    `plaintext` — the structural split, deterministic and negative-default.
    """
    tiers = invisibility["tiers"]
    assert tiers["self"] == "invisible_encrypted", tiers
    assert tiers["family"] == "invisible_encrypted", tiers
    assert tiers["community"] == "community_dek", tiers
    assert tiers["affiliations"] == "community_dek", tiers
    assert tiers["federation"] == "plaintext", tiers


@pytest.mark.requires_persist
@pytest.mark.ccs
def test_self_family_content_emits_no_holds_bytes_attestation(invisibility):
    """CC 5.2: self/family content is structurally invisible — held locally but
    emitting NO `holds_bytes:sha256:*` holder-directory attestation.

    `store_blob_local_json` persists the bytes (they are readable via
    `get_blob_json`) yet the substrate announces nothing: both the federation-
    discovery and local-truth holder directories are EMPTY for the blob. A
    non-member peer cannot discover the bytes exist — the unconditional §5.2 (1)
    invisibility layer, at the `holds_bytes`-suppression seam itself.
    """
    self_ = invisibility["self"]
    assert self_["readable"], "self/family bytes must be locally held (readable), just undiscoverable"
    assert self_["local_holders"] == [], (
        f"self/family content emitted a holds_bytes attestation — structural "
        f"invisibility violated: local_holders={self_['local_holders']}")
    assert self_["fed_holders"] == [], (
        f"self/family content is discoverable on the federation holder directory — "
        f"structural invisibility violated: fed_holders={self_['fed_holders']}")


@pytest.mark.requires_persist
@pytest.mark.ccs
def test_community_content_does_emit_holds_bytes_attestation(invisibility):
    """CC 5.2 contrast: community-scope content DOES emit a discoverable
    `holds_bytes` attestation (only the self/family path is suppressed).

    The load-bearing contrast that makes the invisibility claim a real wire-level
    distinction and not a blanket "persist never announces": the SAME node, via
    `put_blob_signing`, writes a community blob and the holder directory names its
    own key. Suppression is scope-selective, exactly as §5.2 requires.
    """
    comm = invisibility["community"]
    assert comm["readable"], "community bytes must be locally held"
    assert comm["local_holders"] == [invisibility["kid"]], (
        f"community-scope content did not emit a holds_bytes attestation naming the "
        f"local key — the suppression is not scope-selective: "
        f"local_holders={comm['local_holders']}, kid={invisibility['kid']}")
