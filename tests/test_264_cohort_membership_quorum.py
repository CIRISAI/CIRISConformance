"""
Fabric tier — CC 0.6 §3.4.2 / §4.4.3.2 cohort membership-change quorum.

A community/affiliations roster is not changed by fiat: a membership change
(grow / swap / remove) must be **authorized by the standing roster's
strict-majority quorum** (CC §3.4.2 membership-quorum; CC §4.4.3.4.2 admission
per `consensus_protocol`; the same `supersedes` machinery as the accord-holder
family, CC §4.2.3). persist 11.5.0 exposes this as a real three-part surface
over the shared substrate:

  1. `cohort_build_membership_change_envelope(cohort, group, new_member_ids,
     entrenched, consensus_protocol)` — builds the canonical change envelope
     (a `quorum:M/N` for the NEW count, carrying the anti-replay
     `supersedes.prior_member_key_ids` binding).
  2. each standing member **cosigns the envelope's JCS bytes** with a bound
     hybrid signature (Ed25519 over the JCS bytes; ML-DSA-65 over
     `jcs_bytes ‖ ed25519_signature`).
  3. `cohort_verify_membership_quorum(cohort, group, envelope, signatures)` —
     verifies the cosignatures meet the **prior** roster's strict-majority
     threshold (`2·M > N`). Returns `None` on success; raises on insufficiency.

This gate drives a real M-of-N (2-of-3) scenario end-to-end: three registered,
steward-bound (`user`) federation keys form a `quorum:2/3` community; a change
envelope adds a fourth member; each standing member cosigns the canonical bytes;
the founder then asserts that

- a **valid** quorum (2 of the 3 standing members) **verifies**, and
- an **insufficient** quorum (1 signature) is **rejected** (fail-closed).

The threshold-signature shape (discovered by probing persist 11.5.0 + reading
`ciris_verify_core::threshold::ThresholdSignature`) is:

    {"member_id": <key_id>,
     "ed25519_signature_base64": <b64 ed25519 over jcs_bytes>,
     "mldsa65_signature_base64": <b64 ml-dsa-65 over jcs_bytes ‖ ed25519_raw>}

Both halves are mandatory at federation tier (`HybridPolicy::RequireHybrid`).
The verifier resolves signers' pinned hybrid pubkeys from `federation_keys`, so
each signer must be a genuinely-registered node.

Because each cosignature must be produced by the *same* key the verifier resolves
from `federation_keys` — and a per-node fresh random key cannot be re-derived in
a later node subprocess — the full M-of-N ceremony runs inside ONE node body
(over the module's shared substrate `DB_URL`): it registers each standing member
with a stable, re-openable key, signs with that key, then reopens the founder to
verify. This is the only faithful way to drive a multi-signer quorum: the
signers must hold their keys at signing time.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.fabric

_NOW = "2026-06-25T00:00:00.000Z"

# The full quorum ceremony in one subprocess over the shared substrate.
#
# `mk(ref, user)` registers a federation key with a stable seed under `DB_URL`
# (so it can be re-opened to sign later); `oe(ref)` reopens that exact identity.
# Only one Engine is live at a time (reset_engine closes the prior), so each
# signer reopens its own key, signs the canonical bytes, and yields its bound
# hybrid signature — exactly the field precedent of an offline cosigning round.
_BODY = r"""
mats = {}

def mk(ref, user=False):
    k = "node-" + secrets.token_hex(8)
    s = os.path.join(_dir, ref + "-seed"); open(s, "wb").write(secrets.token_bytes(32))
    p = os.path.join(_dir, ref + "-pqc"); open(p, "wb").write(secrets.token_bytes(32))
    cp.reset_engine()
    e = cp.Engine(DB_URL, k, local_key_id=k, local_key_path=s,
                  local_pqc_key_id=k + "-pqc", local_pqc_key_path=p)
    fkid = e.register_self_federation_key("user" if user else "agent", ref, None, None, None)
    mats[ref] = (k, s, p, fkid)
    return fkid

def oe(ref):
    k, s, p, _ = mats[ref]
    cp.reset_engine()
    return cp.Engine(DB_URL, k, local_key_id=k, local_key_path=s,
                     local_pqc_key_id=k + "-pqc", local_pqc_key_path=p)

fk = lambda ref: mats[ref][3]

# Standing roster (all steward-bound) + the incoming member.
alice = mk("q-alice", user=True)
bob = mk("q-bob", user=True)
carol = mk("q-carol", user=True)
founder = mk("q-founder", user=True)

# A 3-member community at strict-majority quorum:2/3 → prior threshold == 2.
ef = oe("q-founder")
ef.put_community_json(json.dumps({
    "community_key_id": founder, "community_name": "conformance-quorum",
    "members": [{"key_id": founder, "joined_at": NOW, "role": "founder"},
                {"key_id": alice, "joined_at": NOW},
                {"key_id": bob, "joined_at": NOW}],
    "founded_at": NOW, "consensus_protocol": "quorum:2/3", "persist_row_hash": "",
}))

# Build the change envelope: new roster adds carol → quorum:3/4 for the new count.
env = ef.cohort_build_membership_change_envelope(
    "affiliations", founder, json.dumps([founder, alice, bob, carol]), False, None)
canon = ef.canonicalize_envelope_for_signing(env)
report["envelope"] = json.loads(env)

# Each standing member cosigns the canonical bytes with a bound hybrid signature.
def cosign(ref):
    e = oe(ref)
    ed = e.local_sign(canon)              # raw Ed25519 signature bytes
    pqc = e.local_pqc_sign(canon + ed)    # ML-DSA-65 over jcs_bytes ‖ ed_raw
    return {
        "member_id": fk(ref),
        "ed25519_signature_base64": base64.b64encode(ed).decode(),
        "mldsa65_signature_base64": base64.b64encode(pqc).decode(),
    }

sig = {ref: cosign(ref) for ref in ("q-founder", "q-alice", "q-bob")}

# Reopen the founder to verify the assembled quorums.
ef = oe("q-founder")

def probe(label, refs):
    selected = [sig[r] for r in refs]
    try:
        ef.cohort_verify_membership_quorum(
            "affiliations", founder, env, json.dumps(selected))
        report[label] = {"verified": True}
    except Exception as exc:  # noqa: BLE001
        report[label] = {"verified": False, "error": str(exc)}

# Valid: 2 of the 3 standing members (strict majority of the prior 3-roster).
probe("valid_two_of_three", ("q-founder", "q-alice"))
# Also confirm the full 3-of-3 set verifies (over-quorum is still authorized).
probe("all_three", ("q-founder", "q-alice", "q-bob"))
# Insufficient: a single signature, below the threshold of 2 → fail-closed.
probe("insufficient_one", ("q-founder",))

report["stage"] = "done"
"""


@pytest.fixture(scope="module")
def quorum_scenario(federation_module):
    """Run the full build → cosign → verify M-of-N quorum ceremony in one node."""
    return federation_module(_BODY, identity_ref="quorum-driver", NOW=_NOW)


@pytest.mark.requires_persist
def test_membership_change_envelope_is_built(quorum_scenario):
    """The change envelope is a well-formed strict-majority quorum payload."""
    r = quorum_scenario
    assert r["stage"] == "done", r
    env = r["envelope"]
    # New count is 4 → strict majority quorum:3/4; anti-replay binds the prior 3.
    assert env["consensus_protocol"] == "quorum:3/4", env
    assert len(env["supersedes"]["prior_member_key_ids"]) == 3, env


@pytest.mark.requires_persist
def test_valid_quorum_verifies(quorum_scenario):
    """CC §3.4.2: a strict-majority (2-of-3) cosignature set authorizes the change."""
    r = quorum_scenario
    assert r["stage"] == "done", r
    assert r["valid_two_of_three"]["verified"] is True, (
        f"a valid 2-of-3 membership-change quorum was rejected: {r['valid_two_of_three']}")
    assert r["all_three"]["verified"] is True, (
        f"the full 3-of-3 standing roster failed to authorize the change: {r['all_three']}")


@pytest.mark.requires_persist
def test_insufficient_quorum_is_rejected(quorum_scenario):
    """CC §3.4.2: fewer than the strict-majority threshold MUST fail (fail-closed)."""
    r = quorum_scenario
    assert r["stage"] == "done", r
    v = r["insufficient_one"]
    assert v["verified"] is False, (
        "a single signature (below the 2-of-3 threshold) wrongly authorized a "
        f"membership change — the quorum gate is unenforced: {v}")
