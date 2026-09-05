"""
Fabric tier — CC 3.4.8 detector-only prefix discriminator (CC 1.0-rc2).

CC 1.0-rc2 pins the wire discriminator for detector emission as a **prefix
contract** (part_3_the_namespace.md §3.4.8, "The discriminator is the prefix, not
an envelope field"):

- **Any** `detection:*` row **is** a *primary* detector emission and MUST satisfy
  `lenscore_detector ∈ attesting_key.identity_type`; the substrate **rejects** it
  otherwise. Admission needs **no** `is_primary_detection` flag and **no**
  envelope-shape parsing — it is a blanket CC 3.4 reserved-prefix rule keyed on the
  emitter's `identity_type` set membership.
- A **cross-attestation** about a detection rides the distinct
  `truth_grounding:detection:*` prefix, which carries **no** `lenscore_detector`
  requirement (a score *on* the detector's verdict, shadowing-free).

**How the detector role is expressed (probed on persist 13.0.1).** `identity_type`
is a SET of roles (CC 3.4.7.1). The detector right is granted by
`lenscore_detector ∈ identity_type`, expressed on `register_self_federation_key`'s
FIRST arg either as the bare string `"lenscore_detector"` OR as the canonical
comma-joined sorted set `"agent,lenscore_detector"` (the CC 3.4.7.1 encoding /
the CC §3.4.8 LensCore-fold worked example, `{agent, lenscore_detector}`). It is
NOT expressed via the separate `roles=` kwarg: a key registered
`identity_type="agent", roles=["lenscore_detector"]` is still REFUSED on
`detection:*` (`federation_reserved_prefix_emitter_mismatch`) — the reserved-prefix
gate reads `identity_type` membership, not the roles list.

**What is REAL on the floor (persist 13.0.1):**

- The two ENUMERATED detector leaves — `detection:correlated_action:*` and
  `detection:distributive:access:*` — are reserved: an agent-type key emitting
  either is refused with `federation_reserved_prefix_emitter_mismatch`
  (green gate, `test_detection_leaves_refused_from_agent_key`).
- A key holding `lenscore_detector` in its `identity_type` set IS admitted on
  `detection:correlated_action:*` (green positive gate,
  `test_lenscore_detector_key_admitted_on_detection`).
- A `truth_grounding:detection:*` cross-attestation from an ordinary agent key is
  admitted (green gate, `test_truth_grounding_cross_attestation_admitted`).

**What is NOT yet enforced (the CIRISPersist#379 gap):** the §3.4.8 **prefix-
wildcard**. A NOVEL subkind `detection:{newkind}:*` from an agent key is wrongly
ADMITTED — only the two enumerated leaves are in `default_reserved_prefix_rules()`,
not the `detection:*` wildcard. §3.4.8 is explicit: "Landing that wildcard
reservation in `default_reserved_prefix_rules()` is tracked at CIRISPersist#379;
this section is the normative grounding it needs, not a claim that the gate already
ships." So the wildcard leg is `xfail(strict=True)` — it flips to a real green gate
the moment #365 lands the `detection:*` prefix-wildcard reservation.
"""

from __future__ import annotations

import pytest

from conftest import TRUST_ROOT_CEREMONY_SRC, get_database_url, run_python_script

pytestmark = pytest.mark.fabric

# One shared substrate: register an agent key + a lenscore_detector-role key (both
# the bare form and the CC 3.4.8 fold set `agent,lenscore_detector`), then have
# each emit and report the outcome token. Honors the chosen backend for
# sqlite+postgres parity (postgres is already shared; sqlite needs an on-disk file
# so the reserved-prefix gate can read each emitter's federation_keys row).
_BODY = r"""
import json, sys, os, tempfile, secrets
try:
    import ciris_persist as cp
except ImportError as exc:
    print(json.dumps({"_error": "import", "detail": str(exc)})); sys.exit(2)

if INJECTED_URL.startswith("postgres"):
    DB_URL = INJECTED_URL
else:
    _dbf = os.path.join(tempfile.mkdtemp(), "f.db"); open(_dbf, "a").close()
    DB_URL = "sqlite:///" + _dbf


class Ident:
    def __init__(self, prefix, itype, ref, roles=None):
        d = tempfile.mkdtemp()
        self.s = os.path.join(d, "s"); open(self.s, "wb").write(secrets.token_bytes(32))
        self.p = os.path.join(d, "p"); open(self.p, "wb").write(secrets.token_bytes(32))
        self.k = prefix + "-" + secrets.token_hex(8)
        self.itype = itype
        self.kid = self.engine().register_self_federation_key(itype, ref, None, None, roles)

    def engine(self):
        cp.reset_engine()
        eng = cp.Engine(DB_URL, self.k, local_key_id=self.k, local_key_path=self.s,
                        local_pqc_key_id=self.k + "-pqc", local_pqc_key_path=self.p)
        # persist v40: a fresh Engine has no node identity until it registers;
        # the conferral gates resolve "does THIS NODE trust the root", so bind
        # it on every reconstruction (see conftest.TRUST_ROOT_CEREMONY_SRC).
        if getattr(self, "kid", None):
            _bind_node_identity(eng, self.itype)
        return eng


probe = Ident("probe", "agent", "probe")
if not hasattr(probe.engine(), "emit_attestation_self"):
    print(json.dumps({"_error": "absent"})); sys.exit(2)


def emit(ident, inp):
    try:
        ident.engine().emit_attestation_self(json.dumps(inp))
        return "accepted"
    except Exception as exc:
        return str(exc)[:80]


AGENT = Ident("agent", "agent", "agent-ref")                    # ordinary agent key
DET_BARE = Ident("det", "lenscore_detector", "det-ref")         # bare detector role
DET_FOLD = Ident("fold", "agent,lenscore_detector", "fold-ref") # CC 3.4.8 fold set
DET_ROLES = Ident("rls", "agent", "roles-ref", roles=["lenscore_detector"])  # roles= kwarg

# CIRISConformance#87 — the enumerated detector leaves are gated on a CONFERRED
# `infra:detect` (persist v30.4.0) held from a trust root this node trusts, on
# top of `lenscore_detector ∈ identity_type`. Confer it on ALL THREE candidate
# keys so the remaining discriminator is exactly the identity_type membership:
# the roles= kwarg key stays refused WITH the conferral in hand.
ROOT = Ident("root", "agent", "trust-root")
_TRUST_ROOT_CEREMONY = {name: confer_from_trust_root(ROOT, det, "infra:detect")
                            for name, det in (("bare", DET_BARE), ("fold", DET_FOLD), ("roles", DET_ROLES))}

report = {}
# Sanity — a plain scores attestation from the agent key is admitted, so the
# rejections below can't pass for the wrong reason.
report["agent_baseline_scores"] = emit(
    AGENT, {"attestation_type": "scores:quality:x", "attestation_envelope": {"n": "x"}, "weight": 0.5})

# ── CC 3.4.8 — the two ENUMERATED detector leaves, from an agent key: REFUSED ──
report["agent_detection_correlated"] = emit(
    AGENT, {"attestation_type": "detection:correlated_action:rights_asymmetry:pop",
            "attestation_envelope": {}})
report["agent_detection_distributive"] = emit(
    AGENT, {"attestation_type": "detection:distributive:access:compute",
            "attestation_envelope": {}})

# ── CC 3.4.8 prefix-WILDCARD — a novel subkind, from an agent key ──
# (Should be refused by the §3.4.8 wildcard; not yet in default_reserved_prefix_rules
#  — CIRISPersist#379.)
report["agent_detection_novel"] = emit(
    AGENT, {"attestation_type": "detection:newkind:some_axis", "attestation_envelope": {}})

# ── CC 3.4.8 — a lenscore_detector-role key IS admitted on detection:* ──
report["detector_bare_detection"] = emit(
    DET_BARE, {"attestation_type": "detection:correlated_action:rights_asymmetry:pop",
               "attestation_envelope": {}})
report["detector_fold_detection"] = emit(
    DET_FOLD, {"attestation_type": "detection:correlated_action:rights_asymmetry:pop",
               "attestation_envelope": {}})
# The roles= kwarg does NOT grant the detector right (identity_type membership does).
report["roles_kwarg_detection"] = emit(
    DET_ROLES, {"attestation_type": "detection:correlated_action:rights_asymmetry:pop",
                "attestation_envelope": {}})

# ── CC 3.4.8 — cross-attestation rides truth_grounding:detection:* (no detector req) ──
report["agent_truth_grounding_detection"] = emit(
    AGENT, {"attestation_type": "truth_grounding:detection:correlated_action:rights_asymmetry:pop",
            "attestation_envelope": {}})

report["stage"] = "done"
print(json.dumps(report)); sys.stdout.flush(); os._exit(0)
"""


@pytest.fixture(scope="module")
def admission():
    script = f"INJECTED_URL = {get_database_url()!r}\n" + TRUST_ROOT_CEREMONY_SRC + _BODY
    payload = run_python_script(script).parsed_stdout()
    if payload.get("_error") == "absent":
        pytest.fail("persist.emit_attestation_self is missing — the attestation "
                    "admission surface is not on the wheel")
    assert payload.get("stage") == "done", payload
    # Guard: the surface must accept a legitimate attestation, else the rejection
    # assertions below would pass for the wrong reason.
    assert payload["agent_baseline_scores"] == "accepted", payload
    return payload


@pytest.mark.requires_persist
def test_detection_leaves_refused_from_agent_key(admission):
    """CC 3.4.8: an agent key cannot emit the enumerated `detection:*` detector leaves.

    Real gate on persist 13.0.1: `detection:correlated_action:*` and
    `detection:distributive:access:*` are reserved to `lenscore_detector ∈
    identity_type`; an agent-type emitter is refused at admission with
    `federation_reserved_prefix_emitter_mismatch` — the CC 3.4 reserved-prefix
    set-membership mechanism, no envelope-shape parsing.
    """
    r = admission
    assert r["agent_detection_correlated"] != "accepted", (
        f"agent key minted detection:correlated_action:* (CC 3.4.8): "
        f"{r['agent_detection_correlated']}")
    assert "reserved_prefix_emitter_mismatch" in r["agent_detection_correlated"], (
        r["agent_detection_correlated"])
    assert r["agent_detection_distributive"] != "accepted", (
        f"agent key minted detection:distributive:access:* (CC 3.4.8): "
        f"{r['agent_detection_distributive']}")
    assert "reserved_prefix_emitter_mismatch" in r["agent_detection_distributive"], (
        r["agent_detection_distributive"])


@pytest.mark.requires_persist
def test_lenscore_detector_key_admitted_on_detection(admission):
    """CC 3.4.8: a key holding `lenscore_detector` in `identity_type` IS admitted on detection:*.

    The positive leg of the discriminator. The detector right is granted by
    `lenscore_detector ∈ identity_type` (CC 3.4.7.1 set) — probed real on persist
    13.0.1 for both the bare `identity_type="lenscore_detector"` form and the
    canonical comma-joined fold set `"agent,lenscore_detector"` (the §3.4.8
    LensCore-fold worked example `{agent, lenscore_detector}`). The `agent` role in
    the fold neither grants nor blocks the detector right — only the held
    `lenscore_detector` role does.
    """
    r = admission
    assert r["detector_bare_detection"] == "accepted", (
        f"a bare lenscore_detector key was refused on detection:* (CC 3.4.8): "
        f"{r['detector_bare_detection']}")
    assert r["detector_fold_detection"] == "accepted", (
        f"the {{agent, lenscore_detector}} fold key was refused on detection:* "
        f"(CC 3.4.8 fold example): {r['detector_fold_detection']}")


@pytest.mark.requires_persist
def test_detector_role_is_identity_type_membership_not_roles_kwarg(admission):
    """CC 3.4.8/3.4.7.1: the detector right is `identity_type` set membership, not the roles= kwarg.

    Discriminates HOW the role is expressed: a key registered
    `identity_type="agent", roles=["lenscore_detector"]` is still REFUSED on
    `detection:*` (`federation_reserved_prefix_emitter_mismatch`) — the
    reserved-prefix gate reads the `identity_type` SET, not the separate roles
    list. (Pins the probed mechanism so a regression that silently starts honoring
    the roles kwarg — or stops honoring identity_type membership — is caught.)
    """
    r = admission
    assert r["roles_kwarg_detection"] != "accepted", (
        f"the roles= kwarg unexpectedly granted the detector right — CC 3.4.8 keys "
        f"it on identity_type membership: {r['roles_kwarg_detection']}")
    assert "reserved_prefix_emitter_mismatch" in r["roles_kwarg_detection"], (
        r["roles_kwarg_detection"])


@pytest.mark.requires_persist
def test_truth_grounding_cross_attestation_admitted(admission):
    """CC 3.4.8: a `truth_grounding:detection:*` cross-attestation carries no detector requirement.

    A cross-attestation ABOUT a detection rides the distinct
    `truth_grounding:detection:*` prefix — a score *on* the detector's verdict, not
    a shadowing re-emission — so an ordinary agent key IS admitted on it (real on
    persist 13.0.1). This is the shadowing-free path §3.4.8 mandates for
    non-LensCore peers cross-checking a detector.
    """
    r = admission
    assert r["agent_truth_grounding_detection"] == "accepted", (
        f"a truth_grounding:detection:* cross-attestation from an agent key was "
        f"refused — it carries no lenscore_detector requirement (CC 3.4.8): "
        f"{r['agent_truth_grounding_detection']}")


@pytest.mark.requires_persist
def test_novel_detection_subkind_wildcard_refused_from_agent_key(admission):
    """CC 3.4.8: a NOVEL `detection:{newkind}:*` from an agent key MUST be refused.

    The §3.4.8 wildcard reservation covers novel subkinds by construction, not only
    the two enumerated leaves. Undrivable today (persist 13.0.1 admits the novel
    subkind); asserts the conformant refusal so it auto-flips when CIRISPersist#379
    lands the `detection:*` prefix-wildcard rule.
    """
    r = admission
    assert r["agent_detection_novel"] != "accepted", (
        f"agent key minted a novel detection:{{newkind}}:* subkind — the CC 3.4.8 "
        f"prefix-wildcard reservation is not enforced (CIRISPersist#379): "
        f"{r['agent_detection_novel']}")
