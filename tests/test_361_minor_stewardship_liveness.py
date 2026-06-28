"""
Fabric tier — CC 3.2 minor-stewardship liveness (the no-slavery fail-secure).

CC 3.2 (part_3_the_namespace.md, "Minor-stewardship rule"): an under-18 `user`
identity MUST have a **live steward-binding** — a non-superseded, non-withdrawn
`delegates_to(adult-user → minor-user)` — from an over-18 `user` at all times.
"No minor `user` identity operates without a live adult steward." A minor whose
binding goes non-live (superseded-without-replacement or **withdrawn**) is
**steward-less and MUST NOT operate** until re-stewarded — fail-secure, identical
in posture to a steward-less `node`/`agent`.

The lifecycle rides existing structural composers (no new primitive): the binding
is a `delegates_to` (here via `steward_bind` / `grant_delegation`); revocation is
a `withdraws` (here via `revoke_delegation` by the original granter).

What is REAL on the floor (persist 11.5.0), asserted as live gates:

- **node/agent fail-secure (control)** — a steward-bound agent resolves
  `is_steward_bound` true; after the adult granter `revoke_delegation`s the
  binding, `is_steward_bound` flips to **false** and `steward_bindings_of` empties.
  This is the exact fail-secure posture CC 3.2 says a steward-less minor must
  share, proven on the surface that DOES expose it.
- **the minor-guardianship binding is forbidden wholesale** — a user-target
  `steward_bind` onto a minor rejects with
  `federation_user_target_steward_binding_forbidden`, identical to an adult
  target. The legal §3.2 conditional minor-admit is not exposed over the FFI.

What is NOT yet enforced / drivable (probed on persist 11.5.0), `xfail(strict=True)`:

- **the minor-specific fail-secure** — undrivable, because the adult→minor
  binding cannot even be CREATED over the Engine. persist 11.5.0 forbids ALL
  user-target steward bindings wholesale (adult AND minor alike), so there is no
  live adult→minor `delegates_to` to withdraw and no minor-liveness transition to
  observe. Only the blanket forbid is exposed, never the conditional
  minor-guardianship admit (the §3.2 `admit_user_steward_binding` minor case).
  The "minor MUST NOT operate without a live adult steward" guarantee is therefore
  not machine-checkable for a `user` target. Gap to file upstream CIRISPersist:
  expose the conditional minor-guardianship admit plus a steward-less-minor
  liveness predicate gated on the I1 age band (`age_assurance:*`, CC 3.3.12) — so
  a withdrawn minor binding fails secure like a node/agent's does.
"""

from __future__ import annotations

import pytest

from conftest import get_database_url, run_python_script

pytestmark = pytest.mark.fabric

_BODY = r"""
import json, sys, os, tempfile, secrets
try:
    import ciris_persist as cp
except ImportError as exc:
    print(json.dumps({"_error": "import", "detail": str(exc)})); sys.exit(2)

# Shared substrate so every reconstructed engine sees the same keys. The harness
# injects INJECTED_URL to honor the chosen backend (full sqlite+postgres parity):
# postgres is shared across subprocesses; the sqlite default needs an ON-DISK file
# (`:memory:` gives each Engine a private DB — no cross-engine visibility).
if INJECTED_URL.startswith("postgres"):
    DB_URL = INJECTED_URL
else:
    _dbf = os.path.join(tempfile.mkdtemp(), "f.db"); open(_dbf, "a").close()
    DB_URL = "sqlite:///" + _dbf


# Only one Engine is live at a time (`reset_engine` closes the prior); each
# identity carries stable alias + key paths and is reconstructed to sign. The kid
# is stable across reconstructions (same alias + seed → same derived key_id).
class Ident:
    def __init__(self, prefix, itype, ref):
        d = tempfile.mkdtemp()
        self.s = os.path.join(d, "s"); open(self.s, "wb").write(secrets.token_bytes(32))
        self.p = os.path.join(d, "p"); open(self.p, "wb").write(secrets.token_bytes(32))
        self.k = prefix + "-" + secrets.token_hex(8)
        self.kid = self.engine().register_self_federation_key(itype, ref, None, None, None)

    def engine(self):
        cp.reset_engine()
        return cp.Engine(DB_URL, self.k, local_key_id=self.k, local_key_path=self.s,
                         local_pqc_key_id=self.k + "-pqc", local_pqc_key_path=self.p)


for surface in ("steward_bind", "revoke_delegation", "is_steward_bound_json",
                "steward_bindings_of_json"):
    probe = Ident("probe", "agent", "probe")
    if not hasattr(probe.engine(), surface):
        print(json.dumps({"_error": "absent", "surface": surface})); sys.exit(2)

S = Ident("steward", "user", "adult-steward")   # the adult-user guardian (signer)
M = Ident("minor", "user", "minor-ward")         # the minor user ward
N = Ident("node", "agent", "node-ref")           # node/agent control

report = {"S": S.kid, "M": M.kid, "N": N.kid}

# ── Minor: attempt to bind to the adult steward ──
# On persist 11.5.0 a user-target steward_bind is forbidden WHOLESALE
# (federation_user_target_steward_binding_forbidden), so the binding can't even be
# created over the FFI. Wrap it so the body completes and capture the outcome; the
# minor-specific liveness assertion is undrivable as a result (see the xfail).
try:
    appt_m = S.engine().steward_bind(M.kid, ["infra:transport"])
    report["minor_bind"] = {"outcome": "admitted", "id": appt_m}
except Exception as exc:
    appt_m = None
    report["minor_bind"] = {"outcome": "rejected", "token": str(exc)[:160]}

# ── Control: node/agent fail-secure — bind then withdraw ──
appt_n = S.engine().steward_bind(N.kid, ["infra:transport"])
e = S.engine()
report["node_bound_is_steward_bound"] = e.is_steward_bound_json(N.kid)
report["node_bound_bindings_of"] = json.loads(e.steward_bindings_of_json(N.kid))

S.engine().revoke_delegation(appt_n, N.kid)
e = S.engine()
report["node_revoked_is_steward_bound"] = e.is_steward_bound_json(N.kid)
report["node_revoked_bindings_of"] = json.loads(e.steward_bindings_of_json(N.kid))

report["stage"] = "done"
print(json.dumps(report)); sys.stdout.flush(); os._exit(0)
"""


@pytest.fixture(scope="module")
def liveness():
    script = f"INJECTED_URL = {get_database_url()!r}\n" + _BODY
    payload = run_python_script(script).parsed_stdout()
    if payload.get("_error") == "absent":
        pytest.fail(f"persist steward surface missing: {payload.get('surface')}")
    assert payload.get("stage") == "done", payload
    return payload


# ── Control: node/agent steward-binding fail-secure IS real (the posture CC 3.2
#    says a steward-less minor must share) ──
@pytest.mark.requires_persist
def test_node_binding_revocation_fails_secure(liveness):
    """A steward-bound node, once its binding is withdrawn, is steward-less again."""
    r = liveness
    assert r["node_bound_is_steward_bound"] == "true", r
    assert r["S"] in r["node_bound_bindings_of"], r
    assert r["node_revoked_is_steward_bound"] == "false", (
        f"a node's binding was withdrawn yet is_steward_bound still resolves true "
        f"— the node/agent fail-secure path is broken: {r}")
    assert r["node_revoked_bindings_of"] == [], (
        f"a withdrawn node binding still lists a steward: {r}")


# ── Control: the minor-guardianship binding cannot even be created over FFI ──
@pytest.mark.requires_persist
def test_minor_guardianship_binding_is_forbidden_wholesale(liveness):
    """On persist 11.5.0 a user-target steward_bind onto a minor is forbidden wholesale.

    The CC 3.2 minor-guardianship `delegates_to(adult-user → minor-user)` is the
    LEGAL user-target case, yet persist 11.5.0 rejects it with the same blanket
    `federation_user_target_steward_binding_forbidden` it applies to an adult
    target — the conditional minor-admit is not exposed over the Engine FFI. This
    documents (as a real, green observation) why the minor-liveness assertion below
    is undrivable: the binding whose withdrawal we'd test cannot be created.
    """
    r = liveness
    assert r["minor_bind"]["outcome"] == "rejected", (
        f"a user-target minor steward_bind was admitted — persist 11.5.0 is "
        f"expected to forbid user-target bindings wholesale: {r['minor_bind']}")
    assert "user_target_steward_binding_forbidden" in r["minor_bind"]["token"], (
        f"unexpected rejection token for a minor user-target steward_bind: "
        f"{r['minor_bind']}")


# ── CC 3.2 minor fail-secure — undrivable: the binding can't even be created ──
@pytest.mark.requires_persist
@pytest.mark.xfail(strict=True, reason=(
    "CC 3.2 minor-stewardship liveness is undrivable over persist 11.5.0: the "
    "minor-guardianship binding cannot even be CREATED — a user-target steward_bind "
    "onto a minor rejects with federation_user_target_steward_binding_forbidden "
    "(forbidden wholesale, the same as an adult target). With no admissible "
    "adult→minor binding to withdraw, the steward-less-minor fail-secure posture "
    "(a withdrawn minor binding must flip is_steward_bound to false like a node's) "
    "is not machine-checkable. File upstream CIRISPersist: expose the conditional "
    "minor-guardianship admit (§3.2 admit_user_steward_binding minor case) plus a "
    "steward-less-minor liveness predicate gated on the I1 age band — only the "
    "wholesale forbid is exposed, not the positive minor path."))
def test_steward_less_minor_fails_secure(liveness):
    """CC 3.2: a minor whose adult steward is withdrawn MUST be steward-less.

    Undrivable on persist 11.5.0: the adult→minor binding cannot be created (the
    user-target binding is forbidden wholesale), so there is no live binding to
    withdraw and no minor-liveness transition to observe. Encoded as the missing
    signal the substrate does not provide; flips to a real gate when persist
    exposes the conditional minor-guardianship admit + age-band-gated liveness.
    """
    r = liveness
    assert r.get("minor_revoked_is_steward_bound") == "false", (
        f"the minor steward-less fail-secure transition is not observable — the "
        f"adult→minor binding could not be created (forbidden wholesale), so its "
        f"withdrawal cannot be tested on persist 11.5.0: {r['minor_bind']}")
