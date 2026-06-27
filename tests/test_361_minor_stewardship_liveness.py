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

What is REAL on the floor (persist 11.0.0), asserted as live gates:

- **node/agent fail-secure (control)** — a steward-bound agent resolves
  `is_steward_bound` true; after the adult granter `revoke_delegation`s the
  binding, `is_steward_bound` flips to **false** and `steward_bindings_of` empties.
  This is the exact fail-secure posture CC 3.2 says a steward-less minor must
  share, proven on the surface that DOES expose it.
- **adult-steward revocation is observable for a minor** — after binding the
  minor to the adult and then revoking, the **adult drops out of the minor's
  `steward_bindings_of`**. The structural withdrawal is real and readable.

What is NOT yet enforced (probed on persist 11.0.0), `xfail(strict=True)`:

- **the minor-specific fail-secure** — `is_steward_bound(minor)` stays **true**
  after the adult steward is revoked, because a `user`-role key self-satisfies
  `is_steward_bound` (the "K *is* U" clause: a user is its own steward anchor).
  The predicate therefore cannot distinguish a *steward-less minor* (must
  fail-secure) from a *self-sovereign adult* (legitimately steward-less) — there
  is no I1 age band (`age_assurance:*`, CC 3.3.12) over the Engine to make the
  distinction. So the "minor MUST NOT operate without a live adult steward"
  guarantee is not yet machine-checkable for a `user` target. Gap to file
  upstream CIRISPersist: a steward-less-minor liveness predicate gated on the I1
  age band (so a withdrawn minor binding fails secure like a node/agent's does).
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

# ── Minor: bind to the adult steward, then withdraw it ──
appt_m = S.engine().steward_bind(M.kid, ["infra:transport"])
e = S.engine()
report["minor_bound_is_steward_bound"] = e.is_steward_bound_json(M.kid)
report["minor_bound_bindings_of"] = json.loads(e.steward_bindings_of_json(M.kid))

S.engine().revoke_delegation(appt_m, M.kid)        # the adult withdraws the binding
e = S.engine()
report["minor_revoked_is_steward_bound"] = e.is_steward_bound_json(M.kid)
report["minor_revoked_bindings_of"] = json.loads(e.steward_bindings_of_json(M.kid))

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


# ── Real: the adult steward's withdrawal is observable on the minor ──
@pytest.mark.requires_persist
def test_minor_adult_steward_revocation_is_observable(liveness):
    """The adult guardian binds the minor, then withdraws — the adult drops out.

    The structural withdrawal of the adult→minor `delegates_to` is real and
    readable: while bound, the adult appears in the minor's `steward_bindings_of`;
    after `revoke_delegation`, the adult is gone from it. (The minor's own key
    remains as a self-anchor — see the xfail below.)
    """
    r = liveness
    assert r["S"] in r["minor_bound_bindings_of"], (
        f"the adult guardian is not listed as the minor's steward while bound: {r}")
    assert r["S"] not in r["minor_revoked_bindings_of"], (
        f"the adult guardian is still listed after withdrawal — the revocation "
        f"was not applied: {r}")


# ── CC 3.2 minor fail-secure — not yet machine-checkable on the floor ──
@pytest.mark.requires_persist
@pytest.mark.xfail(strict=True, reason=(
    "CC 3.2 minor-stewardship liveness not fail-secure on persist 11.0.0: after "
    "the adult steward is withdrawn, is_steward_bound(minor) stays TRUE because a "
    "user-role key self-satisfies is_steward_bound (the 'K is U' anchor). With no "
    "I1 age band (age_assurance:*, CC 3.3.12) over the Engine, the substrate "
    "cannot tell a steward-less MINOR (must fail-secure) from a self-sovereign "
    "ADULT. File upstream CIRISPersist#306: a steward-less-minor liveness predicate "
    "gated on the I1 age band."))
def test_steward_less_minor_fails_secure(liveness):
    """CC 3.2: a minor whose adult steward is withdrawn MUST be steward-less."""
    r = liveness
    assert r["minor_revoked_is_steward_bound"] == "false", (
        f"a minor whose only adult steward was withdrawn still resolves "
        f"is_steward_bound=true — the no-slavery fail-secure guarantee is not "
        f"enforced for a user-as-minor: {r}")
