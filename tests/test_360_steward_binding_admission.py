"""
Fabric tier — CC 3.2 user-target steward-binding admission rule.

CC 3.2 (part_3_the_namespace.md, "User-target admission rule") closes the gap
left by the node/agent steward-binding gate: a `delegates_to(S → T)` whose
**target `T` resolves to a `user`-role identity** is otherwise unguarded —
"stewarding a person" is admissible. The rule narrows the admissible set to
exactly minor-guardianship:

    admit_user_steward_binding(delegates_to S -> T):
      require  age_band(T) == minor   (< 18)      # ward is a minor
      require  user in S.identity_type            # steward is a user identity
      require  age_band(S) == adult   (>= 18)     # steward is an adult
      require  S == delegates_to.attesting_key_id # steward signed it
      otherwise REJECT

A user-target binding whose target `T` is an **adult** is **rejected
unconditionally** (the un-stewardable, self-sovereign case, CC 3.2 / CC 1.15.6).
A binding where the steward `S` is a minor, or where the signer is not the
steward, is likewise rejected. `node`/`agent`-target admission is governed by the
older steward-binding gate and is NOT affected by this rule.

What is REAL on the floor (persist 12.5.0): the structural steward surface
exists — `steward_bind`, `grant_delegation`, `is_steward_bound_json`,
`steward_bindings_of_json`. A node/agent steward-binding is admitted and resolves
`is_steward_bound` true (asserted real, the control). The **adult-target
rejection is now REAL**: `grant_delegation`/`steward_bind` onto a `user`-role
identity reject with `federation_user_target_steward_binding_forbidden` — the CC
3.2 un-stewardable-adult guarantee is enforced (was xfail on persist 12.5.0).

What is NOT exposed (probed on persist 12.5.0): the **conditional minor-admit**.
The user-target forbid is WHOLESALE — adult AND minor targets reject with the
SAME `federation_user_target_steward_binding_forbidden`. So the positive CC 3.2
case (admit a user-target binding iff `age_band(T)==minor ∧ age_band(S)==adult ∧
S signed it`) is NOT drivable over the Engine FFI: a legal adult→minor
guardianship binding cannot be created at all, only refused alongside the adult
case. That assertion is `xfail(strict=True)` — it flips to xpass the moment the
substrate exposes the conditional minor-guardianship admit. Gap to file upstream:
CIRISPersist — expose the §3.2 conditional minor-guardianship admit (the
minor-target case of `admit_user_steward_binding`), not just the blanket
user-target forbid.
"""

from __future__ import annotations

import pytest

from conftest import get_database_url, run_python_script

pytestmark = pytest.mark.fabric

# A shared-substrate scenario: register an adult-user steward, a (would-be) minor
# user ward, an adult user, and an agent node — all over one sqlite file — then
# have the steward attempt each binding and report the outcome token.
_BODY = r"""
import json, sys, os, tempfile, secrets
try:
    import ciris_persist as cp
except ImportError as exc:
    print(json.dumps({"_error": "import", "detail": str(exc)})); sys.exit(2)

# A single SHARED substrate so every reconstructed engine sees the same
# federation_keys / attestations — cross-engine key visibility is the whole point.
# The harness injects INJECTED_URL to honor the chosen backend: postgres is already
# shared across subprocesses; for the sqlite default we need an ON-DISK file
# (`sqlite::memory:` gives each Engine its own private DB). Full sqlite+postgres
# parity (the user's hard requirement) — same scenario, both backends.
if INJECTED_URL.startswith("postgres"):
    DB_URL = INJECTED_URL
else:
    _dbf = os.path.join(tempfile.mkdtemp(), "f.db"); open(_dbf, "a").close()
    DB_URL = "sqlite:///" + _dbf


# Only one Engine may be live at a time (`reset_engine` closes the prior one), so
# each identity carries its stable alias + key paths and is RECONSTRUCTED on the
# shared substrate whenever it must be the live signer. The kid is stable across
# reconstructions (same alias + same Ed25519 seed → same derived key_id).
class Ident:
    def __init__(self, prefix, itype, ref):
        d = tempfile.mkdtemp()
        self.s = os.path.join(d, "s"); open(self.s, "wb").write(secrets.token_bytes(32))
        self.p = os.path.join(d, "p"); open(self.p, "wb").write(secrets.token_bytes(32))
        self.k = prefix + "-" + secrets.token_hex(8)
        self.itype, self.ref = itype, ref
        self.kid = self.engine().register_self_federation_key(itype, ref, None, None, None)

    def engine(self):
        cp.reset_engine()
        return cp.Engine(DB_URL, self.k, local_key_id=self.k, local_key_path=self.s,
                         local_pqc_key_id=self.k + "-pqc", local_pqc_key_path=self.p)


for surface in ("steward_bind", "grant_delegation", "is_steward_bound_json",
                "steward_bindings_of_json"):
    probe = Ident("probe", "agent", "probe")
    if not hasattr(probe.engine(), surface):
        print(json.dumps({"_error": "absent", "surface": surface})); sys.exit(2)

S = Ident("steward", "user", "adult-steward")   # the adult-user steward (signer)
T = Ident("minor", "user", "minor-ward")         # the would-be minor ward (user)
A = Ident("adult", "user", "adult-other")        # a self-sovereign adult user
N = Ident("node", "agent", "node-ref")           # a node/agent (the control)

report = {"S": S.kid, "T": T.kid, "A": A.kid, "N": N.kid}


def _attempt(label, fn):
    try:
        report[label] = {"outcome": "admitted", "id": fn()}
    except Exception as exc:
        report[label] = {"outcome": "rejected", "token": str(exc)[:160]}


# ── CC 3.2 user-target admission attempts, signed by the adult steward S ──
# S (adult user) → A (adult user): MUST be rejected unconditionally.
_attempt("adult_target", lambda: S.engine().grant_delegation(A.kid, ["steward"], False))
# S (adult user) → T (would-be minor user): the only legal user-target case.
_attempt("minor_target", lambda: S.engine().grant_delegation(T.kid, ["steward"], False))
# steward_bind onto an adult user — also a user-target binding, MUST be rejected.
_attempt("adult_target_steward_bind", lambda: S.engine().steward_bind(A.kid, ["infra:transport"]))

# ── Control: node/agent steward-binding IS real and enforced ──
_attempt("node_bind", lambda: S.engine().steward_bind(N.kid, ["infra:transport"]))
e = S.engine()
report["node_is_steward_bound"] = e.is_steward_bound_json(N.kid)
report["node_bindings_of"] = json.loads(e.steward_bindings_of_json(N.kid))

report["stage"] = "done"
print(json.dumps(report)); sys.stdout.flush(); os._exit(0)
"""


@pytest.fixture(scope="module")
def admission():
    # Honor the chosen backend: under postgres the injected URL is the shared
    # substrate; under the sqlite default the body mints an on-disk file (the
    # cross-engine key visibility this scenario needs is impossible over the
    # conftest `:memory:` default, where each Engine gets a private database).
    script = f"INJECTED_URL = {get_database_url()!r}\n" + _BODY
    payload = run_python_script(script).parsed_stdout()
    if payload.get("_error") == "absent":
        pytest.fail(f"persist steward surface missing: {payload.get('surface')}")
    assert payload.get("stage") == "done", payload
    return payload


# ── Control: the node/agent steward-binding gate IS real (CC 3.2 unchanged) ──
@pytest.mark.requires_persist
def test_node_steward_binding_is_admitted_and_resolves(admission):
    """A node/agent steward-binding is admitted and resolves `is_steward_bound` true."""
    r = admission
    assert r["node_bind"]["outcome"] == "admitted", (
        f"node steward_bind was refused: {r['node_bind']}")
    assert r["node_is_steward_bound"] == "true", (
        f"steward-bound node not recognized by is_steward_bound: {r}")
    assert r["S"] in r["node_bindings_of"], (
        f"adult steward absent from the node's steward_bindings_of: {r}")


# ── CC 3.2 user-target admission rule — not yet enforced on the floor ──
@pytest.mark.requires_persist
def test_adult_target_user_binding_is_rejected(admission):
    """CC 3.2: a user-target steward-binding onto an adult MUST be rejected.

    Probed real on persist 12.5.0: `grant_delegation` targeting a `user`-role
    identity is rejected with `federation_user_target_steward_binding_forbidden`.
    The CC 3.2 un-stewardable-adult guarantee is now enforced at admission — what
    was an xfail(strict) on persist 12.5.0 is a real green gate.
    """
    r = admission
    assert r["adult_target"]["outcome"] == "rejected", (
        f"a delegates_to targeting an adult user was admitted — the CC 3.2 "
        f"un-stewardable guarantee is not enforced: {r['adult_target']}")
    assert "user_target_steward_binding_forbidden" in r["adult_target"]["token"], (
        f"unexpected rejection token for an adult user-target delegation: "
        f"{r['adult_target']}")


@pytest.mark.requires_persist
def test_adult_target_steward_bind_is_rejected(admission):
    """CC 3.2: `steward_bind` onto an adult user MUST be rejected unconditionally.

    Probed real on persist 12.5.0: `steward_bind` onto a `user`-role identity is
    rejected with `federation_user_target_steward_binding_forbidden`. Now a real
    green gate (was xfail on persist 12.5.0; CIRISPersist#306 shipped the forbid).
    """
    r = admission
    assert r["adult_target_steward_bind"]["outcome"] == "rejected", (
        f"steward_bind onto an adult user was admitted: "
        f"{r['adult_target_steward_bind']}")
    assert "user_target_steward_binding_forbidden" in r["adult_target_steward_bind"]["token"], (
        f"unexpected rejection token for an adult user-target steward_bind: "
        f"{r['adult_target_steward_bind']}")


@pytest.mark.requires_persist
@pytest.mark.xfail(strict=True, reason=(
    "User-target steward binding is forbidden WHOLESALE on persist 12.5.0: "
    "grant_delegation/steward_bind onto ANY user-role target (adult AND minor "
    "alike) reject with federation_user_target_steward_binding_forbidden. The CC "
    "3.2 POSITIVE minor-guardianship admission path (admit a user-target binding "
    "iff age_band(T)==minor ∧ age_band(S)==adult ∧ S signed it) is NOT exposed "
    "over the Engine FFI — only the blanket forbid. So the conditional minor-admit "
    "is undrivable: a legal adult→minor guardianship binding cannot be created at "
    "all. File upstream CIRISPersist: expose the conditional minor-guardianship "
    "admit (the §3.2 admit_user_steward_binding minor case), not just the wholesale "
    "user-target forbid."))
def test_minor_target_user_binding_is_admitted_only_because_minor(admission):
    """CC 3.2: the legal minor-guardianship admit is forbidden wholesale (undrivable).

    The positive case the rule requires — a user-target binding ADMITTED because
    the target is a minor and the steward is a verified adult who signed it — is
    not exposed: persist 12.5.0 forbids ALL user-target bindings wholesale. This
    asserts the conditioned admit that the rule mandates, which the FFI cannot
    express today (the minor leg rejects with the same blanket forbid as the adult
    leg). Flips to a real gate when persist exposes the conditional minor-admit.
    """
    r = admission
    # Today the minor-target binding is forbidden wholesale, identical to the
    # adult leg — the conditional minor-guardianship admit is not exposed.
    assert r["minor_target"]["outcome"] == "admitted", (
        f"the §3.2 conditional minor-guardianship binding is not admissible over "
        f"the FFI — user-target binding is forbidden wholesale (adult AND minor "
        f"alike) on persist 12.5.0: {r['minor_target']}")
