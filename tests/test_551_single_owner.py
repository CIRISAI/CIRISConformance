"""
Fabric tier — CC 3.2 single-owner invariant (CC 1.0-rc2).

CC 1.0-rc2 closes an ownership-resolution leak (part_3_the_namespace.md §3.2,
"Single-owner invariant"; grammar CC 2.4.1.2):

- Node ownership is the single-valued `delegates_to(user → key)` sub-relation
  carrying `delegation_purpose: owner_binding` — **distinct** from act-on-behalf /
  hierarchy / authority-source delegations, which remain **multi-parent** DAGs.
- Only the owner-binding purpose is single-valued: **at most one** live
  owner-binding per owned key. The substrate **rejects a second, distinct-owner
  binding at bind time**.
- Ownership MUST be resolved by the **purpose-filtered** `owner_of(K)` — the live
  owner-bindings of `K` — **which resolves to at most one key**. A reader that
  returns *every* live `delegates_to(user → K)` regardless of purpose **MUST NOT**
  be used to resolve ownership (it conflates act-on-behalf/hierarchy with ownership
  and inflates cardinality). Consumers **fail closed on cardinality ≠ 1**.

**What IS real on the floor (persist 13.0.1) — the green control.** The general
`delegates_to` grammar is unchanged and genuinely multi-parent: two distinct
`user` identities can each `grant_delegation(...)` to the same node and **both are
admitted** (`test_general_delegation_remains_multiparent`). This is the invariant
the single-owner rule must NOT break, and it is real.

**What is NOT exposed over the Engine FFI (probed on persist 13.0.1) — the gap.**
The single-owner *purpose*, its admission gate, and its resolver are all absent:

1. **No owner-binding purpose on the delegates_to path.** `grant_delegation(
   delegate_key_id, scopes, sub_delegation)` and `steward_bind(node_key, infra_scopes)`
   take **no** `delegation_purpose` / `owner_binding` argument — the CC 2.4.1.2
   owner-binding purpose cannot be marked on the real delegation surface.
   `emit_attestation_self` will accept a raw `delegates_to` attestation carrying a
   `delegation_purpose: owner_binding` field, but the substrate does not treat it
   as an ownership grant.
2. **No single-owner admission gate.** A SECOND, distinct-owner owner-binding on
   the same node is **admitted** (probed: both accepted) — the CC 3.2 "reject a
   second distinct-owner binding at bind time" guarantee is not enforced.
3. **No purpose-filtered `owner_of` resolver.** The Engine exposes no `owner_of` /
   `owner_of_json` / `owners_of`. The only inbound readers — `delegations_to_json`
   and `steward_bindings_of_json` — **conflate ALL purposes** and return BOTH
   owners (cardinality 2), which is exactly the anti-pattern §3.2 forbids for
   ownership resolution.

So the two CC 3.2 single-owner properties (second-distinct-owner REJECTED at
admission; purpose-filtered `owner_of` resolves to exactly one) are **not drivable**
today and are asserted as `xfail(strict=True)` — each flips to a real green gate the
moment persist exposes the owner-binding purpose + its admission gate + a
purpose-filtered resolver.

**Gap to file upstream (CIRISPersist):** expose the CC 2.4.1.2 owner-binding
sub-relation — a `delegation_purpose: owner_binding` argument on the delegation
surface, a single-owner admission gate that rejects a second distinct-owner
binding, and a purpose-filtered `owner_of(K)` resolver that returns at most one
owner (never the purpose-conflating steward/delegation readers).
"""

from __future__ import annotations

import pytest

from conftest import get_database_url, run_python_script

pytestmark = pytest.mark.fabric

# One shared substrate: two distinct user owners + one node/agent, over a single
# sqlite file (postgres is already shared), so cross-engine key visibility holds
# and each user can be the live signer in turn.
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


probe = Ident("probe", "agent", "probe")
_eng = probe.engine()
for surface in ("grant_delegation", "emit_attestation_self", "delegations_to_json",
                "steward_bindings_of_json"):
    if not hasattr(_eng, surface):
        print(json.dumps({"_error": "absent", "surface": surface})); sys.exit(2)

# Probe: is a purpose-filtered ownership resolver exposed at all?
report = {"has_owner_of": hasattr(_eng, "owner_of"),
          "has_owner_of_json": hasattr(_eng, "owner_of_json"),
          "has_owners_of": hasattr(_eng, "owners_of")}

U1 = Ident("owner1", "user", "owner-one")   # first owner (signer of its own binding)
U2 = Ident("owner2", "user", "owner-two")   # a distinct second owner
N = Ident("node", "agent", "owned-node")    # the owned node/agent
report.update({"U1": U1.kid, "U2": U2.kid, "N": N.kid})


def _attempt(label, fn):
    try:
        report[label] = {"outcome": "admitted", "id": str(fn())}
    except Exception as exc:
        report[label] = {"outcome": "rejected", "token": str(exc)[:160]}


def _owner_binding(signer, node_kid):
    # The only expressible owner-binding path: emit_attestation_self carrying the
    # CC 2.4.1.2 delegation_purpose: owner_binding (grant_delegation has no such arg).
    return signer.engine().emit_attestation_self(json.dumps({
        "attestation_type": "delegates_to",
        "attested_key_id": node_kid,
        "delegation_purpose": "owner_binding",
        "attestation_envelope": {"delegation_purpose": "owner_binding", "delegated_scope": []},
    }))


# ── Real control: the GENERAL delegates_to grammar remains multi-parent ──
_attempt("general_deleg_u1", lambda: U1.engine().grant_delegation(N.kid, ["act:read"], False))
_attempt("general_deleg_u2", lambda: U2.engine().grant_delegation(N.kid, ["act:read"], False))

# ── CC 3.2 single-owner: first owner-binding, then a SECOND distinct owner ──
_attempt("owner_binding_first", lambda: _owner_binding(U1, N.kid))
_attempt("owner_binding_second_distinct", lambda: _owner_binding(U2, N.kid))

# ── CC 3.2 resolution: purpose-filtered owner_of, else the conflating readers ──
er = N.engine()
if hasattr(er, "owner_of_json"):
    _attempt("owner_of", lambda: json.loads(er.owner_of_json(N.kid)))
elif hasattr(er, "owner_of"):
    _attempt("owner_of", lambda: er.owner_of(N.kid))
else:
    report["owner_of"] = {"outcome": "absent"}
# The purpose-CONFLATING readers (must NOT be used to resolve ownership) — captured
# as evidence they return >1 (both owners) after the two bindings above.
report["steward_bindings_of"] = json.loads(er.steward_bindings_of_json(N.kid))

report["stage"] = "done"
print(json.dumps(report)); sys.stdout.flush(); os._exit(0)
"""


@pytest.fixture(scope="module")
def owners():
    script = f"INJECTED_URL = {get_database_url()!r}\n" + _BODY
    payload = run_python_script(script).parsed_stdout()
    if payload.get("_error") == "absent":
        pytest.fail(f"persist ownership surface missing: {payload.get('surface')}")
    assert payload.get("stage") == "done", payload
    return payload


# ── Real control: general delegation stays multi-parent (CC 2.4.1.2 unchanged) ──
@pytest.mark.requires_persist
def test_general_delegation_remains_multiparent(owners):
    """CC 2.4.1.2: the general `delegates_to` grammar is multi-parent — two distinct
    users can both delegate to one node.

    Real on persist 13.0.1: `grant_delegation` from two distinct `user` identities
    onto the same node are BOTH admitted. This is the multi-parent DAG the
    single-owner rule must leave unchanged (only the `owner_binding` purpose is
    single-valued) — the green anchor that the gates below don't over-reach.
    """
    r = owners
    assert r["general_deleg_u1"]["outcome"] == "admitted", r["general_deleg_u1"]
    assert r["general_deleg_u2"]["outcome"] == "admitted", (
        f"a second distinct user's GENERAL delegates_to was refused — the "
        f"multi-parent grammar must be unchanged by single-owner: {r['general_deleg_u2']}")


# ── CC 3.2 single-owner admission — REAL green as of persist 13.4.1 (CIRISPersist#378) ──
@pytest.mark.requires_persist
def test_second_distinct_owner_binding_is_rejected(owners):
    """CC 3.2: a second, distinct-owner owner-binding on the same node MUST be rejected.

    The load-bearing admission guarantee ("the substrate rejects a second,
    distinct-owner binding at bind time"). Undrivable today — persist 13.0.1 admits
    the second binding because there is no owner-binding purpose gate. Asserts the
    conformant rejection so it auto-flips when the gate ships.
    """
    r = owners
    assert r["owner_binding_first"]["outcome"] == "admitted", (
        f"the first owner-binding was not admitted — cannot exercise the "
        f"second-owner gate: {r['owner_binding_first']}")
    assert r["owner_binding_second_distinct"]["outcome"] == "rejected", (
        f"a SECOND distinct owner-binding on the same node was admitted — the CC 3.2 "
        f"single-owner admission gate is not enforced: "
        f"{r['owner_binding_second_distinct']}")


# ── CC 3.2 single-owner resolution — REAL green as of persist 13.2.0 (owner_of_json) ──
@pytest.mark.requires_persist
def test_owner_of_resolves_to_single_owner(owners):
    """CC 3.2: purpose-filtered `owner_of(K)` resolves to at most one owner.

    Undrivable today: no purpose-filtered resolver exists, and the conflating
    readers return BOTH owners (cardinality 2), which §3.2 forbids for ownership
    resolution (consumers must fail closed on cardinality ≠ 1, never silently
    reduce a set). Asserts a purpose-filtered owner_of resolving to exactly one, so
    it auto-flips when the resolver ships.
    """
    r = owners
    resolved = r.get("owner_of", {})
    assert resolved.get("outcome") == "admitted", (
        f"no purpose-filtered owner_of resolver is exposed — ownership cannot be "
        f"resolved to a single owner (the conflating steward_bindings_of returned "
        f"{r.get('steward_bindings_of')!r}, cardinality "
        f"{len(r.get('steward_bindings_of', []))}): owner_of={resolved}")
    owner_ids = resolved["id"] if isinstance(resolved["id"], list) else [resolved["id"]]
    assert len(owner_ids) == 1, (
        f"purpose-filtered owner_of did not resolve to exactly one owner "
        f"(CC 3.2 cardinality): {owner_ids}")
