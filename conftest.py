"""
Pytest fixtures + helpers for the CIRISConformance harness.

Two principles drive every fixture here:

1. **Subprocess isolation.** PyO3 type registration is process-global.
   Once `import ciris_persist` runs, the `PyEngine` PyTypeInfo is
   registered in the running interpreter's type table for the rest of
   the process's life. A test that imports persist cannot be cleanly
   followed by a test that DOESN'T import persist — the registration
   leaks. Every cohabitation scenario runs in a fresh `subprocess`
   (we use plain `subprocess` + an inline Python script, not
   pytest-forked, because forked tests share the parent's import
   state at fork-time).

2. **No imports of ciris-* at module level in this file.** This
   conftest runs in the pytest main process. If we imported anything
   here, every test would inherit that import. We pass module names
   as strings into subprocess scripts.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parent
MATRIX_PATH = REPO_ROOT / "matrices" / "current.yaml"


# ─── Backend-under-test resolution ────────────────────────────────────
# `CIRIS_CONFORMANCE_DATABASE_URL` chooses which persist backend the
# scenarios exercise. The same conformance suite runs against BOTH
# `sqlite::memory:` and `postgres://...` URLs — most cross-module
# PyClass / cohabitation invariants are backend-agnostic, but some
# (e.g. concurrent-cohabitation Engine construction against a shared
# WAL/postgres pool) only surface under the right backend. Two runners
# per platform per the v0.1.1 CI matrix.
#
# When unset, defaults to `sqlite::memory:` so a local `pytest` works
# without standing up postgres.
DEFAULT_DATABASE_URL = "sqlite::memory:"


def get_database_url() -> str:
    return os.environ.get("CIRIS_CONFORMANCE_DATABASE_URL", DEFAULT_DATABASE_URL)


def get_backend_label() -> str:
    """`sqlite` or `postgres` — derived from the URL scheme. For test ids."""
    url = get_database_url()
    if url.startswith("sqlite"):
        return "sqlite"
    if url.startswith("postgres"):
        return "postgres"
    return "unknown"


@pytest.fixture(scope="session")
def database_url() -> str:
    return get_database_url()


@pytest.fixture(scope="session")
def backend_label() -> str:
    return get_backend_label()


# ─── Canonical wheel inventory ────────────────────────────────────────
# Python module names of the ciris-* wheels under cohabitation test.
# NOTE: ciris-keyring + ciris-crypto are NOT here — they're Rust-only
# crates inside CIRISVerify, embedded in `ciris_verify` and
# `ciris_edge`'s compiled cdylibs. There's no separate Python wheel
# to import for them.
#
# When a new ciris-* crate ships a Python wheel, add the module name
# here AND the package version to matrices/current.yaml.
ALL_WHEELS: tuple[str, ...] = (
    "ciris_persist",
    "ciris_verify",
    "ciris_edge",
    # ciris_lens_core is ABSORBED into ciris_server (CIRISServer owns lens-core;
    # the standalone wheel is retired). The lens Python surface
    # (LensClient / install_relay / PROJECTION_VERSION) now ships INSIDE the
    # ciris-server wheel via the same `register()` — so `requires_lens` maps to
    # ciris_server below, and the lens cohabitation tests import ciris_server.
    "ciris_server",     # the fabric-node wheel — carries lens; enters as the under-test artifact
)


@dataclass(frozen=True)
class WheelMatrix:
    """The coherent set under test, parsed from matrices/current.yaml.

    The set spans two channels: `versions` holds the PyPI members
    (`name==version`) and `substrate` holds the git-tag members, which have no
    PyPI release at head and are built from source. `version()` resolves across
    both — a caller asking "what edge is under test?" wants an answer whether
    edge arrived as a wheel or as a tag.
    """

    versions: dict[str, str]
    substrate: dict[str, str]
    constitution: dict[str, str]
    python_versions: list[str]
    known_failures: list[dict]

    @classmethod
    def load(cls, path: Path = MATRIX_PATH) -> "WheelMatrix":
        data = yaml.safe_load(path.read_text())
        substrate = {}
        for pkg, entry in (data.get("substrate") or {}).items():
            substrate[pkg] = entry["tag"] if isinstance(entry, dict) else str(entry)
        return cls(
            versions=data.get("stack", {}),
            substrate=substrate,
            constitution=data.get("constitution", {}),
            python_versions=data.get("python_versions", []),
            known_failures=data.get("known_failures", []),
        )

    @property
    def members(self) -> dict[str, str]:
        """Every member of the coherent set, both channels, one mapping."""
        return {**self.versions, **self.substrate}

    def version(self, package: str) -> str | None:
        """Resolve `ciris_persist` → `v32.3.0` etc. Handles underscore/hyphen.

        Substrate members answer with their git tag (leading `v`), PyPI members
        with their bare version — the string is the member's identity on the
        channel it actually ships through, so a test comparing against
        `__version__` must strip the tag's `v`.
        """
        for key, value in self.members.items():
            if key.replace("-", "_") == package.replace("-", "_"):
                return value
        return None


@pytest.fixture(scope="session")
def matrix() -> WheelMatrix:
    return WheelMatrix.load()


# ─── Subprocess Python runner ─────────────────────────────────────────


@dataclass
class ScriptResult:
    """What a subprocess Python script returns to the test."""

    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def parsed_stdout(self) -> dict | list:
        """Parse stdout as JSON (the canonical script-to-test channel).

        On JSON-decode failure (typically a subprocess that died before
        flushing its result) re-raise with the captured stderr +
        returncode embedded — pytest's failure message then shows the
        real crash signature instead of just "Expecting value: line 1
        column 1 (char 0)" (CIRISEdge#50 darwin × sqlite debug pass).
        """
        try:
            return json.loads(self.stdout)
        except json.JSONDecodeError as e:
            raise json.JSONDecodeError(
                f"{e.msg}  [subprocess rc={self.returncode}]\n"
                f"--- STDOUT (len={len(self.stdout)}) ---\n{self.stdout!r}\n"
                f"--- STDERR (len={len(self.stderr)}) ---\n{self.stderr}",
                e.doc,
                e.pos,
            ) from None


def run_python_script(
    script: str,
    *,
    timeout: float = 30.0,
    expect_ok: bool = False,
) -> ScriptResult:
    """
    Run `script` in a fresh Python subprocess (same interpreter as pytest).

    The fresh subprocess is the load-bearing primitive — it guarantees
    no prior `import ciris_*` state leaks into the scenario under test.

    Pass `expect_ok=True` to fail the test (via assert) if the script
    exits non-zero; otherwise return the result for the caller to inspect.
    """
    completed = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(script)],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    result = ScriptResult(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )
    if expect_ok and not result.ok:
        pytest.fail(
            f"Subprocess script exited {result.returncode}\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )
    return result


# ─── persist 12.2.0 × postgres edge-runtime crash (CIRISPersist#354) ───
# On the postgres backend, persist 12.2.0 makes edge's init_edge_runtime abort the
# subprocess (SIGABRT/SIGSEGV) via a background tokio net/addr panic that unwinds
# across the FFI — shortly AFTER bring-up, so it lands non-deterministically on
# whichever edge-runtime scenario is live when it fires. sqlite is fine; persist
# 11.0.0 is fine (attributed one variable at a time). It is a native-crash noise
# source, not a conformance signal, so any edge-runtime fixture calls this right
# after run_python_script: on the postgres crash signature it imperatively xfails
# (real gate preserved on sqlite AND on postgres when the abort doesn't fire),
# tracked to the issue; the gate flips back the moment persist stops aborting.
_PG_EDGE_CRASH_REASON = (
    "persist 12.2.0 + postgres: init_edge_runtime background tokio task panicked in "
    "net/addr and aborted the subprocess (rc=%s). sqlite + persist 11.0.0 both fine. "
    "Tracked: CIRISPersist#354.")


# ── CIRISConformance#87 — the trust-root capability conferral ceremony ────────
# Since persist v30.2.0 (CIRISPersist#607) the witness-reserved prefixes
# (`age_assurance:`, `capacity_assurance:`) and the detector leaves (`detection:*`)
# are gated on a CONFERRED capability — `infra:attest_assurance` / `infra:detect` —
# held from a trust root THIS NODE trusts, resolved by
# `trust_root::capability_roots_to_trusted_root(node, subject, scope)`. Holding
# the role is necessary, never sufficient. The ceremony a real deployment performs,
# driven here over the real wheel as three federation-tier `delegates_to` rows:
#
#   charter  root → root     dimension trust:charter:v1, scope {infra:serve, infra:attest},
#                            pre_rotation_commitment = sha256(JCS(sorted successor ids))
#   confer   root → subject  dimension trust:confers:v1, scope [<scope>]
#   accept   node → root     dimension trust:accepts:v1, scope [infra:serve]
#
# "node" is whoever the emitting Engine says it is. persist binds that identity
# inside `register_self_federation_key` — and NOWHERE else on the Python surface
# — as an in-memory field of the backend, so a freshly constructed Engine (the
# one-live-engine-per-process rule forces reconstruction) knows no node identity
# until it registers again. Re-registering an existing key is refused as
# `federation_conflict`, but the binding happens BEFORE the refused write, so the
# refusal is the binding. `_bind_node_identity` relies on exactly that; if a
# future persist reorders register_self, the witness emits below start refusing
# with the emitter-mismatch token again and this comment is where to look.
TRUST_ROOT_CEREMONY_SRC = r"""
import hashlib as _hashlib, json as _json


def _bind_node_identity(engine, itype):
    # A fresh Engine knows no node identity; persist binds it inside
    # register_self_federation_key BEFORE the (refused) duplicate write.
    try:
        engine.register_self_federation_key(itype, "rebind", None, None, None)
    except Exception as exc:
        if "federation_conflict" not in str(exc):
            raise


def _trust_edge(ident, attested_kid, dimension, extra):
    env = {"attesting_key_id": ident.kid, "attested_key_id": attested_kid,
           "dimension": dimension, "score": 1.0,
           "asserted_at": "2026-05-28T14:00:00.000Z", "witness_relation": "self"}
    env.update(extra)
    return ident.engine().emit_attestation_self(_json.dumps(
        {"attestation_type": "delegates_to", "attested_key_id": attested_kid,
         "attestation_envelope": env}))


def confer_from_trust_root(root, subject, scope):
    # Stand up `root` as a chartered trust root this node accepts, and confer
    # `scope` on `subject` from it. Returns the three attestation ids.
    commitment = _hashlib.sha256(_json.dumps(
        sorted([root.kid + "-successor"]), separators=(",", ":")).encode()).hexdigest()
    return {
        "charter": _trust_edge(root, root.kid, "trust:charter:v1",
                               {"scope": ["infra:serve", "infra:attest"],
                                "pre_rotation_commitment": commitment}),
        "confer": _trust_edge(root, subject.kid, "trust:confers:v1", {"scope": [scope]}),
        "accept": _trust_edge(subject, root.kid, "trust:accepts:v1", {"scope": ["infra:serve"]}),
    }
"""


def xfail_if_pg_edge_runtime_crash(result: "ScriptResult") -> None:
    """Imperatively `pytest.xfail` iff this is the postgres init_edge_runtime abort.

    Signature: postgres backend + the subprocess died on a signal (negative
    returncode — SIGABRT -6 / SIGSEGV -11) with no parseable stdout. Call BEFORE
    `parsed_stdout()` in any fixture that brings up an edge runtime."""
    if (get_backend_label() == "postgres"
            and result.returncode < 0
            and not result.stdout.strip()):
        pytest.xfail(_PG_EDGE_CRASH_REASON % result.returncode)


# ─── Version-skew clean-venv fixture ──────────────────────────────────
# Some conformance properties are about NON-current version combos: does
# edge tolerate an older-but-in-range persist? does pip actually REFUSE a
# below-floor persist (proving the declared cap is real)? The current
# matrix can't answer these — they need other versions installed in
# isolation. This fixture builds an ephemeral venv per combo, installs the
# requested wheels, runs a probe script inside it, and returns a structured
# result. A resolution/install failure is RETURNED (not raised) so the
# "known-incompatible must refuse" case can assert on it.


@dataclass
class SkewResult:
    """Outcome of a version-skew install + probe."""

    installed: bool          # did `pip install <combo>` succeed?
    install_returncode: int
    install_output: str      # combined stdout+stderr of the pip install
    probe: dict | list | None  # parsed JSON the probe printed (None if not run)
    probe_returncode: int | None

    @property
    def resolution_refused(self) -> bool:
        """True when pip refused the combo as unsatisfiable (a real cap)."""
        out = self.install_output.lower()
        return (not self.installed) and (
            "resolutionimpossible" in out
            or "cannot install" in out
            or "no matching distribution" in out
            or "conflicting dependencies" in out
        )


def _run_skew(combo: dict[str, str], probe_src: str | None,
              *, timeout: float = 300.0) -> SkewResult:
    """Install `combo` (pkg->ver) into a throwaway venv, optionally probe it.

    `combo` is installed with `--ignore-requires-python` so the py-floor
    metadata never masks a genuine *cohabitation* outcome — we want pip's
    DEPENDENCY resolution to be the only gate. The venv is created with
    `--system-site-packages=False` so nothing leaks from the host.
    """
    import tempfile
    import venv as _venv

    workdir = tempfile.mkdtemp(prefix="ciris-skew-")
    venv_dir = os.path.join(workdir, "venv")
    _venv.create(venv_dir, with_pip=True, clear=True, symlinks=True)
    py = os.path.join(venv_dir, "bin", "python")

    pins = [f"{pkg}=={ver}" for pkg, ver in combo.items()]
    install = subprocess.run(
        [py, "-m", "pip", "install", "--disable-pip-version-check",
         "--no-input", "--ignore-requires-python", *pins],
        capture_output=True, text=True, timeout=timeout,
    )
    installed = install.returncode == 0
    result = SkewResult(
        installed=installed,
        install_returncode=install.returncode,
        install_output=install.stdout + install.stderr,
        probe=None,
        probe_returncode=None,
    )
    if installed and probe_src is not None:
        proc = subprocess.run([py, "-c", textwrap.dedent(probe_src)],
                              capture_output=True, text=True, timeout=timeout)
        result.probe_returncode = proc.returncode
        try:
            result.probe = json.loads((proc.stdout or "").strip().splitlines()[-1])
        except (ValueError, IndexError):
            result.probe = {"_unparsed_stdout": proc.stdout, "_stderr": proc.stderr}
    return result


@pytest.fixture
def skew_venv():
    """Return `run(combo, probe=...) -> SkewResult`.

    `combo` is a {package: version} mapping (e.g.
    `{"ciris-persist": "10.0.0", "ciris-edge": "7.0.6"}`); `probe` is
    optional Python source run inside the venv that should `print(json.dumps(...))`
    its findings on the last stdout line. Heavyweight (real pip + venv), so
    these tests live behind the `version_skew` marker / their own CI lane.
    """
    return _run_skew


@pytest.fixture
def python_subprocess():
    """Function fixture: returns the `run_python_script` helper."""
    return run_python_script


# ─── Multi-node federation fixture ────────────────────────────────────
# The cross-wheel suite's nodes are PyO3-isolated subprocesses, so a
# "federation" is N node subprocesses sharing one substrate. The shared
# substrate is a single on-disk SQLite file (persist's `sqlite:////abs.db`
# 4-slash DSN) — every node's Engine points at it, so they see each other's
# `federation_keys` / `federation_attestations` / `federation_blobs`. This
# is the substrate-level federation directory; it needs no transport (which
# sidesteps the Reticulum-self-route / HTTPS-not-in-wheel blockers) and no
# postgres.
#
# Design note — why not multiple processes over a real transport: the field
# precedent (libp2p) abandoned heavyweight multi-node frameworks (Testground)
# for "start N nodes and have them interact" in favour of the simplest thing
# that works. For the *substrate* fabric scenarios (federation directory,
# holder discovery, per-actor eviction, trust graph), a shared store IS how
# peers see each other — no wire round-trip required. Transport-level
# multi-node (cross-transport delivery, #4) is a separate fixture pending
# the HTTPS wheel.


def _federation_node_script(db_url: str, identity_ref: str, context: dict, body: str) -> str:
    header = f"DB_URL = {db_url!r}\nIDENTITY_REF = {identity_ref!r}\n"
    header += "".join(f"{k} = {v!r}\n" for k, v in context.items())
    preamble = r'''
import json, sys, base64, hashlib, os, tempfile, secrets, uuid
try:
    import ciris_persist as cp
except ImportError as exc:
    print(json.dumps({"_node_error": "import", "error": str(exc)})); sys.exit(2)
key_id = "node-" + secrets.token_hex(8)           # unique federation identity per node
_dir = tempfile.mkdtemp()
_seed = os.path.join(_dir, "seed"); open(_seed, "wb").write(secrets.token_bytes(32))
# Federation-tier hybrid emission (holds_bytes + withdraws) is verified
# Ed25519 + ML-DSA-65 Strict as of persist 10.1.1 (CIRISPersist#275): an
# Ed25519-only engine leaves register_self's ML-DSA pubkey absent, so every
# withdraws emit is rejected (verify_hybrid_pqc_fields_mismatch). A real
# federation node carries both keys — construct one.
_pqc_seed = os.path.join(_dir, "pqc"); open(_pqc_seed, "wb").write(secrets.token_bytes(32))
cp.reset_engine()
engine = cp.Engine(DB_URL, key_id, local_key_id=key_id, local_key_path=_seed,
                   local_pqc_key_id=key_id + "-pqc", local_pqc_key_path=_pqc_seed)
# identity_type defaults to "agent"; inject IDENTITY_TYPE="user" for an
# steward-bound identity (is_steward_bound checks the type set contains `user`;
# persist 11 renamed the owner→steward surface, semantics preserved).
_id_type = globals().get("IDENTITY_TYPE", "agent")
kid = engine.register_self_federation_key(_id_type, IDENTITY_REF, None, None, None)
report = {"key_id": key_id}

# ─── Roster-growth authority (persist v31.0.0, CIRISPersist#654) ──────
# `cohort_add_member` / `cohort_swap_member` / `cohort_revoke_member` take a
# caller-supplied authority signature. Before #654 roster growth was reachable
# from PyO3 with NO authority check at all, which left `federation_communities`
# holding a roster nobody had signed next to signature columns still describing
# the roster that used to be there — and the roster is both numerator and
# denominator of the family/WA quorum, so a free seat changes who can charter a
# trust root. These helpers build the specs that gate now demands.
#
# NOTE the asymmetry, which is a real usability seam and not our choice:
# `put_community_json` SELF-SIGNS when the caller supplies no authority (the
# node creating a community it is the authority for), but the very same node
# growing that community's roster must hand-build a signature. Same key, same
# wheel-local API, two different contracts.

def _canonical_ts(ts):
    """Spell a timestamp the way persist's own serializer will spell it.

    The signature covers persist's serialization of the GROWN record, not the
    string we passed in, so a trailing `.000` we send but persist drops would
    silently produce a preimage that cannot verify. chrono's `DateTime<Utc>`
    serde writes RFC-3339 at automatic precision — a zero fractional part is
    omitted. Derived here, and ASSERTED against persist's own output in
    `_cohort_signing_envelope` below, so a spelling change upstream fails loudly
    instead of as a mystery hybrid-verify rejection.
    """
    return ts.replace(".000Z", "Z") if ts.endswith(".000Z") else ts


def _sign_envelope(envelope):
    """Hybrid-sign a canonical envelope as THIS node's registered authority.

    `engine.canonicalize_envelope` is the produce-side CEG gate
    (`ceg_produce_canonicalize`) that the admission path re-runs on verify.
    Deliberately NOT `canonicalize_envelope_for_signing`, whose docstring
    claims the two are the same canonicalizer: at persist v32.3.0 they are not
    — that one runs the pre-cut Python canonicalizer and strips `signature`
    fields, so signing through it yields bytes the gate never reconstructs,
    and the failure reads as a generic hybrid-verify rejection. Filed as
    CIRISPersist#714; drop this note if that lands and the names agree.
    """
    canonical = engine.canonicalize_envelope(json.dumps(envelope))
    sigs = engine.local_sign_hybrid(canonical)
    return {
        "authority_key_id": kid,
        "scrub_signature_classical": base64.b64encode(sigs["classical_sig"]).decode(),
        "scrub_signature_pqc": base64.b64encode(sigs["pqc_sig"]).decode(),
    }


# `affiliations` is the fourth rostered tier and shares the community
# machinery exactly (CC 4.4.3.2.8 / CIRISPersist#308) — same storage, same
# revocation table, so the same preimage shape.
_COHORT_PLANE = {"family": "family", "community": "community",
                 "affiliations": "community"}


def _stored_group(cohort, group_key_id):
    plane = _COHORT_PLANE[cohort]
    raw = (engine.lookup_family_json(group_key_id) if plane == "family"
           else engine.lookup_community_json(group_key_id))
    stored = json.loads(raw)
    for m in stored.get("members") or []:
        # Ground-truth check of _canonical_ts against a member persist itself
        # serialized. If this fires, the derivation above is stale.
        assert m["joined_at"] == _canonical_ts(m["joined_at"]), (
            "persist now spells a stored joined_at as %r, which _canonical_ts "
            "would rewrite to %r — the AdmitSpec preimage derivation is stale"
            % (m["joined_at"], _canonical_ts(m["joined_at"])))
    return stored


def roster_member(key_id, joined_at, role=None):
    """A RosterMember spelled the way persist will re-serialize it.

    `role` is `skip_serializing_if = "Option::is_none"`, so a `None` role must
    be ABSENT from the preimage, not present-and-null.
    """
    member = {"key_id": key_id, "joined_at": _canonical_ts(joined_at)}
    if role is not None:
        member["role"] = role
    return member


def admit_spec(cohort, group_key_id, member):
    """The AdmitSpec authorizing `member`'s addition to `group_key_id`.

    Mirrors `authorize_{family,community}_growth`: read the stored record, push
    the member, sign `signing_envelope()` (the record minus the server-computed
    `persist_row_hash`). Reading the record back rather than reusing the dict we
    wrote means the preimage is built from what persist actually stored.
    """
    grown = dict(_stored_group(cohort, group_key_id))
    grown["members"] = list(grown.get("members") or []) + [member]
    grown.pop("persist_row_hash", None)
    return json.dumps(_sign_envelope(grown))


def revoke_spec(cohort, group_key_id, removed_key_id, effective_at,
                reason=None, witness_set=()):
    """The RevokeSpec authorizing `removed_key_id`'s removal.

    Signed over the cohort's `MembershipRevocation::signing_envelope()`.
    `removed_at` IS `effective_at` — every field the gate verifies over must be
    caller-known in advance, so persist never mints a `now` the caller could not
    have signed.
    """
    effective_at = _canonical_ts(effective_at)
    plane = _COHORT_PLANE[cohort]
    group_field = "family_key_id" if plane == "family" else "community_key_id"
    envelope = {
        group_field: group_key_id,
        "removed_identity_key_id": removed_key_id,
        "removed_at": effective_at,
        "effective_at": effective_at,
    }
    if reason is not None:
        envelope["reason"] = reason
    if witness_set:
        envelope["witness_set"] = list(witness_set)
    # The spec carries only the caller's knobs plus the authority signature;
    # persist builds the rest of the revocation row from its own arguments.
    spec = {"effective_at": effective_at}
    if reason is not None:
        spec["reason"] = reason
    if witness_set:
        spec["witness_set"] = list(witness_set)
    spec.update(_sign_envelope(envelope))
    return json.dumps(spec)
'''
    post = '\nprint(json.dumps(report)); sys.stdout.flush(); os._exit(0)\n'
    return header + preamble + body + post


@pytest.fixture
def federation(tmp_path):
    """Run multi-node federation steps over a shared substrate.

    Returns `node(body, *, identity_ref="node", **context)`: runs `body` as a
    fresh node subprocess (its own unique federation key as `key_id` / `kid`,
    its own Engine bound as `engine`) against a SHARED sqlite file all nodes
    see. Inject prior steps' values via keyword `context`; read results from
    the `report` dict the body fills. Steps run sequentially and observe each
    other's federation state.
    """
    # sqlite:// + /abs/path → 4 leading slashes (see _make_federation).
    return _make_federation(tmp_path / "federation.db")


def _make_federation(db_file):
    """Build a `node(...)` callable bound to one shared sqlite substrate file.

    Shared by the function-scoped `federation` fixture (above) and the
    module-scoped `federation_module` fixture (below) — same multi-node-over-one-
    substrate semantics, differing only in lifetime.
    """
    db_file.touch()
    db_url = f"sqlite:///{db_file}"

    def node(body: str, *, identity_ref: str = "node", **context):
        script = _federation_node_script(db_url, identity_ref, context, body)
        result = run_python_script(script)
        try:
            payload = result.parsed_stdout()
        except Exception:
            pytest.fail(
                f"federation node ({identity_ref}) produced no parseable JSON "
                f"(exit {result.returncode}):\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}"
            )
        assert "_node_error" not in payload, payload
        return payload

    node.db_url = db_url
    return node


@pytest.fixture(scope="module")
def federation_module(tmp_path_factory):
    """Module-scoped `federation` — one shared substrate for a whole module.

    Identical contract to `federation` (`node(body, *, identity_ref, **context)`)
    but a single shared sqlite file lives for the module, so a multi-step
    multi-node scenario (register N member nodes, then drive a founder node over
    them) is built once and asserted by many tests without re-running the nodes.
    """
    db_file = tmp_path_factory.mktemp("federation_module") / "federation.db"
    return _make_federation(db_file)



# ─── CC conformance-profile script preamble ──────────────────────────
# The CCP / CCC / CCS profile tests (CC 2.2) all need a persist Engine
# carrying a 32-byte Ed25519 LocalSigner so they can sign + verify
# canonical bytes. This builds that engine as `engine` and its base64
# public key as `pk` inside a fresh subprocess. On import/construction
# failure it prints a JSON diagnostic and exits non-zero, so the test
# sees a parseable signal rather than a bare traceback.
#
# CRITICAL — backend parity: each subprocess gets a UNIQUE key_id +
# Ed25519 seed (`key_id` is exposed for the scenario code). With
# sqlite::memory: every subprocess has its own DB, so a fixed key id was
# invisible — but under postgres ALL subprocesses share one database, and
# a fixed `local_key_id` made the second test's `register_federation_key`
# collide with `federation_conflict` (CIRISConformance#6, an order-
# dependent isolation bug, not a platform bug). A per-subprocess unique
# identity isolates the tests on the shared backend and gives sqlite +
# postgres full parity.


def ceg_local_signer_preamble(database_url: str, *, pqc: bool = False) -> str:
    """Return a subprocess-script prefix that binds `engine`, `pk`, `key_id`.

    Shared by the CEG CCP/CCC/CCS conformance scripts. Append scenario
    code that builds a `report` dict and prints it as JSON to stdout.
    `key_id` is the engine's unique local key id for this subprocess —
    use it instead of a hard-coded label so tests stay isolated on a
    shared (postgres) backend.

    `pqc` selects the engine identity shape:

    - ``pqc=False`` (default) → **Ed25519-only**. Use for the CCC
      `ed25519_fallback` / hybrid-pending verify path, which is only valid
      for a key whose ML-DSA-65 pubkey is absent.
    - ``pqc=True`` → **hybrid (Ed25519 + ML-DSA-65)**. Required for any
      federation-tier EMISSION (`put_blob_signing` holds_bytes, eviction
      `withdraws`): as of persist 10.1.1 (CIRISPersist#275) `register_self`
      leaves the PQC pubkey absent on an Ed25519-only engine, so the
      Strict hybrid emit is rejected (`verify_hybrid_pqc_fields_mismatch`).
    """
    header = f"DB_URL = {database_url!r}\nWANT_PQC = {bool(pqc)!r}\n"
    body = r'''
import json, sys, base64, hashlib, os, tempfile, secrets, uuid
try:
    import ciris_persist as cp
except ImportError as exc:
    print(json.dumps({"stage": "import", "error": str(exc)}))
    sys.exit(2)
# Unique per-subprocess identity so concurrent tests don't collide in a
# shared postgres database (sqlite::memory: is already per-process).
key_id = "ceg-conformance-" + secrets.token_hex(8)
_dir = tempfile.mkdtemp()
_seed_path = os.path.join(_dir, "local.seed")
with open(_seed_path, "wb") as _fh:
    _fh.write(secrets.token_bytes(32))  # a fresh 32-byte Ed25519 seed
_engine_kwargs = dict(local_key_id=key_id, local_key_path=_seed_path)
if WANT_PQC:
    _pqc_path = os.path.join(_dir, "local.pqc.seed")
    with open(_pqc_path, "wb") as _fh:
        _fh.write(secrets.token_bytes(32))
    _engine_kwargs.update(local_pqc_key_id=key_id + "-pqc", local_pqc_key_path=_pqc_path)
cp.reset_engine()
engine = cp.Engine(DB_URL, key_id, **_engine_kwargs)
pk = engine.local_public_key_b64()
'''
    return header + body


# ─── Installed-wheel discovery ────────────────────────────────────────


def is_module_installed(module_name: str) -> bool:
    """Probe whether `module_name` is importable in a fresh subprocess.

    Done in a subprocess so the probe doesn't pollute pytest's import
    state — important when the probe falls through to a real test that
    needs a clean interpreter.
    """
    script = f"""
        import importlib, sys
        try:
            importlib.import_module({module_name!r})
            sys.exit(0)
        except ImportError:
            sys.exit(1)
    """
    result = run_python_script(script, timeout=10.0)
    return result.ok


def installed_wheels() -> list[str]:
    """Return the subset of `ALL_WHEELS` actually installed in this env."""
    return [w for w in ALL_WHEELS if is_module_installed(w)]


@pytest.fixture(scope="session")
def installed() -> list[str]:
    """Session-scoped: which ciris-* wheels are importable."""
    return installed_wheels()


# ─── Marker-driven skip logic ─────────────────────────────────────────


_REQUIREMENT_MARKERS = {
    "requires_persist": "ciris_persist",
    "requires_edge": "ciris_edge",
    "requires_verify": "ciris_verify",
    # lens-core is absorbed into ciris-server; its surface ships in that wheel.
    "requires_lens": "ciris_server",
}


def pytest_collection_modifyitems(config: pytest.Config, items: Iterable[pytest.Item]) -> None:
    """Auto-skip tests whose required wheel isn't installed, and tier them.

    Lets CI install a subset (e.g. edge-only) and have the harness
    cleanly skip the cohabitation tests rather than fail — useful for
    pre-merge runs where the under-test artifact isn't yet on PyPI.

    Tiering: any test not explicitly marked `fabric` is the `substrate`
    tier, so `pytest -m substrate` / `-m fabric` partition the suite
    without hand-tagging every existing module.
    """
    have = set(installed_wheels())
    for item in items:
        if item.get_closest_marker("fabric") is None:
            item.add_marker(pytest.mark.substrate)
    for item in items:
        for marker_name, module in _REQUIREMENT_MARKERS.items():
            if item.get_closest_marker(marker_name) and module not in have:
                item.add_marker(
                    pytest.mark.skip(reason=f"{module} not installed in current env")
                )
    # Record each test's markers for the machine-readable conformance report
    # (after tiering + requires_* skips, so the recorded set is final).
    for item in items:
        _CONFORMANCE["markers"][item.nodeid] = sorted(
            m.name for m in item.iter_markers()
        )


# ─── Machine-readable conformance report ──────────────────────────────
# `pytest --conformance-report=PATH` writes a JSON certification artifact:
# the pinned matrix, per-marker rollups, and per-test outcomes, plus a single
# `passed_all_gates` boolean an implementer can assert on. Keyed on the existing
# marker taxonomy (substrate/fabric/ceg/ccp/ccc/ccs/requires_*), so "does
# Implementation X conform?" becomes a checkable file, not a screenful of dots.

_CONFORMANCE: dict = {"outcomes": {}, "markers": {}}

# Markers that name a *property* worth rolling up (vs. incidental tags).
_REPORT_MARKERS = (
    "substrate", "fabric", "cohabitation", "ceg", "ccp", "ccc", "ccs",
    "version_skew", "requires_persist", "requires_edge", "requires_verify",
    "requires_lens",
)


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--conformance-report", action="store", default=None, metavar="PATH",
        help="write a machine-readable JSON conformance report to PATH",
    )


def _classify(report: pytest.TestReport) -> str | None:
    """Map a phase report to a single conformance outcome token."""
    wasxfail = hasattr(report, "wasxfail")
    if report.when == "call":
        if report.passed:
            return "xpassed" if wasxfail else "passed"
        if report.failed:
            return "failed"
        if report.skipped:
            return "xfailed" if wasxfail else "skipped"
    elif report.when == "setup":
        if report.skipped:
            return "xfailed" if wasxfail else "skipped"
        if report.failed:
            return "error"
    elif report.when == "teardown" and report.failed:
        return "error"
    return None


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    outcome = _classify(report)
    if outcome is None:
        return
    outcomes = _CONFORMANCE["outcomes"]
    if report.when == "call":
        outcomes[report.nodeid] = outcome  # call phase is authoritative
    elif report.when == "setup":
        outcomes.setdefault(report.nodeid, outcome)  # only if it never ran
    elif report.when == "teardown" and outcome == "error":
        outcomes[report.nodeid] = "error"  # a clean test that fails teardown


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    path = session.config.getoption("--conformance-report")
    if not path:
        return
    outcomes = _CONFORMANCE["outcomes"]
    markers = _CONFORMANCE["markers"]
    totals: dict[str, int] = {}
    by_marker: dict[str, dict[str, int]] = {}
    tests = []
    for nodeid, outcome in sorted(outcomes.items()):
        ms = markers.get(nodeid, [])
        tests.append({"test": nodeid, "outcome": outcome, "markers": ms})
        totals[outcome] = totals.get(outcome, 0) + 1
        for m in ms:
            if m in _REPORT_MARKERS:
                bucket = by_marker.setdefault(m, {})
                bucket[outcome] = bucket.get(outcome, 0) + 1
    # A gate is "not passed" if anything failed, errored, or unexpectedly passed
    # (an xpassed strict-xfail means an expected-failure must be flipped).
    passed_all = not (totals.get("failed", 0) or totals.get("error", 0)
                      or totals.get("xpassed", 0))
    url = get_database_url()
    loaded = WheelMatrix.load()
    report = {
        "schema": "ciris-conformance-report/v1",
        # `matrix` stays the flat {member: version} an existing consumer reads.
        # The channel split and the Constitution pin are additive keys, so a
        # report reader written against v1 keeps working.
        "matrix": loaded.members,
        "matrix_channels": {
            "pypi": loaded.versions,
            "git_tag": loaded.substrate,
        },
        "constitution": loaded.constitution,
        "database_backend": "postgres" if url.startswith("postgres") else "sqlite",
        "exit_status": int(exitstatus),
        "passed_all_gates": passed_all,
        "totals": totals,
        "by_marker": by_marker,
        "tests": tests,
    }
    Path(path).write_text(json.dumps(report, indent=2, sort_keys=True))
    print(f"\nconformance report → {path} "
          f"(passed_all_gates={passed_all}, {totals})")
