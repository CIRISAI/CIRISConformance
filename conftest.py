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
)


@dataclass(frozen=True)
class WheelMatrix:
    """The pinned wheel set under test, parsed from matrices/current.yaml."""

    versions: dict[str, str]
    python_versions: list[str]
    known_failures: list[dict]

    @classmethod
    def load(cls, path: Path = MATRIX_PATH) -> "WheelMatrix":
        data = yaml.safe_load(path.read_text())
        return cls(
            versions=data.get("stack", {}),
            python_versions=data.get("python_versions", []),
            known_failures=data.get("known_failures", []),
        )

    def version(self, package: str) -> str | None:
        """Resolve `ciris_persist` → `2.2.0` etc. Handles underscore/hyphen."""
        for key, value in self.versions.items():
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
        """Parse stdout as JSON (the canonical script-to-test channel)."""
        return json.loads(self.stdout)


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


@pytest.fixture
def python_subprocess():
    """Function fixture: returns the `run_python_script` helper."""
    return run_python_script


# ─── CEG conformance-profile script preamble ──────────────────────────
# The CCP / CCC / CCS profile tests (CEG §0.2) all need a persist Engine
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


def ceg_local_signer_preamble(database_url: str) -> str:
    """Return a subprocess-script prefix that binds `engine`, `pk`, `key_id`.

    Shared by the CEG CCP/CCC/CCS conformance scripts. Append scenario
    code that builds a `report` dict and prints it as JSON to stdout.
    `key_id` is the engine's unique local key id for this subprocess —
    use it instead of a hard-coded label so tests stay isolated on a
    shared (postgres) backend.
    """
    header = f"DB_URL = {database_url!r}\n"
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
_seed_path = os.path.join(tempfile.mkdtemp(), "local.seed")
with open(_seed_path, "wb") as _fh:
    _fh.write(secrets.token_bytes(32))  # a fresh 32-byte Ed25519 seed
cp.reset_engine()
engine = cp.Engine(
    DB_URL, key_id,
    local_key_id=key_id, local_key_path=_seed_path,
)
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
