"""
Version-skew conformance: explicit known-good and known-bad version
pairs that exercise the cohabitation contract under non-current pins.

The pinned matrix in `matrices/current.yaml` defines the canonical
"works today" set. This file holds tests that intentionally install
OTHER version combinations to verify the cohabitation contract
remains stable across the expected version-skew envelope.

Test cases planned:

- **Forward-compat**: edge v0.9.x against persist v2.{2,3,4,5}.0 — does
  edge tolerate newer persist releases that the matrix doesn't pin?
- **Backward-compat**: edge v0.9.x against persist v2.2.0 (the floor
  in Cargo.toml). Verifies the documented floor actually works.
- **Known-incompatible**: edge v0.9.x against persist v1.x. Should
  cleanly refuse at import time with a typed error, not silently
  misbehave.
- **Mid-release-train**: edge v0.8.x against persist v2.2.0 — does the
  prior edge release still cohabit with the current persist? Catches
  silent persist-side breakage between persist releases.

These tests need pip to install specific versions into a clean venv,
which means they're heavyweight (network I/O, real wheel resolution).
Run them in their own CI job rather than blocking the fast inner-loop
conformance suite.

Currently a placeholder — these come online once the harness's
clean-venv-per-matrix-cell fixture is wired up (separate task; see
GH-issue tracking).
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.skip(
    reason="Version-skew suite pending the clean-venv-per-matrix fixture"
)


def test_forward_compat_edge_against_newer_persist(python_subprocess):
    """edge v0.9.x cohabits with persist v2.3.0+ (unreleased) once those tag."""
    pytest.fail("Not implemented yet")


def test_backward_compat_edge_against_floor_persist(python_subprocess):
    """edge v0.9.x cohabits with its Cargo floor persist version."""
    pytest.fail("Not implemented yet")


def test_known_incompatible_refuses_cleanly(python_subprocess):
    """Pairing edge v0.9.x with persist v1.x raises a typed error at import."""
    pytest.fail("Not implemented yet")
