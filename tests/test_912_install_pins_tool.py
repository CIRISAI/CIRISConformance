"""
Unit coverage for the pin-install retry helper (`tools/install_pins.py`).

Every CI install step routes through this helper — the core conformance cells,
the chaquopy bundle, bench, AND the reusable `run-against-wheels.yml` consumers
call. Two things are worth pinning here:

1. **The classifier.** A same-minute matrix bump that races PyPI/CDN
   propagation must retry instead of going red, while a genuine pin conflict
   still fails fast.
2. **Set resolution.** The matrix has two channels (PyPI `stack` + git-tag
   `substrate`). `run-against-wheels.yml` used to carry its own inline copy of
   this logic; when the second channel landed, that copy would have kept
   installing only the PyPI half — a cell that goes green while never
   installing the substrate it claims to test. There is now one implementation,
   and these tests are what hold it to the matrix's real shape.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_TOOL = Path(__file__).resolve().parent.parent / "tools" / "install_pins.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("install_pins", _TOOL)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def tool():
    return _load_tool()


_PINS = {"ciris-persist": "5.5.5", "ciris-edge": "2.2.2"}


@pytest.mark.parametrize(
    "output, expected, label",
    [
        ("No matching distribution found for ciris-edge==2.2.2",
         True, "pinned pkg not yet on this CDN edge → retry"),
        ("ERROR: Could not find a version that satisfies the requirement "
         "ciris-persist==5.5.5 (from versions: 5.5.3)",
         True, "can't-find pinned version → retry"),
        ("ResolutionImpossible\nNo matching distribution found for ciris-edge==2.2.2",
         False, "a real resolver conflict beats the propagation signal → fail fast"),
        ("No matching distribution found for some-other-dep==1.0",
         False, "a non-ciris missing dep is not our race → fail fast"),
        ("ERROR: Failed building wheel for cryptography",
         False, "build error → fail fast"),
        ("conflicting dependencies: ciris-edge==2.2.2 and ciris-persist==5.5.5",
         False, "explicit conflict wording → fail fast"),
    ],
)
def test_propagation_race_classifier(tool, output, expected, label):
    assert tool._is_propagation_race(output, _PINS) is expected, label


# ─── retention eviction vs propagation race ───────────────────────────
# Both print "Could not find a version that satisfies the requirement", and
# they need OPPOSITE responses. This is not hypothetical: CIRISConformance
# `main`'s scheduled run went red nightly from 2026-08-13 because
# ciris-server 0.5.131 aged out of the index's ~5-release retention window,
# and every one of those runs spent the full six-attempt linear backoff before
# reporting a transient-sounding reason for a failure that could never clear.

_SERVER_PINS = {"ciris-server": "0.5.131"}
_EVICTED = (
    "ERROR: Could not find a version that satisfies the requirement "
    "ciris-server==0.5.131 (from versions: 0.5.165, 0.5.166, 0.5.167, 0.5.169, "
    "0.5.170, 0.5.171, 0.5.172, 0.5.173, 0.5.174)\n"
    "ERROR: No matching distribution found for ciris-server==0.5.131"
)
_NOT_YET_PROPAGATED = (
    "ERROR: Could not find a version that satisfies the requirement "
    "ciris-server==0.5.176 (from versions: 0.5.169, 0.5.170, 0.5.171)\n"
    "ERROR: No matching distribution found for ciris-server==0.5.176"
)


def test_retention_eviction_is_not_retried(tool):
    """Index holds ONLY newer versions ⇒ the pin aged out. Fail fast."""
    assert tool._is_propagation_race(_EVICTED, _SERVER_PINS) is False


def test_retention_eviction_names_itself_in_the_error(tool):
    report = tool._eviction_report(_EVICTED, _SERVER_PINS)
    assert report and "ciris-server==0.5.131" in report
    assert "retention window" in report, report


def test_pin_newer_than_the_index_is_still_a_race(tool):
    """Index holds only OLDER versions ⇒ our publish hasn't landed here yet."""
    assert tool._is_propagation_race(
        _NOT_YET_PROPAGATED, {"ciris-server": "0.5.176"}) is True
    assert tool._eviction_report(
        _NOT_YET_PROPAGATED, {"ciris-server": "0.5.176"}) is None


def test_no_from_versions_list_stays_a_race(tool):
    """Without pip's inventory there is nothing to compare — keep retrying."""
    out = "ERROR: No matching distribution found for ciris-server==0.5.131"
    assert tool._is_propagation_race(out, _SERVER_PINS) is True


def test_from_versions_none_stays_a_race(tool):
    """`(from versions: none)` says nothing about ordering."""
    out = ("ERROR: Could not find a version that satisfies the requirement "
           "ciris-server==0.5.131 (from versions: none)")
    assert tool._is_propagation_race(out, _SERVER_PINS) is True


def test_load_pins_reads_stack(tool, tmp_path):
    m = tmp_path / "current.yaml"
    m.write_text(
        "stack:\n"
        '  ciris-persist: "5.5.5"\n'
        '  ciris-edge: "2.2.2"\n'
    )
    pins = tool.load_pins(str(m))
    assert pins == {"ciris-persist": "5.5.5", "ciris-edge": "2.2.2"}
    # versions are strings (so f"{pkg}=={ver}" is exact, never 5.5 → "5.5")
    assert all(isinstance(v, str) for v in pins.values())


def test_real_matrix_resolves_to_string_versions(tool):
    """The live matrix parses and every pin is a concrete string version."""
    root = Path(__file__).resolve().parent.parent
    pins = tool.load_pins(str(root / "matrices" / "current.yaml"))
    assert pins, "no pins parsed from matrices/current.yaml"
    for pkg, ver in pins.items():
        assert pkg.startswith("ciris-"), pkg
        assert isinstance(ver, str) and ver[0].isdigit(), (pkg, ver)


# ─── the git-tag channel ──────────────────────────────────────────────

_MATRIX = (
    "stack:\n"
    '  ciris-server: "0.5.176"\n'
    '  ciris-verify: "13.3.1"\n'
    "substrate:\n"
    "  ciris-persist:\n"
    '    repo: "https://github.com/CIRISAI/CIRISPersist"\n'
    '    tag: "v32.3.0"\n'
    '    sha: "5d1cd36e3d9fd8131cfc38ff4b023667a8d42b6d"\n'
    "  ciris-edge:\n"
    '    repo: "https://github.com/CIRISAI/CIRISEdge"\n'
    '    tag: "v17.4.1"\n'
    '    sha: "abee3686e2ee5f52282619f5fbce7771d126544a"\n'
)


@pytest.fixture
def matrix_file(tmp_path):
    m = tmp_path / "current.yaml"
    m.write_text(_MATRIX)
    return str(m)


def test_load_substrate_builds_git_specs(tool, matrix_file):
    assert tool.load_substrate(matrix_file) == {
        "ciris-persist": "git+https://github.com/CIRISAI/CIRISPersist@5d1cd36e3d9fd8131cfc38ff4b023667a8d42b6d",
        "ciris-edge": "git+https://github.com/CIRISAI/CIRISEdge@abee3686e2ee5f52282619f5fbce7771d126544a",
    }


@pytest.mark.parametrize("entry, label", [
    ('    repo: "https://github.com/CIRISAI/CIRISPersist"\n',
     "no tag and no sha"),
    ('    repo: "https://github.com/CIRISAI/CIRISPersist"\n'
     '    tag: "v32.3.0"\n',
     "tag without sha — would reinstall from a mutable ref"),
    ('    repo: "https://github.com/CIRISAI/CIRISPersist"\n'
     '    sha: "5d1cd36e3d9fd8131cfc38ff4b023667a8d42b6d"\n',
     "sha without tag — nothing a human can read"),
])
def test_incomplete_substrate_member_is_a_hard_error(tool, tmp_path, entry, label):
    """A half-written substrate entry must not resolve to a floating ref."""
    m = tmp_path / "current.yaml"
    m.write_text("substrate:\n  ciris-persist:\n" + entry)
    with pytest.raises(SystemExit):
        tool.load_substrate(str(m))


@pytest.mark.parametrize("sha, label", [
    ("5d1cd36", "abbreviated"),
    ("5ee7ce3aa8ce8ffd2a0da8692cbb409fb876f0b0", "the TAG OBJECT's id"),
])
def test_sha_must_be_a_full_commit_id(tool, tmp_path, sha, label):
    """pip caches a VCS build only on an immutable full-length ref.

    The tag-object case is the live footgun: `git ls-remote <repo>
    refs/tags/v32.3.0` prints the annotated tag's own id, and the commit only
    comes back from the `^{}` dereference. Both are 40 hex chars, so only the
    upstream check (--verify-refs) can tell them apart — but the length rule
    still catches the abbreviated paste.
    """
    m = tmp_path / "current.yaml"
    m.write_text("substrate:\n  ciris-persist:\n"
                 '    repo: "https://github.com/CIRISAI/CIRISPersist"\n'
                 '    tag: "v32.3.0"\n'
                 f'    sha: "{sha}"\n')
    if len(sha) != 40:
        with pytest.raises(SystemExit):
            tool.load_substrate(str(m))
    else:
        # Well-formed, so parsing accepts it — this is exactly the case that
        # needs the network check, not a local one.
        assert tool.load_substrate(str(m))["ciris-persist"].endswith(sha)


def test_live_matrix_substrate_is_fully_specified(tool):
    """The real matrix carries repo + tag + full sha for every git member."""
    root = Path(__file__).resolve().parent.parent
    specs = tool.load_substrate(str(root / "matrices" / "current.yaml"))
    assert specs, "no substrate members parsed from matrices/current.yaml"
    for pkg, spec in specs.items():
        assert spec.startswith("git+https://"), (pkg, spec)
        assert tool._SHA_RE.match(spec.rsplit("@", 1)[1]), (pkg, spec)


def test_resolve_covers_both_channels(tool, matrix_file):
    """The whole coherent set installs — not just the half that's on PyPI."""
    args, pins = tool.resolve_install_args(matrix_file)
    assert args == [
        "ciris-server==0.5.176",
        "ciris-verify==13.3.1",
        "git+https://github.com/CIRISAI/CIRISPersist@5d1cd36e3d9fd8131cfc38ff4b023667a8d42b6d",
        "git+https://github.com/CIRISAI/CIRISEdge@abee3686e2ee5f52282619f5fbce7771d126544a",
    ]
    # Only the PyPI half is subject to the propagation race.
    assert pins == {"ciris-server": "0.5.176", "ciris-verify": "13.3.1"}


def test_under_test_member_is_skipped(tool, matrix_file):
    """A consumer's own artifact must not be shadowed by the pinned version.

    CIRISEdge's tag-run supplies a built `ciris_edge` wheel; installing
    the matrix's edge alongside it would mean the cell tests the pin, green,
    while never touching the artifact under test.
    """
    args, _ = tool.resolve_install_args(matrix_file, under_test="ciris-edge")
    assert not any("CIRISEdge" in a for a in args), args
    assert "git+https://github.com/CIRISAI/CIRISPersist@5d1cd36e3d9fd8131cfc38ff4b023667a8d42b6d" in args


def test_under_test_matches_across_name_spelling(tool, matrix_file):
    """`ciris_edge` and `ciris-edge` name the same member."""
    args, _ = tool.resolve_install_args(matrix_file, under_test="ciris_edge")
    assert not any("CIRISEdge" in a for a in args), args


def test_override_replaces_a_matrix_member(tool, matrix_file):
    """Branch fire-tests pin a sibling to an untagged ref (see the workflow)."""
    ref = "git+https://github.com/CIRISAI/CIRISPersist.git@v4.0-das"
    args, pins = tool.resolve_install_args(
        matrix_file, overrides={"ciris-persist": ref})
    assert ref in args
    assert "git+https://github.com/CIRISAI/CIRISPersist@5d1cd36e3d9fd8131cfc38ff4b023667a8d42b6d" not in args
    # An overridden PyPI member drops out of the race set — the pinned version
    # it would have retried for is no longer what's being installed.
    args, pins = tool.resolve_install_args(
        matrix_file, overrides={"ciris-verify": "ciris-verify==13.0.0"})
    assert "ciris-verify" not in pins


def test_override_loses_to_the_under_test_artifact(tool, matrix_file):
    args, _ = tool.resolve_install_args(
        matrix_file,
        under_test="ciris-edge",
        overrides={"ciris-edge": "git+https://github.com/CIRISAI/CIRISEdge@vX"},
    )
    assert not any("CIRISEdge" in a for a in args), args


def test_git_member_failure_is_never_a_propagation_race(tool, matrix_file):
    """A bad tag or a failed cargo build must fail fast, not burn the budget.

    Git refs don't propagate through a CDN. If a substrate member leaked into
    the race set, a typo'd tag would retry six times with linear backoff before
    reporting a failure it could have reported immediately.
    """
    _, pins = tool.resolve_install_args(matrix_file)
    output = ("ERROR: Could not find a version that satisfies the requirement "
              "ciris-persist (from versions: none)")
    assert tool._is_propagation_race(output, pins) is False
