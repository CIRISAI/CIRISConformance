"""
Unit coverage for the pin-install retry helper (`tools/install_pins.py`).

All three CI install steps (core conformance cells, chaquopy bundle, bench)
route through this helper so a same-minute matrix bump that races PyPI/CDN
propagation retries instead of going red — while a genuine pin conflict still
fails fast. The value is entirely in the classifier, so we pin it here.
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
