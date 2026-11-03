"""scripts/release_version.py decides when merging to main tags a release."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[3]


def _script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "release_version", ROOT / "scripts/release_version.py"
    )
    assert spec
    assert spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _tree(tmp: Path, versions: tuple[str, str, str], changelog: str) -> Path:
    for (dist, mod), v in zip(_script().PACKAGES.items(), versions, strict=True):
        d = tmp / "packages" / dist / "src" / mod
        d.mkdir(parents=True)
        (d / "__init__.py").write_text(f'"""x"""\n\n__version__ = "{v}"\n')
    (tmp / "CHANGELOG.md").write_text(changelog)
    return tmp


def test_a_dated_changelog_section_makes_it_releasable(tmp_path: Path) -> None:
    root = _tree(
        tmp_path, ("0.2.0", "0.2.0", "0.2.0"), "# Changelog\n\n## 0.2.0 (2026-12-01)\n\n- x\n"
    )
    assert _script().releasable(root) == "0.2.0"


def test_an_undated_section_is_not_released(tmp_path: Path) -> None:
    root = _tree(
        tmp_path, ("0.2.0", "0.2.0", "0.2.0"), "# Changelog\n\n## 0.2.0 (not yet released)\n"
    )
    assert _script().releasable(root) == ""


def test_packages_that_disagree_stop_the_release(tmp_path: Path) -> None:
    root = _tree(tmp_path, ("0.2.0", "0.2.0", "0.1.0"), "## 0.2.0 (2026-12-01)\n")
    with pytest.raises(SystemExit, match="disagree"):
        _script().releasable(root)


def test_this_repository_is_consistent() -> None:
    v = _script().releasable(ROOT)
    assert v in ("", _script().versions(ROOT)["mobiusguard"])
