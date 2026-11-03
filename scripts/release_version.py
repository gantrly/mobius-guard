"""Print the version to release from this checkout, or nothing if it is not ready.

Ready means: the three packages carry the same ``__version__`` and CHANGELOG.md has a dated
section for it (``## 0.1.0 (2026-11-03)``). Used by the Tag release workflow.

Usage:  python scripts/release_version.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGES = {
    "mobiusguard-redact": "mobiusguard_redact",
    "mobiusguard": "mobiusguard",
    "mobiusguard-eval": "mobiusguard_eval",
}


def versions(root: Path = ROOT) -> dict[str, str]:
    out: dict[str, str] = {}
    for dist, mod in PACKAGES.items():
        text = (root / "packages" / dist / "src" / mod / "__init__.py").read_text()
        m = re.search(r'^__version__ = "([^"]+)"', text, re.M)
        if m is None:
            raise SystemExit(f"{dist}: no __version__")
        out[dist] = m.group(1)
    return out


def releasable(root: Path = ROOT) -> str:
    found = versions(root)
    if len(set(found.values())) != 1:
        raise SystemExit(f"the packages disagree on the version: {found}")
    (v,) = set(found.values())
    changelog = (root / "CHANGELOG.md").read_text()
    if not re.search(rf"^## {re.escape(v)} \(\d{{4}}-\d{{2}}-\d{{2}}\)$", changelog, re.M):
        print(f"{v}: CHANGELOG.md has no dated section for it yet; not releasing", file=sys.stderr)
        return ""
    return v


if __name__ == "__main__":
    print(releasable())
