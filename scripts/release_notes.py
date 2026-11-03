"""Print the release notes for a version: its CHANGELOG.md section, then how to install it.

Usage:  python scripts/release_notes.py 0.1.0 > notes.md   (used by the Release workflow)
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

CHANGELOG = Path(__file__).resolve().parent.parent / "CHANGELOG.md"


def notes(version: str, changelog: str) -> str:
    m = re.search(rf"^## {re.escape(version)}\b[^\n]*\n(.*?)(?=^## |\Z)", changelog, re.M | re.S)
    if m is None:
        raise SystemExit(f"CHANGELOG.md has no section for {version}")
    return (
        m.group(1).strip()
        + "\n\n## Install\n\n```sh\n"
        + f"pip install mobiusguard=={version}          # the proxy\n"
        + f"pip install mobiusguard-redact=={version}   # the streaming redactor on its own\n"
        + "```\n\nThe wheels attached here are the ones on PyPI; check where they were built with\n"
        + "`gh attestation verify <file> -R gantrly/mobius-guard`.\n"
    )


if __name__ == "__main__":
    print(notes(sys.argv[1], CHANGELOG.read_text()))
