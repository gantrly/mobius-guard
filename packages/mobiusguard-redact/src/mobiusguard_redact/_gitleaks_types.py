"""Plain data types for the generated gitleaks rules (see scripts/import_gitleaks.py)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True, slots=True)
class Allowlist:
    """A gitleaks allowlist reduced to checks that make sense on streamed text."""

    target: Literal["secret", "match"]
    regexes: tuple[str, ...]
    stopwords: tuple[str, ...]  # lower-case; matched as substrings of the secret
    require_all: bool  # gitleaks condition = "AND"


@dataclass(frozen=True, slots=True)
class RuleData:
    id: str
    description: str
    regex: str
    entropy: float  # 0.0 = no entropy check
    secret_group: int  # 0 = first non-empty capture group, else the whole match
    allowlists: tuple[Allowlist, ...]
