"""The provenance ledger: every dataset, where it comes from, and who trained on it.

Decision 0006, rule 1. A source is registered with its licence, the exact revision we
read, and the known models trained on it, so a table can mark contaminated comparisons.
Data is never committed: each source knows how to fetch its pinned files into a local
cache and turn them into :class:`~mobiusguard_eval.items.Item` objects.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .items import Item

Role = Literal["attack", "benign", "mixed", "calibration"]


@dataclass(frozen=True, slots=True)
class Remote:
    """One file to fetch. ``sha256`` is required for plain URLs; Hugging Face pins by
    ``revision`` (a commit hash), which already fixes the content."""

    kind: Literal["hf_dataset", "url"]
    location: str  # repo ID for hf_dataset, URL for url
    path: str = ""  # file inside the repo (hf_dataset)
    revision: str = ""
    sha256: str = ""


@dataclass(frozen=True, slots=True)
class Source:
    id: str
    title: str
    homepage: str
    licence: str  # SPDX ID, or a short description when there is none
    role: Role
    files: tuple[Remote, ...]
    parse: Callable[[list[Path]], Iterable[Item]]
    languages: tuple[str, ...] = ("en",)
    trained_on_by: tuple[str, ...] = ()  # detector names known to have trained on it
    redistributable: bool = True
    notes: str = ""


LEDGER: dict[str, Source] = {}


def register(source: Source) -> Source:
    if source.id in LEDGER:
        raise ValueError(f"duplicate source {source.id}")
    for f in source.files:
        if f.kind == "url" and not f.sha256:
            raise ValueError(f"{source.id}: url files need a sha256")
        if f.kind == "hf_dataset" and len(f.revision) != 40:
            raise ValueError(f"{source.id}: pin Hugging Face files to a commit hash")
    LEDGER[source.id] = source
    return source
