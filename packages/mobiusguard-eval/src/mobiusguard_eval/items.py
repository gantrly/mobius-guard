"""The unit of evaluation: one text with a label and where it came from."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

Label = Literal[0, 1]  # 1 = attack, 0 = benign
Split = Literal["dev", "test", ""]

ATTACK: Label = 1
BENIGN: Label = 0


@dataclass(frozen=True, slots=True)
class Item:
    """One evaluation input.

    ``id`` is ``<source>:<content hash>``, so it stays the same when a dataset is re-read.
    ``family`` is the source ID, or ``obf:<transform>`` for an obfuscated copy of an attack.
    ``cluster`` and ``split`` are set when the suite is built (see :mod:`.suite`).
    """

    id: str
    text: str
    label: Label
    source: str
    family: str
    lang: str = "und"
    split: Split = ""
    cluster: str = ""
    meta: dict[str, str] = field(default_factory=dict[str, str])

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)

    @staticmethod
    def from_dict(d: dict[str, Any]) -> Item:
        return Item(**d)


def normalize(text: str) -> str:
    """The form used for duplicate detection: NFKC, case-folded, whitespace collapsed."""
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())


def content_hash(text: str) -> str:
    return hashlib.sha256(normalize(text).encode()).hexdigest()[:16]


def make_item(
    text: str, label: Label, source: str, *, lang: str = "und", meta: dict[str, str] | None = None
) -> Item:
    return Item(
        id=f"{source}:{content_hash(text)}",
        text=text,
        label=label,
        source=source,
        family=source,
        lang=lang,
        meta=meta or {},
    )


def write_jsonl(path: Path, items: Iterable[Item]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as f:
        for it in items:
            f.write(it.to_json() + "\n")
            n += 1
    return n


def read_jsonl(path: Path) -> Iterator[Item]:
    with path.open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                yield Item.from_dict(json.loads(line))
