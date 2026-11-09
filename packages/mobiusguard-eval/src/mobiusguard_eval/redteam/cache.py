"""A classifier score cache for red-team runs (decision 0014).

Each distinct text is scored once. The inner scorer still sees one text at a time when it
was built that way (the proxy's ``batch_size=1``), so a cached score is exactly the score
the text would get again: the cache changes how long a run takes, not its result.

Scores are kept in memory by the text's SHA-256 and appended to a JSONL file, which a
resumed run reads back. A last line cut short by a crash is skipped.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import IO, Any

from mobiusguard.guard import Score, Scorer

FLUSH_EVERY = 500


def text_key(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _score(v: Any) -> Score:
    if isinstance(v, list):
        a, h = v  # pyright: ignore[reportUnknownVariableType]
        return (float(a), float(h))  # pyright: ignore[reportUnknownArgumentType]
    return float(v)


class ScoreCache:
    def __init__(
        self, inner: Scorer, path: Path | None = None, *, read: Iterable[Path] = ()
    ) -> None:
        self.inner = inner
        self.scores: dict[str, Score] = {}
        self.hits = 0
        self.misses = 0
        for p in [*read, *([path] if path else [])]:
            self._load(p)
        self._file: IO[str] | None = None
        self._pending = 0
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._file = path.open("a", encoding="utf-8")

    def _load(self, path: Path) -> None:
        if not path.exists():
            return
        with path.open(encoding="utf-8") as f:
            for line in f:
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                self.scores[str(row["k"])] = _score(row["s"])

    def __call__(self, texts: Sequence[str]) -> list[Score]:
        keys = [text_key(t) for t in texts]
        first: dict[str, int] = {}
        for i, k in enumerate(keys):
            if k not in self.scores:
                first.setdefault(k, i)
        todo = list(first.values())  # each new text once, even if it repeats in this call
        self.hits += len(keys) - len(todo)
        self.misses += len(todo)
        if todo:
            new = self.inner([texts[i] for i in todo])
            for i, s in zip(todo, new, strict=True):
                self.scores[keys[i]] = s
                if self._file is not None:
                    value = list(s) if isinstance(s, tuple) else s
                    self._file.write(json.dumps({"k": keys[i], "s": value}) + "\n")
                    self._pending += 1
            if self._pending >= FLUSH_EVERY:
                self.flush()
        return [self.scores[k] for k in keys]

    def flush(self) -> None:
        if self._file is not None:
            self._file.flush()
            self._pending = 0

    def close(self) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None
