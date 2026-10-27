"""Checkpoints: save finished work as it happens, so a run resumes instead of restarting.

A checkpoint is an append-only JSONL file. Its first line is a *key*: everything that
decides the result (detector and model revision, the suite's item IDs, the patterns). The
other lines are finished units of work. Opening a checkpoint whose key differs sets the
old file aside (``.stale``) and starts afresh, so saved work is never reused for a
different question. A last line cut short by a crash is ignored, and its unit redone.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, cast


def fingerprint(value: Any) -> str:
    """A stable hash of JSON-able data (keys sorted)."""
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


class Checkpoint:
    def __init__(self, path: Path, key: dict[str, Any]) -> None:
        self.path = path
        self.key = key
        self.key_hash = fingerprint(key)
        self.units: dict[str, Any] = {}
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and not self._load():
            path.replace(path.with_suffix(path.suffix + ".stale"))
        if not path.exists():
            with path.open("w", encoding="utf-8") as f:
                f.write(json.dumps({"checkpoint": self.key_hash, "key": key}) + "\n")

    def _load(self) -> bool:
        """Read saved units; False when the file belongs to a different key."""
        with self.path.open(encoding="utf-8") as f:
            lines = f.read().splitlines()
        try:
            header = cast("dict[str, Any]", json.loads(lines[0])) if lines else {}
        except json.JSONDecodeError:
            return False
        if header.get("checkpoint") != self.key_hash:
            return False
        for line in lines[1:]:
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue  # cut short by a crash: that unit is done again
            self.units[row["unit"]] = row["data"]
        return True

    def __contains__(self, unit: str) -> bool:
        return unit in self.units

    def add(self, unit: str, data: Any) -> None:
        """Record a finished unit; it is on disk before this returns."""
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"unit": unit, "data": data}, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())
        self.units[unit] = data


def write_atomic(path: Path, text: str) -> None:
    """Write a file so that readers see the old or the new content, never half of it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)
