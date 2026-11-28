"""Honest screening: candidates are compared on one half of the suite's test items, and the
other half is used once, for the release decision (ROADMAP B3).

From 2026-11-23 to 25, about ten candidates were compared on the whole suite, which slowly
turns the suite into a tuning set (decision 0006 warns against that). Here the suite's test
items are split by near-duplicate cluster, so near copies, and an attack's disguised copies,
stay in the same half:

- ``screen``: every comparison between candidates;
- ``final``: the release check only, once per release candidate.

Both halves keep the whole calibration half (thresholds are unchanged) and the developer
check's eight fixed messages. The final half's item IDs are hashed into its manifest, so a
later change to the split is visible.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from .items import Item, read_jsonl, write_jsonl

SALT = "mobius-guard screening split v1"
BOTH = frozenset({"dev_check"})  # fixed checks, in both halves


def half(it: Item) -> str:
    # A source that must keep two things apart sets the half itself (bipia_embedded: no
    # document or attack in both halves).
    if it.meta.get("half") in ("screen", "final"):
        return it.meta["half"]
    key = it.cluster or it.id
    return (
        "screen" if int(hashlib.sha256(f"{SALT}:{key}".encode()).hexdigest(), 16) % 2 else "final"
    )


def split_suite(suite: Path, out: Path) -> dict[str, Any]:
    items = list(read_jsonl(suite / "items.jsonl"))
    parts: dict[str, list[Item]] = {"screen": [], "final": []}
    for it in items:
        if it.split != "test" or it.source in BOTH:
            parts["screen"].append(it)
            parts["final"].append(it)
        else:
            parts[half(it)].append(it)
    manifest: dict[str, Any] = {"from": str(suite), "salt": SALT}
    for name, part in parts.items():
        write_jsonl(out / name / "items.jsonl", part)
        test = sorted(it.id for it in part if it.split == "test")
        manifest[name] = {
            "items": len(part),
            "test_items": len(test),
            "test_by_family": dict(sorted(Counter(it.family for it in part
                                                  if it.split == "test").items())),
            "test_ids_sha256": hashlib.sha256("\n".join(test).encode()).hexdigest(),
        }  # fmt: skip
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest
