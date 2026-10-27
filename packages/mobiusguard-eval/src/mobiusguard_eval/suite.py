"""Build an evaluation suite: load sources, remove duplicates, split, add obfuscated attacks.

Splits (decision 0009):

- Thresholds are set on the ``dev`` half of the *calibration* source (ordinary chat), so
  every hard benign set and every attack set is reported out of sample.
- Everything else is ``test``. Nothing in v0.1 is trained or tuned on these sets; the
  TF-IDF baseline trains leave-one-source-out (see :mod:`.detectors.tfidf`).
- A near-duplicate cluster lands in one split as a whole, decided by a hash of the cluster,
  so the split doesn't depend on load order.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .checkpoint import fingerprint
from .dedup import BANDS, JACCARD, N_PERM, SHINGLE, clusters
from .items import ATTACK, Item, normalize, read_jsonl, write_jsonl
from .ledger import LEDGER, Source
from .obfuscate import TRANSFORMS, obfuscate

DEV_FRACTION = 0.5  # of the calibration source
OBFUSCATE_PER_TRANSFORM = 1000


def _unit(key: str) -> float:
    """A stable number in [0, 1) for a key."""
    return int.from_bytes(hashlib.sha256(key.encode()).digest()[:8], "big") / 2**64


def dedupe(items: Iterable[Item]) -> tuple[list[Item], dict[str, int]]:
    """Drop repeats inside a source, and texts labelled both attack and benign anywhere."""
    seen: set[str] = set()
    kept: list[Item] = []
    dropped = Counter[str]()
    for it in items:
        if it.id in seen:
            dropped["duplicate_in_source"] += 1
            continue
        seen.add(it.id)
        kept.append(it)
    labels: dict[str, set[int]] = defaultdict(set)
    for it in kept:
        labels[normalize(it.text)].add(it.label)
    out = [it for it in kept if len(labels[normalize(it.text)]) == 1]
    dropped["conflicting_labels"] = len(kept) - len(out)
    return out, dict(dropped)


def assign_splits(items: Sequence[Item], calibration: set[str]) -> list[Item]:
    idx = clusters([it.text for it in items])
    members: dict[int, list[int]] = defaultdict(list)
    for i, c in enumerate(idx):
        members[c].append(i)
    out = list(items)
    for c, group in members.items():
        cid = items[c].id
        has_cal = any(items[i].source in calibration for i in group)
        split = "dev" if has_cal and _unit(cid) < DEV_FRACTION else "test"
        for i in group:
            out[i] = replace(items[i], cluster=cid, split=split)
    return out


def obfuscated(items: Sequence[Item], per_transform: int = OBFUSCATE_PER_TRANSFORM) -> list[Item]:
    """Obfuscated copies of up to ``per_transform`` test attacks, spread across sources."""
    by_source: dict[str, list[Item]] = defaultdict(list)
    for it in sorted(items, key=lambda i: _unit(i.id)):
        if it.label == ATTACK and it.split == "test" and not it.family.startswith("obf:"):
            by_source[it.source].append(it)
    picked: list[Item] = []
    queues = [list(v) for _, v in sorted(by_source.items())]
    while len(picked) < per_transform and any(queues):
        for q in queues:
            if q and len(picked) < per_transform:
                picked.append(q.pop(0))
    return [obfuscate(it, name) for name in TRANSFORMS for it in picked]


def build_key(sources: Sequence[Source]) -> str:
    """Everything that decides a suite's contents: pinned files and the build settings."""
    return fingerprint(
        {
            "sources": [
                [s.id, [[f.location, f.path, f.revision, f.sha256] for f in s.files]]
                for s in sources
            ],
            "dev_fraction": DEV_FRACTION,
            "obfuscate": [OBFUSCATE_PER_TRANSFORM, sorted(TRANSFORMS)],
            "dedup": [SHINGLE, N_PERM, BANDS, JACCARD],
            "mobiusguard_eval": __version__,
        }
    )


def is_built(sources: Sequence[Source], out: Path) -> bool:
    """Whether ``out`` already holds a suite built from these sources and settings."""
    manifest = out / "manifest.json"
    if not manifest.exists() or not (out / "items.jsonl").exists():
        return False
    return json.loads(manifest.read_text()).get("build_key") == build_key(sources)


def build(sources: Sequence[Source], loaded: dict[str, list[Item]], out: Path) -> dict[str, Any]:
    """Write ``items.jsonl`` and ``manifest.json`` into ``out``; return the manifest."""
    raw = [it for s in sources for it in loaded[s.id]]
    items, dropped = dedupe(raw)
    calibration = {s.id for s in sources if s.role == "calibration"}
    items = assign_splits(items, calibration)
    items += obfuscated(items)
    items.sort(key=lambda it: it.id)
    write_jsonl(out / "items.jsonl", items)

    per_source: dict[str, Any] = {}
    for s in sources:
        mine = [it for it in items if it.source == s.id and not it.family.startswith("obf:")]
        per_source[s.id] = {
            "licence": s.licence,
            "role": s.role,
            "files": [f"{f.location}/{f.path}@{f.revision or f.sha256[:12]}" for f in s.files],
            "items": Counter(f"{'attack' if it.label else 'benign'}/{it.split}" for it in mine),
            "ids_sha256": hashlib.sha256("\n".join(it.id for it in mine).encode()).hexdigest(),
        }
    manifest: dict[str, Any] = {
        "built": datetime.now(UTC).isoformat(timespec="seconds"),
        "build_key": build_key(sources),
        "mobiusguard_eval": __version__,
        "dropped": dropped,
        "items": len(items),
        "families": Counter(it.family for it in items),
        "sources": per_source,
        "ids_sha256": hashlib.sha256("\n".join(it.id for it in items).encode()).hexdigest(),
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def load_suite(path: Path) -> list[Item]:
    return list(read_jsonl(path / "items.jsonl"))


def ledger_sources(ids: Iterable[str] | None = None) -> list[Source]:
    from . import sources as _  # noqa: F401 - registers the built-in sources

    return [LEDGER[i] for i in ids] if ids else list(LEDGER.values())
