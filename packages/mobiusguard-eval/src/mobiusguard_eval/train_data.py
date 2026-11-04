"""Build the v0.2 classifier's training set from the training ledger (decision 0012).

The rules, in order:

1. Exact repeats inside a source are dropped, and so are texts labelled both ways.
2. Each source is pre-capped at three times its cap, chosen by hash, to bound the work.
3. Near duplicates (MinHash, the suite's settings) are clustered together with every text
   of the evaluation suite. A training text is dropped when its cluster holds a suite text
   (the suite stays held out) or texts of both labels (a WildChat message that is really a
   jailbreak, say). Every such drop is written out for review.
4. Each source is capped, chosen by hash, so no single game or style dominates.
5. Whole clusters go to ``train`` or ``val`` (10%), so near copies never straddle the two.
   Model selection uses ``val``; the suite scores only the final candidates.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from collections.abc import Callable, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .checkpoint import fingerprint
from .dedup import clusters
from .items import Item, write_jsonl
from .ledger import Source
from .suite import dedupe

CAP = 20_000
VAL_FRACTION = 0.1
BUILD = 1  # bump when the rules change


def _unit(key: str) -> float:
    return int.from_bytes(hashlib.sha256(key.encode()).digest()[:8], "big") / 2**64


def _by_hash(items: Sequence[Item]) -> list[Item]:
    return sorted(items, key=lambda it: hashlib.sha256(it.id.encode()).hexdigest())


def suite_key(suite: Sequence[Item]) -> str:
    """Which suite was held out: a hash of its item IDs."""
    return hashlib.sha256("\n".join(sorted(it.id for it in suite)).encode()).hexdigest()


def build_key(sources: Sequence[Source], suite_ids: str, cap: int) -> str:
    files = {s.id: [f"{f.location}/{f.path}@{f.revision}" for f in s.files] for s in sources}
    return fingerprint({"files": files, "suite": suite_ids, "cap": cap, "build": BUILD})


def is_built(out: Path, key: str) -> bool:
    summary = out / "summary.json"
    if not summary.exists() or not (out / "train.jsonl").exists():
        return False
    return json.loads(summary.read_text()).get("build_key") == key


def build(
    sources: Sequence[Source],
    loaded: dict[str, list[Item]],
    suite: Sequence[Item],
    out: Path,
    *,
    cap: int = CAP,
    log: Callable[[str], None] = lambda _m: None,
) -> dict[str, Any]:
    """Write ``train.jsonl``, ``val.jsonl``, ``dropped.jsonl`` and ``summary.json``."""
    suite_ids = suite_key(suite)
    counts: dict[str, Counter[str]] = defaultdict(Counter)
    for s in sources:
        counts[s.id]["parsed"] = len(loaded[s.id])

    items, _ = dedupe(it for s in sources for it in loaded[s.id])
    by_source: dict[str, list[Item]] = defaultdict(list)
    for it in items:
        by_source[it.source].append(it)
    pre: list[Item] = []
    for s in sources:
        mine = by_source[s.id]
        counts[s.id]["after_dedupe"] = len(mine)
        pre += _by_hash(mine)[: 3 * cap]

    log(f"train-data: clustering {len(pre):,} training texts with {len(suite):,} suite texts")
    idx = clusters([it.text for it in suite] + [it.text for it in pre])
    n_suite = len(suite)
    has_suite: set[int] = set(idx[:n_suite])
    labels: dict[int, set[int]] = defaultdict(set)
    for i, it in enumerate(pre):
        labels[idx[n_suite + i]].add(it.label)
    suite_of: dict[int, str] = {}
    for i, it in enumerate(suite):
        suite_of.setdefault(idx[i], it.id)

    kept: list[tuple[Item, int]] = []
    dropped: list[dict[str, Any]] = []
    for i, it in enumerate(pre):
        c = idx[n_suite + i]
        reason = "near_suite" if c in has_suite else "both_labels" if len(labels[c]) > 1 else ""
        if reason:
            counts[it.source][reason] += 1
            near = suite_of.get(c, "")
            dropped.append({"id": it.id, "source": it.source, "label": it.label,
                            "reason": reason, "near": near, "text": it.text})  # fmt: skip
        else:
            kept.append((it, c))

    final: list[Item] = []
    per_source: dict[str, list[tuple[Item, int]]] = defaultdict(list)
    for it, c in kept:
        per_source[it.source].append((it, c))
    for s in sources:
        mine = sorted(per_source[s.id], key=lambda p: hashlib.sha256(p[0].id.encode()).hexdigest())
        for it, c in mine[:cap]:
            # Name a cluster by its first training member's ID: stable across rebuilds.
            final.append(replace(it, cluster=str(c)))
    first_id: dict[str, str] = {}
    for it in final:
        first_id.setdefault(it.cluster, it.id)
    final = [
        replace(it, cluster=first_id[it.cluster],
                split="val" if _unit(first_id[it.cluster]) < VAL_FRACTION else "train")
        for it in final
    ]  # fmt: skip
    final.sort(key=lambda it: it.id)
    for it in final:
        counts[it.source][it.split] += 1

    write_jsonl(out / "train.jsonl", (it for it in final if it.split == "train"))
    write_jsonl(out / "val.jsonl", (it for it in final if it.split == "val"))
    with (out / "dropped.jsonl").open("w", encoding="utf-8") as f:
        for d in dropped:
            f.write(json.dumps(d, ensure_ascii=False) + "\n")

    summary: dict[str, Any] = {
        "built": datetime.now(UTC).isoformat(timespec="seconds"),
        "build_key": build_key(sources, suite_ids, cap),
        "mobiusguard_eval": __version__,
        "cap": cap,
        "suite_ids_sha256": suite_ids,
        "items": {
            "train": sum(it.split == "train" for it in final),
            "val": sum(it.split == "val" for it in final),
        },
        "labels": Counter(f"{'attack' if it.label else 'benign'}/{it.split}" for it in final),
        "languages": Counter(it.lang for it in final),
        "sources": {
            s.id: {
                "licence": s.licence,
                "role": s.role,
                "files": [f"{f.location}/{f.path}@{f.revision}" for f in s.files],
                "counts": dict(counts[s.id]),
            }
            for s in sources
        },
        "ids_sha256": hashlib.sha256("\n".join(it.id for it in final).encode()).hexdigest(),
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary
