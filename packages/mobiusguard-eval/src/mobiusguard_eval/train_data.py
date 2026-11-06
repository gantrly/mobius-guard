"""Build the v0.2 classifier's training set from the training ledger (decision 0012).

The rules, in order:

1. Exact repeats inside a source are dropped, and so are texts labelled both ways.
2. Each source is pre-capped at three times its cap, chosen by hash, to bound the work.
3. Near duplicates (MinHash, the suite's settings) are clustered together with every text
   of the evaluation suite. A training text is dropped when its cluster holds a suite text
   (the suite stays held out) or texts of both labels (a WildChat message that is really a
   jailbreak, say). MinHash misses a suite text reused inside a longer one (a jailbreak
   template with a new question attached), so 8-word shingles catch those: a training text
   is also dropped when half its shingles occur in the suite, or it holds half of some
   suite text's shingles. A near-duplicate cluster whose attack labels, or known harmful
   labels, disagree is dropped too, unless all its sources form one declared contrast pair
   (CONTRAST: a harmful request and its harmless twin, an injected document and the same
   document clean), whose near-identical texts with opposite labels are the point.
   Every drop is written out for review.
4. Each source is capped, chosen by hash, so no single game or style dominates. Twins
   (an injected document and its clean version, ``meta["pair"]``) are ranked together,
   so a cap keeps both or neither.
5. Whole clusters go to ``train`` or ``val`` (10%), so near copies never straddle the two;
   twins count as one cluster, so a clean twin never sits in ``val`` while its injected
   version is in ``train``.
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
from .items import Item, normalize, write_jsonl
from .ledger import Source
from .suite import dedupe

CAP = 20_000
VAL_FRACTION = 0.1
SHINGLE_WORDS = 8
CONTAINMENT = 0.5
BUILD = 6  # bump when the rules change
# Sources whose items are near-identical twins with opposite labels, on purpose.
CONTRAST = (
    frozenset({"jbb_harmful", "jbb_benign"}),
    frozenset({"syn_indirect", "syn_twin"}),
    frozenset({"browsesafe_md"}),
    frozenset({"browsesafe_html"}),
    frozenset({"nemotron_ipi"}),
    frozenset({"rgeada_tool"}),
    frozenset({"coconot"}),
    frozenset({"cse_frr", "cse_mitre"}),
)


def word_shingles(text: str, k: int = SHINGLE_WORDS) -> set[str]:
    words = normalize(text).split()
    return {" ".join(words[i : i + k]) for i in range(len(words) - k + 1)}


def suite_overlap(suite: Sequence[Item], texts: Sequence[str]) -> list[bool]:
    """For each text: does it share most of its word shingles with the suite, or hold most
    of one suite text's? Texts too short for three shingles are left to MinHash."""
    index: dict[str, list[int]] = defaultdict(list)
    sizes: list[int] = []
    for j, it in enumerate(suite):
        sh = word_shingles(it.text)
        sizes.append(len(sh))
        for s in sh:
            index[s].append(j)
    result: list[bool] = []
    for text in texts:
        sh = word_shingles(text)
        if len(sh) < 3:
            result.append(False)
            continue
        hits = [s for s in sh if s in index]
        if len(hits) >= CONTAINMENT * len(sh):
            result.append(True)
            continue
        held = Counter(j for s in hits for j in index[s])
        result.append(any(sizes[j] >= 3 and n >= CONTAINMENT * sizes[j] for j, n in held.items()))
    return result


def _unit(key: str) -> float:
    """A stable number in [0, 1) for a key, for the train/val split. Salted: the cap ranks
    items by an unsalted hash of the same IDs, so without the salt the items a cap keeps
    (the lowest hashes) would all fall below VAL_FRACTION and land in val."""
    return int.from_bytes(hashlib.sha256(f"split:{key}".encode()).digest()[:8], "big") / 2**64


def _rank(it: Item, seed: str) -> tuple[str, str]:
    """The order a cap takes items in: twins share a key, so they stay together. A seed
    draws a different random sample."""
    key = it.meta.get("pair") or it.id
    return hashlib.sha256(f"{seed}:{key}".encode() if seed else key.encode()).hexdigest(), it.id


def _source_cap(source: Source, cap: int) -> int:
    return min(cap, source.cap) if source.cap else cap


def suite_key(suite: Sequence[Item]) -> str:
    """Which suite was held out: a hash of its item IDs."""
    return hashlib.sha256("\n".join(sorted(it.id for it in suite)).encode()).hexdigest()


def build_key(sources: Sequence[Source], suite_ids: str, cap: int, seed: str = "") -> str:
    files = {s.id: [f"{f.location}/{f.path}@{f.revision}" for f in s.files] for s in sources}
    return fingerprint(
        {"files": files, "suite": suite_ids, "cap": cap, "seed": seed, "build": BUILD}
    )


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
    seed: str = "",
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
        pre += sorted(mine, key=lambda it: _rank(it, seed))[: 3 * _source_cap(s, cap)]

    log(f"train-data: clustering {len(pre):,} training texts with {len(suite):,} suite texts")
    idx = clusters([it.text for it in suite] + [it.text for it in pre])
    n_suite = len(suite)
    has_suite: set[int] = set(idx[:n_suite])
    labels: dict[int, set[int]] = defaultdict(set)
    harmful: dict[int, set[str]] = defaultdict(set)
    members: dict[int, set[str]] = defaultdict(set)
    for i, it in enumerate(pre):
        labels[idx[n_suite + i]].add(it.label)
        members[idx[n_suite + i]].add(it.source)
        if h := it.meta.get("harmful", ""):
            harmful[idx[n_suite + i]].add(h)
    suite_of: dict[int, str] = {}
    for i, it in enumerate(suite):
        suite_of.setdefault(idx[i], it.id)

    log("train-data: word-shingle overlap with the suite")
    overlap = suite_overlap(suite, [it.text for it in pre])

    def contrast(c: int) -> bool:
        return any(members[c] <= pair for pair in CONTRAST)

    kept: list[tuple[Item, int]] = []
    dropped: list[dict[str, Any]] = []
    for i, it in enumerate(pre):
        c = idx[n_suite + i]
        reason = (
            "near_suite" if c in has_suite
            else "suite_overlap" if overlap[i]
            else "both_labels" if len(labels[c]) > 1 and not contrast(c)
            else "both_harmful" if len(harmful[c]) > 1 and not contrast(c)
            else ""
        )  # fmt: skip
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
        mine = sorted(per_source[s.id], key=lambda p: _rank(p[0], seed))
        for it, c in mine[: _source_cap(s, cap)]:
            # Name a cluster by its first training member's ID: stable across rebuilds.
            final.append(replace(it, cluster=str(c)))
    # Twins join their clusters into one unit for the split (union-find over clusters).
    parent: dict[str, str] = {}

    def root(c: str) -> str:
        while parent.get(c, c) != c:
            c = parent[c] = parent.get(parent[c], parent[c])
        return c

    twin_of: dict[str, str] = {}
    for it in final:
        if pair := it.meta.get("pair"):
            if pair in twin_of:
                a, b = root(twin_of[pair]), root(it.cluster)
                if a != b:
                    parent[b] = a
            else:
                twin_of[pair] = it.cluster
    final = [replace(it, cluster=root(it.cluster)) for it in final]
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
        "build_key": build_key(sources, suite_ids, cap, seed),
        "seed": seed,
        "mobiusguard_eval": __version__,
        "cap": cap,
        "suite_ids_sha256": suite_ids,
        "items": {
            "train": sum(it.split == "train" for it in final),
            "val": sum(it.split == "val" for it in final),
        },
        "labels": Counter(f"{'attack' if it.label else 'benign'}/{it.split}" for it in final),
        "harmful": Counter(f"{it.meta.get('harmful', '')}/{it.split}" for it in final),
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
