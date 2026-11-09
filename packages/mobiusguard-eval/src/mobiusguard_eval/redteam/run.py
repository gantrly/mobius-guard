"""The red-team runner (decision 0014): every attempt to a target, one row per attempt.

Output directory:

- ``run.json``: the run's key (target, seeds file hash, chains, deliveries, sample,
  shards). A directory holds one run; a different key is refused.
- ``attempts-<shard>.jsonl``: one row per attempt: its ID, seed, source, family, probe,
  chain, delivery and the target's verdict. No attack text: an attempt is rebuilt from
  its seed and chain when someone needs to read it.
- ``done-<shard>.jsonl``: a :class:`~..checkpoint.Checkpoint` of finished seeds. A resumed
  run skips them. A seed with a target error (no verdict) is not marked done, so it is sent
  again; the newest row for an attempt ID is the one that counts.
- ``scores-<shard>.jsonl``: the classifier score cache (:mod:`.cache`), in-process only.

``shard=(i, n)`` runs the seeds whose ID hashes to ``i`` of ``n``, so several processes can
share a box; all variants of a seed go to the same shard and share its cache.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import random
import time
import uuid
from collections import Counter
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..checkpoint import Checkpoint
from .cache import ScoreCache
from .mutate import CHAINS, DELIVERIES, Chain, attempts_for, chain_name
from .seeds import Seed, read_seeds
from .targets import GuardTarget, Target

PROGRESS_SECONDS = 60.0


def _log(msg: str) -> None:
    print(msg, flush=True)  # a run's log is usually a file, which Python would buffer


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def shard_of(seed_id: str, n: int) -> int:
    return int.from_bytes(hashlib.sha256(seed_id.encode()).digest()[:8], "big") % n


def parse_shard(text: str) -> tuple[int, int]:
    i, _, n = text.partition("/")
    shard = (int(i), int(n or "1"))
    if not 0 <= shard[0] < shard[1]:
        raise ValueError(f"shard must be i/n with 0 <= i < n, not {text!r}")
    return shard


def select(seeds: Sequence[Seed], sample: int, sample_seed: int) -> list[Seed]:
    """All seeds, or a fixed random ``sample`` of them (the small run)."""
    if not sample or sample >= len(seeds):
        return list(seeds)
    ordered = sorted(seeds, key=lambda s: s.id)
    return random.Random(sample_seed).sample(ordered, sample)  # noqa: S311 - a fixed sample


@dataclass(frozen=True)
class Plan:
    seeds: Path
    out: Path
    chains: tuple[Chain, ...] = CHAINS
    deliveries: tuple[str, ...] = DELIVERIES
    sample: int = 0
    sample_seed: int = 0
    shard: tuple[int, int] = (0, 1)

    def key(self, target: Target, seeds_sha: str) -> dict[str, Any]:
        return {
            "target": target.info(),
            "seeds_sha256": seeds_sha,
            "chains": [chain_name(c) for c in self.chains],
            "deliveries": list(self.deliveries),
            "sample": self.sample,
            "sample_seed": self.sample_seed,
            "shards": self.shard[1],
        }


def _check_key(out: Path, key: dict[str, Any]) -> None:
    """Create ``run.json`` with the run's key, or check the one there.

    Shards start at the same time, so the file is created with a link from a temporary file
    of its own (create-if-absent is atomic); a shard that loses the race reads
    the winner's file and compares keys like any later run.
    """
    path = out / "run.json"
    if not path.exists():
        info = {"key": key, "host": platform.node(), "python": platform.python_version(),
                "machine": platform.machine(), "processor": platform.processor()}  # fmt: skip
        tmp = out / f".run.json.{os.getpid()}.{uuid.uuid4().hex}.tmp"
        tmp.write_text(json.dumps(info, indent=2) + "\n")
        try:
            os.link(tmp, path)
        except FileExistsError:
            pass
        finally:
            tmp.unlink()
    saved = json.loads(path.read_text())
    if saved.get("key") != key:
        raise SystemExit(f"{out} holds a different run; use a new --out")


def row_for(attempt: Any, verdict: Any) -> dict[str, Any]:
    return {
        "id": attempt.id,
        "seed": attempt.seed,
        "source": attempt.source,
        "family": attempt.family,
        "probe": attempt.probe,
        "chain": attempt.chain,
        "delivery": attempt.delivery,
        **verdict.to_json(),
    }


def use_cache(target: Target, out: Path, shard: int) -> ScoreCache | None:
    """Put a score cache in front of an in-process guard's classifier."""
    if not isinstance(target, GuardTarget) or target.guard.scorer is None:
        return None
    others = [p for p in sorted(out.glob("scores-*.jsonl")) if p.name != f"scores-{shard}.jsonl"]
    cache = ScoreCache(target.guard.scorer, out / f"scores-{shard}.jsonl", read=others)
    target.guard.scorer = cache
    return cache


def run(
    plan: Plan,
    target: Target,
    *,
    log: Callable[[str], None] | None = None,
    stop_after_seconds: float = 0.0,
) -> dict[str, Any]:
    """Send this shard's attempts; return counts for what this call sent."""
    log = log or _log
    plan.out.mkdir(parents=True, exist_ok=True)
    key = plan.key(target, sha256_file(plan.seeds))
    _check_key(plan.out, key)
    i, n = plan.shard
    seeds = select(list(read_seeds(plan.seeds)), plan.sample, plan.sample_seed)
    mine = [s for s in seeds if shard_of(s.id, n) == i]
    done = Checkpoint(plan.out / f"done-{i}.jsonl", key)
    todo = [s for s in mine if s.id not in done]
    cache = use_cache(target, plan.out, i)
    log(f"shard {i}/{n}: {len(mine)} seeds, {len(mine) - len(todo)} done, {len(todo)} to send")
    counts: Counter[str] = Counter()
    start = last = time.monotonic()
    with (plan.out / f"attempts-{i}.jsonl").open("a", encoding="utf-8") as f:
        for k, seed in enumerate(todo, 1):
            blocked = errors = 0
            for att in attempts_for(seed, plan.chains, plan.deliveries):
                v = target.send(list(att.messages))
                f.write(json.dumps(row_for(att, v)) + "\n")
                counts["attempts"] += 1
                blocked += v.blocked
                errors += bool(v.error)
            f.flush()
            counts["blocked"] += blocked
            counts["errors"] += errors
            if errors:
                counts["seeds_with_errors"] += 1
            else:
                done.add(seed.id, {"blocked": blocked})
            now = time.monotonic()
            if now - last >= PROGRESS_SECONDS or k == len(todo):
                last = now
                rate = counts["attempts"] / max(now - start, 1e-9)
                eta = (len(todo) - k) * counts["attempts"] / k / max(rate, 1e-9)
                hit = cache.hits / max(cache.hits + cache.misses, 1) if cache else 0.0
                log(f"shard {i}: {k}/{len(todo)} seeds, {rate:.1f} attempts/s, "
                    f"ETA {eta / 3600:.1f} h, cache hits {hit:.0%}")  # fmt: skip
            if stop_after_seconds and now - start >= stop_after_seconds:
                log(f"shard {i}: stopping after {stop_after_seconds:.0f}s as asked")
                break
    if cache:
        cache.close()
    return dict(counts)


def latest_rows(out: Path) -> Iterator[dict[str, Any]]:
    """The newest row for each attempt ID across all shards."""
    rows: dict[str, dict[str, Any]] = {}
    for p in sorted(out.glob("attempts-*.jsonl")):
        with p.open(encoding="utf-8") as f:
            for line in f:
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                rows[str(r["id"])] = r
    yield from rows.values()


def summary(out: Path) -> dict[str, Any]:
    """Counts across shards: attempts, caught, got through, errors; by family, chain, delivery."""
    total: Counter[str] = Counter()
    by: dict[str, dict[str, Counter[str]]] = {"family": {}, "chain": {}, "delivery": {}}
    for r in latest_rows(out):
        status = "error" if r["error"] else ("caught" if r["blocked"] else "through")
        total[status] += 1
        for field in by:
            by[field].setdefault(str(r[field]), Counter())[status] += 1

    def table(groups: dict[str, Counter[str]]) -> dict[str, dict[str, int]]:
        return {k: dict(v) for k, v in sorted(groups.items())}

    return {"total": dict(total), **{f: table(g) for f, g in by.items()}}
