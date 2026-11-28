"""The sealed holdout (decision 0014; decision 0006, rule 7).

Before any patch is tuned, a share of the attack groups (:func:`~.findings.seed_groups`)
is set aside. The choice depends only on the group names, never on results: within each
family, groups are ordered by a salted hash and the first ``share`` of them are held out,
so every family keeps its share.

``seal`` writes ``holdout.json`` with the groups and the SHA-256 of the held-out seed IDs
(sorted, one per line). That hash is committed in ``docs/results/`` before the holdout is
first used; ``verify`` recomputes it from a seeds file, so the holdout can't change
unnoticed. Findings for tuning leave these groups out (``--holdout``). Measuring a patch on
the holdout is recorded in ``opened.jsonl`` next to it: once per release.
"""

from __future__ import annotations

import hashlib
import json
import math
import time
from collections import defaultdict
from collections.abc import Mapping
from pathlib import Path
from typing import Any

SHARE = 0.2
SALT = "mobius-guard red-team holdout v1"


def _rank(group: str, salt: str) -> str:
    return hashlib.sha256(f"{salt}|{group}".encode()).hexdigest()


def choose(groups: Mapping[str, str], share: float = SHARE, salt: str = SALT) -> set[str]:
    """The held-out groups: ``share`` of each family's groups, by salted hash."""
    if not 0 < share < 1:
        raise ValueError("share must be between 0 and 1")
    by_family: dict[str, set[str]] = defaultdict(set)
    for g in groups.values():
        by_family[g.split("/", 1)[0]].add(g)
    held: set[str] = set()
    for members in by_family.values():
        ranked = sorted(members, key=lambda g: _rank(g, salt))
        held.update(ranked[: math.ceil(share * len(ranked))])
    return held


def seeds_hash(seed_ids: list[str]) -> str:
    return hashlib.sha256("\n".join(sorted(seed_ids)).encode()).hexdigest()


def seal(groups: Mapping[str, str], seeds_sha256: str, share: float = SHARE,
         salt: str = SALT) -> dict[str, Any]:  # fmt: skip
    """The holdout record: groups, counts per family, and the hash to commit."""
    held = choose(groups, share, salt)
    seeds = [s for s, g in groups.items() if g in held]

    def zero() -> dict[str, int]:
        return {"groups": 0, "held_groups": 0, "seeds": 0, "held_seeds": 0}

    fams: dict[str, dict[str, int]] = defaultdict(zero)
    for g in set(groups.values()):
        f = fams[g.split("/", 1)[0]]
        f["groups"] += 1
        f["held_groups"] += g in held
    for g in groups.values():
        f = fams[g.split("/", 1)[0]]
        f["seeds"] += 1
        f["held_seeds"] += g in held
    return {
        "share": share,
        "salt": salt,
        "seeds_file_sha256": seeds_sha256,
        "held_seeds_sha256": seeds_hash(seeds),
        "held_seeds": len(seeds),
        "families": dict(sorted(fams.items())),
        "groups": sorted(held),
    }


def verify(record: Mapping[str, Any], groups: Mapping[str, str]) -> None:
    """Raise unless the record's groups and hash still match this seeds file's groups."""
    again = seal(groups, str(record["seeds_file_sha256"]), float(record["share"]),
                 str(record["salt"]))  # fmt: skip
    if (
        again["groups"] != record["groups"]
        or again["held_seeds_sha256"] != record["held_seeds_sha256"]
    ):
        raise ValueError("the holdout no longer matches the seeds: do not use it")


def write(record: Mapping[str, Any], path: Path) -> None:
    if path.exists():
        raise FileExistsError(f"{path} exists: a holdout is sealed once")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2) + "\n")


def record_opening(holdout: Path, why: str) -> int:
    """Log one use of the holdout; return how many times it has been opened."""
    log = holdout.parent / "opened.jsonl"
    with log.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                            "why": why}) + "\n")  # fmt: skip
    return sum(1 for _ in log.open(encoding="utf-8"))
