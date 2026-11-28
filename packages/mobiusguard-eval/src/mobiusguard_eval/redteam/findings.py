"""Red-team findings (decision 0014): what got through, grouped so a person can act on it.

- **Groups.** Seeds are clustered by near-duplicate text within their family (MinHash, as
  the suite does), so the variants of near copies of one prompt are one group. A group is
  named after its first seed ID. The sealed holdout (:mod:`.holdout`) sets aside whole
  groups, and findings for tuning leave them out.
- **Findings.** For each group and mutation chain: attempts, how many got through, the
  rate, the layer that caught the rest, and the classifier scores of the ones that got
  through (what a threshold patch would need). Plus totals by family, chain, chain depth
  and delivery.
- Reports carry counts, rates, scores and IDs only, never attack text.
"""

from __future__ import annotations

import json
import statistics
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..dedup import clusters
from .run import latest_rows
from .seeds import Seed

EXAMPLES = 5


def seed_groups(seeds: Sequence[Seed]) -> dict[str, str]:
    """Seed ID -> group: ``<family>/<first seed ID of its near-duplicate cluster>``."""
    by_family: dict[str, list[Seed]] = defaultdict(list)
    for s in sorted(seeds, key=lambda s: s.id):
        by_family[s.family].append(s)
    out: dict[str, str] = {}
    for family, members in by_family.items():
        labels = clusters([s.text for s in members])
        first: dict[int, str] = {}
        for s, c in zip(members, labels, strict=True):
            first.setdefault(c, s.id)
            out[s.id] = f"{family}/{first[c]}"
    return out


@dataclass
class Tally:
    attempts: int = 0
    through: int = 0
    caught_by: Counter[str] = field(default_factory=Counter[str])
    through_scores: list[float] = field(default_factory=list[float])
    examples: list[str] = field(default_factory=list[str])
    seeds: set[str] = field(default_factory=set[str])

    def add(self, row: Mapping[str, Any]) -> None:
        self.attempts += 1
        self.seeds.add(str(row["seed"]))
        if row["blocked"]:
            self.caught_by[str(row["reason"]) or "unknown"] += 1
            return
        self.through += 1
        if isinstance(row.get("score"), int | float):
            self.through_scores.append(float(row["score"]))
        if len(self.examples) < EXAMPLES:
            self.examples.append(str(row["id"]))

    def to_json(self) -> dict[str, Any]:
        sc = sorted(self.through_scores)
        out: dict[str, Any] = {
            "attempts": self.attempts,
            "through": self.through,
            "rate": round(self.through / self.attempts, 4) if self.attempts else 0.0,
            "seeds": len(self.seeds),
            "caught_by": dict(sorted(self.caught_by.items())),
        }
        if sc:
            out["through_score"] = {"min": round(sc[0], 3),
                                    "median": round(statistics.median(sc), 3),
                                    "max": round(sc[-1], 3)}  # fmt: skip
        if self.examples:
            out["examples"] = sorted(self.examples)
        return out


def depth(chain: str) -> int:
    return 0 if chain == "plain" else chain.count("+") + 1


def findings(
    rows: Iterable[Mapping[str, Any]],
    groups: Mapping[str, str],
    *,
    exclude: Iterable[str] = (),
) -> dict[str, Any]:
    """Findings from a run's rows. ``exclude``: groups to leave out (the sealed holdout)."""
    skip = set(exclude)
    total, errors = Tally(), 0
    keys = ("family", "chain", "depth", "delivery")
    by: dict[str, dict[str, Tally]] = {k: defaultdict(Tally) for k in keys}
    cells: dict[tuple[str, str], Tally] = defaultdict(Tally)
    left_out = 0
    for r in rows:
        group = groups.get(str(r["seed"]))
        if group is None:
            raise ValueError(f"attempt {r['id']} has a seed that is not in the seeds file")
        if group in skip:
            left_out += 1
            continue
        if r.get("error"):
            errors += 1
            continue
        total.add(r)
        by["family"][str(r["family"])].add(r)
        by["chain"][str(r["chain"])].add(r)
        by["depth"][str(depth(str(r["chain"])))].add(r)
        by["delivery"][str(r["delivery"])].add(r)
        cells[(group, str(r["chain"]))].add(r)
    ranked = sorted(((g, c, t) for (g, c), t in cells.items() if t.through),
                    key=lambda x: (-x[2].through, x[0], x[1]))  # fmt: skip
    return {
        "total": {**total.to_json(), "errors": errors, "left_out_holdout": left_out},
        **{k: {name: t.to_json() for name, t in sorted(v.items())} for k, v in by.items()},
        "groups": len({g for g, _ in cells}),
        "findings": [{"group": g, "chain": c, **t.to_json()} for g, c, t in ranked],
    }


def findings_for_run(
    out: Path, seeds: Sequence[Seed], *, exclude: Iterable[str] = ()
) -> dict[str, Any]:
    return findings(latest_rows(out), seed_groups(seeds), exclude=exclude)


def _pct(x: float) -> str:
    return f"{100 * x:.1f}%"


def markdown(f: Mapping[str, Any], top: int = 40) -> str:
    """A report a person can read: rates and IDs, no attack text."""
    t = f["total"]
    lines = [
        "# Red-team findings",
        "",
        f"{t['attempts']:,} attempts with a verdict, {t['through']:,} got through "
        f"({_pct(t['rate'])}); {t['errors']:,} without a verdict; "
        f"{t['left_out_holdout']:,} in the sealed holdout, left out. {f['groups']:,} groups.",
        "",
    ]
    for key, title in (("family", "Family"), ("depth", "Mutations stacked"),
                       ("delivery", "Delivery"), ("chain", "Chain")):  # fmt: skip
        lines += [f"## By {title.lower()}", "", f"| {title} | Attempts | Got through | Rate |",
                  "|---|---:|---:|---:|"]  # fmt: skip
        for name, v in f[key].items():
            lines.append(f"| {name} | {v['attempts']:,} | {v['through']:,} | {_pct(v['rate'])} |")
        lines.append("")
    lines += [f"## Largest findings (top {top} of {len(f['findings'])})", "",
              "| Group | Chain | Got through | Rate | Score of those through (median) | Examples |",
              "|---|---|---:|---:|---:|---|"]  # fmt: skip
    for x in f["findings"][:top]:
        med = x.get("through_score", {}).get("median", "")
        ex = ", ".join(f"`{e}`" for e in x.get("examples", [])[:2])
        lines.append(f"| `{x['group']}` | {x['chain']} | {x['through']:,}/{x['attempts']:,} | "
                     f"{_pct(x['rate'])} | {med} | {ex} |")  # fmt: skip
    return "\n".join(lines) + "\n"


def write(f: Mapping[str, Any], out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "findings.json").write_text(json.dumps(f, indent=2) + "\n")
    (out / "findings.md").write_text(markdown(f))
