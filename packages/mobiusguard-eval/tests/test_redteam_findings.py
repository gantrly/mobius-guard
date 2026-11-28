"""Red-team findings: groups, counts, ranking, holdout exclusion, no text in reports."""

from __future__ import annotations

import json
from typing import Any

import pytest
from mobiusguard_eval.redteam.findings import depth, findings, markdown, seed_groups
from mobiusguard_eval.redteam.seeds import Seed

BASE = "quarterly report for the board, section " * 4


def seed(i: int, text: str, family: str = "latentinjection") -> Seed:
    return Seed(id=f"garak:{i:016x}", source="garak", family=family, probe=f"{family}.X",
                messages=({"role": "user", "content": text},), payload=0)  # fmt: skip


SEEDS = [
    seed(1, BASE + "one"),
    seed(2, BASE + "one!"),  # a near copy of seed 1
    seed(3, "a completely different placeholder text about gardens and rain"),
    seed(4, BASE + "one", family="encoding"),  # same text, other family: its own group
]


def row(s: Seed, chain: str, delivery: str, blocked: bool, **kw: Any) -> dict[str, Any]:
    r: dict[str, Any] = {"id": f"{s.id}~{chain}~{delivery}", "seed": s.id, "source": "garak",
         "family": s.family, "probe": s.probe, "chain": chain, "delivery": delivery,
         "blocked": blocked, "reason": "classifier" if blocked else "", "rules": [],
         "score": 4.0 if blocked else 1.5, "harmful": -5.0, "flagged": [], "ms": 1.0,
         "error": ""}  # fmt: skip
    return {**r, **kw}


def test_near_copies_share_a_group_within_a_family() -> None:
    g = seed_groups(SEEDS)
    assert g[SEEDS[0].id] == g[SEEDS[1].id] == f"latentinjection/{SEEDS[0].id}"
    assert g[SEEDS[2].id] == f"latentinjection/{SEEDS[2].id}"
    assert g[SEEDS[3].id] == f"encoding/{SEEDS[3].id}"


def rows() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for s in SEEDS:
        for chain in ("plain", "leetspeak", "leetspeak+spaced"):
            for d in ("user", "tool"):
                through = chain == "leetspeak+spaced" or (s is SEEDS[2] and chain == "plain")
                out.append(row(s, chain, d, blocked=not through))
    out.append(row(SEEDS[0], "spaced", "user", False, error="ConnectError"))
    return out


def test_findings_count_rank_and_leave_out_the_holdout() -> None:
    groups = seed_groups(SEEDS)
    f = findings(rows(), groups)
    t = f["total"]
    assert (t["attempts"], t["through"], t["errors"]) == (24, 10, 1)
    assert f["groups"] == 3
    assert f["chain"]["leetspeak+spaced"]["through"] == 8
    assert f["chain"]["leetspeak+spaced"]["rate"] == 1.0
    assert f["depth"]["2"]["attempts"] == 8
    assert f["delivery"]["user"]["through"] == f["delivery"]["tool"]["through"] == 5
    top = f["findings"][0]
    assert top["group"] == f"latentinjection/{SEEDS[0].id}"
    assert top["chain"] == "leetspeak+spaced"
    assert (top["through"], top["seeds"]) == (4, 2)  # both near copies
    assert top["through_score"]["median"] == 1.5
    assert f["family"]["latentinjection"]["caught_by"] == {"classifier": 10}  # 18 rows, 8 through

    held = f"latentinjection/{SEEDS[0].id}"
    f2 = findings(rows(), groups, exclude=[held])
    assert f2["total"]["left_out_holdout"] == 13  # 12 rows + the error row
    assert all(x["group"] != held for x in f2["findings"])

    with pytest.raises(ValueError, match="not in the seeds file"):
        findings([row(seed(9, "x"), "plain", "user", True)], groups)


def test_reports_carry_no_seed_text() -> None:
    f = findings(rows(), seed_groups(SEEDS))
    text = json.dumps(f) + markdown(f)
    for s in SEEDS:
        assert s.text not in text
    assert "quarterly" not in text
    assert "Largest findings" in markdown(f)


def test_depth() -> None:
    assert (depth("plain"), depth("spaced"), depth("spaced+base64")) == (0, 1, 2)
