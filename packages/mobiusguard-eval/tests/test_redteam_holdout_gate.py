"""The sealed holdout and the false-positive gate (decision 0014)."""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from mobiusguard.config import Config
from mobiusguard.guard import Guard
from mobiusguard_eval.cli import main as cli_main
from mobiusguard_eval.items import Item, make_item, write_jsonl
from mobiusguard_eval.redteam import holdout
from mobiusguard_eval.redteam.gate import (
    GATE_SETS,
    benign_items,
    blocked_counts,
    judge,
    run_gate,
)
from mobiusguard_eval.redteam.targets import GuardTarget


def groups(n_by_family: dict[str, int]) -> dict[str, str]:
    """seed ID -> group, two seeds per group."""
    out: dict[str, str] = {}
    for fam, n in n_by_family.items():
        for g in range(n):
            for k in range(2):
                out[f"garak:{fam}{g:04d}{k}"] = f"{fam}/garak:{fam}{g:04d}0"
    return out


def test_holdout_takes_a_share_of_each_family_by_name_only() -> None:
    g = groups({"latentinjection": 50, "encoding": 30, "promptinject": 3})
    held = holdout.choose(g)
    per = {f: sum(h.startswith(f + "/") for h in held) for f in ("latentinjection", "encoding",
                                                                    "promptinject")}  # fmt: skip
    assert per == {"latentinjection": 10, "encoding": 6, "promptinject": 1}
    shuffled = dict(reversed(list(g.items())))
    assert holdout.choose(shuffled) == held  # order does not matter
    assert holdout.choose(g, salt="other") != held
    with pytest.raises(ValueError, match="share"):
        holdout.choose(g, share=1.0)


def test_seal_verify_and_open(tmp_path: Path) -> None:
    g = groups({"latentinjection": 20, "encoding": 10})
    rec = holdout.seal(g, "abc")
    held_seeds = [s for s, grp in g.items() if grp in rec["groups"]]
    assert rec["held_seeds"] == len(held_seeds) == 2 * 6
    assert rec["held_seeds_sha256"] == holdout.seeds_hash(held_seeds)
    assert rec["families"]["latentinjection"] == {"groups": 20, "held_groups": 4,
                                                   "seeds": 40, "held_seeds": 8}  # fmt: skip
    holdout.verify(rec, g)
    changed = dict(g)
    moved = next(s for s, grp in g.items() if grp in rec["groups"])
    changed[moved] = "latentinjection/garak:somewhere-else"
    with pytest.raises(ValueError, match="no longer matches"):
        holdout.verify(rec, changed)
    path = tmp_path / "h" / "holdout.json"
    holdout.write(rec, path)
    with pytest.raises(FileExistsError):
        holdout.write(rec, path)
    assert holdout.record_opening(path, "patch 1") == 1
    assert holdout.record_opening(path, "patch 2") == 2


def suite(tmp_path: Path) -> Path:
    items: list[Item] = []
    for fam in GATE_SETS:
        for k in range(10):
            text = f"an ordinary harmless message number {k} for {fam}"
            items.append(replace(make_item(text, 0, fam), split="test"))
        items.append(replace(make_item(f"a dev message for {fam}", 0, fam), split="dev"))
    items.append(replace(make_item("an attack placeholder", 1, "llmail"), split="test"))
    path = tmp_path / "suite" / "items.jsonl"
    path.parent.mkdir(parents=True)
    write_jsonl(path, items)
    return path.parent


def test_benign_items_reads_the_test_split_of_the_four_sets(tmp_path: Path) -> None:
    sets = benign_items(suite(tmp_path))
    assert set(sets) == set(GATE_SETS)
    assert all(len(v) == 10 for v in sets.values())
    assert not any("dev message" in t for v in sets.values() for t in v)
    with pytest.raises(ValueError, match="no val items"):
        benign_items(suite(tmp_path / "x"), split="val")


def test_judge_applies_the_tolerances() -> None:
    base = {"oasst": [10, 1000], "notinject": [20, 1000], "orbench": [100, 1000],
            "llmail_benign": [0, 1000]}  # fmt: skip
    assert judge(base, base)["passed"]
    up = dict(base, oasst=[11, 1000])
    r = judge(base, up)
    assert not r["passed"]
    assert not r["sets"]["oasst"]["passed"]
    assert judge(base, dict(base, notinject=[25, 1000]))["passed"]  # +0.5 pt: allowed
    assert not judge(base, dict(base, notinject=[26, 1000]))["passed"]  # +0.6 pt
    assert judge(base, dict(base, orbench=[50, 1000]))["passed"]  # fewer blocks: fine
    with pytest.raises(ValueError, match="different items"):
        judge(base, dict(base, oasst=[10, 999]))


def test_gate_catches_a_config_that_blocks_more(tmp_path: Path) -> None:
    sets = benign_items(suite(tmp_path))

    def scorer(texts: Sequence[str]) -> list[tuple[float, float]]:
        return [(2.5 if "number 3" in t else -4.0, -5.0) for t in texts]

    base = GuardTarget(Guard(Config(), scorer=scorer, thresholds={"attack": 3.0}))
    lower = GuardTarget(Guard(Config(), scorer=scorer, thresholds={"attack": 2.0}))
    b, p = blocked_counts(base, sets), blocked_counts(lower, sets)
    assert b["oasst"] == [0, 10]
    assert p["oasst"] == [1, 10]
    assert not judge(b, p)["passed"]

    cfg = tmp_path / "rules.toml"
    cfg.write_text("")
    r = run_gate(suite(tmp_path / "y"), str(cfg), str(cfg))  # same config: nothing changes
    assert r["passed"]
    assert r["sets"]["oasst"]["rise"] == 0.0


def test_cli_seal_and_verify(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rows: list[dict[str, Any]] = []
    for k in range(12):
        msg = {"role": "user", "content": f"placeholder {k} " * (k + 3)}
        rows.append({"id": f"garak:{k:016x}", "source": "garak", "family": "encoding",
                     "probe": "encoding.X", "payload": 0, "messages": [msg]})  # fmt: skip
    seeds = tmp_path / "seeds.jsonl"
    seeds.write_text("".join(json.dumps(r) + "\n" for r in rows))
    assert cli_main(["redteam", "seal", "--seeds", str(seeds), "--out", str(tmp_path / "h")]) == 0
    out = capsys.readouterr().out
    rec = json.loads((tmp_path / "h" / "holdout.json").read_text())
    assert rec["held_seeds_sha256"] in out
    assert len(rec["groups"]) >= 1
    assert cli_main(["redteam", "verify-holdout", "--seeds", str(seeds),
                     "--holdout", str(tmp_path / "h" / "holdout.json")]) == 0  # fmt: skip
    with pytest.raises(FileExistsError):
        cli_main(["redteam", "seal", "--seeds", str(seeds), "--out", str(tmp_path / "h")])
