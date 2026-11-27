"""Distillation (decision 0022): the loss terms, the extra-text pool and the spill."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from mobiusguard_eval import distill, train_data
from mobiusguard_eval.items import ATTACK, BENIGN, make_item, read_jsonl, write_jsonl
from mobiusguard_eval.ledger import Source
from mobiusguard_eval.train import TrainConfig, loss_terms


def _texts(n: int, stem: str) -> list[str]:
    return [f"{stem} number {i}: a distinct sentence about topic {i * 7919} here" for i in range(n)]


def test_loss_terms_without_a_teacher_are_the_plain_label_loss() -> None:
    torch = pytest.importorskip("torch")
    bce = torch.nn.BCEWithLogitsLoss(reduction="none")
    logits = torch.tensor([[2.0, -1.0], [0.5, 0.3]])
    targets = torch.tensor([[1.0, 0.0], [0.0, -1.0]])  # the second harmful label is unknown
    weights = torch.tensor([[1.0], [0.5]])
    num, den = loss_terms(torch, bce, logits, targets, weights, None, 1.0, 1.0)
    known = (targets >= 0).float()
    want = (bce(logits, targets.clamp(min=0)) * known * weights).sum()
    assert float(num) == pytest.approx(float(want))
    assert float(den) == pytest.approx(float((known * weights).sum()))
    soft = torch.tensor([[3.0, -2.0], [0.0, 1.0]])
    num1, den1 = loss_terms(torch, bce, logits, targets, weights, soft, 1.0, 2.0)
    assert (float(num1), float(den1)) == (pytest.approx(float(num)), pytest.approx(float(den)))


def test_loss_terms_mix_labels_and_teacher() -> None:
    torch = pytest.importorskip("torch")
    bce = torch.nn.BCEWithLogitsLoss(reduction="none")
    logits = torch.tensor([[1.0, -1.0]])
    soft = torch.tensor([[1.0, -1.0]])
    # A distill-only item: no labels, so only the teacher term, over both outputs.
    targets = torch.tensor([[-1.0, -1.0]])
    weights = torch.tensor([[1.0]])
    num, den = loss_terms(torch, bce, logits, targets, weights, soft, 0.5, 2.0)
    teach = bce(logits / 2, torch.sigmoid(soft / 2)) * 4
    assert float(num) == pytest.approx(0.5 * float(teach.sum()))
    assert float(den) == pytest.approx(0.5 * 2)  # (1 - alpha) on each of the two outputs
    # The student that matches the teacher has the smallest teacher term.
    other = torch.tensor([[-1.0, 1.0]])
    worse, _ = loss_terms(torch, bce, other, targets, weights, soft, 0.5, 2.0)
    assert float(worse) > float(num)


def test_runs_before_distillation_keep_their_identity() -> None:
    plain = TrainConfig(base="deberta-v3-xsmall").key()
    assert "alpha" not in plain
    assert "teacher_scores" not in plain
    distilled = TrainConfig(base="deberta-v3-xsmall", alpha=0.5, temperature=2.0,
                            teacher_scores="/x/t.jsonl").key()  # fmt: skip
    assert distilled["alpha"] == 0.5
    assert "teacher_scores" not in distilled  # by its sha256, in train(), not by path


def _src(id_: str, role: str = "attack", cap: int = 0) -> Source:
    return Source(id=id_, title=id_, homepage="", licence="MIT", role=role,  # type: ignore[arg-type]
                  files=(), parse=lambda _p: [], cap=cap)  # fmt: skip


def test_the_build_spills_what_the_cap_cuts(tmp_path: Path) -> None:
    items = [make_item(t, ATTACK, "a") for t in _texts(80, "attack")]
    train_data.build([_src("a")], {"a": items}, [], tmp_path, cap=50, spill=True)
    kept = list(read_jsonl(tmp_path / "train.jsonl")) + list(read_jsonl(tmp_path / "val.jsonl"))
    spilled = list(read_jsonl(tmp_path / "spill.jsonl"))
    assert len(kept) == 50
    assert spilled
    assert not {it.id for it in kept} & {it.id for it in spilled}
    assert len(kept) + len(spilled) <= 80


def test_the_pool_drops_near_held_out_and_training_items(tmp_path: Path) -> None:
    held = make_item("a held-out suite message about the quarterly report numbers today",
                     BENIGN, "oasst")  # fmt: skip
    near = make_item("A held-out suite message about the quarterly report numbers today!",
                     BENIGN, "wildchat")  # fmt: skip
    in_train = make_item("a training item that is already in the build, word for word here",
                         BENIGN, "wildchat")  # fmt: skip
    doc = make_item("an email body that a tool returned to the agent, with a planted line",
                    ATTACK, "rgeada_tool")  # fmt: skip
    fresh = [make_item(t, BENIGN, "wildchat") for t in _texts(20, "fresh")]
    write_jsonl(tmp_path / "spill.jsonl", [near, in_train, doc, *fresh])
    write_jsonl(tmp_path / "suite.jsonl", [held])
    write_jsonl(tmp_path / "train.jsonl", [in_train])
    s = distill.pool(tmp_path / "spill.jsonl", [tmp_path / "suite.jsonl"],
                     [tmp_path / "train.jsonl"], tmp_path / "pool", size=15)  # fmt: skip
    out = list(read_jsonl(tmp_path / "pool" / "items.jsonl"))
    ids = {it.id for it in out}
    assert near.id not in ids
    assert in_train.id not in ids
    assert s["near_held_out"] == 1
    assert len(out) == 15
    assert all(it.meta["distill_only"] == "1" and it.split == "train" for it in out)
    assert all(it.text.startswith(("[user]\n", "[tool]\n")) for it in out)
    for it in out:
        if it.id == doc.id:
            assert it.text.startswith("[tool]\n")
    assert json.loads((tmp_path / "pool" / "summary.json").read_text())["items"] == 15
