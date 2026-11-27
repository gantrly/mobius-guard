"""fortress.json for a released model (decision 0024): thresholds per role and per view."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from mobiusguard_eval import model_meta
from mobiusguard_eval.items import ATTACK, BENIGN, make_item, write_jsonl
from mobiusguard_eval.metrics import threshold_at_fpr


def _run(d: Path, scores: dict[str, float]) -> Path:
    d.mkdir(parents=True)
    (d / "run.json").write_text("{}")
    with (d / "scores.jsonl").open("w") as f:
        for k, v in scores.items():
            f.write(json.dumps({"id": k, "score": v}) + "\n")
    return d


def _setup(tmp: Path, n_user: int = 2000, n_doc: int = 300) -> dict[str, Path]:
    cal = [make_item(f"ordinary message number {i} about topic {i * 31}", BENIGN, "oasst")
           for i in range(n_user)]  # fmt: skip
    test = [make_item(f"an attack text {i}", ATTACK, "gandalf") for i in range(50)]
    cal = [replace(it, split="dev") for it in cal]
    test = [replace(it, split="test") for it in test]
    (tmp / "suite").mkdir()
    write_jsonl(tmp / "suite" / "items.jsonl", [*cal, *test])
    user = {it.id: (i % 1000) / 100 for i, it in enumerate(cal)}
    user.update({it.id: 50.0 for it in test})  # attacks: not calibration, must not count
    doc = {f"doc:{i}": i / 10 for i in range(n_doc)}
    (tmp / "train").mkdir()
    (tmp / "train" / "summary.json").write_text(json.dumps({"ids_sha256": "ab" * 32}))
    return {
        "suite": tmp / "suite",
        "attack": _run(tmp / "a", user),
        "attack_views": _run(tmp / "av", {k: v + 1 for k, v in user.items()}),
        "attack_tool": _run(tmp / "t", doc),
        "attack_tool_views": _run(tmp / "tv", {k: v + 2 for k, v in doc.items()}),
        "harmful": _run(tmp / "h", {k: -v for k, v in user.items()}),
        "training": tmp / "train",
    }


def _meta(p: dict[str, Path]) -> dict[str, Any]:
    return model_meta.fortress_meta(name="fortress-base", version=1, base="b@c",
                                    code_commit="abc1234", **p)  # type: ignore[arg-type]  # fmt: skip


def test_thresholds_per_role_and_view(tmp_path: Path) -> None:
    p = _setup(tmp_path)
    m = _meta(p)
    th, vt = m["thresholds"], m["views_thresholds"]
    user = [(i % 1000) / 100 for i in range(2000)]
    assert th["attack"]["0.01"] == pytest.approx(threshold_at_fpr(user, 0.01).value, abs=1e-4)
    assert vt["attack"]["0.01"] == pytest.approx(th["attack"]["0.01"] + 1, abs=1e-4)
    assert vt["attack_tool"]["0.01"] == pytest.approx(th["attack_tool"]["0.01"] + 2, abs=1e-4)
    # The harmful score is the original text's, with or without views.
    assert vt["harmful"] == th["harmful"]
    assert m["role_marker"] is True
    assert m["training_data_ids_sha256"] == "ab" * 32
    # A threshold needs 10 / fpr texts: 2,000 messages set 1% and 5%, 300 documents only 5%.
    assert m["thresholds_not_reliable"] == {
        "attack": ["0.001"], "harmful": ["0.001"], "views:attack": ["0.001"],
        "attack_tool": ["0.001", "0.01"], "views:attack_tool": ["0.001", "0.01"],
    }  # fmt: skip
    assert "2,000 ordinary user messages" in str(m["thresholds_set_on"])


def test_the_proxy_reads_it(tmp_path: Path) -> None:
    """The keys the proxy's loader reads (mobiusguard.classifier.OnnxClassifier)."""
    m = _meta(_setup(tmp_path))
    fpr = str(m["default_fpr"])
    th, vt = m["thresholds"], m["views_thresholds"]
    for o in m["outputs"]:
        float(th[o][fpr])
    float(th["attack_tool"][fpr])
    assert {k: float(v[fpr]) for k, v in vt.items()}.keys() == {"attack", "attack_tool", "harmful"}


def test_a_run_missing_calibration_items_is_refused(tmp_path: Path) -> None:
    p = _setup(tmp_path)
    rows = (p["harmful"] / "scores.jsonl").read_text().splitlines()
    (p["harmful"] / "scores.jsonl").write_text("\n".join(rows[5:]) + "\n")
    with pytest.raises(ValueError, match="calibration items not scored"):
        _meta(p)
