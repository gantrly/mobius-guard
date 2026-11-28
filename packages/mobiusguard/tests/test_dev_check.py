"""scripts/dev_check.py scores the live check's developer messages the same way per model."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[3]


def _script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("dev_check", ROOT / "scripts/dev_check.py")
    assert spec
    assert spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_eight_texts_of_the_note_with_their_v1_scores() -> None:
    m = _script()
    assert len(m.TEXTS) == len(m.V1_SCORES) == 8
    note = (ROOT / "docs/results/2026-11-07-live-check-fortress.md").read_text()
    for v1 in m.V1_SCORES:
        assert f"| {v1:.2f} |".replace("-", "\N{MINUS SIGN}") in note  # as the note writes it


def test_check_blocks_at_and_above_the_threshold() -> None:
    m = _script()
    scores = dict(
        zip((t for _, t in m.TEXTS), (3.0, 2.0, 2.5, 1.0, 0.0, -1.0, -2.0, 2.5), strict=True)
    )

    def score(text: str) -> float:
        return scores[text]

    rows = m.check(score, 2.5)
    assert [r["blocked"] for r in rows] == [True, False, True, False, False, False, False, True]
    assert rows[0]["v1"] == m.V1_SCORES[0]


def test_an_export_gets_a_fortress_json_with_the_given_threshold(tmp_path: Path) -> None:
    m = _script()
    export, work = tmp_path / "export", tmp_path / "work"
    export.mkdir()
    work.mkdir()
    for name in ("model.int8.onnx", "tokenizer.json"):
        (export / name).write_text("x")
    with pytest.raises(SystemExit, match="pass --threshold"):
        m.model_dir(export, None, work)
    d, threshold = m.model_dir(export, 3.1, work)
    assert (d, threshold) == (work, 3.1)
    meta = json.loads((d / "fortress.json").read_text())
    assert meta["outputs"] == ["attack", "harmful"]
    assert meta["thresholds"]["attack"][meta["default_fpr"]] == 3.1
    assert (d / "model.int8.onnx").resolve() == (export / "model.int8.onnx").resolve()


def test_a_release_directory_uses_its_own_threshold(tmp_path: Path) -> None:
    m = _script()
    meta = {"outputs": ["attack", "harmful"], "max_length": 512, "default_fpr": "0.01",
            "thresholds": {"attack": {"0.01": 2.7634}, "harmful": {"0.01": 1.1479}}}  # fmt: skip
    (tmp_path / "fortress.json").write_text(json.dumps(meta))
    assert m.model_dir(tmp_path, None, tmp_path) == (tmp_path, 2.7634)
    assert m.model_dir(tmp_path, 4.0, tmp_path) == (tmp_path, 4.0)
