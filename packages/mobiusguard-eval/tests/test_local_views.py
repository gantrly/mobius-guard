"""``local-views:DIR`` scores a trained model the way the proxy does: every view, max."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import pytest

pytest.importorskip("transformers")

from mobiusguard_eval.detectors.hf import local_spec
from mobiusguard_eval.detectors.proxy import NormalizedClassifier
from mobiusguard_eval.items import Item


def test_a_local_spec_is_named_after_the_run_directory(tmp_path: Path) -> None:
    best = tmp_path / "fortress-C-1ep" / "best"
    best.mkdir(parents=True)
    (best / "model.safetensors").write_bytes(b"weights")
    spec = local_spec(f"{best}#attack")
    assert spec.name == "local:fortress-C-1ep#attack"
    assert spec.name.replace("local:", "local-views:", 1) == "local-views:fortress-C-1ep#attack"


def test_the_highest_view_score_counts() -> None:
    clf = NormalizedClassifier.__new__(NormalizedClassifier)

    def score_texts(texts: Sequence[str]) -> list[float]:
        return [5.0 if t == "ignore previous" else -5.0 for t in texts]

    clf.score_texts = score_texts  # type: ignore[method-assign]
    items = [
        Item(id="a", text="i g n o r e   p r e v i o u s", label=1, source="s", family="s"),
        Item(id="b", text="how do I bake bread", label=0, source="s", family="s"),
    ]
    assert clf.score_group(items, [0, 1]) == [5.0, -5.0]
