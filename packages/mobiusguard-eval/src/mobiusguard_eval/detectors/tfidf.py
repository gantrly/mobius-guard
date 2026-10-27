"""TF-IDF + logistic regression, trained leave-one-source-out.

To score the items of source S, a model is trained on every other source, minus any item in
a near-duplicate cluster that also appears in S. So no score comes from a model that saw its
source, which is the same condition the pretrained baselines face on a source they did not
train on. Obfuscated copies are never trained on. Needs the ``sklearn`` extra.
"""

from __future__ import annotations

import importlib
from collections import defaultdict
from collections.abc import Sequence
from typing import Any

from ..items import Item


def _pipeline() -> Any:
    text: Any = importlib.import_module("sklearn.feature_extraction.text")
    linear: Any = importlib.import_module("sklearn.linear_model")
    pipeline: Any = importlib.import_module("sklearn.pipeline")

    return pipeline.make_pipeline(
        text.TfidfVectorizer(
            analyzer="char_wb", ngram_range=(3, 5), min_df=2, max_features=300_000,
            sublinear_tf=True,
        ),
        linear.LogisticRegression(max_iter=2000, class_weight="balanced", C=4.0),
    )  # fmt: skip


class TfidfLosoDetector:
    name = "tfidf"

    def __init__(self) -> None:
        self._trained: dict[str, int] = {}

    def info(self) -> dict[str, str]:
        sklearn: Any = importlib.import_module("sklearn")
        return {
            "model": "char 3-5 gram TF-IDF + logistic regression, leave-one-source-out",
            "sklearn": sklearn.__version__,
            "train_sizes": ", ".join(f"{k}={v}" for k, v in sorted(self._trained.items())),
        }

    def fingerprint(self) -> dict[str, str]:
        sklearn: Any = importlib.import_module("sklearn")
        return {"model": "char_wb 3-5, max 300k, sublinear; LR C=4 balanced", "loso": "source",
                "sklearn": sklearn.__version__}  # fmt: skip

    def groups(self, items: Sequence[Item]) -> list[tuple[str, list[int]]]:
        """One group per source: its items are scored by a model trained without it."""
        by_source: dict[str, list[int]] = defaultdict(list)
        for i, it in enumerate(items):
            by_source[it.source].append(i)
        return [(f"source-{s}", idx) for s, idx in sorted(by_source.items())]

    def score_group(self, items: Sequence[Item], idx: Sequence[int]) -> list[float]:
        source = items[idx[0]].source
        held_clusters = {items[i].cluster for i in idx}
        train = [
            it
            for it in items
            if not it.family.startswith("obf:")
            and it.source != source
            and it.cluster not in held_clusters
        ]
        if len({it.label for it in train}) < 2:
            raise ValueError(f"training set without {source} has only one label")
        model = _pipeline()
        model.fit([it.text for it in train], [it.label for it in train])
        self._trained[source] = len(train)
        return [float(p[1]) for p in model.predict_proba([items[i].text for i in idx])]
