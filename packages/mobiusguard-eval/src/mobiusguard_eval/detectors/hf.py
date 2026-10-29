"""Pretrained classifiers for the harness: the proxy's own ``mobiusguard.classifier``,
with the methods the harness needs (fingerprint, groups). Needs the ``hf`` extra.
"""

from __future__ import annotations

from collections.abc import Sequence

from mobiusguard.classifier import HF_MODELS, HFModel
from mobiusguard.classifier import HFClassifier as _ProxyClassifier

from ..items import Item
from . import chunks

__all__ = ["HF_MODELS", "HFClassifier", "HFModel"]


class HFClassifier(_ProxyClassifier):
    def fingerprint(self) -> dict[str, str]:
        return {
            "repo": self.spec.repo,
            "revision": self.spec.revision,
            "max_length": str(self.spec.max_length),
            "device": self.device.split(":")[0],
            "output": "log-odds",
        }

    def groups(self, items: Sequence[Item]) -> list[tuple[str, list[int]]]:
        return chunks(len(items))

    def score_group(self, items: Sequence[Item], idx: Sequence[int]) -> list[float]:
        # Sort by length so batches pad less; return in the given order.
        order = sorted(range(len(idx)), key=lambda k: len(items[idx[k]].text))
        scores = self.score_texts([items[idx[k]].text for k in order])
        result = [0.0] * len(idx)
        for k, s in zip(order, scores, strict=True):
            result[k] = s
        return result
