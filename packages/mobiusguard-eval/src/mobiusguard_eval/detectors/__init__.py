"""Detectors the harness can score: our own and the baselines (decision 0006, rule 6).

A detector gives every item a score where higher means "more likely an attack". It sees the
whole list of items so that a baseline which needs training (TF-IDF) can train
leave-one-source-out; detectors that don't train just score the texts.

Work is split into *groups* (chunks of items, or one source for TF-IDF) so that a run can
save each group as it finishes and resume after a crash (:mod:`..checkpoint`).
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Protocol

from ..items import Item


class Detector(Protocol):
    name: str

    def info(self) -> dict[str, str]:
        """Model ID, revision, versions, device: whatever identifies what was measured."""
        ...

    def fingerprint(self) -> dict[str, str]:
        """What must match for saved scores to be reused (no timings or counts)."""
        ...

    def groups(self, items: Sequence[Item]) -> list[tuple[str, list[int]]]:
        """Units of work: a name and the positions of the items it scores."""
        ...

    def score_group(self, items: Sequence[Item], idx: Sequence[int]) -> list[float]:
        """Scores for ``items[i]`` for each ``i`` in ``idx``, in that order."""
        ...


CHUNK = 2048


def chunks(n: int, size: int = CHUNK) -> list[tuple[str, list[int]]]:
    """Fixed-size groups by position, for detectors that score items independently."""
    return [(f"chunk-{i // size:05d}", list(range(i, min(i + size, n)))) for i in range(0, n, size)]


def score_items(detector: Detector, items: Sequence[Item]) -> list[float]:
    """Score everything in one go, without checkpoints."""
    scores = [0.0] * len(items)
    for _, idx in detector.groups(items):
        for i, s in zip(idx, detector.score_group(items, idx), strict=True):
            scores[i] = s
    return scores


def get(name: str, *, device: str = "cpu", batch_size: int = 32) -> Detector:
    """A detector by name (see NAMES)."""
    factories: dict[str, Callable[[], Detector]] = {}

    from .keyword import KeywordDetector

    factories["keyword"] = KeywordDetector

    def tfidf() -> Detector:
        from .tfidf import TfidfLosoDetector

        return TfidfLosoDetector()

    def hf(key: str) -> Callable[[], Detector]:
        def make() -> Detector:
            from .hf import HF_MODELS, HFClassifier

            return HFClassifier(HF_MODELS[key], device=device, batch_size=batch_size)

        return make

    def rules() -> Detector:
        from .proxy import RulesDetector

        return RulesDetector()

    def norm(key: str) -> Callable[[], Detector]:
        def make() -> Detector:
            from .proxy import NormalizedClassifier

            return NormalizedClassifier(key, device=device, batch_size=batch_size)

        return make

    factories["tfidf"] = tfidf
    factories["protectai-v2"] = hf("protectai-v2")
    factories["piguard"] = hf("piguard")
    factories["mobiusguard-rules"] = rules
    factories["protectai-v2-norm"] = norm("protectai-v2")
    factories["piguard-norm"] = norm("piguard")
    if name.startswith("local:"):
        from .hf import local_classifier

        return local_classifier(name.removeprefix("local:"), device=device, batch_size=batch_size)
    if name not in factories:
        raise KeyError(f"unknown detector {name!r}; choose from {sorted(factories)}")
    return factories[name]()


NAMES = (
    "keyword",
    "tfidf",
    "protectai-v2",
    "piguard",
    "mobiusguard-rules",
    "protectai-v2-norm",
    "piguard-norm",
)
GPU = ("protectai-v2", "piguard", "protectai-v2-norm", "piguard-norm")
