"""The proxy's own request check, measured with the same rules as the baselines.

- ``mobiusguard-rules``: normalisation + rules, exactly as the proxy runs them. Score =
  2 x high-severity hits + medium hits, so a score of 2 or more is the proxy's default
  block decision.
- ``<model>-norm``: a pretrained classifier given every view of each text (original,
  normalised, decoded base64) with the highest score kept, to show what normalisation
  alone does for an existing model.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

from mobiusguard.normalize import views
from mobiusguard.rules import RULES, check

from ..items import Item
from . import chunks
from .hf import HF_MODELS, HFClassifier


class RulesDetector:
    name = "mobiusguard-rules"

    def info(self) -> dict[str, str]:
        return {"model": "Mobius Guard normalisation + rules", "rules": str(len(RULES))}

    def fingerprint(self) -> dict[str, str]:
        src = "\n".join(f"{r.id}|{r.severity}|{r.pattern}" for r in RULES)
        import mobiusguard.normalize as norm

        with open(norm.__file__, "rb") as f:
            norm_hash = hashlib.sha256(f.read()).hexdigest()
        return {"rules": hashlib.sha256(src.encode()).hexdigest(), "normalize": norm_hash}

    def score_text(self, text: str) -> float:
        hits = check(views(text), "t")
        return float(sum(2 if h.severity == "high" else 1 for h in hits))

    def groups(self, items: Sequence[Item]) -> list[tuple[str, list[int]]]:
        return chunks(len(items))

    def score_group(self, items: Sequence[Item], idx: Sequence[int]) -> list[float]:
        return [self.score_text(items[i].text) for i in idx]


class NormalizedClassifier(HFClassifier):
    """A pretrained classifier scored on every view of a text; the highest score counts."""

    def __init__(self, key: str, *, device: str = "cpu", batch_size: int = 32) -> None:
        super().__init__(HF_MODELS[key], device=device, batch_size=batch_size)
        self.name = f"{key}-norm"

    def fingerprint(self) -> dict[str, str]:
        return {**super().fingerprint(), "views": "original+normalized+base64, max"}

    def score_group(self, items: Sequence[Item], idx: Sequence[int]) -> list[float]:
        owners: list[int] = []
        texts: list[str] = []
        for k, i in enumerate(idx):
            for v in views(items[i].text):
                owners.append(k)
                texts.append(v.text)
        order = sorted(range(len(texts)), key=lambda j: len(texts[j]))
        scored = self.score_texts([texts[j] for j in order])
        best = [float("-inf")] * len(idx)
        for j, s in zip(order, scored, strict=True):
            best[owners[j]] = max(best[owners[j]], s)
        return best
