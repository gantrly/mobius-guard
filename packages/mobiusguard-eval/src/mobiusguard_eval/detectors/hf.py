"""Pretrained classifiers for the harness: the proxy's own ``mobiusguard.classifier``,
with the methods the harness needs (fingerprint, groups). Needs the ``hf`` extra.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from pathlib import Path

from mobiusguard.classifier import HF_MODELS, HFModel
from mobiusguard.classifier import HFClassifier as _ProxyClassifier

from ..items import Item
from . import chunks

__all__ = ["HF_MODELS", "HFClassifier", "HFModel", "local_classifier", "local_spec"]


class HFClassifier(_ProxyClassifier):
    roles: bool = False  # mark each text with its item's role (decision 0020)

    def fingerprint(self) -> dict[str, str]:
        return {
            "repo": self.spec.repo,
            "revision": self.spec.revision,
            "max_length": str(self.spec.max_length),
            "device": self.device.split(":")[0],
            "output": "log-odds",
            **({"long": "windows"} if self.windows else {}),
            **({"roles": "marked (decision 0020)"} if self.roles else {}),
        }

    def _text(self, it: Item) -> str:
        if not self.roles:
            return it.text
        from mobiusguard.classifier import mark

        from ..roles import role_of

        return mark(it.text, role_of(it))

    def groups(self, items: Sequence[Item]) -> list[tuple[str, list[int]]]:
        return chunks(len(items))

    def score_group(self, items: Sequence[Item], idx: Sequence[int]) -> list[float]:
        # Sort by length so batches pad less; return in the given order.
        order = sorted(range(len(idx)), key=lambda k: len(items[idx[k]].text))
        scores = self.score_texts([self._text(items[idx[k]]) for k in order])
        result = [0.0] * len(idx)
        for k, s in zip(order, scores, strict=True):
            result[k] = s
        return result


def local_classifier(path: str, *, device: str = "cpu", batch_size: int = 32,
                     windows: bool = False, roles: bool = False) -> HFClassifier:  # fmt: skip
    """A model trained here (``train``), from its directory; ``DIR#harmful`` scores its
    harmful output instead of the attack output. Its fingerprint holds the weights' hash,
    so a retrained model is never mistaken for the old one's scores."""
    c = HFClassifier(local_spec(path), device=device, batch_size=batch_size, windows=windows)
    c.roles = roles
    tag = ("+windows" if windows else "") + ("+roles" if roles else "")
    if tag:
        c.name = c.name.replace("local:", f"local{tag}:", 1)
    return c


def local_spec(path: str) -> HFModel:
    """The model spec of a directory trained here; named after the directory's parent."""
    path, _, output = path.partition("#")
    d = Path(path)
    h = hashlib.sha256()
    for f in sorted(d.glob("*.safetensors")) + sorted(d.glob("*.bin")):
        h.update(f.read_bytes())
    label = output or "attack"
    return HFModel(name=f"local:{d.parent.name}#{label}", repo=str(d),
                   revision=h.hexdigest()[:40], licence="Apache-2.0",
                   positive_label=label)  # fmt: skip
