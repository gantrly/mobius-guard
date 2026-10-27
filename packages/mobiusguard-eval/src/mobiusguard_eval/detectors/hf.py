"""Pretrained classifiers from Hugging Face, pinned to a commit. Needs the ``hf`` extra.

PIGuard ships its model class as remote code. We never run downloaded code: the class is
re-implemented below from the pinned ``modeling_piguard.py`` (a DeBERTa-v2 encoder, the
first token's hidden state, one linear layer) and only the weights are downloaded.
"""

from __future__ import annotations

import importlib
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from ..items import Item
from . import chunks


@dataclass(frozen=True, slots=True)
class HFModel:
    name: str
    repo: str
    revision: str
    licence: str
    positive_label: str
    arch: str = "auto"  # or "piguard"
    max_length: int = 512


HF_MODELS = {
    "protectai-v2": HFModel(
        name="protectai-v2",
        repo="protectai/deberta-v3-base-prompt-injection-v2",
        revision="90c9989b1a342275dd0d1a95aad283c04e075671",
        licence="Apache-2.0",
        positive_label="INJECTION",
    ),
    "piguard": HFModel(
        name="piguard",
        repo="leolee99/PIGuard",
        revision="dd78b24e330193a22d2293ac66922dd4f982f563",
        licence="MIT",
        positive_label="injection",
        arch="piguard",
    ),
}


def _piguard_class(transformers: Any, torch: Any) -> Any:
    outputs = importlib.import_module("transformers.modeling_outputs")

    class PIGuard(transformers.DebertaV2ForSequenceClassification):
        def __init__(self, config: Any) -> None:
            super().__init__(config)  # pyright: ignore[reportUnknownMemberType]
            self.classifier = torch.nn.Linear(config.hidden_size, config.num_labels)

        def forward(self, input_ids: Any, attention_mask: Any, **kwargs: Any) -> Any:
            out = self.deberta(input_ids=input_ids, attention_mask=attention_mask)
            logits = self.classifier(out.last_hidden_state[:, 0, :])
            return outputs.SequenceClassifierOutput(logits=logits)

    return PIGuard


class HFClassifier:
    def __init__(self, spec: HFModel, *, device: str = "cpu", batch_size: int = 32) -> None:
        self.spec = spec
        self.name = spec.name
        self.device = device
        self.batch_size = batch_size
        self.torch: Any = importlib.import_module("torch")
        self.transformers: Any = importlib.import_module("transformers")
        tf = self.transformers
        self.tokenizer: Any = tf.AutoTokenizer.from_pretrained(
            spec.repo, revision=spec.revision, trust_remote_code=False
        )
        if spec.arch == "piguard":
            config = tf.DebertaV2Config.from_pretrained(
                spec.repo, revision=spec.revision, trust_remote_code=False
            )
            cls = _piguard_class(tf, self.torch)
            model = cls.from_pretrained(
                spec.repo, revision=spec.revision, config=config, trust_remote_code=False
            )
        else:
            model = tf.AutoModelForSequenceClassification.from_pretrained(
                spec.repo, revision=spec.revision, trust_remote_code=False
            )
        self.model: Any = model.to(device).eval()
        labels = {str(v).lower(): int(k) for k, v in self.model.config.id2label.items()}
        self.positive = labels[spec.positive_label.lower()]

    def info(self) -> dict[str, str]:
        t = self.torch
        info = {
            "repo": self.spec.repo,
            "revision": self.spec.revision,
            "licence": self.spec.licence,
            "device": self.device,
            "torch": t.__version__,
            "transformers": self.transformers.__version__,
            "max_length": str(self.spec.max_length),
            "score": "log-odds of the attack label",
            "truncation": "longer inputs are cut to max_length tokens (the model card usage)",
        }
        if self.device.startswith("cuda"):
            info["gpu"] = t.cuda.get_device_name(0)
        else:
            info["threads"] = str(t.get_num_threads())
        return info

    def score_texts(self, texts: Sequence[str]) -> list[float]:
        t = self.torch
        out: list[float] = []
        with t.inference_mode():
            for i in range(0, len(texts), self.batch_size):
                enc = self.tokenizer(
                    list(texts[i : i + self.batch_size]),
                    truncation=True,
                    max_length=self.spec.max_length,
                    padding=True,
                    return_tensors="pt",
                ).to(self.device)
                logits = self.model(
                    input_ids=enc["input_ids"], attention_mask=enc["attention_mask"]
                ).logits
                # Log-odds of the positive label, not its probability: probabilities round to
                # exactly 1.0 in float32 for confident inputs, and ties can't be thresholded.
                lp = t.log_softmax(logits.double(), dim=-1)
                rest = t.logsumexp(
                    t.cat([lp[:, : self.positive], lp[:, self.positive + 1 :]], dim=-1), dim=-1
                )
                out.extend(float(v) for v in (lp[:, self.positive] - rest).cpu().tolist())
        return out

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
