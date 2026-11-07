"""Optional classifiers: Mobius Guard's own Fortress (``mobiusguard[onnx]``) and two
published prompt-injection classifiers (``mobiusguard[classifier]``).

**Fortress** is an INT8 ONNX model with two outputs, attack and harmful, run with
onnxruntime and tokenizers (no torch). It ships its thresholds in ``fortress.json``.

The others are pinned to a commit. PIGuard ships its model class as remote code; we never
run downloaded code: the class is re-implemented below from the pinned ``modeling_piguard.py`` (a
DeBERTa-v2 encoder, the first token's hidden state, one linear layer) and only the weights
are downloaded. Scores are log-odds of the attack label (higher = more likely an attack).
The evaluation harness measures this same code.
"""

from __future__ import annotations

import importlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any


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
        # Mobius Guard's own model has two independent outputs (attack, harmful).
        self.multi_label = self.model.config.problem_type == "multi_label_classification"

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
                if self.multi_label:  # independent sigmoid outputs: the logit is the log-odds
                    out.extend(float(v) for v in logits[:, self.positive].double().cpu().tolist())
                    continue
                # Log-odds of the positive label, not its probability: probabilities round to
                # exactly 1.0 in float32 for confident inputs, and ties can't be thresholded.
                lp = t.log_softmax(logits.double(), dim=-1)
                rest = t.logsumexp(
                    t.cat([lp[:, : self.positive], lp[:, self.positive + 1 :]], dim=-1), dim=-1
                )
                out.extend(float(v) for v in (lp[:, self.positive] - rest).cpu().tolist())
        return out


# ------------------------------------------------------------------------------ Fortress


@dataclass(frozen=True, slots=True)
class OnnxModel:
    name: str
    repo: str
    revision: str  # a Hugging Face commit; "" = not published, only ``classifier_dir`` works
    licence: str
    file: str = "model.int8.onnx"


ONNX_MODELS = {
    "fortress-xs": OnnxModel(
        name="fortress-xs",
        repo="gantrly/fortress-xs",
        revision="420ca0aa43fdee63ae6d7be44524a890f275c12a",  # v1
        licence="Apache-2.0",
    ),
}
ONNX_FILES = ("model.int8.onnx", "tokenizer.json", "fortress.json")


class OnnxClassifier:
    """Fortress: one forward pass gives both outputs' log-odds. ``score_texts`` returns
    ``(attack, harmful)`` per text; ``thresholds`` are the model's own (at the false-positive
    rate named in ``fortress.json``), set on ordinary user messages."""

    def __init__(
        self, spec: OnnxModel, *, directory: str = "", threads: int = 0, batch_size: int = 8
    ) -> None:
        self.spec = spec
        self.name = spec.name
        self.batch_size = batch_size
        if directory:
            d = Path(directory)
        elif spec.revision:
            hub: Any = importlib.import_module("huggingface_hub")
            d = Path(
                hub.snapshot_download(
                    spec.repo, revision=spec.revision, allow_patterns=list(ONNX_FILES)
                )
            )
        else:
            raise ValueError(f"{spec.name} is not published yet: set policy.classifier_dir")
        meta: dict[str, Any] = json.loads((d / "fortress.json").read_text())
        self.outputs: list[str] = [str(o) for o in meta["outputs"]]
        self.max_length = int(meta["max_length"])
        fpr = str(meta["default_fpr"])
        self.thresholds = {o: float(meta["thresholds"][o][fpr]) for o in self.outputs}
        self.np: Any = importlib.import_module("numpy")
        ort: Any = importlib.import_module("onnxruntime")
        tok: Any = importlib.import_module("tokenizers").Tokenizer.from_file(
            str(d / "tokenizer.json")
        )
        tok.enable_truncation(self.max_length)
        pad = "[PAD]"  # a token name, not a secret
        tok.enable_padding(pad_id=tok.token_to_id(pad), pad_token=pad)
        self.tokenizer = tok
        opts = ort.SessionOptions()
        if threads:
            opts.intra_op_num_threads = threads
        self.session: Any = ort.InferenceSession(
            str(d / spec.file), opts, providers=["CPUExecutionProvider"]
        )
        self.versions = {"onnxruntime": str(ort.__version__)}

    def score_texts(self, texts: Sequence[str]) -> list[tuple[float, float]]:
        np = self.np
        a, h = self.outputs.index("attack"), self.outputs.index("harmful")
        out: list[tuple[float, float]] = [(0.0, 0.0)] * len(texts)
        # Sort by length so batches pad less; return in the given order.
        order = sorted(range(len(texts)), key=lambda i: len(texts[i]))
        for i in range(0, len(order), self.batch_size):
            idx = order[i : i + self.batch_size]
            enc = self.tokenizer.encode_batch([texts[k] for k in idx])
            feed = {
                "input_ids": np.array([e.ids for e in enc], dtype=np.int64),
                "attention_mask": np.array([e.attention_mask for e in enc], dtype=np.int64),
            }
            logits = self.session.run(["logits"], feed)[0]
            for k, row in zip(idx, logits.tolist(), strict=True):
                out[k] = (float(row[a]), float(row[h]))
        return out
