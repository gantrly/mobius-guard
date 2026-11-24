"""Optional classifiers: Mobius Guard's own Fortress (``mobiusguard[onnx]``) and two
published prompt-injection classifiers (``mobiusguard[classifier]``).

**Fortress** is an INT8 ONNX model with two outputs, attack and harmful, run with
onnxruntime and tokenizers (no torch). It ships its thresholds in ``fortress.json``.

The others are pinned to a commit. PIGuard ships its model class as remote code; we never
run downloaded code: the class is re-implemented below from the pinned ``modeling_piguard.py`` (a
DeBERTa-v2 encoder, the first token's hidden state, one linear layer) and only the weights
are downloaded. Scores are log-odds of the attack label (higher = more likely an attack).
The evaluation harness measures this same code.

**Long inputs.** By default a text longer than the model's 512 tokens is cut, so an
injection at the end of a long document is never seen. With ``windows=True`` (the policy's
``classifier_long = "windows"``), the text is scored in overlapping windows of 512 tokens,
``WINDOW_STRIDE`` tokens shared between neighbours, and the highest score counts. Each extra
window costs one more model call. Short texts score exactly as before.
"""

from __future__ import annotations

import importlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

WINDOW_STRIDE = 128  # tokens shared by neighbouring windows, so no phrase is only ever split


def window_stride(max_length: int) -> int:
    """``WINDOW_STRIDE``, or a quarter of the window for a model with short inputs."""
    return min(WINDOW_STRIDE, max_length // 4)


def max_by_owner(owners: Sequence[int], values: Sequence[float], n: int) -> list[float]:
    """The highest value per owner (a text's windows share an owner)."""
    best = [float("-inf")] * n
    for o, v in zip(owners, values, strict=True):
        best[o] = max(best[o], v)
    return best


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
    def __init__(self, spec: HFModel, *, device: str = "cpu", batch_size: int = 32,
                 windows: bool = False) -> None:  # fmt: skip
        self.spec = spec
        self.name = spec.name
        self.windows = windows
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
            "truncation": (f"overlapping windows of max_length tokens (stride {WINDOW_STRIDE}),"
                           " highest score" if self.windows else
                           "longer inputs are cut to max_length tokens (the model card usage)"),
        }  # fmt: skip
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
                chunk = list(texts[i : i + self.batch_size])
                extra: dict[str, Any] = (
                    {"stride": window_stride(self.spec.max_length),
                     "return_overflowing_tokens": True}
                    if self.windows else {}
                )  # fmt: skip
                enc = self.tokenizer(chunk, truncation=True, max_length=self.spec.max_length,
                                     padding=True, return_tensors="pt", **extra)  # fmt: skip
                owners = (enc.pop("overflow_to_sample_mapping").tolist() if self.windows
                          else list(range(len(chunk))))  # fmt: skip
                enc = enc.to(self.device)
                logits = self.model(
                    input_ids=enc["input_ids"], attention_mask=enc["attention_mask"]
                ).logits
                if self.multi_label:  # independent sigmoid outputs: the logit is the log-odds
                    vals = [float(v) for v in logits[:, self.positive].double().cpu().tolist()]
                else:
                    # Log-odds of the positive label, not its probability: probabilities round
                    # to exactly 1.0 in float32 for confident inputs; ties can't be thresholded.
                    lp = t.log_softmax(logits.double(), dim=-1)
                    rest = t.logsumexp(
                        t.cat([lp[:, : self.positive], lp[:, self.positive + 1 :]], dim=-1), dim=-1
                    )
                    vals = [float(v) for v in (lp[:, self.positive] - rest).cpu().tolist()]
                out.extend(max_by_owner(owners, vals, len(chunk)))
        return out


# ------------------------------------------------------------------------------ Fortress


@dataclass(frozen=True, slots=True)
class OnnxModel:
    name: str
    repo: str
    revision: str  # a Hugging Face commit; "" = not published, only ``classifier_dir`` works
    licence: str
    file: str = "model.int8.onnx"
    # The attack threshold for scoring every view of a text (decision 0015), as (the model's
    # own attack threshold it was set for, the threshold). Set on the same ordinary messages
    # as the model's own, so it blocks no more of them; None = original text only.
    views_attack: tuple[float, float] | None = None


ONNX_MODELS = {
    "fortress-xs": OnnxModel(
        name="fortress-xs",
        repo="gantrly/fortress-xs",
        revision="420ca0aa43fdee63ae6d7be44524a890f275c12a",  # v1
        licence="Apache-2.0",
        # set 2026-11-10 on oasst1's dev half: 153 of 16,284 blocked, as at 2.7634 on the
        # original text (docs/results/2026-11-10-classifier-views.md)
        views_attack=(2.7634, 3.110666513442993),
    ),
}
ONNX_FILES = ("model.int8.onnx", "tokenizer.json", "fortress.json")


class OnnxClassifier:
    """Fortress: one forward pass gives both outputs' log-odds. ``score_texts`` returns
    ``(attack, harmful)`` per text; ``thresholds`` are the model's own (at the false-positive
    rate named in ``fortress.json``), set on ordinary user messages."""

    def __init__(
        self,
        spec: OnnxModel,
        *,
        directory: str = "",
        threads: int = 0,
        batch_size: int = 1,
        windows: bool = False,
    ) -> None:
        # One text per run by default: dynamic INT8 quantizes each batch as a whole, so in a
        # batch a text's score moves (up to ~0.5 log-odds) with its neighbours and padding.
        # Alone, a text always gets the same score.
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
        # Only for the files it was set on: another model keeps to its original text.
        own, every = spec.views_attack or (None, None)
        self.views_thresholds: dict[str, float] | None = (
            {**self.thresholds, "attack": every}
            if every is not None and own is not None and abs(self.thresholds["attack"] - own) < 1e-9
            else None
        )
        self.np: Any = importlib.import_module("numpy")
        ort: Any = importlib.import_module("onnxruntime")
        tok: Any = importlib.import_module("tokenizers").Tokenizer.from_file(
            str(d / "tokenizer.json")
        )
        self.windows = windows
        tok.enable_truncation(
            self.max_length, stride=window_stride(self.max_length) if windows else 0
        )
        pad = "[PAD]"  # a token name, not a secret
        self.pad_id: int = tok.token_to_id(pad)
        tok.enable_padding(pad_id=self.pad_id, pad_token=pad)
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
        if self.windows:
            return self._score_windows(texts, order, a, h)
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

    def _score_windows(
        self, texts: Sequence[str], order: Sequence[int], a: int, h: int
    ) -> list[tuple[float, float]]:
        """Every window of every text, ``batch_size`` windows per run; the highest score of
        a text's windows counts, per output."""
        np = self.np
        owners: list[int] = []
        wins: list[tuple[list[int], list[int]]] = []
        for k in order:
            e = self.tokenizer.encode(texts[k])
            for w in [e, *e.overflowing]:
                owners.append(k)
                wins.append((list(w.ids), list(w.attention_mask)))
        attack: list[float] = []
        harmful: list[float] = []
        for i in range(0, len(wins), self.batch_size):
            part = wins[i : i + self.batch_size]
            n = max(len(ids) for ids, _ in part)
            feed = {
                "input_ids": np.array([ids + [self.pad_id] * (n - len(ids)) for ids, _ in part],
                                      dtype=np.int64),
                "attention_mask": np.array([m + [0] * (n - len(m)) for _, m in part],
                                           dtype=np.int64),
            }  # fmt: skip
            for row in self.session.run(["logits"], feed)[0].tolist():
                attack.append(float(row[a]))
                harmful.append(float(row[h]))
        best_a = max_by_owner(owners, attack, len(texts))
        best_h = max_by_owner(owners, harmful, len(texts))
        return list(zip(best_a, best_h, strict=True))
