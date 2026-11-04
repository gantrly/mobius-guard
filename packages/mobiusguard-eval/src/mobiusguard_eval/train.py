"""Fine-tune a base encoder on the v0.2 training set (decision 0012). Needs the ``hf`` and
``train`` extras and, in practice, a GPU.

One run = one base model and one seed. After each epoch the model is scored on ``val``
(never on the evaluation suite): AUC and recall at 1% false positives, with the threshold
set on val's own benign items. The epoch with the best val recall is kept in ``best/``.
Each epoch also saves a resume point, so a stopped run continues where it was.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import math
import random
import time
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .checkpoint import fingerprint, write_atomic
from .items import Item, read_jsonl
from .metrics import auc, threshold_at_fpr

BASES = {  # name: (repo, revision)
    "deberta-v3-xsmall": (
        "microsoft/deberta-v3-xsmall",
        "4b419818330868dff6a60ad3e6b1c730f8b8c0c6",
    ),
    "mmbert-small": ("jhu-clsp/mmBERT-small", "abc32620dd4f6ab06f5fbe905dc25f310618e09f"),
}
LABELS = {0: "benign", 1: "attack"}


@dataclass(frozen=True, slots=True)
class TrainConfig:
    base: str
    seed: int = 0
    epochs: int = 3
    lr: float = 5e-5
    batch_size: int = 32
    max_length: int = 256
    warmup: float = 0.06
    weight_decay: float = 0.01
    limit: int = 0  # use only N training items (and N/9 val items): the small run


def _subset(items: list[Item], n: int) -> list[Item]:
    if not n or n >= len(items):
        return items
    return sorted(items, key=lambda it: hashlib.sha256(it.id.encode()).hexdigest())[:n]


def val_metrics(scores: Sequence[float], labels: Sequence[int]) -> dict[str, float]:
    pos = [s for s, y in zip(scores, labels, strict=True) if y == 1]
    neg = [s for s, y in zip(scores, labels, strict=True) if y == 0]
    t = threshold_at_fpr(neg, 0.01)
    return {
        "auc": auc(pos, neg),
        "recall_at_1pct_fpr": sum(s >= t.value for s in pos) / max(1, len(pos)),
        "fpr_at_threshold": t.calibration_fpr,
        "n_attack": len(pos),
        "n_benign": len(neg),
    }


def train(
    data: Path, cfg: TrainConfig, out: Path, *, device: str = "cuda",
    log: Callable[[str], None] = print,
) -> dict[str, Any]:  # fmt: skip
    torch: Any = importlib.import_module("torch")
    tf: Any = importlib.import_module("transformers")
    repo, revision = BASES[cfg.base]
    summary = json.loads((data / "summary.json").read_text())
    key = {"config": asdict(cfg), "data": summary["ids_sha256"], "base": [repo, revision]}
    out.mkdir(parents=True, exist_ok=True)
    done = out / "metrics.json"
    if done.exists() and json.loads(done.read_text()).get("key") == fingerprint(key):
        log(f"train: {out} is done on this data and config, skipping")
        return json.loads(done.read_text())

    random.seed(cfg.seed)
    torch.manual_seed(cfg.seed)
    train_items = _subset(list(read_jsonl(data / "train.jsonl")), cfg.limit)
    val_items = _subset(list(read_jsonl(data / "val.jsonl")), cfg.limit // 9 if cfg.limit else 0)
    log(f"train: {cfg.base} seed {cfg.seed}: {len(train_items):,} train, {len(val_items):,} val")

    tok: Any = tf.AutoTokenizer.from_pretrained(repo, revision=revision)
    # float32 weights: DeBERTa-v3's checkpoint is float16, which transformers 5 keeps by
    # default, and training float16 weights with AdamW gives NaN from the second step.
    # Mixed precision (bf16 autocast) is applied to the computation only.
    model: Any = tf.AutoModelForSequenceClassification.from_pretrained(
        repo, revision=revision, num_labels=2, id2label=LABELS,
        label2id={v: k for k, v in LABELS.items()}, dtype=torch.float32,
    ).to(device)  # fmt: skip
    steps_per_epoch = math.ceil(len(train_items) / cfg.batch_size)
    total = steps_per_epoch * cfg.epochs
    opt: Any = torch.optim.AdamW(model.parameters(), lr=cfg.lr, weight_decay=cfg.weight_decay)
    sched: Any = tf.get_linear_schedule_with_warmup(opt, int(cfg.warmup * total), total)
    use_bf16 = device.startswith("cuda") and torch.cuda.is_bf16_supported()

    def batches(items: Sequence[Item], shuffle: bool) -> Any:
        order = list(range(len(items)))
        if shuffle:
            random.shuffle(order)
        for i in range(0, len(order), cfg.batch_size):
            chunk = [items[j] for j in order[i : i + cfg.batch_size]]
            enc = tok([it.text for it in chunk], truncation=True, max_length=cfg.max_length,
                      padding=True, return_tensors="pt")  # fmt: skip
            yield {k: v.to(device) for k, v in enc.items()}, [it.label for it in chunk]

    def scores(items: Sequence[Item]) -> list[float]:
        model.eval()
        result: list[float] = []
        with torch.no_grad(), torch.autocast("cuda", dtype=torch.bfloat16, enabled=use_bf16):
            for enc, _ in batches(items, shuffle=False):
                logits = model(**enc).logits.float()
                result += (logits[:, 1] - logits[:, 0]).tolist()
        model.train()
        return result

    history: list[dict[str, Any]] = []
    start_epoch = 0
    resume = out / "resume.pt"
    if resume.exists():
        state = torch.load(resume, map_location=device, weights_only=False)
        if state["key"] == fingerprint(key):
            model.load_state_dict(state["model"])
            opt.load_state_dict(state["opt"])
            sched.load_state_dict(state["sched"])
            random.setstate(state["random"])
            torch.set_rng_state(state["torch_rng"])
            start_epoch, history = state["epoch"], state["history"]
            log(f"train: resuming after epoch {start_epoch}")

    best = max((h["val"]["recall_at_1pct_fpr"] for h in history), default=-1.0)
    model.train()
    for epoch in range(start_epoch, cfg.epochs):
        t0, loss_sum, n = time.time(), 0.0, 0
        for step, (enc, labels) in enumerate(batches(train_items, shuffle=True), 1):
            with torch.autocast("cuda", dtype=torch.bfloat16, enabled=use_bf16):
                loss = model(**enc, labels=torch.tensor(labels, device=device)).loss
            if not torch.isfinite(loss):
                raise FloatingPointError(f"{cfg.base}: loss is {float(loss)} at epoch {epoch + 1} "
                                         f"step {step}; nothing saved from this epoch")  # fmt: skip
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            sched.step()
            opt.zero_grad(set_to_none=True)
            loss_sum, n = loss_sum + float(loss), n + 1
            if step % 500 == 0:
                where = f"epoch {epoch + 1} step {step}/{steps_per_epoch}"
                log(f"train: {where} loss {loss_sum / n:.4f}")
        val = val_metrics(scores(val_items), [it.label for it in val_items])
        history.append({"epoch": epoch + 1, "train_loss": loss_sum / max(1, n),
                        "seconds": round(time.time() - t0, 1), "val": val})  # fmt: skip
        log(f"train: epoch {epoch + 1}: loss {loss_sum / max(1, n):.4f}, val AUC "
            f"{val['auc']:.4f}, recall@1%FPR {val['recall_at_1pct_fpr']:.4f}")  # fmt: skip
        if val["recall_at_1pct_fpr"] > best:
            best = val["recall_at_1pct_fpr"]
            model.save_pretrained(out / "best")
            tok.save_pretrained(out / "best")
        torch.save({"key": fingerprint(key), "model": model.state_dict(), "opt": opt.state_dict(),
                    "sched": sched.state_dict(), "random": random.getstate(),
                    "torch_rng": torch.get_rng_state(), "epoch": epoch + 1,
                    "history": history}, resume)  # fmt: skip

    result: dict[str, Any] = {
        "key": fingerprint(key),
        "config": asdict(cfg),
        "base": {"repo": repo, "revision": revision},
        "data": {
            "dir": str(data),
            "ids_sha256": summary["ids_sha256"],
            "train": len(train_items),
            "val": len(val_items),
        },
        "device": torch.cuda.get_device_name(0) if device.startswith("cuda") else device,
        "torch": torch.__version__,
        "transformers": tf.__version__,
        "history": history,
        "best_epoch": max(history, key=lambda h: h["val"]["recall_at_1pct_fpr"])["epoch"],
    }
    write_atomic(done, json.dumps(result, indent=2) + "\n")
    resume.unlink(missing_ok=True)  # the run is complete; best/ holds the model
    return result
