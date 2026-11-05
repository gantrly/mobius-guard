"""Fine-tune a base encoder on the v0.2 training set (decision 0012). Needs the ``hf`` and
``train`` extras and, in practice, a GPU.

One run = one base model and one seed. The model has two independent outputs (sigmoid,
each read as log-odds): ``attack`` (an injection or a jailbreak) and ``harmful`` (a harmful
request). The harmful loss skips items whose harmful label is unknown.

After each epoch both outputs are scored on ``val`` (never on the evaluation suite): AUC and
recall at 1% false positives, the threshold set on val's own negatives. The epoch with the
best mean of the two recalls is kept in ``best/``.

Batches group texts of similar length (most are short, so padding to the longest text in a
random batch wastes most of the compute); each epoch's order is fixed by the seed and the
epoch, so a resumed run continues at the exact batch where it stopped. A resume point is
written every ``checkpoint_minutes`` and at the end of each epoch, atomically.
``stop_after_minutes`` (rehearsals) stops cleanly: resume point, val, and the model in
``partial/``.
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
LABELS = {0: "attack", 1: "harmful"}  # two independent outputs (multi-label)


@dataclass(frozen=True, slots=True)
class TrainConfig:
    base: str
    seed: int = 0
    epochs: int = 3
    lr: float = 5e-5
    batch_size: int = 32
    max_length: int = 512
    warmup: float = 0.06
    weight_decay: float = 0.01
    limit: int = 0  # use only N training items (and N/9 val items): the small run
    checkpoint_minutes: float = 20.0  # not part of the run's identity
    stop_after_minutes: float = 0.0  # 0 = run to the end; not part of the run's identity

    def key(self) -> dict[str, Any]:
        """What makes two runs the same run (and a resume point usable)."""
        d = asdict(self)
        d.pop("checkpoint_minutes")
        d.pop("stop_after_minutes")
        return d


BUCKET = 50  # batches per length-sorted window


def _subset(items: list[Item], n: int) -> list[Item]:
    if not n or n >= len(items):
        return items
    return sorted(items, key=lambda it: hashlib.sha256(it.id.encode()).hexdigest())[:n]


def restore_rng(torch: Any, state: dict[str, Any], *, cuda: bool) -> None:
    """Restore the RNG state saved in a resume point. ``torch.load(map_location="cuda")``
    moves every tensor to the GPU, but the RNG setters only accept CPU byte tensors."""
    torch.set_rng_state(state["torch_rng"].cpu())
    if cuda and state.get("cuda_rng") is not None:
        torch.cuda.set_rng_state_all([s.cpu() for s in state["cuda_rng"]])


def _harmful(it: Item) -> float:
    """1.0, 0.0, or -1.0 when unknown (masked out of the loss and the metrics)."""
    return {"1": 1.0, "0": 0.0}.get(it.meta.get("harmful", ""), -1.0)


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
    key = {"config": cfg.key(), "data": summary["ids_sha256"], "base": [repo, revision]}
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
        problem_type="multi_label_classification",
    ).to(device)  # fmt: skip
    bce: Any = torch.nn.BCEWithLogitsLoss(reduction="none")
    total = math.ceil(len(train_items) / cfg.batch_size) * cfg.epochs
    opt: Any = torch.optim.AdamW(model.parameters(), lr=cfg.lr, weight_decay=cfg.weight_decay)
    sched: Any = tf.get_linear_schedule_with_warmup(opt, int(cfg.warmup * total), total)
    use_bf16 = device.startswith("cuda") and torch.cuda.is_bf16_supported()

    def encode(chunk: Sequence[Item]) -> tuple[dict[str, Any], Any]:
        enc = tok([it.text for it in chunk], truncation=True, max_length=cfg.max_length,
                  padding=True, return_tensors="pt")  # fmt: skip
        targets = torch.tensor([[float(it.label), _harmful(it)] for it in chunk], device=device)
        return {k: v.to(device) for k, v in enc.items()}, targets

    def plan(epoch: int) -> list[list[int]]:
        """The epoch's batches: shuffled, then length-sorted inside windows, then shuffled
        again as batches. Fixed by (seed, epoch), so a resume replays the same order."""
        rng = random.Random(f"{cfg.seed}:{epoch}")  # noqa: S311 - a training order, not a secret
        order = list(range(len(train_items)))
        rng.shuffle(order)
        window = cfg.batch_size * BUCKET
        result: list[list[int]] = []
        for w in range(0, len(order), window):
            part = sorted(order[w : w + window], key=lambda j: lengths[j])
            result += [part[i : i + cfg.batch_size] for i in range(0, len(part), cfg.batch_size)]
        rng.shuffle(result)
        return result

    def loss_of(logits: Any, targets: Any) -> Any:
        known = targets >= 0
        per = bce(logits.float(), targets.clamp(min=0)) * known
        return per.sum() / known.sum().clamp(min=1)

    def scores(items: Sequence[Item]) -> tuple[list[float], list[float]]:
        model.eval()
        attack = [0.0] * len(items)
        harmful = [0.0] * len(items)
        order = sorted(range(len(items)), key=lambda j: len(items[j].text))  # less padding
        with torch.no_grad(), torch.autocast("cuda", dtype=torch.bfloat16, enabled=use_bf16):
            for i in range(0, len(order), cfg.batch_size):
                idx = order[i : i + cfg.batch_size]
                enc, _ = encode([items[j] for j in idx])
                logits = model(**enc).logits.float()
                for j, a, h in zip(idx, logits[:, 0].tolist(), logits[:, 1].tolist(), strict=True):
                    attack[j], harmful[j] = a, h
        model.train()
        return attack, harmful

    def evaluate(items: Sequence[Item]) -> dict[str, Any]:
        attack, harmful = scores(items)
        known = [(s, int(_harmful(it))) for s, it in zip(harmful, items, strict=True)
                 if _harmful(it) >= 0]  # fmt: skip
        result: dict[str, Any] = {"attack": val_metrics(attack, [it.label for it in items])}
        if known and any(y for _, y in known) and not all(y for _, y in known):
            result["harmful"] = val_metrics([s for s, _ in known], [y for _, y in known])
        recalls = [result[k]["recall_at_1pct_fpr"] for k in ("attack", "harmful") if k in result]
        result["selection"] = sum(recalls) / len(recalls)
        return result

    lengths = [len(it.text) for it in train_items]
    cuda = device.startswith("cuda")
    if cuda:
        torch.cuda.reset_peak_memory_stats()

    def peak_gb() -> float:
        return round(torch.cuda.max_memory_allocated() / 2**30, 2) if cuda else 0.0

    history: list[dict[str, Any]] = []
    start_epoch, start_step, carried = 0, 0, (0.0, 0)
    resume = out / "resume.pt"
    if resume.exists():
        state = torch.load(resume, map_location=device, weights_only=False)
        if state["key"] == fingerprint(key):
            model.load_state_dict(state["model"])
            opt.load_state_dict(state["opt"])
            sched.load_state_dict(state["sched"])
            restore_rng(torch, state, cuda=cuda)
            start_epoch, start_step = state["epoch"], state["step"]
            history, carried = state["history"], (state["loss_sum"], state["n"])
            log(f"train: resuming at epoch {start_epoch + 1}, step {start_step}")

    def save_resume(epoch: int, step: int, loss_sum: float, n: int) -> None:
        tmp = resume.with_suffix(".tmp")
        torch.save({"key": fingerprint(key), "model": model.state_dict(), "opt": opt.state_dict(),
                    "sched": sched.state_dict(), "torch_rng": torch.get_rng_state(),
                    "cuda_rng": torch.cuda.get_rng_state_all() if cuda else None,
                    "epoch": epoch, "step": step, "loss_sum": loss_sum, "n": n,
                    "history": history}, tmp)  # fmt: skip
        tmp.replace(resume)  # a kill mid-save leaves the old resume point intact

    best = max((h["val"]["selection"] for h in history), default=-1.0)
    started = last_save = time.time()
    model.train()
    for epoch in range(start_epoch, cfg.epochs):
        batches = plan(epoch)
        first = start_step if epoch == start_epoch else 0
        loss_sum, n = carried if epoch == start_epoch else (0.0, 0)
        t0, seen = time.time(), 0
        for step in range(first, len(batches)):
            enc, targets = encode([train_items[j] for j in batches[step]])
            with torch.autocast("cuda", dtype=torch.bfloat16, enabled=use_bf16):
                loss = loss_of(model(**enc).logits, targets)
            if not torch.isfinite(loss):
                where = f"epoch {epoch + 1} step {step}"
                raise FloatingPointError(f"{cfg.base}: loss is {float(loss)} at {where}; "
                                         "the last resume point is unchanged")  # fmt: skip
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            sched.step()
            opt.zero_grad(set_to_none=True)
            loss_sum, n, seen = loss_sum + loss.detach().item(), n + 1, seen + len(batches[step])
            if (step + 1) % 500 == 0:
                rate = seen / (time.time() - t0)
                log(f"train: epoch {epoch + 1} step {step + 1}/{len(batches)} loss "
                    f"{loss_sum / n:.4f}, {rate:.0f} items/s, peak GPU {peak_gb()} GB")  # fmt: skip
            now = time.time()
            if now - last_save >= cfg.checkpoint_minutes * 60:
                save_resume(epoch, step + 1, loss_sum, n)
                last_save = now
                log(f"train: resume point at epoch {epoch + 1} step {step + 1}")
            if cfg.stop_after_minutes and now - started >= cfg.stop_after_minutes * 60:
                save_resume(epoch, step + 1, loss_sum, n)
                val = evaluate(val_items)
                model.save_pretrained(out / "partial")
                tok.save_pretrained(out / "partial")
                stopped = {"stopped_at": {"epoch": epoch + 1, "step": step + 1,
                                          "of": len(batches)},
                           "items_per_second": round(seen / (now - t0), 1),
                           "peak_gpu_gb": peak_gb(), "train_loss": loss_sum / max(1, n),
                           "val": val, "val_seconds": round(time.time() - now, 1)}  # fmt: skip
                write_atomic(out / "partial.json", json.dumps(stopped, indent=2) + "\n")
                log(f"train: stopped after {cfg.stop_after_minutes} min as asked; "
                    f"wrote {out / 'partial'}")  # fmt: skip
                return stopped
        val = evaluate(val_items)
        history.append({"epoch": epoch + 1, "train_loss": loss_sum / max(1, n),
                        "seconds": round(time.time() - t0, 1),
                        "items_per_second": round(seen / max(1e-9, time.time() - t0), 1),
                        "peak_gpu_gb": peak_gb(), "val": val})  # fmt: skip
        parts = [f"{k} AUC {val[k]['auc']:.4f} recall@1%FPR {val[k]['recall_at_1pct_fpr']:.4f}"
                 for k in ("attack", "harmful") if k in val]  # fmt: skip
        log(f"train: epoch {epoch + 1}: loss {loss_sum / max(1, n):.4f}, val " + "; ".join(parts))
        if val["selection"] > best:
            best = val["selection"]
            model.save_pretrained(out / "best")
            tok.save_pretrained(out / "best")
        save_resume(epoch + 1, 0, 0.0, 0)
        last_save = time.time()

    result: dict[str, Any] = {
        "key": fingerprint(key),
        "config": cfg.key(),
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
        "best_epoch": max(history, key=lambda h: h["val"]["selection"])["epoch"],
    }
    write_atomic(done, json.dumps(result, indent=2) + "\n")
    resume.unlink(missing_ok=True)  # the run is complete; best/ holds the model
    return result
