"""Distillation (decision 0022): the teacher's scores as soft targets for xsmall.

Two steps before training:

- ``pool``: extra text for the teacher to score. These are items the training build's
  per-source caps cut (``train-data --spill``): they passed every check, but no model
  trained on them, so the teacher's scores there are honest. Near duplicates of any
  evaluation item are dropped, and so are items already in the training set. Each text is
  role-marked as training is. The labels are ignored (``meta["distill_only"]``): only the
  teacher's scores teach.
- ``teacher_scores``: the teacher's two logits (attack, harmful) for every item of the
  given files, as it was trained to read them (marked text, up to 512 tokens). One row
  per item: ``{"id", "attack", "harmful"}``.
"""

from __future__ import annotations

import hashlib
import importlib
import json
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

from mobiusguard.classifier import mark

from .dedup import clusters
from .items import Item, read_jsonl, write_jsonl
from .roles import role_of

POOL_SALT = "mobius-guard distillation pool v1"


def _rank(it: Item) -> str:
    return hashlib.sha256(f"{POOL_SALT}:{it.id}".encode()).hexdigest()


def pool(spill: Path, held_out: Sequence[Path], train: Sequence[Path], out: Path, *,
         size: int, log: Callable[[str], None] = lambda _m: None) -> dict[str, Any]:  # fmt: skip
    """Write ``out/items.jsonl`` (at most ``size`` items) and ``out/summary.json``.

    ``held_out``: items files whose texts must not be near duplicated (suites, held-out
    tool outputs, the document calibration set). ``train``: the training files, whose IDs
    are left out."""
    seen = {it.id for f in train for it in read_jsonl(f)}
    held = [it.text for f in held_out for it in read_jsonl(f)]
    cand = [it for it in read_jsonl(spill) if it.id not in seen]
    log(f"distill-pool: {len(cand):,} spilled items not in training; checking against "
        f"{len(held):,} held-out texts")  # fmt: skip
    idx = clusters(held + [it.text for it in cand])
    near = set(idx[: len(held)])
    keep = [it for i, it in enumerate(cand) if idx[len(held) + i] not in near]
    n_near = len(cand) - len(keep)
    keep.sort(key=_rank)
    keep = keep[:size]
    marked = [
        replace(it, text=mark(it.text, role_of(it)), split="train",
                meta={**it.meta, "role": role_of(it), "distill_only": "1"})
        for it in keep
    ]  # fmt: skip
    marked.sort(key=lambda it: it.id)
    out.mkdir(parents=True, exist_ok=True)
    write_jsonl(out / "items.jsonl", marked)
    summary: dict[str, Any] = {
        "from_spill": str(spill),
        "held_out": [str(p) for p in held_out],
        "candidates": len(cand),
        "near_held_out": n_near,
        "items": len(marked),
        "by_source": dict(Counter(it.source for it in marked).most_common()),
        "by_role": dict(Counter(it.meta["role"] for it in marked)),
        "ids_sha256": hashlib.sha256("\n".join(it.id for it in marked).encode()).hexdigest(),
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


def teacher_scores(model: Path, files: Sequence[Path], out: Path, *, device: str = "cuda",
                   batch_size: int = 64, max_length: int = 512,
                   log: Callable[[str], None] = lambda _m: None) -> int:  # fmt: skip
    """Write ``out`` (JSONL): the teacher's raw logits for every item of ``files``."""
    torch: Any = importlib.import_module("torch")
    tf: Any = importlib.import_module("transformers")
    tok: Any = tf.AutoTokenizer.from_pretrained(model)
    net: Any = tf.AutoModelForSequenceClassification.from_pretrained(model).to(device).eval()
    use_bf16 = device.startswith("cuda") and torch.cuda.is_bf16_supported()
    items = [it for f in files for it in read_jsonl(f)]
    order = sorted(range(len(items)), key=lambda j: len(items[j].text))  # less padding
    rows: dict[int, tuple[float, float]] = {}
    with torch.no_grad(), torch.autocast("cuda", dtype=torch.bfloat16, enabled=use_bf16):
        for i in range(0, len(order), batch_size):
            idx = order[i : i + batch_size]
            enc = tok([items[j].text for j in idx], truncation=True, max_length=max_length,
                      padding=True, return_tensors="pt")  # fmt: skip
            logits = net(**{k: v.to(device) for k, v in enc.items()}).logits.float()
            for j, a, h in zip(idx, logits[:, 0].tolist(), logits[:, 1].tolist(), strict=True):
                rows[j] = (a, h)
            if (i // batch_size) % 500 == 0:
                log(f"teacher-scores: {i + len(idx):,} of {len(items):,}")
    tmp = out.with_suffix(".tmp")
    out.parent.mkdir(parents=True, exist_ok=True)
    with tmp.open("w") as f:
        for j, it in enumerate(items):
            a, h = rows[j]
            f.write(json.dumps({"id": it.id, "attack": round(a, 5), "harmful": round(h, 5)}) + "\n")
    tmp.replace(out)  # a kill mid-write leaves no half file
    return len(items)


def load_teacher_scores(path: Path) -> dict[str, tuple[float, float]]:
    scores: dict[str, tuple[float, float]] = {}
    with path.open() as f:
        for line in f:
            r = json.loads(line)
            scores[r["id"]] = (float(r["attack"]), float(r["harmful"]))
    return scores


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()
