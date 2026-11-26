"""Per-role thresholds, measured: the user's turn and documents (tool results) apart.

The proxy knows each checked text's role: the user's turn or a tool result. A model that
cannot tell a request from a document blocks harmless requests to *do* things ("send an
email to…") and misses the same words hidden in an email. Its threshold can still differ
by role: the user's threshold set on ordinary messages, as now, and a document threshold
set on harmless documents. This measures that without changing the report.

- ``document_calibration`` writes harmless documents from a training set's ``val`` split
  (never trained on by that set's model), dropping any that another compared model trained
  on.
- ``role_offset`` shifts the scores of the suite's document sources (``DOCUMENT_SOURCES``,
  which arrive as tool results in deployment) by the difference between the two thresholds.
  At the 1% operating point, a shifted score at or over the user threshold is the same as
  the original score at or over the document threshold.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

from mobiusguard.classifier import mark

from .items import Item, read_jsonl, write_jsonl
from .metrics import threshold_at_fpr
from .run import load_scores

# Suite sources that arrive in deployment as tool results or documents; "tool_outputs" is
# the held-out half of the tool-call sources' outputs (``mark_roles``).
DOCUMENT_SOURCES = frozenset({"llmail", "bipia", "llmail_benign", "tool_outputs",
                              "llmail_full", "bipia_embedded"})  # fmt: skip
# Training sources whose texts are documents or tool results (decision 0020).
TOOL_TRAIN_SOURCES = frozenset({"browsesafe_md", "browsesafe_html", "nemotron_ipi", "sep",
                                "injecagent", "rgeada_tool", "gandalf_sum"})  # fmt: skip
TOOL_CALL_SOURCES = frozenset({"glaive_fc", "hermes_fc", "toolace", "toucan", "when2call"})
HOLDOUT_SALT = "mobius-guard tool-output holdout v1"


def role_of(it: Item) -> str:
    """``tool`` for a document or tool result (by source, or a tool turn), else ``user``."""
    if it.meta.get("turn") == "tool" or it.source in TOOL_TRAIN_SOURCES | DOCUMENT_SOURCES:
        return "tool"
    return "user"


def _held(it: Item) -> str | None:
    """For a tool output of the tool-call sources: which held-out half its cluster is in,
    or None when it trains. Half the clusters train, a quarter set the tool threshold and a
    quarter test it."""
    if it.source not in TOOL_CALL_SOURCES or it.meta.get("turn") != "tool":
        return None
    k = int(hashlib.sha256(f"{HOLDOUT_SALT}:{it.cluster or it.id}".encode()).hexdigest(), 16) % 4
    return {0: "calibration", 1: "test"}.get(k)


def mark_roles(data: Path, out: Path, holdout: Path) -> dict[str, Any]:
    """``data`` with each text marked with its role (``out``), less half the tool-call
    sources' tool outputs, written unmarked to ``holdout/{calibration,test}/items.jsonl``.
    A disguised copy goes wherever its original goes (they share a cluster); held-out
    copies are dropped, not tested."""
    counts: Counter[str] = Counter()
    held: dict[str, list[Item]] = {"calibration": [], "test": []}
    ids: list[str] = []
    out.mkdir(parents=True, exist_ok=True)
    for part in ("train", "val"):
        kept: list[Item] = []
        for it in read_jsonl(data / f"{part}.jsonl"):
            h = _held(it)
            if h:
                if not it.meta.get("augmented"):
                    held[h].append(replace(it, source="tool_outputs", family="tool_outputs",
                                           split="test",
                                           meta={**it.meta, "from_source": it.source}))  # fmt: skip
                counts[f"held/{h}"] += 1
                continue
            role = role_of(it)
            kept.append(replace(it, text=mark(it.text, role), meta={**it.meta, "role": role}))
            counts[f"{role}/{'attack' if it.label else 'benign'}/{part}"] += 1
        write_jsonl(out / f"{part}.jsonl", kept)
        ids += [f"{it.id}\t{it.meta.get('weight', '1')}\tmarked" for it in kept]
    for h, items in held.items():
        write_jsonl(holdout / h / "items.jsonl", items)
    base = json.loads((data / "summary.json").read_text())
    summary = {**{k: v for k, v in base.items() if k not in ("ids_sha256", "counts")},
               "from_ids_sha256": base.get("ids_sha256"), "role_marker": True,
               "counts": dict(sorted(counts.items())),
               "ids_sha256": hashlib.sha256("\n".join(sorted(ids)).encode()).hexdigest(),
               }  # fmt: skip
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


def add_items(suite: Path, items: Path, out: Path) -> dict[str, Any]:
    """A copy of ``suite`` with the items of ``items`` added (as they are)."""
    base = list(read_jsonl(suite / "items.jsonl"))
    extra = list(read_jsonl(items))
    write_jsonl(out / "items.jsonl", sorted(base + extra, key=lambda it: it.id))
    m = {"from_suite": str(suite), "added_from": str(items), "added": len(extra),
         "items": len(base) + len(extra)}  # fmt: skip
    (out / "manifest.json").write_text(json.dumps(m, indent=2, sort_keys=True) + "\n")
    return m


CALIBRATION_SOURCES = frozenset({"browsesafe_md", "browsesafe_html", "nemotron_ipi", "sep"})
TARGET = 0.01


def document_calibration(data: Path, exclude_train: Sequence[Path], out: Path,
                         extra: Sequence[Path] = ()) -> dict[str, Any]:  # fmt: skip
    """Harmless documents from ``data``'s val split, minus any ID in the ``exclude_train``
    files, plus the items of ``extra`` (held-out tool outputs), written as a suite of
    calibration items (``items.jsonl``). ``data`` must be unmarked."""
    seen = {it.id for p in exclude_train for it in read_jsonl(p)}
    items = [
        it for it in read_jsonl(data / "val.jsonl")
        if it.label == 0 and it.source in CALIBRATION_SOURCES and it.id not in seen
        and not it.meta.get("augmented")
    ]  # fmt: skip
    items += [it for p in extra for it in read_jsonl(p)]
    out.mkdir(parents=True, exist_ok=True)
    write_jsonl(out / "items.jsonl", items)
    counts: dict[str, int] = {}
    for it in items:
        counts[it.source] = counts.get(it.source, 0) + 1
    manifest = {"from": str(data), "excluded_train": [str(p) for p in exclude_train],
                "items": len(items), "by_source": counts}  # fmt: skip
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def role_offset(run: Path, calibration: Path, suite: Path, out: Path) -> dict[str, Any]:
    """A copy of ``run`` whose document-source scores are shifted to the document threshold
    (set at ``TARGET`` on ``calibration``'s scores); named ``<detector>+roles``."""
    meta, scores = load_scores(run)
    _, doc_scores = load_scores(calibration)
    items = list(read_jsonl(suite / "items.jsonl"))
    user = [scores[it.id] for it in items if it.split == "dev" and it.label == 0]
    t_user = threshold_at_fpr(user, TARGET).value
    t_doc = threshold_at_fpr(list(doc_scores.values()), TARGET).value
    shift = t_doc - t_user
    docs = {it.id for it in items if it.source in DOCUMENT_SOURCES}
    out.mkdir(parents=True, exist_ok=True)
    with (out / "scores.jsonl").open("w") as f:
        for i, s in scores.items():
            f.write(json.dumps({"id": i, "score": s - shift if i in docs else s}) + "\n")
    info = {"user_threshold": t_user, "document_threshold": t_doc,
            "document_items": len(doc_scores), "shifted_items": len(docs)}  # fmt: skip
    meta = {**meta, "detector": f"{meta['detector']}+roles",
            "roles": info, "info": {**meta.get("info", {}), "roles": json.dumps(info)}}  # fmt: skip
    (out / "run.json").write_text(json.dumps(meta, indent=2) + "\n")
    return info
