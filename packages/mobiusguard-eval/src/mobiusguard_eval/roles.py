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

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .items import read_jsonl, write_jsonl
from .metrics import threshold_at_fpr
from .run import load_scores

DOCUMENT_SOURCES = frozenset({"llmail", "bipia", "llmail_benign"})
CALIBRATION_SOURCES = frozenset({"browsesafe_md", "browsesafe_html", "nemotron_ipi", "sep"})
TARGET = 0.01


def document_calibration(data: Path, exclude_train: Sequence[Path], out: Path) -> dict[str, Any]:
    """Harmless documents from ``data``'s val split, minus any ID in the ``exclude_train``
    files, written as a suite of calibration items (``items.jsonl``)."""
    seen = {it.id for p in exclude_train for it in read_jsonl(p)}
    items = [
        it for it in read_jsonl(data / "val.jsonl")
        if it.label == 0 and it.source in CALIBRATION_SOURCES and it.id not in seen
        and not it.meta.get("augmented")
    ]  # fmt: skip
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
