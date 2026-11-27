"""``fortress.json`` for a released model, from its score runs (decision 0024).

The proxy reads a model's thresholds from this file (``mobiusguard.classifier``). Each one is
set the way the evaluation set it, on harmless text of its role, at 0.1%, 1% and 5%
false positives:

- ``thresholds``: each text scored once, as it is.
  - ``attack`` and ``harmful``: on the suite's calibration half of ordinary user messages
    (``split == "dev"``, label 0).
  - ``attack_tool``: on the document calibration set (decision 0019).
- ``views_thresholds``: the attack score is the highest over every view of a text
  (decision 0015), on the same sets. The harmful score is the original text's, so its
  threshold is the one above.

With fewer than ``10 / fpr`` calibration texts a threshold is not reliable; the file says
which ones, and how many texts each was set on.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .items import read_jsonl
from .metrics import threshold_at_fpr
from .run import load_scores

FPRS = ("0.001", "0.01", "0.05")


def _at(scores: list[float]) -> dict[str, float]:
    return {f: round(threshold_at_fpr(scores, float(f)).value, 4) for f in FPRS}


def _unreliable(scores: list[float]) -> list[str]:
    return [f for f in FPRS if not threshold_at_fpr(scores, float(f)).reliable]


def fortress_meta(*, name: str, version: int, base: str, suite: Path, attack: Path,
                  attack_views: Path, attack_tool: Path, attack_tool_views: Path,
                  harmful: Path, training: Path, code_commit: str,
                  default_fpr: str = "0.01") -> dict[str, Any]:  # fmt: skip
    """The ``fortress.json`` of a role-marked model.

    ``attack``, ``attack_views``, ``harmful``: score runs on ``suite``; ``attack_tool``,
    ``attack_tool_views``: score runs on the document calibration set; ``training``: the
    training build (its ``summary.json`` holds the IDs' hash)."""
    if default_fpr not in FPRS:
        raise ValueError(f"default_fpr must be one of {FPRS}")
    calibration = {it.id for it in read_jsonl(suite / "items.jsonl")
                   if it.split == "dev" and it.label == 0}  # fmt: skip

    def user(run: Path) -> list[float]:
        _, s = load_scores(run)
        missing = calibration - s.keys()
        if missing:
            raise ValueError(f"{run}: {len(missing):,} calibration items not scored")
        return [s[i] for i in sorted(calibration)]

    def tool(run: Path) -> list[float]:
        return list(load_scores(run)[1].values())

    sets = {
        "attack": user(attack), "harmful": user(harmful), "attack_tool": tool(attack_tool),
        "views:attack": user(attack_views), "views:attack_tool": tool(attack_tool_views),
    }  # fmt: skip
    n_tool = len(sets["attack_tool"])
    if len(sets["views:attack_tool"]) != n_tool:
        raise ValueError("the two document calibration runs scored different item counts")
    unreliable = {k: u for k, v in sets.items() if (u := _unreliable(v))}
    summary = json.loads((training / "summary.json").read_text())
    return {
        "name": name,
        "version": version,
        "base": base,
        "outputs": ["attack", "harmful"],
        "score": "log-odds (logit) per output, independent sigmoids",
        "max_length": 512,
        "role_marker": True,
        "default_fpr": default_fpr,
        "thresholds": {k: _at(sets[k]) for k in ("attack", "harmful", "attack_tool")},
        "views_thresholds": {
            "attack": _at(sets["views:attack"]),
            "attack_tool": _at(sets["views:attack_tool"]),
            "harmful": _at(sets["harmful"]),
        },
        "thresholds_set_on": (
            f"attack, harmful: {len(calibration):,} ordinary user messages (the calibration "
            f"half of oasst1); attack_tool: {n_tool:,} harmless documents (the document "
            "calibration set); scored with the PyTorch model, each text marked with its role"
        ),
        "thresholds_not_reliable": unreliable,
        "training_data_ids_sha256": summary["ids_sha256"],
        "code_commit": code_commit,
    }


def write(meta: dict[str, Any], out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(meta, indent=2) + "\n")
