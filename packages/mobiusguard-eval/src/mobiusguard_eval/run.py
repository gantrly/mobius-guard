"""Score a suite with a detector, and turn scores into a report.

Scoring and reporting are separate steps so that scoring can run on a GPU machine and the
report is computed anywhere from the score files. Every run records what produced it.
"""

from __future__ import annotations

import json
import platform
import subprocess
import time
from collections import defaultdict
from collections.abc import Callable, Sequence
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .checkpoint import Checkpoint, fingerprint, write_atomic
from .detectors import Detector
from .items import ATTACK, BENIGN, Item
from .ledger import LEDGER
from .metrics import TARGET_FPRS, Threshold, auc, threshold_at_fpr, wilson


def machine() -> dict[str, str]:
    cpu = platform.processor() or platform.machine()
    try:
        if platform.system() == "Darwin":
            cpu = subprocess.check_output(
                ["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"], text=True
            ).strip()
        elif Path("/proc/cpuinfo").exists():
            for line in Path("/proc/cpuinfo").read_text().splitlines():
                if line.startswith("model name"):
                    cpu = line.split(":", 1)[1].strip()
                    break
    except (OSError, subprocess.CalledProcessError):
        pass
    return {"cpu": cpu, "platform": platform.platform(), "python": platform.python_version()}


def _git_commit() -> str:
    try:
        return subprocess.check_output(
            ["/usr/bin/env", "git", "rev-parse", "--short", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def suite_key(items: Sequence[Item]) -> str:
    """Identifies a suite by its item IDs, in order."""
    return fingerprint([it.id for it in items])


def score(
    items: Sequence[Item],
    detector: Detector,
    out: Path,
    *,
    force: bool = False,
    log: Callable[[str], None] = lambda _: None,
) -> Path:
    """Write ``scores.jsonl`` and ``run.json`` for one detector into ``out``.

    Resumable: each group of items is saved to ``scores.partial.jsonl`` as it finishes,
    and a run that is already complete for the same suite and detector is skipped.
    """
    key = {"detector": detector.name, "config": detector.fingerprint(), "suite": suite_key(items)}
    run_file = out / "run.json"
    done = not force and run_file.exists() and (out / "scores.jsonl").exists()
    if done and json.loads(run_file.read_text()).get("key") == fingerprint(key):
        log(f"{detector.name}: already scored, skipping (--force to redo)")
        return out
    partial = out / "scores.partial.jsonl"
    if force and partial.exists():
        partial.unlink()
    ckpt = Checkpoint(partial, key)
    groups = detector.groups(items)
    todo = [g for g in groups if g[0] not in ckpt]
    saved = len(groups) - len(todo)
    log(f"{detector.name}: {saved} of {len(groups)} groups saved, {len(todo)} to go")
    for unit, idx in todo:
        t0 = time.perf_counter()
        values = detector.score_group(items, idx)
        ckpt.add(unit, {"scores": values, "seconds": time.perf_counter() - t0})
        log(f"{detector.name}: {unit} done ({len(idx)} items)")

    scores = [0.0] * len(items)
    seconds = 0.0
    for unit, idx in groups:
        saved = ckpt.units[unit]
        seconds += saved["seconds"]
        for i, v in zip(idx, saved["scores"], strict=True):
            scores[i] = v
    write_atomic(
        out / "scores.jsonl",
        "".join(
            json.dumps({"id": it.id, "score": v}) + "\n"
            for it, v in zip(items, scores, strict=True)
        ),
    )
    run = {
        "detector": detector.name,
        "info": detector.info(),
        "items": len(items),
        "seconds": round(seconds, 1),  # compute time, summed over groups and restarts
        "when": datetime.now(UTC).isoformat(timespec="seconds"),
        "machine": machine(),
        "commit": _git_commit(),
        "mobiusguard_eval": __version__,
        "key": fingerprint(key),
    }
    write_atomic(run_file, json.dumps(run, indent=2) + "\n")
    return out


def load_scores(run_dir: Path) -> tuple[dict[str, Any], dict[str, float]]:
    run = json.loads((run_dir / "run.json").read_text())
    scores: dict[str, float] = {}
    with (run_dir / "scores.jsonl").open() as f:
        for line in f:
            row = json.loads(line)
            scores[row["id"]] = float(row["score"])
    return run, scores


# ------------------------------------------------------------------------------ report


def _contaminated(detector: str, source: str) -> bool:
    """Whether the detector's model trained on the source (a "-norm" variant is the same model)."""
    detector = detector.removesuffix("-norm")
    s = LEDGER.get(source)
    return bool(s and detector in s.trained_on_by)


def compute(items: Sequence[Item], runs: dict[str, dict[str, float]]) -> dict[str, Any]:
    """All metrics for every detector, as plain data (written to ``metrics.json``)."""
    calibration = [it for it in items if it.split == "dev" and it.label == BENIGN]
    test = [it for it in items if it.split == "test"]
    attacks_by_family: dict[str, list[Item]] = defaultdict(list)
    benign_by_source: dict[str, list[Item]] = defaultdict(list)
    benign_by_lang: dict[str, list[Item]] = defaultdict(list)
    for it in test:
        if it.label == ATTACK:
            attacks_by_family[it.family].append(it)
        else:
            benign_by_source[it.source].append(it)
            if it.source in {s.id for s in LEDGER.values() if s.role == "calibration"}:
                benign_by_lang[it.lang].append(it)
    test_benign = [it for it in test if it.label == BENIGN]

    out: dict[str, Any] = {"calibration_items": len(calibration), "detectors": {}}
    for name, scores in runs.items():
        missing = [it.id for it in items if it.id not in scores]
        if missing:
            raise ValueError(f"{name}: {len(missing)} items without a score, e.g. {missing[0]}")
        ths: list[Threshold] = [
            threshold_at_fpr([scores[it.id] for it in calibration], f) for f in TARGET_FPRS
        ]

        def rates(
            group: Sequence[Item], ths: list[Threshold] = ths, scores: dict[str, float] = scores
        ) -> list[dict[str, Any]]:
            res: list[dict[str, Any]] = []
            for th in ths:
                k = sum(1 for it in group if scores[it.id] >= th.value)
                lo, hi = wilson(k, len(group))
                res.append({"target_fpr": th.target_fpr, "rate": k / len(group), "k": k,
                            "n": len(group), "ci95": [lo, hi]})  # fmt: skip
            return res

        benign_scores = [scores[it.id] for it in test_benign]
        out["detectors"][name] = {
            "thresholds": [asdict(t) for t in ths],
            "recall": {
                fam: {
                    "at": rates(group),
                    "auc": auc([scores[it.id] for it in group], benign_scores),
                    "contaminated": _contaminated(name, fam),
                }
                for fam, group in sorted(attacks_by_family.items())
            },
            "fpr": {
                src: {"at": rates(group), "contaminated": _contaminated(name, src)}
                for src, group in sorted(benign_by_source.items())
            },
            "fpr_by_language": {
                lang: rates(group)
                for lang, group in sorted(benign_by_lang.items(), key=lambda kv: -len(kv[1]))
                if len(group) >= 100
            },
        }
    return out


def _pct(x: float) -> str:
    return f"{100 * x:.1f}"


def render(metrics: dict[str, Any], runs: dict[str, dict[str, Any]]) -> str:
    """The Markdown report."""
    dets = list(metrics["detectors"])
    lines = ["# Mobius Guard evaluation", ""]
    lines += [
        "Recall on attacks and false-positive rate (FPR) on benign text, at thresholds set "
        f"on {metrics['calibration_items']:,} ordinary user messages (the calibration half of "
        "oasst1) for a target FPR. Nothing reported here was used to set a threshold or to "
        "train. Cells are % (95% interval in metrics.json); **†** marks a set the detector "
        "trained on, so its number there is not a fair comparison. `obf:*` rows are "
        "obfuscated copies of test attacks drawn from every attack source, including sets "
        "marked † for some detectors.",
        "",
        "## Detectors",
        "",
        "| Detector | What was run | Scored on | Time |",
        "|---|---|---|---|",
    ]
    for name in dets:
        r = runs[name]
        info = r["info"]
        what = info.get("repo", info.get("model", "")) + (
            f" @ {info['revision'][:8]}" if "revision" in info else ""
        )
        where = info.get("gpu") or r["machine"]["cpu"]
        lines.append(f"| {name} | {what} | {where} | {r['seconds']}s |")

    for i, target in enumerate(TARGET_FPRS):
        lines += ["", f"## At a target FPR of {target:.1%}", ""]
        lines += ["Thresholds (achieved FPR on calibration):", ""]
        for name in dets:
            th = metrics["detectors"][name]["thresholds"][i]
            note = "" if th["reliable"] else " (too few calibration items for this target)"
            lines.append(
                f"- {name}: score > {th['above']:.4g} ({_pct(th['calibration_fpr'])}% "
                f"of {th['n_calibration']:,}){note}"
            )
        lines += ["", "**Recall on attacks (%)**", ""]
        lines += ["| Family | n | " + " | ".join(dets) + " |"]
        lines += ["|---|---:|" + "---:|" * len(dets)]
        fams = metrics["detectors"][dets[0]]["recall"]
        for fam in fams:
            n = fams[fam]["at"][i]["n"]
            cells: list[str] = []
            for name in dets:
                row = metrics["detectors"][name]["recall"][fam]
                cells.append(_pct(row["at"][i]["rate"]) + (" †" if row["contaminated"] else ""))
            lines.append(f"| {fam} | {n:,} | " + " | ".join(cells) + " |")
        lines += ["", "**False positives on benign sets (%)**", ""]
        lines += ["| Set | n | " + " | ".join(dets) + " |"]
        lines += ["|---|---:|" + "---:|" * len(dets)]
        srcs = metrics["detectors"][dets[0]]["fpr"]
        for src in srcs:
            n = srcs[src]["at"][i]["n"]
            cells: list[str] = []
            for name in dets:
                row = metrics["detectors"][name]["fpr"][src]
                cells.append(_pct(row["at"][i]["rate"]) + (" †" if row["contaminated"] else ""))
            lines.append(f"| {src} | {n:,} | " + " | ".join(cells) + " |")

    lines += ["", "## AUC by attack family (against all benign test items)", ""]
    lines += ["| Family | " + " | ".join(dets) + " |", "|---|" + "---:|" * len(dets)]
    for fam in metrics["detectors"][dets[0]]["recall"]:
        cells = [f"{metrics['detectors'][d]['recall'][fam]['auc']:.3f}" for d in dets]
        lines.append(f"| {fam} | " + " | ".join(cells) + " |")

    lines += ["", "## Ordinary messages by language: FPR at the 1% threshold (%)", ""]
    lines += ["| Language | n | " + " | ".join(dets) + " |", "|---|---:|" + "---:|" * len(dets)]
    j = TARGET_FPRS.index(0.01)
    for lang, rows in metrics["detectors"][dets[0]]["fpr_by_language"].items():
        cells = [_pct(metrics["detectors"][d]["fpr_by_language"][lang][j]["rate"]) for d in dets]
        lines.append(f"| {lang} | {rows[j]['n']:,} | " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def report(items: Sequence[Item], run_dirs: Sequence[Path], out: Path) -> Path:
    """Write ``report.md``, ``metrics.json`` and per-item ``scored_items.jsonl``."""
    runs: dict[str, dict[str, Any]] = {}
    scores: dict[str, dict[str, float]] = {}
    for d in run_dirs:
        run, s = load_scores(d)
        runs[run["detector"]] = run
        scores[run["detector"]] = s
    metrics = compute(items, scores)
    out.mkdir(parents=True, exist_ok=True)
    (out / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n")
    (out / "report.md").write_text(render(metrics, runs))
    j = TARGET_FPRS.index(0.01)
    with (out / "scored_items.jsonl").open("w") as f:
        for it in items:
            row: dict[str, Any] = {
                "id": it.id, "source": it.source, "family": it.family, "label": it.label,
                "split": it.split, "lang": it.lang, "scores": {}, "flagged_at_1pct": {},
            }  # fmt: skip
            for name, s in scores.items():
                th = metrics["detectors"][name]["thresholds"][j]["value"]
                row["scores"][name] = s[it.id]
                row["flagged_at_1pct"][name] = s[it.id] >= th
            f.write(json.dumps(row) + "\n")
    return out
