"""Command line: ``mobiusguard-eval <command>``.

    sources                          list the ledger
    build  --out runs/suite          fetch sources and build a suite
    score  --suite S --detector D --out runs/D [--device cuda]
    report --suite S --runs runs/a runs/b --out runs/report
    latency --detector D [--threads N] --out runs/latency-D.json [--suite S]
    redaction --suite S --out runs/redaction [--per-pattern 200]
    pipeline --out runs [--tag v0.1] [--device cuda]   all of the above, in order

Every step saves its work as it goes and skips what is already done for the same inputs,
so running a command again resumes it. ``--force`` redoes a step from the start.
"""

from __future__ import annotations

import argparse
import importlib
import json
import sys
import time
import traceback
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import detectors
from .checkpoint import fingerprint, write_atomic
from .fetch import fetch
from .items import Item
from .suite import build, is_built, ledger_sources, load_suite


def log(message: str) -> None:
    print(f"[{datetime.now(UTC):%H:%M:%S}] {message}", file=sys.stderr, flush=True)


# ------------------------------------------------------------------------------ steps


def step_build(out: Path, source_ids: Sequence[str] | None = None, *, force: bool = False) -> None:
    sources = ledger_sources(source_ids)
    if not force and is_built(sources, out):
        log(f"suite: {out} is up to date, skipping (--force to rebuild)")
        return
    loaded: dict[str, list[Item]] = {}
    for s in sources:
        loaded[s.id] = list(s.parse(fetch(s)))
        log(f"suite: {s.id} {len(loaded[s.id]):,} items")
    manifest = build(sources, loaded, out)
    log(f"suite: {manifest['items']:,} items, dropped {manifest['dropped']}")


def step_score(
    suite: Path,
    detector: str,
    out: Path,
    *,
    device: str = "cpu",
    batch_size: int = 32,
    limit: int = 0,
    force: bool = False,
) -> None:
    from .run import score

    items = load_suite(suite)
    if limit:
        items = items[:limit]
    score(items, detectors.get(detector, device=device, batch_size=batch_size), out,
          force=force, log=log)  # fmt: skip
    log(f"score: wrote {out}")


def step_latency(
    detector: str,
    out: Path,
    *,
    suite: Path | None = None,
    threads: int = 0,
    iterations: int = 200,
    force: bool = False,
) -> None:
    from .latency import LENGTHS, measure

    if threads:
        importlib.import_module("torch").set_num_threads(threads)
    det = detectors.get(detector)
    config = {k: v for k, v in det.fingerprint().items() if k != "output"}
    key: dict[str, Any] = {"config": config, "lengths": list(LENGTHS),
                           "iterations": iterations, "threads": threads}  # fmt: skip
    if detector == "tfidf":
        if suite is None:
            raise ValueError("tfidf latency needs --suite (it trains first)")
        from .detectors.tfidf import _pipeline  # pyright: ignore[reportPrivateUsage]

        items = [it for it in load_suite(suite) if not it.family.startswith("obf:")]
        key["suite"] = fingerprint([it.id for it in items])
        if not force and _latency_done(out, key):
            return
        model = _pipeline().fit([it.text for it in items], [it.label for it in items])

        def one(text: str) -> float:
            return float(model.predict_proba([text])[0][1])
    elif detector == "keyword":
        from .detectors.keyword import KeywordDetector

        one = KeywordDetector().score_text
    else:
        from .detectors.hf import HFClassifier

        if not isinstance(det, HFClassifier):
            raise TypeError(detector)
        hf = det

        def one(text: str) -> float:
            return hf.score_texts([text])[0]

    if detector != "tfidf" and not force and _latency_done(out, key):
        return
    result = measure(det, one, iterations=iterations)
    result["key"] = fingerprint(key)
    write_atomic(out, json.dumps(result, indent=2) + "\n")
    log(f"latency: {detector} {json.dumps(result['tokens'])}")


def _latency_done(out: Path, key: dict[str, Any]) -> bool:
    if out.exists() and json.loads(out.read_text()).get("key") == fingerprint(key):
        log(f"latency: {out} is up to date, skipping (--force to redo)")
        return True
    return False


def step_redaction(suite: Path, out: Path, *, per_pattern: int = 200, force: bool = False) -> None:
    from .redaction import evaluate

    summary = evaluate(load_suite(suite), out, per_pattern=per_pattern, force=force, log=log)
    log(f"redaction: {summary['texts']:,} texts; wrote {out}/redaction_report.md")


def step_report(suite: Path, runs: Sequence[Path], out: Path) -> None:
    from .run import report

    ledger_sources()  # register sources so contamination marks resolve
    report(load_suite(suite), runs, out)
    log(f"report: wrote {out / 'report.md'}")


# ------------------------------------------------------------------------------ pipeline


def pipeline(
    root: Path,
    *,
    tag: str = "v0.1",
    names: Sequence[str] = detectors.NAMES,
    device: str = "cpu",
    batch_size: int = 32,
    threads: int = 4,
    per_pattern: int = 200,
    latency: bool = True,
    redaction: bool = True,
    force: bool = False,
) -> int:
    """Every step in order. A failed step is reported and the rest still run; running the
    pipeline again resumes from what was saved."""
    suite = root / f"suite-{tag}"
    scores = root / f"scores-{tag}"
    steps: list[tuple[str, Callable[[], None]]] = [
        ("build", lambda: step_build(suite, force=force))
    ]
    for name in names:
        dev = device if name in ("protectai-v2", "piguard") else "cpu"
        steps.append((f"score {name}", lambda n=name, d=dev: step_score(
            suite, n, scores / n, device=d, batch_size=batch_size, force=force)))  # fmt: skip
    if redaction:
        steps.append(("redaction", lambda: step_redaction(
            suite, root / f"redaction-{tag}", per_pattern=per_pattern, force=force)))  # fmt: skip
    if latency:  # last before the report, so nothing else competes for the CPU
        for name in names:
            steps.append((f"latency {name}", lambda n=name: step_latency(
                n, root / f"latency-{tag}" / f"{n}.json", suite=suite, threads=threads,
                force=force)))  # fmt: skip

    def report() -> None:
        done = [scores / n for n in names if (scores / n / "run.json").exists()]
        if not done:
            raise RuntimeError("no finished scores to report")
        step_report(suite, done, root / f"report-{tag}")

    steps.append(("report", report))

    results: list[tuple[str, str, float]] = []
    for name, run in steps:
        t0 = time.perf_counter()
        log(f"== {name}")
        try:
            run()
            results.append((name, "ok", time.perf_counter() - t0))
        except Exception:
            traceback.print_exc()
            results.append((name, "FAILED", time.perf_counter() - t0))
            if name == "build":
                break  # nothing else can run without a suite
    log("summary:")
    for name, status, seconds in results:
        log(f"  {status:<6} {name:<24} {seconds:7.1f}s")
    return 1 if any(status != "ok" for _, status, _ in results) else 0


# ------------------------------------------------------------------------------ main


def _sources(_: argparse.Namespace) -> int:
    for s in ledger_sources():
        trained = ", ".join(s.trained_on_by) or "-"
        print(f"{s.id:<14} {s.role:<12} {s.licence:<11} trained on by: {trained:<22} {s.title}")
    return 0


def _run(a: argparse.Namespace) -> int:
    cmd: str = a.command
    if cmd == "sources":
        return _sources(a)
    if cmd == "build":
        step_build(Path(a.out), a.sources, force=a.force)
    elif cmd == "score":
        step_score(Path(a.suite), a.detector, Path(a.out), device=a.device,
                   batch_size=a.batch_size, limit=a.limit, force=a.force)  # fmt: skip
    elif cmd == "report":
        step_report(Path(a.suite), [Path(r) for r in a.runs], Path(a.out))
    elif cmd == "latency":
        step_latency(a.detector, Path(a.out), suite=Path(a.suite) if a.suite else None,
                     threads=a.threads, iterations=a.iterations, force=a.force)  # fmt: skip
    elif cmd == "redaction":
        step_redaction(Path(a.suite), Path(a.out), per_pattern=a.per_pattern, force=a.force)
    elif cmd == "pipeline":
        return pipeline(Path(a.out), tag=a.tag, names=a.detectors, device=a.device,
                        batch_size=a.batch_size, threads=a.threads, per_pattern=a.per_pattern,
                        latency=not a.no_latency, redaction=not a.no_redaction,
                        force=a.force)  # fmt: skip
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="mobiusguard-eval", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)  # fmt: skip
    sub = ap.add_subparsers(dest="command", required=True)

    sub.add_parser("sources")

    p = sub.add_parser("build")
    p.add_argument("--out", required=True)
    p.add_argument("--sources", nargs="*", help="source IDs (default: all)")
    p.add_argument("--force", action="store_true")

    p = sub.add_parser("score")
    p.add_argument("--suite", required=True)
    p.add_argument("--detector", required=True, choices=detectors.NAMES)
    p.add_argument("--out", required=True)
    p.add_argument("--device", default="cpu")
    p.add_argument("--batch-size", type=int, default=32)
    p.add_argument("--limit", type=int, default=0, help="score only the first N items")
    p.add_argument("--force", action="store_true")

    p = sub.add_parser("report")
    p.add_argument("--suite", required=True)
    p.add_argument("--runs", nargs="+", required=True)
    p.add_argument("--out", required=True)

    p = sub.add_parser("latency")
    p.add_argument("--detector", required=True, choices=detectors.NAMES)
    p.add_argument("--out", required=True)
    p.add_argument("--suite", help="needed for tfidf, which trains first")
    p.add_argument("--threads", type=int, default=0)
    p.add_argument("--iterations", type=int, default=200)
    p.add_argument("--force", action="store_true")

    p = sub.add_parser("redaction")
    p.add_argument("--suite", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--per-pattern", type=int, default=200)
    p.add_argument("--force", action="store_true")

    p = sub.add_parser("pipeline", help="every step in order, resuming what was saved")
    p.add_argument("--out", default="runs")
    p.add_argument("--tag", default="v0.1")
    p.add_argument("--detectors", nargs="+", default=list(detectors.NAMES),
                   choices=detectors.NAMES)  # fmt: skip
    p.add_argument("--device", default="cpu", help="for the transformer baselines")
    p.add_argument("--batch-size", type=int, default=32)
    p.add_argument("--threads", type=int, default=4, help="CPU threads for latency")
    p.add_argument("--per-pattern", type=int, default=200)
    p.add_argument("--no-latency", action="store_true")
    p.add_argument("--no-redaction", action="store_true")
    p.add_argument("--force", action="store_true", help="redo every step")

    return _run(ap.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
