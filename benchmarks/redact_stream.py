"""Benchmark streaming redaction: time per chunk, and how much text is held back.

Usage:  uv run python benchmarks/redact_stream.py [--chunk 4] [--repeat 3]

The input is this repository's own Markdown and Python (real prose and code), with fake
secrets inserted, streamed in fixed-size chunks the way an LLM streams tokens. Reported:

- time spent in ``feed()`` per chunk (P50/P95/P99/max), for curated-only and all patterns,
  and all patterns without the keyword prefilter;
- characters held back after each chunk (how far output lags input), P50/P95/P99/max;
- overall throughput;
- with ``--held``: time per chunk while a possible match stays open (a private key with no
  END line), by how much text is held at that point, up to the holdback limit.

Results depend on hardware; the script prints the machine and versions with the numbers.
"""

from __future__ import annotations

import argparse
import base64
import platform
import random
import statistics
import sys
import time
from collections.abc import Sequence
from pathlib import Path

import regex
from mobiusguard_redact import Pattern, StreamRedactor, default_patterns
from mobiusguard_redact.curated import CURATED

ROOT = Path(__file__).resolve().parent.parent
SECRETS = [
    "AKIAQWERTYUIOPASDFGH",
    "ghp_" + "Zx9Q" * 9,
    "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
    "jo.doe@example.co.uk",
    "4111 1111 1111 1111",
    "postgres://app:Sup3rS3cret!@db:5432/x",
]


def corpus() -> str:
    files = sorted(ROOT.glob("docs/**/*.md")) + sorted(ROOT.glob("packages/*/src/**/*.py"))
    files = [f for f in files if "_gitleaks_rules" not in f.name]
    parts: list[str] = []
    for i, f in enumerate(files):
        parts.append(f.read_text())
        parts.append(f"\nExample credential: {SECRETS[i % len(SECRETS)]}\n")
    return "".join(parts)


def pct(values: Sequence[float], q: float) -> float:
    s = sorted(values)
    return s[min(len(s) - 1, int(q * len(s)))]


def run(
    text: str, patterns: Sequence[Pattern], chunk: int, *, prefilter: bool = True
) -> tuple[list[float], list[int], float]:
    r = StreamRedactor(patterns, prefilter=prefilter)
    times: list[float] = []
    held: list[int] = []
    t_all = time.perf_counter()
    for i in range(0, len(text), chunk):
        t0 = time.perf_counter()
        r.feed(text[i : i + chunk])
        times.append(time.perf_counter() - t0)
        held.append(r.held)
    r.flush()
    return times, held, time.perf_counter() - t_all


def held_run(
    patterns: Sequence[Pattern], chunk: int, *, prefilter: bool = True
) -> tuple[dict[int, list[float]], float]:
    """Feed a private key that never ends; time each chunk by how much text is held."""
    body = base64.b64encode(random.Random(0).randbytes(6400)).decode()  # noqa: S311 (fixed sample)
    lines = "\n".join(body[i : i + 64] for i in range(0, len(body), 64))
    text = "key:\n-----BEGIN PRIVATE KEY-----\n" + lines
    r = StreamRedactor(patterns, prefilter=prefilter)
    by_held: dict[int, list[float]] = {}
    t_all = time.perf_counter()
    for i in range(0, len(text), chunk):
        t0 = time.perf_counter()
        r.feed(text[i : i + chunk])
        by_held.setdefault(r.held // 2048, []).append(time.perf_counter() - t0)
    r.flush()
    return by_held, time.perf_counter() - t_all


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--chunk", type=int, default=4, help="characters per chunk (~1 token)")
    ap.add_argument("--repeat", type=int, default=3)
    ap.add_argument("--held", action="store_true", help="only the open-match case")
    args = ap.parse_args()

    if args.held:
        return main_held(args.chunk)
    text = corpus()
    print(f"machine : {platform.machine()} {platform.processor()} | {platform.platform()}")
    print(f"python  : {sys.version.split()[0]} | regex {regex.__version__}")
    print(f"input   : {len(text):,} chars, {len(text) // args.chunk:,} chunks of {args.chunk}\n")

    sets = {
        "curated": (CURATED, True),
        "all": (default_patterns(), True),
        "all, no prefilter": (default_patterns(), False),
    }
    print(
        f"{'patterns':<17} {'n':>4} | feed ms: {'p50':>6} {'p95':>6} {'p99':>6} {'max':>7}"
        f" | held chars: {'p50':>4} {'p95':>4} {'p99':>5} {'max':>5} | {'MB/s':>5}"
    )
    for name, (pats, prefilter) in sets.items():
        n = max(1, args.repeat)
        runs = [run(text, pats, args.chunk, prefilter=prefilter) for _ in range(n)]
        times, held, total = min(runs, key=lambda r: r[2])  # fastest of the repeats
        ms = [t * 1000 for t in times]
        print(
            f"{name:<17} {len(pats):>4} | {'':8} {statistics.median(ms):6.3f} {pct(ms, 0.95):6.3f}"
            f" {pct(ms, 0.99):6.3f} {max(ms):7.2f} | {'':11} {pct(held, 0.5):4d}"
            f" {pct(held, 0.95):4d} {pct(held, 0.99):5d} {max(held):5d}"
            f" | {len(text) / total / 1e6:5.2f}"
        )
    return 0


def main_held(chunk: int) -> int:
    print(f"machine : {platform.machine()} {platform.processor()} | {platform.platform()}")
    print(f"python  : {sys.version.split()[0]} | regex {regex.__version__}")
    print(f"input   : a private key with no END line, chunks of {chunk}\n")
    bins = [f"{k * 2}-{k * 2 + 2}k" for k in range(4)]
    print(
        f"{'patterns':<17} {'n':>4} | feed ms p50 by chars held: "
        + " ".join(f"{b:>7}" for b in bins)
        + f" | {'total s':>7}"
    )
    sets = {
        "curated": (CURATED, True),
        "all": (default_patterns(), True),
        "all, no prefilter": (default_patterns(), False),
    }
    for name, (pats, prefilter) in sets.items():
        by_held, total = held_run(pats, chunk, prefilter=prefilter)
        cells = [
            f"{statistics.median(by_held[k]) * 1000:7.3f}" if k in by_held else f"{'-':>7}"
            for k in range(4)
        ]
        print(f"{name:<17} {len(pats):>4} | {'':27} " + " ".join(cells) + f" | {total:7.2f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
