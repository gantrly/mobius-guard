"""Benchmark streaming redaction: time per chunk, and how much text is held back.

Usage:  uv run python benchmarks/redact_stream.py [--chunk 4] [--repeat 3]

The input is this repository's own Markdown and Python (real prose and code), with fake
secrets inserted, streamed in fixed-size chunks the way an LLM streams tokens. Reported:

- time spent in ``feed()`` per chunk (P50/P95/P99/max), for curated-only and all patterns;
- characters held back after each chunk (how far output lags input), P50/P95/P99/max;
- overall throughput.

Results depend on hardware; the script prints the machine and versions with the numbers.
"""

from __future__ import annotations

import argparse
import platform
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


def run(text: str, patterns: Sequence[Pattern], chunk: int) -> tuple[list[float], list[int], float]:
    r = StreamRedactor(patterns)
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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--chunk", type=int, default=4, help="characters per chunk (~1 token)")
    ap.add_argument("--repeat", type=int, default=3)
    args = ap.parse_args()

    text = corpus()
    print(f"machine : {platform.machine()} {platform.processor()} | {platform.platform()}")
    print(f"python  : {sys.version.split()[0]} | regex {regex.__version__}")
    print(f"input   : {len(text):,} chars, {len(text) // args.chunk:,} chunks of {args.chunk}\n")

    sets = {"curated": CURATED, "all": default_patterns()}
    print(
        f"{'patterns':<9} {'n':>4} | feed ms: {'p50':>6} {'p95':>6} {'p99':>6} {'max':>7}"
        f" | held chars: {'p50':>4} {'p95':>4} {'p99':>5} {'max':>5} | {'MB/s':>5}"
    )
    for name, pats in sets.items():
        runs = [run(text, pats, args.chunk) for _ in range(max(1, args.repeat))]
        times, held, total = min(runs, key=lambda r: r[2])  # fastest of the repeats
        ms = [t * 1000 for t in times]
        print(
            f"{name:<9} {len(pats):>4} | {'':8} {statistics.median(ms):6.3f} {pct(ms, 0.95):6.3f}"
            f" {pct(ms, 0.99):6.3f} {max(ms):7.2f} | {'':11} {pct(held, 0.5):4d}"
            f" {pct(held, 0.95):4d} {pct(held, 0.99):5d} {max(held):5d}"
            f" | {len(text) / total / 1e6:5.2f}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
