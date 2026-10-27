"""CPU latency per detector at fixed input lengths, batch size 1 (decision 0006, rule 5).

Inputs are cut from a fixed English text to an exact token count with the detector's own
tokenizer (or 4 characters per token for detectors without one). Reported with the CPU
model, thread count and library versions, because latency means nothing without them.
"""

from __future__ import annotations

import statistics
import time
from collections.abc import Callable, Sequence
from typing import Any

from .detectors import Detector
from .run import machine

LENGTHS = (64, 256, 512)

_FILLER = (
    "The quarterly report covers revenue, hiring and the roadmap for the next two releases. "
    "Please review the attached figures before Thursday and send any corrections to the "
    "finance team, who will merge them into the final version for the board meeting. "
    "We also need a decision on the vendor contract, the office move and the support rota. "
)


def _input(detector: Detector, tokens: int) -> str:
    text = _FILLER * (tokens // 8 + 4)
    tokenizer: Any = getattr(detector, "tokenizer", None)
    if tokenizer is None:
        return text[: tokens * 4]
    ids = tokenizer(text, add_special_tokens=False)["input_ids"][: tokens - 2]
    return str(tokenizer.decode(ids))


def _percentile(values: Sequence[float], q: float) -> float:
    s = sorted(values)
    return s[min(len(s) - 1, int(q * len(s)))]


def measure(
    detector: Detector,
    score_one: Callable[[str], float],
    *,
    lengths: Sequence[int] = LENGTHS,
    iterations: int = 200,
    warmup: int = 20,
) -> dict[str, Any]:
    rows: dict[str, Any] = {}
    for n in lengths:
        text = _input(detector, n)
        for _ in range(warmup):
            score_one(text)
        times: list[float] = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            score_one(text)
            times.append((time.perf_counter() - t0) * 1000)
        rows[str(n)] = {
            "p50_ms": round(statistics.median(times), 3),
            "p95_ms": round(_percentile(times, 0.95), 3),
            "p99_ms": round(_percentile(times, 0.99), 3),
            "iterations": iterations,
        }
    return {"detector": detector.name, "info": detector.info(), "machine": machine(),
            "batch_size": 1, "tokens": rows}  # fmt: skip
