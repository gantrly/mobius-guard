"""Metrics: thresholds at a fixed false-positive rate, recall, AUC, confidence intervals.

Decision 0006: detection is reported as recall at a fixed false-positive rate, with the
threshold set on a separate calibration split, never on the data being reported.
"""

# numpy's stubs leave some overloads partially unknown under strict mode.
# pyright: reportUnknownMemberType=false, reportUnknownArgumentType=false

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np

TARGET_FPRS = (0.001, 0.01, 0.05)


@dataclass(frozen=True, slots=True)
class Threshold:
    target_fpr: float
    value: float  # flag when score >= value
    above: float  # the highest calibration score that is not flagged (value sits just above)
    calibration_fpr: float  # what the threshold actually gives on the calibration set
    n_calibration: int
    reliable: bool  # False when the calibration set is too small for this target


def threshold_at_fpr(benign_scores: Sequence[float], target_fpr: float) -> Threshold:
    """The lowest threshold whose false-positive rate on ``benign_scores`` is <= target.

    Items are flagged when ``score >= threshold``. With ties at the cut, the threshold moves
    above the tied value, so the achieved rate can be below the target (it is reported).
    The target is only meaningful with at least ``10 / target`` calibration items.
    """
    s = np.sort(np.asarray(benign_scores, dtype=np.float64))[::-1]
    n = len(s)
    if n == 0:
        raise ValueError("no calibration scores")
    k = math.floor(target_fpr * n)  # how many benign items may be flagged
    above = float(s[min(k, n - 1)])
    value = float("inf") if k >= n else float(np.nextafter(s[k], np.inf))
    flagged = int(np.sum(s >= value))
    return Threshold(target_fpr, value, above, flagged / n, n, n >= 10 / target_fpr)


def rate(flags: Sequence[bool]) -> tuple[float, int, int]:
    """(fraction true, count true, count)."""
    n = len(flags)
    k = int(sum(flags))
    return (k / n if n else float("nan"), k, n)


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a proportion k/n."""
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


BOOTSTRAP = 1000  # resamples for an interval by unit
_CHUNK = 100  # resamples per numpy draw, to bound memory on sets with many units


def unit_interval(flags: Sequence[bool], units: Sequence[str]) -> tuple[float, float, int]:
    """95% interval for a rate whose rows come in groups (decision 0023), and the number of
    groups.

    Rows of one unit (an attack placed in many documents, a near-duplicate cluster) are not
    independent, so Wilson's interval over rows is too narrow. This resamples whole units
    (a percentile bootstrap, fixed seed) and returns the wider of that and Wilson's interval.
    When every row is its own unit, it is Wilson's interval, unchanged; one unit says
    nothing about the rate, so the interval is [0, 1].
    """
    n = len(flags)
    k = int(sum(flags))
    lo, hi = wilson(k, n)
    groups: dict[str, list[int]] = {}
    for flag, unit in zip(flags, units, strict=True):
        g = groups.setdefault(unit, [0, 0])
        g[0] += int(flag)
        g[1] += 1
    u = len(groups)
    if u == n:
        return lo, hi, u
    if u == 1:
        return 0.0, 1.0, u
    ks = np.array([g[0] for g in groups.values()], dtype=np.float64)
    ns = np.array([g[1] for g in groups.values()], dtype=np.float64)
    rng = np.random.default_rng(0)
    rates: list[np.ndarray] = []
    for _ in range(BOOTSTRAP // _CHUNK):
        idx = rng.integers(0, u, size=(_CHUNK, u))
        rates.append(ks[idx].sum(axis=1) / ns[idx].sum(axis=1))
    blo, bhi = (float(x) for x in np.quantile(np.concatenate(rates), [0.025, 0.975]))
    return min(lo, blo), max(hi, bhi), u


def auc(positive: Sequence[float], negative: Sequence[float]) -> float:
    """Area under the ROC curve (Mann-Whitney U, ties count half)."""
    pos = np.asarray(positive, dtype=np.float64)
    neg = np.asarray(negative, dtype=np.float64)
    if len(pos) == 0 or len(neg) == 0:
        return float("nan")
    allv = np.concatenate([pos, neg])
    order = allv.argsort(kind="mergesort")
    ranks = np.empty(len(allv), dtype=np.float64)
    sorted_v = allv[order]
    i = 0
    while i < len(sorted_v):  # average ranks over ties
        j = i
        while j + 1 < len(sorted_v) and sorted_v[j + 1] == sorted_v[i]:
            j += 1
        ranks[order[i : j + 1]] = (i + j) / 2 + 1
        i = j + 1
    u = ranks[: len(pos)].sum() - len(pos) * (len(pos) + 1) / 2
    return float(u / (len(pos) * len(neg)))
