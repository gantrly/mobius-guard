"""Intervals by unit (decision 0023)."""

from __future__ import annotations

import pytest
from mobiusguard_eval.metrics import unit_interval, wilson


def test_independent_rows_give_wilson() -> None:
    flags = [i % 4 == 0 for i in range(200)]
    lo, hi, u = unit_interval(flags, [str(i) for i in range(200)])
    assert (lo, hi) == pytest.approx(wilson(50, 200))
    assert u == 200


def test_grouped_rows_widen_the_interval() -> None:
    # 10 units of 100 rows each: 3 units always flagged, 7 never. 1,000 rows, but only 10
    # draws, so the interval must be far wider than Wilson's over 1,000 rows.
    flags: list[bool] = []
    units: list[str] = []
    for g in range(10):
        flags += [g < 3] * 100
        units += [f"u{g}"] * 100
    lo, hi, u = unit_interval(flags, units)
    wlo, whi = wilson(300, 1000)
    assert u == 10
    assert lo < wlo - 0.1
    assert hi > whi + 0.1
    assert unit_interval(flags, units) == (lo, hi, u)  # fixed seed


def test_one_unit_says_nothing() -> None:
    assert unit_interval([True, True, False], ["a", "a", "a"])[:2] == (0.0, 1.0)


def test_never_narrower_than_wilson() -> None:
    flags = [i % 10 == 0 for i in range(300)]
    units = [str(i // 2) for i in range(300)]  # pairs
    lo, hi, _ = unit_interval(flags, units)
    wlo, whi = wilson(30, 300)
    assert lo <= wlo
    assert hi >= whi
