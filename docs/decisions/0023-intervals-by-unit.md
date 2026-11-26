# 0023: 95% intervals count units, not rows

- **Status:** accepted 2026-11-26 (the maintainer's go). Built in `metrics.unit_interval`.
- **Builds on:** [0006](0006-evaluation-rules.md) (evaluation rules),
  [0021](0021-capacity-and-measurement.md) (Phase 1 sets), [0017](0017-disguises-carry-no-label.md) (the gate)

## Context

The report gave each rate a Wilson interval over rows, which assumes every row is an
independent draw. Some sets break that:
- **`bipia_embedded`** has about 10,000 rows per half, but they come from about 62 attacks,
  each placed in about 100 documents at three positions. Its row interval would be about ±1
  point when the real uncertainty is closer to ±8–10.
- **Near-duplicate clusters** (an attack and its rewrites, repeated chat messages) are
  smaller cases of the same thing.

The gate compares a candidate with the baseline's bounds. With intervals that are too
narrow, it reads noise as a regression or a win.

## Decision

- **Each row has a unit:** `meta["unit"]` if the source sets one (`bipia_embedded`: the
  attack), else its near-duplicate cluster, else itself (`items.unit`).
- **`ci95_units`** is a percentile bootstrap over units: 1,000 resamples, fixed seed. The
  interval reported is the wider of that and Wilson's interval over rows.
  - When every row is its own unit, it is Wilson's interval, unchanged.
  - When all rows share one unit, it is [0, 1].
- **`metrics.json` keeps both.** `ci95` is over rows, as before. `ci95_units` and `units` are
  new.
- **The gate uses `ci95_units`** for the baseline's bounds. Reports from before this have
  only `ci95`, and the gate falls back to it.

## Effect

- **Suite v0.3:** sets with few near duplicates keep almost the same bounds. Clustered sets
  get slightly wider ones, so the gate is a little less strict there, honestly so.
- **`bipia_embedded`:** bounds reflect about 62 attacks. A difference there counts only if
  it holds across attacks.

## Limits

`bipia_embedded` rows also share documents (about 100 per half). Only attacks are resampled,
because they are the smaller pool and drive most of the variance. A two-way bootstrap is
possible if needed later.
