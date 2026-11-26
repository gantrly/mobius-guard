# Results: the Phase 1 held-out sets (2026-11-26)

These are the larger held-out sets of decision 0021, Phase 1, scored for v1 as shipped,
R-xsmall (seeds 0 and 1) and the teacher (DeBERTa-v3-base on recipe R, 1 epoch).

**Setup:**
- **The suite:** `runs/suite-p1`, 77,232 items
  ([research note](../research/2026-11-26-phase1-test-sets.md)).
- **What was scored:** the screening half only, 47,633 items; the final half is kept for
  the release check.
- **Thresholds:** the user threshold is set on oasst1's calibration half. For R and the
  teacher, the tool threshold is set on the same 1,682 harmless documents as for
  [the teacher](2026-11-26-fortress-teacher.md).
- **Scoring:** documents (LLMail, BIPIA) are scored as `[tool]`, everything else as `[user]`.
  v1 runs as shipped: every view, one threshold.
- **Intervals:** by unit ([decision 0023](../decisions/0023-intervals-by-unit.md)). LLMail
  has 5,135 near-duplicate clusters; BIPIA has 79 attacks.
- **Hardware:** NVIDIA L4, commit `2960a45`. Scoring took 8 min for each xsmall model and
  18 min for the teacher.

## Results (screening half, 1% target)

| | v1 | R-xsmall s0 | R-xsmall s1 | **Teacher** |
|---|---:|---:|---:|---:|
| LLMail caught (9,744) | 40.3% (33.4–46.9) | 43.7% | 29.9% | **56.5% (50.2–61.8)** |
| BIPIA inside documents caught (8,512) | 6.3% (2.8–10.6) | 34.2% | 32.8% | **55.6% (47.2–63.4)** |
| Real developer messages blocked (2,106) | 9.8% (7.9–11.8) | 6.5% | 0.6% | **3.0% (2.0–4.2)** |
| Ordinary chat blocked (8,092) | 0.9% | 1.1% | 0.8% | 0.8% |
| Clean BIPIA documents blocked (83) | 0 | 1 | 0 | 0 |
| LLMail harmless emails blocked (79) | 0 | 0 | 0 | 0 |
| Disguised attacks caught: spaced / leetspeak / invisible / look-alike | 99 / 59 / 38 / 48% | 57 / 61 / 60 / 55% | 45 / 40 / 54 / 41% | 82 / 81 / 72 / 70% |
| AUC: LLMail / BIPIA | 0.926 / 0.775 | 0.935 / 0.879 | 0.886 / 0.820 | **0.973 / 0.958** |

## What it shows

- **The teacher's gains hold on sets 7× (LLMail) to 100× (BIPIA) larger** than suite v0.3's.
  Its intervals by unit don't overlap v1's on LLMail or BIPIA.
- **The developer bar (decision 0021) is passed with room:** the teacher blocks 3.0% of
  real developer messages, against v1's 9.8%, with ordinary chat unchanged.
- **R-xsmall's seeds differ by 14 points on LLMail.** Seed 1's high user threshold (1.17)
  makes it cautious both ways: it blocks 0.6% of developer messages and catches the least.
  One xsmall seed can't decide anything.
- **v1's disguised-spaced recall of 99%** comes from blocking almost everything spaced
  (decision 0017). It is not comparable.

## Near duplicates of training data

Every test item of the Phase 1 suite (55,955, both halves, without disguised copies) was
checked against the recipe-R training build (266,497 train and validation items, role markers
removed). The check used the training build's own near-duplicate rule (MinHash, estimated
Jaccard 0.8 or more) and exact matches on normalised text. It took 91 s on the box, script
`p1_contam.py`.

| Set | Near duplicates of training | Exact |
|---|---:|---:|
| `llmail_full` (20,357) | 0 | 0 |
| `bipia_embedded` (14,785 + 178) | 0 | 0 |
| `wildchat_dev_test` (4,407) | **3** (screening half, all via `wildchat_dev`) | 0 |
| `oasst`, `llmail_benign` | 0 | 0 |

The 3 near-duplicate developer messages could move a developer rate by at most 0.14 points.
The numbers above stand.

## What follows

Per decision 0021, a teacher that is clearly better goes on to the full teacher, then
distillation ([decision 0022](../decisions/0022-distillation.md), whose choices are open).
Before then, the maintainer may want a second 1-epoch teacher seed to see its spread.
