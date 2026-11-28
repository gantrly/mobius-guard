# Results: recipe R2 and the 3-epoch teacher (overnight, 2026-11-26 to 27)

This is the overnight chain of 2026-11-26 (`mg-v4night`), run at commit `dfe7b74`.
- **The teachers:** DeBERTa-v3-base, seed 0, learning rate 2e-5, batch 32 in pieces of 16.
- **Scoring:** both suites' screening halves: suite v0.3 and the Phase 1 sets.
- **Gate:** against v1 as shipped, with the current rules: the developer set as the bar, and
  intervals by unit.
- **Hardware:** NVIDIA L4. Each epoch took about 71 min and scoring about 40 min. The chain
  finished at 00:19 IST with no failed or retried stage.

| Model | Recipe | Epochs | Gate |
|---|---|---|---|
| T | R | 1 | 55 of 57 |
| T2 | R2 = R + 2× weight on harmless hard-harmless items + 4% extra harmless spaced copies | 1 | **56 of 57** |
| T3 | R2, chosen by the rule fixed before the run (T2 passed more, blocked less of OR-Bench, and LLMail and BIPIA did not drop) | 3 (best: epoch 2) | 55 of 57 |

## Against v1 (screening halves, 1% target)

| | v1 | T (R) | T2 (R2) | T3 (R2, 3 ep.) | Bar for T3 |
|---|---:|---:|---:|---:|---|
| LLMail, full (Phase 1) caught | 40.3% | 56.5% | 64.9% | **66.3%** | ≥ 33.4% |
| BIPIA inside documents caught | 6.3% | 55.6% | **63.8%** | 59.0% | ≥ 2.8% |
| Real developer messages blocked | 9.8% | **3.0%** | 3.7% | 6.6% | ≤ 9.8% |
| LLMail (v0.3) caught | 46.2% | 58.2% | **68.3%** | 66.6% | ≥ 42.3% |
| BIPIA (v0.3) caught | 12.1% | **54.5%** | 53.0% | 50.0% | ≥ 6.3% |
| deepset caught | 35.7% | 41.3% | 38.1% | **46.8%** | ≥ 27.3% |
| SPML caught | 33.8% | 40.5% | 41.7% | 39.2% | ≥ 32.6% |
| Harmless spaced / leetspeak blocked | 95.9 / 78.3% | 7.3 ✗ / 4.3% | 4.3 / 5.5% ✗ | **4.3 / 2.8%** | ≤ 5% |
| Harmful: OR-Bench hard blocked | 49.5% | 59.0% ✗ | 51.9% | **50.8%** | ≤ 53.3% |
| Harmful: XSTest safe blocked | 7.3% | 7.3% | **2.4%** | 7.3% | ≤ 13.3% |
| Harmful: OR-Bench toxic / XSTest unsafe caught | 90.2 / 86.1% | 92.1 / 91.1% | 91.8 / 91.1% | **92.8 / 93.7%** | ≥ 86.5 / 76.8% |
| Ordinary chat (oasst1) blocked | 0.9% | 0.8% | 1.0% | 0.9% | ≤ 1.1% |
| Ordinary Russian messages blocked | 4 of 795 | 9 | 8 | 11 ✗ | ≤ 10 (1.3%) |
| Ordinary chat, all but English, pooled | 0.6% | 0.7% | 0.7% | 0.8% | ≤ 0.9% |
| Held-out tool outputs blocked | 0.7% | 0.7% | 1.1% | 1.8% | ≤ 2.5% |

## What it shows

**R2 fixed both regressions it was built for:**
- **OR-Bench hard (harmful):** 59.0% blocked with R, 51.9% with R2 at 1 epoch and 50.8% at 3
  epochs. v1 is at 49.5%.
- **Harmless spaced text:** 7.3% blocked with R, 4.3% with R2.
- **The costs it might have had did not appear:** spaced attacks are still caught (75.7%;
  plain 66%), and harmful recall rose.

**Each R2 teacher fails exactly one check, by a hair:**
- **T2** blocks 5.5% of harmless leetspeak against the 5% bar.
- **T3** blocks 11 of 795 ordinary Russian messages against a bound of 10. That is one
  message. The pooled non-English check passes.

The gate counts T3's Russian check twice, because both suites hold the same oasst1 test
messages. That is a gate defect to fix: the extra report's language checks repeat the main
report's.

**3 epochs against 1:**
- **Better:** deepset, OR-Bench, leetspeak, and harmful recall.
- **Worse:** BIPIA inside documents (59.0% against 63.8%) and real developer messages (6.6%
  against 3.7%, still far under v1's 9.8%).
- **Training:** epoch 2 was best on validation; epoch 3 was slightly lower.
- **No clear winner;** both are far ahead of v1 on every weak area.

**One seed each.** The differences between T2 and T3 (a few points) are of the size seeds
moved R-xsmall, so they are not decisive.

## What follows (the maintainer's decision)

1. **Which teacher to distil:** T3 (3 epochs) or T2 (1 epoch). Both pass every check but one,
   by one message or half a point.
2. **Distillation** ([decision 0022](../decisions/0022-distillation.md)): the code is not yet
   written. The student must then pass the gate itself.
3. **The gate fix:** count the shared oasst1 language checks once.
