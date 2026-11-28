# Results: the teacher's deciding test (2026-11-26)

This is decision 0021, Phase 2: does a larger model do better on the same data? It is
DeBERTa-v3-base trained on recipe R (role marking, decision 0020), for 1 epoch with seed 0.

**Setup:**
- **Data:** `runs/train-R`, the same data as R-xsmall: 239,941 train and 26,556 validation
  items.
- **Training:** learning rate 2e-5, batch 32 in pieces of 16 (`--micro-batch`, the same
  gradients), bf16 autocast.
- **Hardware and time:** NVIDIA L4 (g6.xlarge). Training took 70 min at 60 items/s, with GPU
  memory peaking at 13.2 GB. Scoring took 22 min. Commit `4ed5c72`.
- **Scoring:** as R was scored, on suite v0.3 with role markers.
  - The user threshold is set on oasst1's calibration half: −0.06.
  - The tool threshold is set on 1,682 harmless documents: −0.61. That is below the user
    threshold: this model scores harmless documents lower than harmless chat. R-xsmall was
    the other way round.
- **Report:** the screening half, against v1 as shipped and R-xsmall's seeds 0 and 1.
- **Gate:** one seed. The gate here uses intervals over rows: the job ran before
  decision 0023.

## Against v1 and R-xsmall

The gate passes **35 of 40** checks. R-xsmall passed 32 of 40, though on two seeds.

| | v1 | R-xsmall s0 / s1 | **Teacher** |
|---|---:|---:|---:|
| LLMail caught | 46.2% | 48.5 / 30.8% | **58.2%** |
| BIPIA caught | 12.1% | 51.5 / 45.5% | **54.5%** |
| deepset caught | 35.7% | 27.0 / 26.2% | **41.3%** |
| SPML caught | 33.8% | 35.3 / 36.5% | **40.5%** |
| jackhhao caught | 86.9% | 86.0 / 84.8% | 89.6% |
| Gandalf caught | 99.0% | 98.8 / 98.1% | 99.8% |
| LLMail / BIPIA AUC | 0.906 / 0.620 | 0.947, 0.906 / 0.900, 0.891 | **0.975 / 0.951** |
| Harmful: XSTest safe prompts blocked | 7.3% | 15.4 / 16.3% | **7.3%** |
| Harmful: XSTest unsafe caught | 86.1% | 86.1 / 87.3% | 91.1% |
| Harmful: OR-Bench hard blocked | 49.5% | 52.9 / 53.6% | **59.0%** (fails) |
| Harmless spaced-out text blocked (bar 5%) | 95.9% | 7.3 / 3.4% | 7.3% (fails) |
| Harmless leetspeak / invisible / look-alike | 78.3 / 20.5 / 5.5% | | 4.3 / 4.1 / 1.8% |
| Ordinary chat (oasst1) blocked | 0.9% | 1.0 / 0.7% | 0.8% |
| Held-out tool outputs blocked | 0.7% | 2.5 / 0.7% | 0.7% |
| Developer check (of 8) blocked | 5 | 5 / 4 | 4 (fails the old bar) |

**The five failed checks:**
- **OR-Bench hard (harmful output):** 59.0% against v1's 49.5%, a real regression. R-xsmall
  was already at 53%.
- **Harmless spaced-out text:** 7.3% against the 5% bar. R-xsmall's seed 0 was the same.
- **Developer check, 4 of 8:** the bar is now the new developer set (decision 0021), and that
  set isn't built yet.
- **Ordinary Chinese messages:** 6 of 327 against v1's 2.
- **Ordinary Brazilian Portuguese messages:** 2 of 120 against v1's 0.

The language rule allows v1 plus 1 point, so a single message there moves 0.8 points.

## What it shows

- **Capacity was a limit.** The weak areas moved for the first time without being paid for
  elsewhere:
  - LLMail is up 12 points on v1 and 10 on R-xsmall's better seed;
  - deepset is up 6 on v1 and 14 on R-xsmall;
  - BIPIA is 4.5×;
  - the harmful XSTest regression of R is gone.

  LLMail's AUC is 0.975 against v1's 0.906. Unlike v3, the ranking and the recall at 1%
  moved together.
- **One seed, 1 epoch.** LLMail varied by 18 points between R-xsmall's seeds. The teacher's
  58.2% is above both of them and above v1's interval, but a second seed would show its
  spread.
- **Still open:**
  - the harmful output over-blocks OR-Bench hard;
  - spaced-out harmless text is just over the bar;
  - the Phase 1 sets (large LLMail, BIPIA inside documents, the developer set) are built
    in code but not yet scored.

## What follows (the maintainer's decision)

Decision 0021 says a teacher that is clearly better goes on to a 3-epoch teacher, then
distillation ([decision 0022](../decisions/0022-distillation.md)). Before that, the Phase 1
sets can be built and scored with this saved teacher, v1 and R-xsmall. That needs no
training.

## Update, the same evening: the gate fixed, and an overnight chain

**The gate's rules now match decisions 0021 and 0023:**
- **The developer bar is the new developer set:** no more blocked than v1. The 8 sentences
  are a smoke test.
- **Languages** are judged by v1's interval, plus a pooled check of all languages but English.
- **The gate reads both suites.**

**Re-gated on suite v0.3 and the Phase 1 suite, the teacher passes 55 of 57 checks.** The two
failures:
- **Harmful output on OR-Bench hard:** 59.0% blocked, against v1's 49.5%.
- **Harmless spaced-out text:** 7.3% blocked, against the 5% bar.

**Recipe R2** targets both: R, plus 2× loss weight on 25,941 harmless items from the
hard-harmless sources (PHTest, CoCoNot, Aegis, WildJailbreak benign, JBB benign), plus 4,191
extra harmless spaced copies. None of the held-out tool outputs is in its training data.

**Overnight** (`mg-v4night`), in order:
1. **A 1-epoch R2 teacher,** scored and gated on both suites.
2. **The recipe choice,** by a rule fixed before the run: R2 only if it passes at least as
   many checks as R, blocks less of OR-Bench hard, and stays within 3 points of R on Phase 1
   LLMail and BIPIA.
3. **The 3-epoch teacher** on the chosen recipe, scored and gated on both suites.

Results follow in a note of 2026-11-27.
