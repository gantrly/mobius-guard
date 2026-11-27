# Results: distilling teacher T3 into xsmall, two tries (2026-11-27)

[Decision 0022](../decisions/0022-distillation.md), Phase 3 of
[decision 0021](../decisions/0021-capacity-and-measurement.md). Neither try passed the gate,
so Fortress-XS v1 stays the default and the teacher ships as an opt-in model instead
([decision 0024](../decisions/0024-fortress-base.md)).

**Setup (both tries):**
- **Teacher:** T3, DeBERTa-v3-base on recipe R2, 3 epochs, best epoch 2
  ([results](2026-11-27-fortress-teacher-r2.md)).
- **Student:** fresh `deberta-v3-xsmall`, learning rate 5e-5, recipe R2's data and weights,
  temperature 2, 2 seeds.
- **Teacher scores:** T3 scored 293,681 items: the R2 training set and 50,000 extra texts
  the teacher never trained on. The extra texts were drawn from the 349,098 items the
  per-source caps had cut (choice 3b); 118 near the test sets were dropped. They carry no
  label, so on them the student learns from the teacher alone.
- **Gate:** against v1 as shipped, on the screening halves of suite v0.3 and the Phase 1
  sets: 46 checks, each must pass on every seed.
- **Hardware:** NVIDIA L4, code at commit `ce4d70a`. Teacher scoring took 30 min. Each
  student took 45 min per epoch and about 18 min to score. Each try ran a small run first
  (640 items, every stage), then the full run, with no failed stage.

| Try | α (labels' share) | Epochs | Gate | Fails |
|---|---:|---:|---|---|
| S | 0.5 | 1 | 44 of 46 | LLMail (seed 0); harmful output on OR-Bench hard (seed 1) |
| S2 | 0.3 | 2 | 44 of 46 | Ordinary Spanish messages (seed 0); harmful output on OR-Bench hard (both seeds) |

## Against v1 and the teacher (screening halves, 1% target)

Seeds 0 / 1; for spaced / leetspeak, seed 0's pair then seed 1's.

| | v1 | S (α 0.5, 1 ep.) | S2 (α 0.3, 2 ep.) | T3 | Bar |
|---|---:|---:|---:|---:|---|
| LLMail, full (Phase 1) caught | 40.3% | 37.1 / 45.7% | 49.9 / 52.0% | 66.3% | ≥ 33.4% |
| BIPIA inside documents caught | 6.3% | 32.1 / 31.5% | 33.7 / 44.0% | 59.0% | ≥ 2.8% |
| Real developer messages blocked | 9.8% | 2.6 / 1.5% | 1.6 / 5.0% | 6.6% | ≤ 9.8% |
| LLMail (v0.3) caught | 46.2% | 41.5 ✗ / 48.9% | 54.1 / 56.2% | 66.6% | ≥ 42.3% |
| BIPIA (v0.3) caught | 12.1% | 37.9 / 31.8% | 39.4 / 31.8% | 50.0% | ≥ 6.3% |
| deepset caught | 35.7% | 31.0 / 32.5% | 34.9 / 38.9% | 46.8% | ≥ 27.3% |
| SPML caught | 33.8% | 38.1 / 36.6% | 37.2 / 39.3% | 39.2% | ≥ 32.6% |
| Harmless spaced / leetspeak blocked | 95.9 / 78.3% | 1.6 / 3.8%, 2.4 / 3.2% | 3.0 / 3.2%, 4.1 / 4.7% | 4.3 / 2.8% | ≤ 5% |
| Held-out tool outputs blocked | 0.7% | 1.1 / 0.7% | 2.1 / 0.7% | 1.8% | ≤ 2.5% |
| Ordinary Spanish messages blocked | 0.7% | 0.7 / 0.7% | 1.3 ✗ / 0.8% | | ≤ 1.2% |
| Harmful: OR-Bench hard blocked | 49.5% | 49.3 / 54.9% ✗ | 54.9 ✗ / 55.0% ✗ | 50.8% | ≤ 53.3% |
| Harmful: OR-Bench toxic caught | 90.2% | 90.3 / 91.5% | 90.9 / 91.5% | 92.8% | ≥ 86.5% |

Validation recall at 1% false positives (attack / harmful): S 0.983 / 0.851; S2 0.988 /
0.875 and 0.990 / 0.877; T3 0.995 / 0.910.

## What it shows

**Both students keep the teacher's false-positive gains:**
- harmless disguised text: under 5% blocked, against v1's 78–96%;
- real developer messages: 1.5–5.0%, against v1's 9.8%.

**They keep only part of its detection gains.** S2 is clearly better than S:
- LLMail full: about 40% of the way from v1 to T3 (S: almost none).
- BIPIA inside documents: half to three-quarters of the way, by seed (S: about half).

**One failure is systematic, the others are near the bound:**
- **The harmful output on OR-Bench hard** blocks about 55% in three of the four student
  runs, against a bound of 53.3% (v1 49.5%, T3 50.8%). The R2 weights apply to the
  teacher's term as well as the labels' term, so they are not lost. The likely cause is
  that the student copies the teacher's soft harmful scores on these harmless-but-scary
  prompts, which sit near the threshold, and separates them less sharply. The extra texts
  also carry no R2 weight. This is a hypothesis, not yet tested.
- **LLMail (S, seed 0):** 41.5% against 42.3%. **Spanish (S2, seed 0):** 1.27% against
  1.2%: one message more than the bound allows.

**The gate has not been checked on a model that should tie v1.** It passes a candidate
only if all 46 checks pass on both seeds, which is 92 outcomes. How often a retrain of v1's
own recipe with a new seed fails one of them is not measured. Until it is, a near-bound
failure cannot be told apart from seed noise.

## What follows (the maintainer's decision)

1. **Fortress-Base** (T3, opt-in) is being released (decision 0024).
2. **A null check of the gate,** about 3 h on the L4: v1's recipe with two new seeds, gated
   against v1. If it fails like the students did, a principled change to the gate goes to
   the maintainer before any further student is scored.
3. **A third try, only with a stated hypothesis:** far more teacher-scored extra text (the
   349,098 cut items are already pulled, licensed and checked against the test sets), and
   the R2 weight on the extra texts' harmless-but-scary sources.
4. **A stopping rule:** if the third try fails, stop distillation. Fortress-XS v1 stays the
   default and Fortress-Base serves accuracy.
