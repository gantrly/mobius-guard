# 0021: More capacity, and measurements that can see progress (Fortress v4 plan)

- **Status:** proposed, 2026-11-25. The plan is agreed in outline; three choices below are
  open for the maintainer. Nothing is built or run yet.
- **Builds on:** [0017](0017-disguises-carry-no-label.md) (disguises and the gate),
  [0020](0020-role-marking.md) (role marking),
  [results 2026-11-25](../results/2026-11-25-fortress-role-marking.md) (why the weak areas
  stopped moving)

## Context

From 2026-11-23 to 25, v2, v3 and role marking (R) were trained and gated against v1. None
was delivered:

- **v3** fixed the false blocks on disguised harmless text and passed 36 of 40 checks.
- **R** quadrupled BIPIA and fixed the jackhhao false positives, passing 32 of 40.

Each fix moved one weak area and cost another, for four reasons:

1. **The weak test sets are small,** so real gains of 3–5 points are invisible:
   - the developer check is 8 sentences;
   - BIPIA has about 66 attacks per screening half and deepset about 150;
   - LLMail varies by up to 18 points between seeds.
2. **The weak families are held out,** so the training mix can only move them indirectly.
3. **The developer check is hand-picked,** and three of its sentences read like injection
   payloads.
4. **DeBERTa-v3-xsmall** (22M-parameter backbone) is likely at its capacity. In v3, LLMail's
   ranking improved (AUC 0.903 to 0.939) while its recall at the 1% threshold did not move.

So the next round changes two things: the measurement first, then the model's capacity.

## Plan

**Phase 1: measurements that can see progress (ROADMAP C2).** No training.
- **Bigger held-out indirect-injection test sets,** from sources no Fortress model trains
  on, each checked for licence and for near duplicates of training data. Candidates to
  research:
  - far more of LLMail-Inject, whose challenge released several hundred thousand
    submissions (the suite holds 2,981);
  - BIPIA's other test combinations;
  - the test splits of benchmarks whose train splits we use, such as BrowseSafe++, kept
    only after a near-duplicate check against training.
- **A developer false-positive set:** hundreds to thousands of real harmless developer
  messages, for example from WildChat-4.8M files never used for training, filtered as
  `wildchat_dev` is. The 8-message developer check becomes a smoke test, not a bar.
- **The noise floor:** three seeds of the xsmall recipe (1 epoch) on the screening half.
  This gives the smallest difference that counts as real.
- **Baselines:** v1 and v3 scored on the new sets.

**Phase 2: a larger teacher (ROADMAP C1a).**
- **DeBERTa-v3-base:** an 86M-parameter backbone, about 4× xsmall's compute.
- **The deciding test:** 1 epoch on the chosen recipe, scored on the screening half and
  the Phase 1 sets.
  - **If the teacher is not clearly better** than v1 and v3, by more than the noise floor,
    capacity is not the limit and the plan stops there.
  - **If it is better,** a full 3-epoch teacher follows.

**Phase 3: distil into xsmall (ROADMAP C1b).**
- **What the student learns:** xsmall is trained to match the teacher's two scores (attack
  and harmful) as well as the labels.
- **On what:** the training data, plus unlabelled text from sources not trained on.
  Distillation gains most from extra text.
- **What stays the same:** the student keeps xsmall's latency (P50 36 ms at 128 tokens and
  183 ms at 512 on 4 CPU threads) and its 81 MB INT8 file.
- **Optionally,** the teacher ships as an opt-in larger model.

**Phase 4: the release decision.** The gate runs once on the final half and the Phase 1
sets, against v1 as shipped. Every comparison before then uses the screening half and
several seeds.

## Open choices (the maintainer's)

| Choice | Options | Recommendation |
|---|---|---|
| The teacher's data recipe | **R**: role marking, BIPIA ×4, jackhhao fixed, harmful XSTest worse. **D**: v3's recipe, simpler. | R: a stronger model may remove the XSTest regression, and the gate would show it |
| GPU | **L4** (g6.xlarge): about 2.5 h per base epoch. **L40S** (g6e): about half the time at about twice the hourly price. | L40S for the teacher: about the same cost, answers sooner |
| The developer-check bar | **At most 1 of 8** (today). **The false-positive rate on the new developer set,** no higher than v1's. | The new set, with the 8 kept as a smoke test |

## Costs

- **Phase 1:** data work and about 1 h of box scoring.
- **Phase 2:** about 2.5 h on an L4 for the deciding test, then about 7 h for the full
  teacher.
- **Phase 3:** about 2 h per student seed.

Every run more than about 30 minutes needs a measured estimate and the maintainer's yes.
There are no paid model calls.
