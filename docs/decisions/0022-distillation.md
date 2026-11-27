# 0022: Distil the teacher into xsmall (Fortress v4, Phase 3)

- **Status:** run with the recommended choices and the maintainer's go, on teacher
  T3. Built at `2be9ea1`. **Tried twice on 2026-11-27, neither student passed the gate**
  (44 of 46 each): α 0.5 for 1 epoch, then α 0.3 for 2 epochs
  ([results](../results/2026-11-27-fortress-distillation.md)). As planned under *What would
  change the plan*, the teacher ships as an opt-in model
  ([decision 0024](0024-fortress-base.md)). A third try waits for the maintainer.
- **Builds on:** [0021](0021-capacity-and-measurement.md) (the plan),
  [0020](0020-role-marking.md) (role marking, recipe R), [0017](0017-disguises-carry-no-label.md)
  (the gate)

## Context

The teacher is DeBERTa-v3-base on recipe R. Its 86M-parameter backbone is about 4× xsmall's,
and it is too slow to ship as the default: the proxy's budget is xsmall's P50 of 36 ms at 128
tokens on 4 CPU threads.

Distillation trains xsmall to copy the teacher's scores as well as the labels. A score says
more than a 0 or 1:
- how sure the teacher is;
- which harmless texts look most like attacks.

That is the information xsmall lacked when its LLMail ranking improved and its recall at 1%
did not (decision 0021, reason 4).

## Proposal

**1. Soft targets.** The teacher scores every training item, with the same role markers
(`[user]`/`[tool]`). This gives two logits per item: attack and harmful. The student's loss
on an item is:

`α · BCE(student, label) + (1 − α) · T² · BCE(student / T, sigmoid(teacher / T))`

- **The second term,** for both outputs, pulls the student's probability towards the
  teacher's. `T` softens both, and `T²` keeps the gradient's scale.
- **An unknown harmful label** (−1, as now) drops only the label term. The teacher's harmful
  score still teaches.
- **Disguised copies, group weights and role markers** stay as in recipe R.

**2. The teacher's scores come from a run, not from training.** A new step
(`mobiusguard-eval teacher-scores`) scores the training set with the saved teacher and
writes `id → (attack, harmful)` logits. `train --teacher-scores FILE --alpha A --temperature T`
reads them.

The scores are part of the run's identity: a different teacher means a different run.

**3. The known weakness.** The teacher has seen these training items, so on them its scores
are more confident than on new text. That is common practice and usually still helps.
- **The clean fix** is two teachers, each trained on half and scoring the other half. It
  costs a second teacher run.
- **The cheaper fix** is extra text the teacher never trained on (choice 3).

**4. Thresholds and gate as before.**
- **Thresholds:** the user threshold on oasst1's calibration half, the tool threshold on the
  harmless documents.
- **Screening:** 2 seeds on the screening half and the Phase 1 sets.
- **Release decision:** the gate runs once on the final half, against v1 as shipped.
- **The student keeps xsmall's speed and file:** the same backbone, 81 MB INT8.

## Choices (the maintainer's)

| Choice | Options | Recommendation |
|---|---|---|
| **1. How much the labels count (α)** | **0.5**: half labels, half teacher. **0.2**: mostly teacher. **0**: teacher only | **0.5.** Labels keep the student honest where the teacher is wrong. Try 0.2 only if 0.5 copies too little |
| **2. Temperature (T)** | **1**: the teacher's probabilities as they are. **2**: softer, more weight on near misses | **2.** Most of what xsmall lacks is in the near misses at the threshold |
| **3. Extra text the teacher scores, with no labels** | **a. None:** training data only. **b. The rest of the training sources:** items the per-source caps cut, still never in the suite. **c. b plus WildChat-4.8M files** read by neither training nor `wildchat_dev_test` | **b.** The text is the same kind and already licensed. Near duplicates of the suite are dropped as for training. The teacher has never trained on it, so its scores there are honest. c adds real user text, at the cost of a larger download |
| **4. Where the student starts** | **a. Fresh xsmall** (the public checkpoint). **b. R-xsmall,** already trained on R | **a.** One recipe, one starting point, so the comparison with R-xsmall is clean. b may train faster but carries R's XSTest regression in with it |
| **5. Epochs and seeds** | **1 epoch, 2 seeds** to screen, then 3 epochs for the candidate. Or **3 epochs, 2 seeds** at once | **1 epoch to screen,** as for every candidate so far. Only the chosen setting gets 3 epochs |

## Costs (L4, measured where marked)

- **Teacher scoring of the training set:** about 240,000 items for R, plus extra text with
  choice 3b. That is about 20–30 min, inference only, scaled from the teacher's measured 61
  items/s in training.
- **Student training:** about 36 min per epoch per seed (measured for R-xsmall, 1 epoch).
  Screening 2 seeds takes about 75 min. A 3-epoch candidate takes about 1 h 50 min.
- **Scoring and gate per seed:** about 10 min (measured for R-xsmall).
- **Code:** `teacher-scores`, the loss terms and the train options, with tests. About 2–3 h.
  The Phase 1 suite build is box work, about 1 h.

Every run over about 30 minutes needs a measured estimate and the maintainer's yes. There
are no paid model calls.

## What would change the plan

- **The teacher is not clearly better** than R-xsmall and v1 on the screening half and the
  Phase 1 sets: distillation has nothing to copy, and this record is withdrawn.
- **The teacher is better only on some sets** (for example BIPIA but not the developer set):
  distil anyway, and the gate shows whether the student keeps the gain.
- **The student stays far below the teacher:** ship the teacher as an opt-in larger model
  (decision 0021, Phase 3), with its own latency numbers.
