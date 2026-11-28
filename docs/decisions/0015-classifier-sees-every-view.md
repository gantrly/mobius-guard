# 0015: The classifier scores every view of a text

- **Status:** accepted, 2026-11-10
- **Builds on:** [0010](0010-proxy-v0.1.md) (views of a text: "detection sees both the
  original and the normalised text"), [0013](0013-releasing-fortress-v0.2.md)
  (Fortress-XS and its threshold), [0014](0014-red-team-runner.md) (the red team and its
  gate)

## Context

Decision 0010 has detection look at several views of each text: the original, a normalised
copy (invisible characters removed, look-alike letters folded, spaced letters joined,
leetspeak undone) and decoded base64. Only the rules did. The classifier scored the
original text, so the disguises the normaliser undoes reached Fortress-XS intact.

The first red-team run (2026-11-09, 1,009,736 attempts) showed it. With Fortress-XS at its
own threshold, more disguised attempts got through than plain ones: 62% with look-alike
letters, 55% with invisible characters and 87% with spaced-out leetspeak, against 50%
plain. The figures leave out the sealed holdout
([2026-11-10](../results/2026-11-10-red-team-holdout.md)).

## Decision

**Attack score.** The classifier scores every distinct view of each checked text, and the
highest attack score over all of them counts. Each distinct text is scored once.

**Harmful score.** The harmful output scores the original text only. It judges what is
asked for, and it only logs by default; its threshold was not re-set.

**Its own threshold.** Scoring more views raises scores on some harmless text, so the
model's 1% threshold no longer gives 1%. The views threshold is set on the same 16,284
ordinary messages as the model's own (the dev half of oasst1). It is the lowest one that
blocks no more of them, scored by the INT8 model the proxy runs, than the model's own
threshold does on their original text. Deployed false positives on ordinary messages
therefore stay what they were. For Fortress-XS v1 (revision `420ca0aa`): own 2.7634; views
threshold in `ONNX_MODELS["fortress-xs"].views_attack`, with the measurement in
[docs/results](../results/2026-11-10-classifier-views.md).

**When it applies.**
- `policy.classifier_views = "all"` (the default) scores every view when the classifier
  has a threshold set for that: the model's views threshold, or `classifier_threshold` in
  the config. A model without thresholds (the published ones, which only log) scores every
  view too.
- The views threshold is tied to the model's own attack threshold in `fortress.json`. Any
  other files under the same name (a different `classifier_dir`) score the original text
  only, at their own threshold, so the stated false-positive rate holds.
- `classifier_views = "original"` keeps the old behaviour.

**Gate.** It passed the red-team gate (decision 0014) on the test items of the four
harmless sets, with no rise on any of them. Its effect on attacks is reported on a fresh
run and on the holdout, not on the attacks it was measured on here.

## Consequences

- **More classifier calls.** A text whose views differ from it costs one call per distinct
  view. About 17.5% of ordinary messages have a second view (mostly words that mix letters
  and digits, such as "v2"); disguised text nearly always does.
- **The model card's numbers stay true for the model.** They describe Fortress-XS on
  original text at 2.7634. The proxy's numbers with every view are in the results note.
- **Every new model release sets its own views threshold** the same way, in the same
  release.

## Considered

- **Every view at the model's own threshold.** It caught more (27.9% → 16.7% got through
  on the tuning sample) but blocked 12 more of 16,061 ordinary test messages (+0.075 pt),
  which the gate does not allow.
- **A lower threshold on original text only.** 2.0 and 1.5 failed the gate (oasst1 144 →
  180 and 202 blocked of 16,061) and leave the disguises in place.
- **Leave it to a retrained model.** The next Fortress needs better data for what remains
  (plain prompts it misses), but disguises are a normalisation problem, solved here for any
  model.
