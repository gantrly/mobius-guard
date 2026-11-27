# 0024: Publish the teacher as Fortress-Base, a separate, opt-in model

- **Status:** accepted, 2026-11-27 (the maintainer). Not yet published: the release waits for
  the maintainer's OK on the model card and the measured CPU latency.
- **Export, 2026-11-27:** the release export's dynamic INT8 (per-channel, `reduce_range`, every
  MatMul and Gather) does not agree with PyTorch for this model: correlation 0.92 (attack)
  and 0.89 (harmful), against the bar of 0.98; the float32 ONNX matches (largest difference
  1.6e-5). In a 24-text small run, keeping each layer's second feed-forward MatMul (its input
  is the GELU output) in float32 passes (0.9994 / 0.9985, 308 MB), as do 8-bit weight-only
  quantisation and float32. A sweep of 8 variants on 500 texts, with latency, runs on the box
  overnight. Shipping anything but the current INT8 needs an `export` option and the
  maintainer's choice, recorded here.
- **Builds on:** [0013](0013-releasing-fortress-v0.2.md) (Fortress-XS; "XS leaves room for a
  larger one"), [0020](0020-role-marking.md) (role marking),
  [0021](0021-capacity-and-measurement.md) (the teacher), [0022](0022-distillation.md)
  (distillation)

## Context

Teacher T3 (DeBERTa-v3-base, recipe R2, 3 epochs, best epoch 2;
[results](../results/2026-11-27-fortress-teacher-r2.md)) is far ahead of Fortress-XS v1 where
v1 is weakest:
- **Injections in documents and email:** LLMail full 66.3% caught against 40.3%; BIPIA
  inside documents 59.0% against 6.3%.
- **Harmless text that looks like an attack:** real developer messages 6.6% blocked against
  9.8%; spaced and leetspeak harmless text 4.3% and 2.8% against 95.9% and 78.3%.

It is too slow to replace v1: the proxy's default must stay fast on a CPU. The first
distillation into xsmall (α 0.5, 1 epoch) kept the false-positive gains but lost most of the
detection gains, and failed the gate (44 of 46).

## Decision

**A second model, next to Fortress-XS, not instead of it.**
- **Name:** **Fortress-Base**, after its base model. "Fortress-S" was rejected: it reads as
  DeBERTa-v3-small, a different model.
- **Where:** `gantrly/fortress-base` on Hugging Face, version **v1**, with the same files as
  Fortress-XS (INT8 ONNX, full-precision weights, tokenizer, `fortress.json`).
- **In the proxy:** `classifier = "fortress-base"`, opt-in like Fortress-XS, pinned by
  Hugging Face commit. Fortress-XS stays the recommended default.
- **`fortress.json`** ships every threshold the proxy uses, at 0.1%, 1% and 5% false
  positives, each set on harmless text of its role: user messages on oasst1's calibration
  half, tool results on the document calibration set, for the original text and for every
  view. The `model-meta` command writes it from the score runs, so no number is copied by
  hand. A threshold its set is too small for is listed as not reliable.
- **The model card** gives its numbers against Fortress-XS from the release gate: run once
  on the final halves (suite v0.3 and the Phase 1 sets), as decisions 0021 and 0022 set.
  The screening halves chose T3, so their numbers are not the card's. It also gives the
  CPU latency measured on the release files, and when to choose which model.

**Two exceptions to the gate, stated on the model card:**
1. **Russian:** on the screening half it blocks 11 of 795 ordinary Russian messages,
   against a bound of 10; all languages but English, pooled, pass. The card states the
   final half's result, whichever way it falls.
2. **One seed:** the gate passes a model only if every seed passes; Fortress-Base is one
   trained model, so the seed check cannot be run. The release files are this model, so
   its numbers are the shipped model's own.

The maintainer accepted both for an opt-in model whose users choose accuracy over speed.

**T3, not T2.** T2 (1 epoch) blocks fewer developer messages (3.7% against 6.6%), but T3
catches more of deepset, of harmful requests and of LLMail, blocks less of OR-Bench's
harmless prompts, and fails only the Russian check by one message.

## Considered

- **Replace Fortress-XS:** rejected for the CPU latency.
- **Wait for a student that passes:** the second distillation (α 0.3, 2 epochs) was running
  when this was decided. A student that passes would become the next Fortress-XS; that does
  not change this decision. It failed the gate too, 44 of 46
  ([results](../results/2026-11-27-fortress-distillation.md)).
- **A second seed first:** about 4 h 20 min of GPU time. It can follow; it would only show
  how much the numbers move between seeds, not change the shipped files.
