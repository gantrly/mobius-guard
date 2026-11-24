# 0018: Long inputs scored in windows (opt-in until measured)

- **Status:** proposed, 2026-11-24. Built behind a setting that is off by default. The
  default changes only after the measurement below, with the maintainer's choice.
- **Builds on:** [0015](0015-classifier-sees-every-view.md) (the views the classifier
  scores)

## Context

Fortress reads 512 tokens. A longer text is cut, so an injection near the end of a long
document is never scored. The model card says so: on LLMail-Inject, inputs over 512 tokens
are caught 32% of the time, against 48% for shorter ones. Indirect injection (emails,
pages, tool results) is where long inputs are common.

## Decision

- **The scoring.** `policy.classifier_long = "windows"` scores a text over 512 tokens in
  overlapping windows. Each window is a valid model input of its own (`[CLS] … [SEP]`), and
  neighbouring windows share 128 tokens (`WINDOW_STRIDE`), so a phrase split by one window
  is whole in the next. The highest score of a text's windows counts, for each output.
  Short texts score exactly as before. Both the ONNX and the PyTorch classifiers do this,
  so the harness measures the proxy's code.
- **Off by default** (`"cut"`). More windows give a long harmless text more chances to
  score high, so false positives on long text can rise.
- **Cost.** Each extra window is one more model call (P50 about 183 ms at 512 tokens on 4
  CPU threads).

## Before the default changes

Score the suite with and without windows. These detectors in the harness cover it:
`local+windows:DIR`, `local-views+windows:DIR`, and Fortress itself with windows. Report:

- recall on LLMail and BIPIA, overall and for inputs over 512 tokens;
- false positives on every harmless set, and on long harmless text in particular;
- whether the threshold has to be set again on the calibration half, as decision 0015 did
  for views.

If false positives rise, set a separate windows threshold on the same ordinary messages,
as decision 0015 did for views.
