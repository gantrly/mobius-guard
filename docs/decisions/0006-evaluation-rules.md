# 0006: Evaluation rules

- **Status:** accepted, 2026-10-27
- **Context:** [research note, part B](../research/2026-10-27-landscape-and-eval.md#part-b--honest-evaluation)

## Decision

Every detection number Mobius Guard publishes follows these rules:

1. **Provenance ledger.** Each dataset is registered with its source, licence, and the known
   models trained on it. Train and test are de-duplicated (exact and near-duplicate) and
   split by attack family, not by row. Sets that can't be redistributed are evaluation-only;
   we ship the loader, not the data.
2. **Held-out families.** Reported attack recall comes from families not used for training
   or tuning, broken down by family and language.
3. **False positives are first-class.** Hard benign sets (text *about* security, prompts with
   trigger words, other languages) are reported alongside attacks.
4. **Recall at a fixed false-positive rate** (0.1%, 1%, 5%, threshold set on a separate dev
   split), plus AUC. Not F1 or accuracy alone.
5. **Latency with hardware.** P50/P95/P99 at stated input lengths, CPU model, thread count,
   runtime version, batch size 1.
6. **Baselines in every table:** rules alone, a TF-IDF + logistic-regression model, and the
   existing open classifiers.
7. **No re-testing on patched attacks.** The v0.2 loop's findings go to training only. Its
   effect is measured on a fresh adaptive run and on a sealed holdout whose hash is
   committed before it is used.
8. **Per-item output.** Every run writes one row per item (input ID, label, score, decision,
   family) that a person can open and review, not just a summary.

## Why

Most public datasets trained some existing classifier, so their published scores aren't
comparable. Adaptive attacks have beaten most published defences, and F1 hides false
positives that block real users.
