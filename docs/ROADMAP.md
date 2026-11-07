# Roadmap

Each part is finished, tested and reviewed before the next one starts.

## v0.1: redaction, evaluation, proxy

| Part | What | Status |
|---|---|---|
| 0 | Foundation: uv workspace, CI, community files, decision records, threat model | **done** (2026-10-27) |
| 1 | `mobiusguard-redact`: streaming redactor, 24 curated + 221 gitleaks patterns, split-at-every-point property tests, latency benchmark | **done** (2026-10-27); keyword prefilter, garbled-echo tolerance and the private-key holdback fix added 2026-11-02 ([results](results/2026-11-02-redactor.md)) |
| 2 | `mobiusguard-eval`: provenance ledger (11 pinned sources), suite builder with near-duplicate clusters and obfuscated attack families, recall at fixed FPR from ordinary-traffic thresholds, AUC, CPU latency, 4 baselines (keyword, TF-IDF leave-one-source-out, ProtectAI v2, PIGuard), redactor evaluation | **done** (2026-10-27); first results in [results/2026-10-27-baselines.md](results/2026-10-27-baselines.md); checkpointed, resumable runs |
| 3 | `mobiusguard` proxy: OpenAI Chat Completions, OpenAI Responses and Anthropic Messages (streamed and not), input normalisation, named rules with severities, optional classifier, policy, streaming redaction per API, audit log, OpenTelemetry spans, `mobiusguard serve` / `check` | **done** (2026-10-29); results in [results/2026-10-29-proxy.md](results/2026-10-29-proxy.md); live check with real SDKs and a real model, 20/20, in [results/2026-10-30-live-check.md](results/2026-10-30-live-check.md) |
| 4 | Release v0.1: user docs, container image, release workflow, published numbers from the harness, PyPI release, make the repository public | **done** (2026-11-03): public, on PyPI; prepared 2026-11-02: docs, `Dockerfile`, version 0.1.0, changelog, tag-triggered release workflow ([decision 0011](decisions/0011-releasing-v0.1.md)), clean-install check; publishing and going public wait for the maintainer |

## v0.2: closed loop and our own model

Plan for the classifier: [decision 0012](decisions/0012-classifier-v0.2.md) (accepted 2026-11-04)
and its [training data](training-data.md). Released so far: 0.1.1 (2026-11-04), the redactor's
held-text fix (#17); 0.1.2 (2026-11-05), the second of two space-separated IBANs (#20).

| Classifier step | Status |
|---|---|
| Decision and training-data ledger (16 sources, two labels: attack, harmful) | **done** 2026-11-04 |
| Training-data builder with suite filters (MinHash, word shingles), contrast pairs, cap, split | **done**; audited on three random samples |
| Two-output fine-tuning (DeBERTa-v3-xsmall, mmBERT-small), 512 tokens | **done** on small samples |
| Length-bucketed batches, resume points every ~20 min, ONNX INT8 export with parity, harmful families in the suite | **done** 2026-11-05 |
| Dress rehearsal on the full data (build, audit, speed and memory, kill and resume, export, label-noise review) | **done** 2026-11-05: about 140 items/s on an L4 for both bases; INT8 needs per-channel + reduce_range |
| Label cleaning with LLM judges (decision 0012) | **done** 2026-11-05: 157,113 items |
| Small runs of the whole training path on the cleaned set (sweep, seed choice, export, scoring; hard kill, time limits, one base failing) | **done** 2026-11-05; mmBERT's INT8 export failed its gate on a barely trained model |
| Learning-rate sweep, three seeds and one suite evaluation on the cleaned public data (the baseline) | **done** 2026-11-06: DeBERTa-v3-xsmall selected; [results](results/2026-11-06-classifier-v0.2-baseline.md). Weak on indirect injection; the harmful output over-blocks |
| Indirect-injection and hard-benign training data (9 sources, see [training-data.md](training-data.md#added-2026-11-06-indirect-injection-and-hard-benign-text)) | **done** 2026-11-06: built, judged ($13.38), spot-checked ($0.72), cleaned: 206,438 items |
| Retrain from scratch on all the data: both bases, three seeds each (DeBERTa 5e-5, mmBERT 2e-5), one suite evaluation | done 2026-11-07: DeBERTa selected again; LLMail 12 → 44%, BIPIA flat, OR-Bench hard over-blocking 55 → 48% ([results](results/2026-11-07-classifier-v0.2-retrain.md)) |
| Model card, release | pending |

- Red-team runner (mutation families, with garak/PyRIT adapters rather than re-writing them).
- Patch proposals (rules or threshold changes) as reviewable diffs, gated on the benign
  canary set and a sealed holdout.
- Train a small permissive classifier (DeBERTa-v3-xsmall / mmBERT-small class) on the GPU
  box; INT8 ONNX; model card with held-out numbers.

## v0.3: reach

- Dashboard.
- Tool-output / RAG / MCP screening (integrate with existing MCP gateways rather than
  compete).
- Adapters: LiteLLM guardrail, Presidio streaming.
