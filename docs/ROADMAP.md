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
| Release as **Fortress-XS v1** in Mobius Guard 0.2.0 ([decision 0013](decisions/0013-releasing-fortress-v0.2.md)): proxy support (`mobiusguard[onnx]`), model card, charts, demo Space | **released** 2026-11-07 as 0.2.0; model at [gantrly/fortress-xs](https://huggingface.co/gantrly/fortress-xs), [demo](https://huggingface.co/spaces/gantrly/fortress-xs) |

Plan for the red-team loop: [decision 0014](decisions/0014-red-team-runner.md) (accepted
2026-11-09).

| Red-team step | Status |
|---|---|
| Decision: targets, garak/PyRIT sources, local attacker in development and a paid one for the measured run, patches as reviewed diffs, gate, sealed holdout | **accepted** 2026-11-09 |
| Target adapters (in-process `Guard`, HTTP proxy) | **done** 2026-11-07: both gave the same verdict on 18/18 attempts against a real proxy with Fortress-XS |
| garak and PyRIT adapters, stacked mutations, ledger entries | **done** 2026-11-07: 19,418 garak prompts from 4 static families (repeatable export), 26 chains × 2 deliveries, 46 PyRIT converters that call nothing |
| Resumable runner, one row per attempt | **done** 2026-11-09: `mobiusguard-eval redteam run / summary`; CPU only (onnxruntime-gpu flipped 1.5% of attack verdicts), per-text score cache, shards |
| Small run on the box (fixed probes, then the local attacker) | fixed probes **done** 2026-11-09: 50 seeds × 52 = 2,600 attempts on 2 shards, killed and resumed with nothing lost or repeated, identical results on two runs, ~25 attempts/s; the local attacker is next |
| Full fixed-probe run against 0.2.0 with Fortress-XS | **done** 2026-11-09: 1,009,736 attempts in 10 h on 4 vCPU, 0 errors; 27.1% got through |
| Findings grouped by family, mutation and cluster | **done** 2026-11-10 (`redteam findings`, holdout left out): disguised attempts got through more often than plain ones |
| Patch proposals: thresholds computed, rules written by a person and measured | 2026-11-10: lower thresholds (2.0, 1.5) failed the gate; the classifier now scores every view ([decision 0015](decisions/0015-classifier-sees-every-view.md)) and three normalisation gaps are fixed, both gated |
| Gate on the four harmless-text sets; sealed holdout with its hash committed first | **done**: code 2026-11-09; holdout sealed 2026-11-10 ([hash](results/2026-11-10-red-team-holdout.md)) |
| CLI `mobiusguard-eval redteam`, user guide, tests | **done** 2026-11-09: [docs/red-team.md](red-team.md) |
| First measured run against 0.2.0 with Fortress (paid attacker, after approval), results note | planned |

- Train a small permissive classifier (DeBERTa-v3-xsmall / mmBERT-small class) on the GPU
  box; INT8 ONNX; model card with held-out numbers.

## v0.3: reach

- Dashboard.
- Tool-output / RAG / MCP screening (integrate with existing MCP gateways rather than
  compete).
- Adapters: LiteLLM guardrail, Presidio streaming.
