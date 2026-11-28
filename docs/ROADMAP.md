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
| Fortress v2: v1's data plus developer, code, tool-call and document sources ([training-data.md](training-data.md)), cleaned by the judges | trained 2026-11-23, **not released**: it lost to v1 on spaced-out letters, leetspeak and LLMail. The cause: disguises carried a label, and v1 never read through them either (it blocks 94% of harmless spaced-out text) ([results](results/2026-11-24-fortress-v2-diagnosis.md)) |
| Fortress v3: disguised copies of both labels, look-alike letters held out, a weighted developer group, harmless disguised test sets and a release gate ([decision 0017](decisions/0017-disguises-carry-no-label.md)) | 1-epoch test runs 2026-11-24: disguises fixed as the proxy runs it, with no harmless set or language worse than v1; LLMail, jackhhao harmless prompts and the developer check still worse. Source test runs: the tool-call sources cause the LLMail drop but help the developer check ([results](results/2026-11-24-fortress-v2-diagnosis.md#4-which-v2-sources-cause-the-rest)). Full run on recipe D (1 seed, 3 epochs) 2026-11-24 evening, gated against v1; release is the maintainer's call. Then: tell the classifier a text's role (user, tool result, document) |

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
| Patch proposals: thresholds computed, rules written by a person and measured | 2026-11-10: lower thresholds (2.0, 1.5) failed the gate; the classifier now scores every view ([decision 0015](decisions/0015-classifier-sees-every-view.md)) and three normalisation gaps are fixed, both gated. On the holdout: 25.4% → 20.6% got through, but leetspeak alone and latentinjection got worse ([results](results/2026-11-10-classifier-views.md#on-the-holdout)) |
| Gate on the four harmless-text sets; sealed holdout with its hash committed first | **done**: code 2026-11-09; holdout sealed 2026-11-10 ([hash](results/2026-11-10-red-team-holdout.md)) |
| CLI `mobiusguard-eval redteam`, user guide, tests | **done** 2026-11-09: [docs/red-team.md](red-team.md) |
| Adaptive attacks: PyRIT PAIR with a local attacker and judge, against 0.2.0 and the patched proxy ([decision 0016](decisions/0016-adaptive-attacks.md)) | code **done** 2026-11-10 (`redteam adapt`); the PyRIT glue is checked on the box with the timing sample, then the 20-prompt small run |
| First measured run against 0.2.0 with Fortress (paid attacker, after approval), results note | planned |

- Train a small permissive classifier (DeBERTa-v3-xsmall / mmBERT-small class) on the GPU
  box; INT8 ONNX; model card with held-out numbers.

### Fortress: the improvement plan (agreed 2026-11-25)

Based on the v2 diagnosis and the v3 run
([v2](results/2026-11-24-fortress-v2-diagnosis.md), [v3](results/2026-11-25-fortress-v3.md)).
Four causes limit the model:

1. **It does not know where a text came from.** The same words are a request from the user
   and an attack inside a document. This drives the LLMail, BIPIA and developer-check
   trade-offs.
2. **It learns shortcuts from how text looks.** Disguises did this, fixed in v3.
3. **Single-seed, 1-epoch screening runs are noisy.**
4. **The suite has been used to compare many candidates.**

| Step | Work | Status |
|---|---|---|
| A1 | Thresholds per role: the proxy uses a higher threshold for the user's turn and a lower one for tool results and documents, each set on harmless text of that role. No training. | **done** 2026-11-25 ([decision 0019](decisions/0019-per-role-thresholds.md)): against web and email documents LLMail 43 → 65–68%, but that blocks about 3% of real tool output. Set fairly on tool output, the gain is +7–13 points and the threshold is unstable, so it stays **off by default**; folded into B1 |
| A2 | Measure long inputs in windows ([decision 0018](decisions/0018-long-inputs-in-windows.md)) on v3, then decide its default. No training. | **done** 2026-11-25: LLMail about +6 points, jackhhao harmless +0.9 for v3; **opt-in** (the maintainer's choice) |
| A3 | Gate: compare look-alike letters (held out) with the candidate's own plain-text recall, as for the other disguises, since v1's number there is a shortcut | **done** 2026-11-25 |
| A4 | Gate v3 with A1–A3 against v1; releasing v3 is the maintainer's decision | **done** 2026-11-25 ([results](results/2026-11-25-fortress-deployment-thresholds.md)): 38 of 41 checks pass against v1 as shipped; fails on the developer check (2 of 8, bar 1), jackhhao harmless prompts (3.2–4.1% against 1.3%) and OR-Bench in the harmful output (51.0% against 50.9%) |
| B1 | Role marking: training items tagged user, tool result or document, and the proxy passes the tag (design note first). Train on real tool outputs as harmless text, and set the tool threshold on a larger tool-output set | **built and screened** 2026-11-25 ([decision 0020](decisions/0020-role-marking.md), [results](results/2026-11-25-fortress-role-marking.md)): BIPIA 12 → 48%, jackhhao harmless fixed; the developer check is not fixed and harmful XSTest gets worse. **Stopped, not delivered** |
| B2 | Find which source (`wildchat_dev` or `dev_secrets`) raises the harmless jackhhao blocks; filter it, do not drop it | **not needed**: role marking with the tool-call data back fixed the jackhhao blocks |
| B3 | Honest screening: a development split for comparing candidates, the suite's test half for the final check only, 3 seeds per screening run | **done** 2026-11-25: `split-suite` (screening and final halves by cluster), multi-seed gate |
| — | **Why the weak areas stopped moving** ([results](results/2026-11-25-fortress-role-marking.md#why-the-weak-areas-stopped-moving-2026-11-23-to-25)): the weak sets are small (8 to about 1,300 items) and noisy between seeds; they cannot be trained on; the developer check is 8 sentences; and the model is likely at its capacity. The data mix has stopped paying off | 2026-11-25 |
| C1 | DeBERTa-v3-base as a teacher, distilled into xsmall (same speed) | v4: **next**, planned in [decision 0021](decisions/0021-capacity-and-measurement.md) (accepted 2026-11-26: recipe R, on the L4). Teacher deciding test 2026-11-26: clearly better, 55/57 on both suites; recipe R2 fixed OR-Bench and spaced text; the R2 teachers pass 56/57 (1 epoch) and 55/57 (3 epochs), each failing one check by a hair ([results](results/2026-11-27-fortress-teacher-r2.md)); distillation ([decision 0022](decisions/0022-distillation.md)) tried twice 2026-11-27, both 44/46: the students keep the false-positive gains and part of the detection gains, and the harmful output over-blocks OR-Bench hard ([results](results/2026-11-27-fortress-distillation.md)); next: a null check of the gate, then at most one more try. The teacher ships as **Fortress-Base**, opt-in ([decision 0024](decisions/0024-fortress-base.md)): **published 2026-11-28** ([model](https://huggingface.co/gantrly/fortress-base), [release check](results/2026-11-28-fortress-base-release.md)): final-half gate PASS 45/45; INT8 with the second feed-forward MatMuls in float32, 308 MB, 2.9× Fortress-XS on a CPU; in the proxy from 0.3.0 |
| C2 | Larger held-out test sets: indirect injection (BIPIA has 125 attacks) and developer false positives (hundreds of real harmless developer messages; the 8-message check becomes a smoke test) | **done** 2026-11-26 ([decision 0021](decisions/0021-capacity-and-measurement.md), Phase 1), with the noise floor from 3 seeds. Sets chosen ([research](research/2026-11-26-phase1-test-sets.md)): LLMail phase 2, BIPIA inside documents, WildChat-4.8M developer messages; suite built 2026-11-26 (`runs/suite-p1`, 77,232 items); [results](results/2026-11-26-fortress-phase1.md): the teacher catches 56.5% of LLMail and 55.6% of BIPIA inside documents (v1 40.3 / 6.3) and blocks 3.0% of real developer messages (v1 9.8); near-duplicate check clean |
| — | The harmful output's over-blocking on prompts that only sound harmful (about 50% on OR-Bench hard). It only logs by default. | later |

## v0.3: Fortress-Base and the red team (released 2026-11-28)

| What | Status |
|---|---|
| **Fortress-Base v1**, opt-in (`classifier = "fortress-base"`), [gantrly/fortress-base](https://huggingface.co/gantrly/fortress-base) ([decision 0024](decisions/0024-fortress-base.md)) | **released** in 0.3.0: on the final halves, LLMail-Inject 68.5% (Fortress-XS 47.4%), BIPIA inside documents 70.5% (12.9%), real developer messages blocked 6.0% (10.6%); release gate 45 of 45; 308 MB, 2.9× Fortress-XS on a CPU ([results](results/2026-11-28-fortress-base-release.md)) |
| Role marks and per-role thresholds in the proxy ([decision 0020](decisions/0020-role-marking.md)), every-view scoring ([decision 0015](decisions/0015-classifier-sees-every-view.md)), long inputs in windows (opt-in, [decision 0018](decisions/0018-long-inputs-in-windows.md)) | **released** in 0.3.0 |
| Red-team runner and adaptive attacks (`mobiusguard-eval redteam`, `redteam adapt`) | **released** in 0.3.0 ([guide](red-team.md)) |
| Red-team Fortress-Base; the first measured adaptive run (paid attacker, after approval) | next |
| A distilled model with Fortress-XS's speed and Fortress-Base's gains | two tries failed the gate ([results](results/2026-11-27-fortress-distillation.md)); a null check of the gate first, then at most one more try, both the maintainer's call |

## v0.4: reach

- Dashboard.
- Tool-output / RAG / MCP screening (integrate with existing MCP gateways rather than
  compete).
- Adapters: LiteLLM guardrail, Presidio streaming.
