# Research: OSS landscape + honest evaluation (2026-10-27)

Two web-research passes run before the from-scratch design. Star counts / dates were read from
GitHub, PyPI and Hugging Face on 2026-10-27. "Unverified" = could not confirm.

## Part A — what already exists

### Runtime guardrails & gateways

| Tool | Shape / license | Status | Notes & gaps |
|---|---|---|---|
| Meta LlamaFirewall | Python lib, Llama-style license | PyPI 1.0.3 (May 2025) stale | PromptGuard 2 (86M/22M), AlignmentCheck, CodeShield; 92.4/19.3 ms on A100 ([paper](https://arxiv.org/pdf/2505.03574)); FP figures disagree 4.88% vs 0.77% ([bench](https://github.com/bastion-soft/pi-detector-bench/blob/main/results/false_positives.md)); OOD recall issue ([#257](https://github.com/meta-llama/PurpleLlama/issues/257)) |
| Protect AI LLM Guard | Python lib/API, MIT | **Archived**; models unmaintained ([repo](https://github.com/protectai/llm-guard)) | Streaming only an example ([#83](https://github.com/protectai/llm-guard/issues/83)); its deberta-v3-base-prompt-injection-v2 still ~660k downloads/month |
| NeMo Guardrails | Python, Apache-style | 7.4k★, v0.24.1 Sep 2026 | Streaming rails chunk 200 / context 50; block-only, no redaction; `stream_first` leaks tokens before block ([docs](https://docs.nvidia.com/nemo/guardrails/latest/configure-guardrails/yaml-schema/streaming/output-rail-streaming)) |
| Guardrails AI | Python, Apache-2.0 | 7.6k★, v0.11.0 | Output-structure validators, not a firewall |
| Rebuff / Vigil | — | Dead (2024) | — |
| Llama Guard 4 / ShieldGemma 2 / Granite Guardian 4.1 | Weights | 4–12B | Too heavy for CPU inline path |
| Lakera Guard | SaaS | Acquired by Check Point 2025 | Vendor claims only |
| Azure Prompt Shields | SaaS | — | Spotlighting; indirect ASR >50% → <2% ([MS](https://techcommunity.microsoft.com/blog/azure-ai-foundry-blog/-/4458404)) |
| AWS Bedrock Guardrails | SaaS | — | Async streaming: **masking not supported** ([AWS](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-streaming.html)) |
| Google Model Armor | SaaS | — | Injection filter capped at 10k tokens ([notes](https://docs.cloud.google.com/model-armor/release-notes)) |
| LiteLLM | Python proxy, MIT | 62k★ | Streaming guardrails buffered/sampled; `stream_holdback_chars` but **split-chunk value passes unmasked, open [#41611](https://github.com/BerriAI/litellm/issues/41611)** |
| Kong AI Gateway | Lua | 44k★ | Regex only in OSS; semantic + PII sanitizer Enterprise-only ([Kong](https://developer.konghq.com/plugins/ai-semantic-prompt-guard/)) |
| agentgateway | Rust, Apache-2.0 | 5.7k★ | Regex + external moderation hooks |
| Plano (ex-archgw) | Rust/Envoy | 7.1k★ | Jailbreak filter chains |
| **Pipelock** | **Go single binary, Apache core + ELv2** | 965★, v3.7.1 (2026-10-22) | Closest overlap: HTTP/WS/MCP/A2A proxy, 65 DLP + 34 injection patterns, 6-pass normalisation, cross-event SSE scanning, signed rule bundles, public bench. **Stream detection terminates (fail-closed); redaction request-side only; no ML classifier, no auto-patching** ([README](https://github.com/pipelab-org/pipelock)) |

### Red-team tools
garak (Apache, 9.7k★, v0.17.1), PyRIT (MIT, v1.1.0), DeepTeam (Apache), Giskard v3, Spikee (Apache) — all offline, none patch defences.
promptfoo "adaptive guardrails" turns failures into policies but is **Enterprise-only, LLM-based, no automated benign gate** ([docs](https://www.promptfoo.dev/docs/enterprise/guardrails/)). RvB paper (Jan 2026) does red-blue guardrail patching, code unverified ([arXiv](https://arxiv.org/abs/2601.19726)).

### Streaming redaction
No mature project rewrites a split secret mid-stream. Presidio [#2312](https://github.com/data-privacy-stack/presidio/issues/2312) open (per-delta analysis leaks). Only 0★ repos: [LLM-Shield-Proxy](https://github.com/xflyhack/LLM-Shield-Proxy), [pii-redaction-gateway](https://github.com/gelevanog/pii-redaction-gateway).

### Agent / MCP
Crowded: Snyk agent-scan, Docker MCP Gateway, ToolHive, Lasso mcp-gateway, Pipelock, agentgateway. CaMeL reference impl self-described buggy; 77% vs 84% AgentDojo utility ([repo](https://github.com/google-research/camel-prompt-injection)).

### Evidence against classifiers
Character injection evades Azure Prompt Shield / Prompt Guard / ProtectAI / NeMo up to 100% ([2504.11168](https://arxiv.org/abs/2504.11168)). "The Attacker Moves Second": adaptive attacks broke 12 defences at >90% ASR ([2510.09023](https://arxiv.org/abs/2510.09023)).

### Gaps (value × feasibility, 1–2 people)
1. Chunk-safe streaming redaction that **rewrites, not terminates**, as a reusable lib + LiteLLM/Presidio plugin, with chunk-invariance property tests and published TTFT cost.
2. Open red-team → patch → **canary-gated** loop with deterministic, reviewable patches and held-out mutation families.
3. Reproducible public eval harness (held-out families, hard-benign, CPU latency, recall@fixed-FPR).
4. Maintained permissive calibrated INT8 ONNX injection classifier (ProtectAI archived; PromptGuard 2 Llama-licensed).
5. Lower value alone: MCP firewall, single binary — integrate, don't compete.

## Part B — honest evaluation

### Attack datasets

| Dataset | Size / labels | License | Contamination notes |
|---|---|---|---|
| deepset/prompt-injections | 662 (546/116) | Apache-2.0 | Trained InjecGuard |
| Lakera/gandalf_ignore_instructions | 1,000 injections | MIT | — |
| Lakera/mosscap_prompt_injection | 279k, by game level, not all attacks | MIT | [paper](https://arxiv.org/pdf/2501.07927) |
| PINT (Lakera) | 4,314; 20.9% hard neg; ~30 langs | Repo MIT, data partly proprietary | Archived; vendor tops own bench |
| jackhhao/jailbreak-classification | 1,306 | Apache-2.0 | Trained ProtectAI v2 + InjecGuard |
| xTRam1/safe-guard-prompt-injection | 10,296 synthetic | Not stated | Trained InjecGuard |
| reshabhs SPML | ~20k inputs | MIT | Core of PIDS-Bench |
| qualifire benchmark | 5,000 | Possibly CC-BY-NC (unverified) → eval-only | Sentinel authors' own |
| HackAPrompt | 100k–1M | MIT, gated | Trained InjecGuard |
| Tensor Trust | 563k attacks | Unverified | — |
| BIPIA | 5 tasks | Unverified, research | Train split used by InjecGuard → test split only |
| InjecAgent | 1,054 | MIT | Trained InjecGuard |
| AgentDojo | 629 security cases | MIT | Prompt Guard 2 reports on it |
| LLMail-Inject (2025) | 208k adaptive | MIT (unverified) | [arXiv](https://arxiv.org/abs/2506.09956) |
| JailbreakBench / HarmBench / AdvBench | 100+100 / 510 / 520 | MIT / unverified | Harmful requests, jailbreak recall only |
| WildJailbreak | 262k + 2,210 eval | ODC-BY, gated | — |
| PIDS-Bench (2026) | 35k + stress sets | Unverified | Seed-family split, 0.90 n-gram dedup ([arXiv](https://arxiv.org/html/2609.15017)) |

### Benign / FP sets
NotInject (339 trigger-word benign), XSTest (CC-BY-4.0; ProtectAI trained on part), OR-Bench (CC-BY-4.0), WildChat-4.8M (ODC-BY, 74 langs), LMSYS-Chat-1M (no redistribution → eval-only, ship scripts), PIDS-Bench hard-benign (best DeBERTa still FPR ~0.23–0.28).

### Classifier results
| Model | License | Reported |
|---|---|---|
| ProtectAI deberta-v3-base v2 | Apache-2.0 | PINT 79.1; NotInject 56.6%; >90% adaptive ASR |
| Llama Prompt Guard 2 86M/22M | Llama 4 license (naming + 700M MAU limits → baseline only, never bundle/distil) | Recall@1%FPR 97.5/88.7; PIDS F1 0.539 |
| Prompt Guard 1 | Llama | NotInject 0.88%; spaced chars evade ~99.8% |
| InjecGuard / PIGuard | MIT | NotInject 87.3%; 15 ms; adaptive ASR 71% |
| Sentinel (qualifire) | Unverified | 0.98 F1 on own set |

Small CPU bases: DeBERTa-v3-xsmall (22M, MIT, English), mmBERT-small (140M/42M non-emb, MIT, 1,800 langs, 8k ctx). No published CPU INT8 latency for xsmall/small — must measure.

### Recommended eval protocol
1. **Provenance ledger** per source: license + which models trained on it. Dedup train↔test (exact + char n-gram cosine ≥0.90), split by seed family. NC/no-redistribution sets eval-only, ship scripts not data.
2. **Train** (permissive): SPML, xTRam1 (if licensed), HackAPrompt, Mosscap/Gandalf (filtered), Tensor Trust (if licensed), WildJailbreak; benign WildChat non-toxic multilingual, OASST/Alpaca, BIPIA/InjecAgent train.
3. **Held-out attacks**, per family, never tuned on: BIPIA test, AgentDojo, LLMail-Inject, deepset test, PINT (if access), JBB/HarmBench, qualifire; leave-one-family-out; obfuscation suite (spaced chars, homoglyphs, zero-width, base64, translation).
4. **FP sets**: NotInject, XSTest safe, OR-Bench-hard-1k, PIDS hard-benign, security docs/articles about injection, frozen non-English WildChat slice.
5. **Metrics**: recall @ FPR 0.1/1/5% (threshold fixed on separate dev), AUC, FPR per benign set, per-language/family, latency P50/P95/P99 at 64/256/512 tokens with CPU model, threads, ORT version, batch 1. Baselines: regex only, TF-IDF+LR, ProtectAI v2, PIGuard, Prompt Guard 2.
6. **Adaptive round**: white-box search/RL attacker with stated budget + human red-team, manually verified success; report ASR before/after.
7. **No self-deception**: red-team loop's patched pool → training only; re-test on a fresh adaptive run vs frozen model + sealed hash-committed holdout opened only at release. Never report on the attacks you patched.
