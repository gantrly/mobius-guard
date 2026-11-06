# Training data for the v0.2 classifier

**Status:** accepted, 2026-11-04 ([decision 0012](decisions/0012-classifier-v0.2.md)). The
source of truth is
[`train_sources.py`](../packages/mobiusguard-eval/src/mobiusguard_eval/train_sources.py):
each source is pinned to a commit and kept in its own ledger, apart from the evaluation's
([datasets.md](datasets.md)). Licences, gating, sizes and columns were checked against each
source on 2026-11-04.

**Two labels per item.** The model has two outputs, so every item has:
- **attack:** 1 for an injection or a jailbreak, 0 otherwise;
- **harmful:** 1 for a harmful request, 0 for not, or unknown. The harmful output's loss
  skips unknown labels.

**Rules for every source** (`mobiusguard-eval train-data`):
- **Not from the evaluation suite.** None of the suite's 11 sources is used, in any split.
- **No near duplicates of suite texts** (MinHash, Jaccard ≥ 0.8), and no suite text reused
  inside a longer one: dropped when half of its 8-word shingles occur in the suite, or it
  holds half of a suite text's shingles.
- **Exact repeats dropped;** so are clusters whose attack labels, or known harmful labels,
  disagree.
- **Capped at 20,000 items per source,** so no single game or style dominates.
- **Split 90/10 into train and val by cluster.**
- **Every drop is written out with its reason,** for review.
- **Each item keeps its source ID.** The model card lists every source with its licence and
  attribution.

"Trained on by" lists published classifiers whose model cards name the set; ProtectAI v2
also used 15 sets it doesn't name.

## Label cleaning (2026-11-05)

Every item was then labelled by two LLM judges (Kimi K2.5 and DeepSeek v3.2), and the
disagreements were settled by a rule that a blind spot check decided. The method, the noise
found and the costs are in [decision 0012](decisions/0012-classifier-v0.2.md#label-cleaning-2026-11-05).
Commands: `mobiusguard-eval judge` (paid) and `apply-judges`.

| Source | Items | Kept | What changed |
|---|---|---|---|
| Salad-Data base | 20,000 | 19,969 | 5,647 harmful labels corrected (topic-based at the source) |
| UltraChat | 20,000 | 19,879 | almost nothing |
| WildJailbreak plain harmful | 20,000 | 19,856 | 3,017 harmful labels made unknown |
| WildChat | 20,000 | 19,455 | 360 dropped (judges disagreed on attack) |
| HackAPrompt | 17,933 | 16,272 | judges' attack flips reverted: the source was right |
| Mosscap | 20,000 | 13,648 | 3,717 dropped (unreliable attack flips) |
| WildJailbreak harmless | 20,000 | 13,292 | 4,372 dropped |
| SaTML | 20,000 | 12,553 | 5,036 dropped (harmless probing turns) |
| WildJailbreak (attack side) | 20,000 | 12,121 | 3,700 dropped; 1,517 harmful labels made unknown |
| In-the-wild regular | 12,726 | 8,563 | 2,998 dropped |
| Salad-Data jailbreaks | 1,008 | 738 | 172 attack labels corrected |
| In-the-wild jailbreaks | 587 | 447 | 91 dropped |
| Gandalf summarisation | 139 | 122 | 6 dropped |
| JailbreakBench harmful / harmless | 99 / 99 | 99 / 99 | a few harmful labels made unknown |

"Dropped" also counts items the two judges disagreed on (15,151 in all).

## Attacks (attack = 1)

| ID | Source | Licence | Access | Harmful | Planned use | Trained on by |
|---|---|---|---|---|---|---|
| hackaprompt | [hackaprompt/hackaprompt-dataset](https://huggingface.co/datasets/hackaprompt/hackaprompt-dataset) | MIT | gated | 0 | The user inputs of the 77,213 submissions that succeeded (`correct`) | - |
| mosscap | [Lakera/mosscap_prompt_injection](https://huggingface.co/datasets/Lakera/mosscap_prompt_injection) | MIT | open | 0 | Prompts aimed at the secret or the instructions (keyword filter); a hand check of 200 found 3–4% that were not attacks | - |
| satml | [ethz-spylab/ctf-satml24](https://huggingface.co/datasets/ethz-spylab/ctf-satml24) | MIT | open | 0 | The attacker's messages from chats marked `is_attack`, without junk | - |
| gandalf_sum | [Lakera/gandalf_summarization](https://huggingface.co/datasets/Lakera/gandalf_summarization) | MIT | open | 0 | Indirect injections, all 140 | - |
| wild_jb | [TrustAIRLab/in-the-wild-jailbreak-prompts](https://huggingface.co/datasets/TrustAIRLab/in-the-wild-jailbreak-prompts) | MIT | open | unknown | 1,405 jailbreak prompts; their requests are often placeholders | - |
| wildjailbreak | [allenai/wildjailbreak](https://huggingface.co/datasets/allenai/wildjailbreak) | ODC-BY | gated | 1 | Adversarial harmful: persuasive jailbreaks around a harmful request | - |
| salad | [OpenSafetyLab/Salad-Data](https://huggingface.co/datasets/OpenSafetyLab/Salad-Data) | Apache-2.0 | open | 1 | Attack-enhanced set: harmful questions in jailbreak wrappers | ProtectAI v2 |

## Harmful requests that are not attacks (attack = 0, harmful = 1)

| ID | Source | Licence | Access | Planned use |
|---|---|---|---|---|
| wildjailbreak_harmful | WildJailbreak (above) | ODC-BY | gated | Vanilla harmful: plain harmful requests |
| salad_base | Salad-Data (above) | Apache-2.0 | open | Base set: plain harmful questions |
| jbb_harmful | [JailbreakBench/JBB-Behaviors](https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors) | MIT | open | 100 harmful behaviours in ten categories |

## Benign (attack = 0)

| ID | Source | Licence | Access | Harmful | Planned use |
|---|---|---|---|---|---|
| wildchat | [allenai/WildChat-1M](https://huggingface.co/datasets/allenai/WildChat-1M) | ODC-BY | open | 0, or unknown when flagged | First user turns of one shard, toxic ones left out. When OpenAI's moderation flagged the turn, its harmful label is unknown |
| ultrachat | [HuggingFaceH4/ultrachat_200k](https://huggingface.co/datasets/HuggingFaceH4/ultrachat_200k) | MIT | open | 0 | First user turns of one shard |
| wild_regular | in-the-wild (above), regular prompts | MIT | open | 0 | 13,735 ordinary prompts from the same communities as the jailbreaks |
| wildjailbreak_benign | WildJailbreak (above) | ODC-BY | gated | 0 | Adversarial benign (jailbreak-style wording around harmless requests) and vanilla benign |
| jbb_benign | JailbreakBench (above) | MIT | open | 0 | 100 harmless requests on the same topics as the harmful ones |

## Added 2026-11-06: indirect injection and hard benign text

Chosen in the research notes on [indirect injection](research/2026-11-05-indirect-injection-datasets.md)
and [over-refusal](research/2026-11-06-over-refusal-datasets.md); licences re-checked on
2026-11-06. Twins (an injected document and its clean version) share `meta["pair"]`: the
build caps them together and keeps them in one split.

| ID | Source | Licence | Access | Kept | What |
|---|---|---|---|---|---|
| browsesafe_md | [perplexity-ai/browsesafe-plus-plus](https://huggingface.co/datasets/perplexity-ai/browsesafe-plus-plus), **train split only** | CC-BY-4.0 | gated | 6,233 | Web pages as ~900-character Markdown windows: an injected window holds an injection fragment (checked); its control is a window at the same relative place. Only pages whose Markdown keeps the injection verbatim (3,130 of 29,500) |
| browsesafe_html | same | CC-BY-4.0 | gated | 5,385 | The same as HTML windows, capped at 10,000; pairs either judge disputed are dropped (see below) |
| nemotron_ipi | [nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1](https://huggingface.co/datasets/nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1) | CC-BY-4.0 | open | 2,542 | The tool-returned record holding the injection, and the same record without it |
| rgeada_tool | [rgeada/tool-response-injections](https://huggingface.co/datasets/rgeada/tool-response-injections) | Apache-2.0 | open | 10,377 | JSON tool responses with an inserted injection, and the clean response. Only injections traced to neuralchemy's Apache, MIT or CC-BY parts (its WildGuard part is "Research"); long responses cut to a window around the injection |
| aegis2 | [nvidia/Aegis-AI-Content-Safety-Dataset-2.0](https://huggingface.co/datasets/nvidia/Aegis-AI-Content-Safety-Dataset-2.0) | CC-BY-4.0 | open | 19,586 | Red-team prompts with human safe/unsafe labels (train and validation splits) |
| phtest | [furonghuang-lab/PHTest](https://huggingface.co/datasets/furonghuang-lab/PHTest) | MIT (card; no licence file in the repository) | open | 2,044 | Harmless prompts made to trigger refusals |
| cse_frr | [CyberSecEval MITRE-FRR](https://github.com/meta-llama/PurpleLlama/tree/main/CybersecurityBenchmarks) | MIT | open | 736 | Borderline security-research requests, benign. Written by Llama-2-70b-chat |
| cse_mitre | CyberSecEval MITRE (base prompts) | MIT | open | 860 | Requests for help with cyber attacks: harmful |
| coconot | [allenai/coconot](https://huggingface.co/datasets/allenai/coconot) | ODC-BY-1.0 (LICENSE.md) | open | 1,928 | Safety subcategories: the original requests (harmful) and the contrast set (benign) |

BrowseSafe++'s card ends with a canary line asking that benchmark data stay out of
training corpora. Its train split is CC BY 4.0, and it is used as training data for a
detector (decided 2026-11-06); its test split, under an evaluation-only licence, is never
downloaded. The model card says so.

**Label cleaning of these sources (2026-11-06):** the same two judges ($13.38), then a blind
spot check of 231 disputed items by Claude Sonnet 4.6 ($0.72); the rule is
`judge.RULE_2026_11_06` and [decision 0012](decisions/0012-classifier-v0.2.md) has the
numbers. The cleaned set has **206,438 items** (185,852 train, 20,586 val; 68,754 attacks).

## Synthetic (Claude on Bedrock, see decision 0012)

**Not built** (2026-11-05): the first training run uses the public data above; see
[decision 0012](decisions/0012-classifier-v0.2.md#status-of-the-synthetic-data-2026-11-05).
The plan is kept for reference.

| ID | What | Attack | Harmful | Planned size |
|---|---|---|---|---|
| syn_indirect | Carrier documents (10 genres, 10 languages) with an inserted injection | 1 | 0 | 8,000 |
| syn_twin | The same documents without the injection | 0 | 0 | 8,000 |
| syn_hard_benign | Legitimate instructions, security writing, trigger words in harmless text | 0 | 0 | 4,000 |

## Left out, and why

| Source | Why |
|---|---|
| deepset, Gandalf (ignore instructions), jackhhao, SPML, BIPIA, LLMail-Inject, NotInject, XSTest, OR-Bench, oasst1 (all splits) | The evaluation suite's sources: held out. XSTest's unsafe prompts and OR-Bench's toxic set measure the harmful output |
| qxcv/tensor-trust | No licence on the dataset or its GitHub repository |
| xTRam1/safe-guard-prompt-injection, jayavibhav/prompt-injection, imoxto/prompt_injection_cleaned_dataset-v2, rubend18/ChatGPT-Jailbreak-Prompts | No licence |
| Harelix/Prompt-Injection-Mixed-Techniques-2024 | Not accessible any more (401) |
| qualifire/prompt-injections-benchmark, HuggingFaceH4/no_robots | CC-BY-NC: non-commercial |
| databricks/databricks-dolly-15k | CC-BY-SA: share-alike terms for a trained model are unclear |
| lmsys/lmsys-chat-1m | Its own licence, not a permissive one |
| walledai/AdvBench | Gated, and JailbreakBench covers the same kind of request openly (some of its behaviours come from AdvBench) |
| Lakera PINT | Not public |
| Open-Orca/OpenOrca | Not needed: WildChat and UltraChat cover ordinary prompts |
