# Training data for the v0.2 classifier (proposed)

**Status:** proposed, 2026-11-04, for the maintainer's check
([decision 0012](decisions/0012-classifier-v0.2.md)). Nothing is downloaded or trained until
each source is accepted. Once accepted, the source of truth moves into code next to the
evaluation ledger ([datasets.md](datasets.md)), pinned to a commit.

**How we checked:**
- Licences, gating and sizes come from each source's Hugging Face metadata and card, read
  on 2026-11-04.
- The two gated sets (HackAPrompt, WildJailbreak) need a Hugging Face login before their
  files and columns can be read. Their columns are to be confirmed then, and the plan
  below may change.

**Rules for every source:**
- **Not from the evaluation suite.** None of the suite's 11 sources is used, in any split.
- **No near duplicates** of any suite text (MinHash, Jaccard ≥ 0.8).
- **Exact repeats dropped.** A text labelled both ways is dropped.
- **Capped at 20,000 items per source,** so that no single game or style dominates.
- **Each item keeps its source ID.** The model card lists every source with its licence
  and attribution.

"Trained on by" lists published classifiers whose model cards name the set; ProtectAI v2
also used 15 sets it doesn't name.

## Attacks

| ID | Source | Licence | Access | Size | Planned use | Trained on by |
|---|---|---|---|---|---|---|
| hackaprompt | [hackaprompt/hackaprompt-dataset](https://huggingface.co/datasets/hackaprompt/hackaprompt-dataset) | MIT | gated (accept terms) | 600k+ competition submissions | The user inputs of submissions that succeeded, deduplicated (to confirm: a success column) | - |
| mosscap | [Lakera/mosscap_prompt_injection](https://huggingface.co/datasets/Lakera/mosscap_prompt_injection) | MIT | open | 279k prompts (DEF CON 31 game) | Attacks, but the card says not every prompt is one. Plan: keep prompts aimed at the secret (password words, instruction overrides). Read a random 200 by hand; if more than 10% are not attacks, ask before labelling with Claude | - |
| satml | [ethz-spylab/ctf-satml24](https://huggingface.co/datasets/ethz-spylab/ctf-satml24) | MIT | open | 137k attack chats | The attacker's messages from chats marked `is_attack`, deduplicated | - |
| wild_jb | [TrustAIRLab/in-the-wild-jailbreak-prompts](https://huggingface.co/datasets/TrustAIRLab/in-the-wild-jailbreak-prompts) | MIT | open | 1,405 jailbreak prompts (2023-12-25) | Attacks. Near-duplicate filter against the suite's jackhhao set, which collected from similar sites | - |
| wildjailbreak | [allenai/wildjailbreak](https://huggingface.co/datasets/allenai/wildjailbreak) | ODC-BY | gated (accept AI2 terms) | 262k synthetic prompts | Adversarial harmful as attacks; vanilla harmful left out (a harmful request is not injection) | - |
| salad | [OpenSafetyLab/Salad-Data](https://huggingface.co/datasets/OpenSafetyLab/Salad-Data) | Apache-2.0 | open | attack-enhanced set | Jailbreak-wrapped questions as attacks; the base set is left out | ProtectAI v2 |
| gandalf_sum | [Lakera/gandalf_summarization](https://huggingface.co/datasets/Lakera/gandalf_summarization) | MIT | open | 140 | Indirect injections, all used | - |

## Benign and hard benign

| ID | Source | Licence | Access | Size | Planned use |
|---|---|---|---|---|---|
| wildchat | [allenai/WildChat-1M](https://huggingface.co/datasets/allenai/WildChat-1M) | ODC-BY | open | 1M real conversations, many languages | First user turns, toxic-flagged ones left out. Real users also try jailbreaks there, so items near a known attack text, or flagged by our rules, are dropped and counted |
| ultrachat | [HuggingFaceH4/ultrachat_200k](https://huggingface.co/datasets/HuggingFaceH4/ultrachat_200k) | MIT | open | 200k synthetic dialogues | First user turns |
| wild_regular | in-the-wild (above), regular prompts | MIT | open | 13,735 | Ordinary prompts from the same communities as the jailbreaks: a hard contrast |
| wildjailbreak_benign | WildJailbreak (above) | ODC-BY | gated | | Adversarial benign (jailbreak-style wording around harmless requests) and vanilla benign |

## Synthetic (Claude on Bedrock; needs approval, see decision 0012)

| ID | What | Planned size |
|---|---|---|
| syn_indirect | Carrier documents (10 genres, about 10 languages) with an inserted injection (a fixed list of goals and techniques) | 8,000 |
| syn_twin | The same documents without the injection | 8,000 |
| syn_hard_benign | Legitimate instructions, security writing, trigger words in harmless text | 4,000 |

## Left out, and why

| Source | Why |
|---|---|
| deepset, Gandalf (ignore instructions), jackhhao, SPML, BIPIA, LLMail-Inject, NotInject, XSTest, OR-Bench, oasst1 (all splits) | The evaluation suite's sources: held out |
| qxcv/tensor-trust | No licence on the dataset or its GitHub repository |
| xTRam1/safe-guard-prompt-injection, jayavibhav/prompt-injection, imoxto/prompt_injection_cleaned_dataset-v2, rubend18/ChatGPT-Jailbreak-Prompts | No licence |
| Harelix/Prompt-Injection-Mixed-Techniques-2024 | Not accessible any more (401) |
| qualifire/prompt-injections-benchmark, HuggingFaceH4/no_robots | CC-BY-NC: non-commercial |
| databricks/databricks-dolly-15k | CC-BY-SA: share-alike terms for a trained model are unclear |
| lmsys/lmsys-chat-1m | Its own licence, not a permissive one |
| walledai/AdvBench, JailbreakBench/JBB-Behaviors, Salad-Data base set | Harmful requests, not injection (decision 0012) |
| Lakera PINT | Not public |
| Open-Orca/OpenOrca | Not needed: WildChat and UltraChat cover ordinary prompts |
