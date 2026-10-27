# Datasets (provenance ledger)

The evaluation harness downloads these at a pinned revision into a local cache
(`$MOBIUSGUARD_CACHE`, default `~/.cache/mobiusguard`). No data is stored in this repository.
The source of truth is
[`sources.py`](../packages/mobiusguard-eval/src/mobiusguard_eval/sources.py); licences and
training use were checked against each source on 2026-10-27.

"Trained on by" lists baselines whose *published* training data includes the set; their
numbers on it are marked † in reports. ProtectAI v2 also trained on 15 datasets it does not
name, so it may have seen others.

| ID | Source | Licence | Role | Items used | Trained on by |
|---|---|---|---|---|---|
| deepset | [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) | CC-BY-4.0 ¹ | attacks + benign | 662 (EN/DE) | PIGuard (train split) |
| gandalf | [Lakera/gandalf_ignore_instructions](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions) | MIT | attacks | 1,000 | - |
| jackhhao | [jackhhao/jailbreak-classification](https://huggingface.co/datasets/jackhhao/jailbreak-classification) | Apache-2.0 | jailbreaks + benign | 1,998 | ProtectAI, PIGuard |
| spml | [reshabhs/SPML_Chatbot_Prompt_Injection](https://huggingface.co/datasets/reshabhs/SPML_Chatbot_Prompt_Injection) | MIT | attacks + benign | 16,011 user prompts | - |
| bipia | [microsoft/BIPIA](https://github.com/microsoft/BIPIA) test attacks | MIT ² | attacks | 125 | - (PIGuard used the train attacks) |
| llmail | [microsoft/llmail-inject-challenge](https://huggingface.co/datasets/microsoft/llmail-inject-challenge) phase 2 | MIT | attack attempts | fixed 3,000 sample | - |
| llmail_benign | same, `emails_for_fp_tests.json` | MIT | benign emails | 203 | - |
| notinject | [leolee99/NotInject](https://huggingface.co/datasets/leolee99/NotInject) | MIT | hard benign | 339 | - (made by PIGuard's authors as an eval set) |
| xstest | [Paul/XSTest](https://huggingface.co/datasets/Paul/XSTest), safe prompts | CC-BY-4.0 | hard benign | 250 | ProtectAI, PIGuard |
| orbench | [bench-llm/or-bench](https://huggingface.co/datasets/bench-llm/or-bench) hard-1k | CC-BY-4.0 | hard benign | 1,319 | - |
| oasst | [OpenAssistant/oasst1](https://huggingface.co/datasets/OpenAssistant/oasst1) user messages | Apache-2.0 | ordinary traffic (calibration) | 32,765 | - |

¹ The card's metadata says both Apache-2.0 and CC-BY-4.0; we follow the stricter.
² MIT for the repository; some third-party data under `benchmark/` has other licences.
These two files are not among the exceptions, but we don't redistribute them.

**Credits.** XSTest (Röttger et al.), OR-Bench (Cui et al.) and deepset/prompt-injections are
CC-BY-4.0; reports that use them credit them here. BIPIA (Yi et al.), LLMail-Inject (Abdelnabi
et al.), NotInject (Li et al.), SPML (Sharma et al.), Gandalf (Lakera), jailbreak-classification
(jackhhao) and OpenAssistant (LAION) are credited the same way.

Not in v0.1: AgentDojo (attacks are code templates), HackAPrompt, WildJailbreak and PINT
(gated), Llama Prompt Guard 2 (gated model, licence forbids bundling). See
[decision 0009](decisions/0009-evaluation-harness-v0.1.md).
