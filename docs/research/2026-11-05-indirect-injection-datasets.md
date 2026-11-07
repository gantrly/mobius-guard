# Indirect-injection training data: published candidates (2026-11-05)

**Why:** the cleaned v0.2 training set has 122 indirect injections (Gandalf summarisation)
out of 157,113 items. The rest of its attacks are direct injections typed into a chat, and
jailbreaks. The suite's indirect families (BIPIA, LLMail-Inject) were the hardest for every
detector in v0.1. The synthetic generator in [decision 0012](../decisions/0012-classifier-v0.2.md)
was not built, so this note lists published sets instead.

**How:** about 45 candidates were checked through their dataset cards, licence files, the
Hugging Face and GitHub APIs, and their papers. No data rows were downloaded.
**Every licence below is to be verified again, on the card and in the repository, before
a set enters [`train_sources.py`](../../packages/mobiusguard-eval/src/mobiusguard_eval/train_sources.py).**
Sets built from a suite source are excluded, like the suite itself.

**Labels:**
- An injected document: attack 1, and harmful unknown. Most of these injections ask an agent
  to act (send, forward, click), not for harmful content.
- A clean twin: attack 0, harmful 0.

## Candidates, best first

| Set | Licence (as stated) | Access | What | Paired clean twin | Notes |
|---|---|---|---|---|---|
| [BrowseSafe++](https://huggingface.co/datasets/perplexity-ai/browsesafe-plus-plus), **train split only** | CC-BY-4.0 (train); the test split is evaluation-only | gated (form) | 29,500 web pages with an injection, each with a benign control; many languages; injection spans marked | yes | Injections observed on real sites. Take the text columns only; never the test split |
| [Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1](https://huggingface.co/datasets/nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1) | CC-BY-4.0 | open | 1,272 tool-returned records in 9 business domains | can be built: the injection is stored separately | Synthetic; the injections were rewritten until they fooled a model |
| [rgeada/tool-response-injections](https://huggingface.co/datasets/rgeada/tool-response-injections) | Apache-2.0 | open | 7,396 clean/injected pairs of JSON tool responses | yes | One upstream source is labelled "Research": check the chain. Some injections come from HackAPrompt, already in training |
| [BrowseSafe-Bench](https://huggingface.co/datasets/perplexity-ai/browsesafe-bench) | MIT | open | 14,719 HTML pages; benign pages carry look-alike distractors | no | Labelled per page only (no chunk labels); probably overlaps BrowseSafe++ |
| [SEP](https://github.com/egozverev/Should-It-Be-Executed-Or-Processed) | data CC-BY-4.0, code MIT | open | 9,160 passages with and without a probe | yes | The probes are harmless questions: may teach that any instruction in data is an attack |
| [SecFid](https://huggingface.co/datasets/mjhermon/SecFid) | Apache-2.0 | open | 1,168 documents plus 252 agent rows | yes | One slice comes from a CC-BY-SA source; same caveat as SEP |
| [prodnull/prompt-injection-repo-dataset](https://huggingface.co/datasets/prodnull/prompt-injection-repo-dataset) | Apache-2.0 | gated (terms) | 5,671 repository files (code, configs, READMEs, CI), with security-themed hard negatives | no | Covers the code carrier |
| [ScaleAI/aspi](https://huggingface.co/datasets/ScaleAI/aspi) | CC-BY-4.0 on the card; no licence in the repository | open | 728 rows, each with 1 benign and 3 injected clarification answers | yes | The licences disagree |
| [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent), [AgentDojo](https://github.com/ethz-spylab/agentdojo) | MIT | open | Tool responses and agent environments | partly | Templated, low variety; InjecAgent trained PIGuard |

## Left out

| Set | Why |
|---|---|
| microsoft/TaskTracker, BIPIA re-packs | Built from BIPIA, a suite source |
| facebookresearch/wasp, SecAlign, Mindgard, rogue-security sets | Non-commercial |
| StruQ, WAInjectBench, MCPTox, R-Judge and others | No licence |
| facebook/llamafirewall-alignmentcheck-evals | The card says not to train on it |
| Lakera/b3-agent-security-benchmark-weak | The licence file is research-only |
| AgentHarm | Evaluation only; harmful agent tasks, not injection |
| PIArena, PromptShield, gentelbench | Built on share-alike or non-commercial sources |
| PoisonedRAG | False facts, not instructions |

## Plan

The baseline trains first on the cleaned public data. These sets come after it, in the
order of [decision 0012](../decisions/0012-classifier-v0.2.md#order-of-training-2026-11-05):
1. Licence checks.
2. The maintainer's Hugging Face form for the gated sets.
3. The same filters against the suite.
4. The two judges, a paid step that waits for the maintainer.
5. Retraining from scratch on everything together.
