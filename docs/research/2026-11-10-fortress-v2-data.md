# Fortress v2 training data: what to add (2026-11-10)

**Why:** two gaps in Fortress-XS (0.2.0) are now measured.
- **Gap A, injections inside documents.** In the red-team run, plain garak prompts that
  hide an instruction in a document get through far more often than the other families
  ([results](../results/2026-11-10-classifier-views.md)). Decision 0015 fixed disguised text;
  this gap is the classifier missing the plain prompt.
- **Gap B, harmless developer and agent text.** The live check blocked harmless developer
  messages that mention keys, databases, tokens and tool calls (scores 5.7 to 6.9 against a
  threshold of 2.76; [live check](../results/2026-11-07-live-check-fortress.md)).

The view after the [0.2.0 retrain](../results/2026-11-07-classifier-v0.2-retrain.md) still
holds: the catch is the training data, not the model's size.

**How:** red-team rows outside the sealed holdout, counted per garak probe; licences read
from dataset cards, licence files and the Hugging Face API on 2026-11-10. No data rows were
downloaded. **Every licence is checked again, on the card and in the repository, before a
set enters [`train_sources.py`](../../packages/mobiusguard-eval/src/mobiusguard_eval/train_sources.py).**

**Never trained on:** garak prompts (the red-team set), the suite and anything built from a
suite source (BIPIA, LLMail-Inject).

## Gap A: what gets through

Plain prompts (no mutation) of garak's `latentinjection` family, outside the holdout,
against the patched proxy:

| Probe | What carries the instruction | Got through | Attempts |
|---|---|---:|---:|
| LatentJailbreak | a request wrapped around a task | 100% | 960 |
| Resume | a résumé | 86.1% | 2,400 |
| Report | a report | 84.3% | 864 |
| WhoisSnippet | a whois record | 79.5% | 800 |
| FactSnippetEiffel | a set of facts | 64.5% | 4,800 |
| Whois | a whois record | 62.1% | 248 |
| FactSnippetLegal | a set of legal facts | 53.1% | 2,160 |
| TranslationEnZh | a text to translate | 6.0% | 804 |
| TranslationEnFr | a text to translate | 0.0% | 468 |

The misses are prose and records with an instruction planted in the middle. Short
"translate this" carriers are caught. The 0.2.0 training set already has tool responses
(rgeada, Nemotron) and web pages (BrowseSafe++), so the missing carriers are documents a
person writes: résumés, reports, notes, records.

## Gap A: sources

### Published sets

The [11-05 note](2026-11-05-indirect-injection-datasets.md) lists sets not used in 0.2.0.
They still stand:

| Set | Licence (as stated) | Use for v2 | Open question |
|---|---|---|---|
| SEP | data CC-BY-4.0, code MIT | passages with and without a probe | The README names a `data/` folder that isn't there; the data is `SEP_dataset/SEP_dataset.json` (12 MB). Ask the author to confirm the licence covers it |
| SecFid | Apache-2.0 | documents, agent rows | One slice comes from a CC-BY-SA source: leave that slice out |
| prodnull/prompt-injection-repo-dataset | Apache-2.0, gated (terms) | repository files with security-themed hard negatives | The maintainer accepts the terms |
| ScaleAI/aspi | CC-BY-4.0 on the card, none in the repository | clarification answers | The licences disagree |
| InjecAgent, AgentDojo | MIT | tool responses | Templated, low variety |

SEP's and SecFid's probes are harmless questions. On their own they may teach the
classifier that any instruction inside data is an attack. The clean twins and the Gap B
data are there to balance that.

### Built: insert into documents

TaskTracker (Microsoft) is left out, because it is built from BIPIA (a suite source) and
from SQuAD (CC-BY-SA) and Alpaca (non-commercial). Its recipe is the main proposal:
1. Take harmless documents of the missing kinds (résumés, reports, notes, records) from a
   permissively licensed source.
2. Insert an attack **from our own licensed training set** at a random position. Mobius
   Guard writes no attack text.
3. Keep the document without the insert as its clean twin, in the same split.

Labels follow the 11-05 note: the document with the insert is attack 1, harmful unknown;
the twin is attack 0, harmful 0. The carrier source is not chosen yet: it needs a licence
check, and its documents must not overlap garak's carriers.

## Gap B: harmless developer and agent text

Checked through the Hugging Face API on 2026-11-10:

| Set | Licence | What | Note |
|---|---|---|---|
| Agent-Ark/Toucan-1.5M | Apache-2.0 | tool calls and real outputs from 495 MCP servers | personal data removed by rules only: check before use |
| glaiveai/glaive-function-calling-v2 | Apache-2.0 | function-calling chats | |
| NousResearch/hermes-function-calling-v1 | Apache-2.0 | function-calling chats | |
| Team-ACE/ToolACE | Apache-2.0 | tool-use chats | |
| Salesforce/xlam-function-calling-60k | CC-BY-4.0 | 60k function calls | gated, approved automatically |
| nvidia/When2Call | CC-BY-4.0 | 15k tool-or-not decisions | synthetic |
| ise-uiuc/Magicoder-OSS-Instruct-75K | MIT | coding questions | |
| bigcode/self-oss-instruct-sc2-exec-filter-50k | ODC-BY | coding questions | |
| nvidia/OpenCodeInstruct | CC-BY-4.0 | coding questions | |
| m-a-p/CodeFeedback-Filtered-Instruction | Apache-2.0 | coding questions | |
| allenai/WildChat-4.8M | ODC-BY | real chats, filtered to developer topics | |
| nebius/SWE-agent-trajectories | CC-BY-4.0 | agent runs on real repositories | **caution:** the model outputs fall under the Llama 3.1 licence, so a model trained on them must be named "Llama…". Use only the tool observations, or leave it out |

Left out: SWE-Gym's OpenHands trajectories and lmarena-ai/arena-human-preference-100k (no
licence tag).

Two more ideas:
- **Synthetic secrets.** The live-check misses were messages that contain keys and tokens.
  Insert fake secrets from our own redaction test generator into harmless developer text,
  labelled harmless.
- **A held-out false-positive set.** A developer and agent set, from a source never used in
  training, to measure Gap B in the suite (a suite v0.3 decision).

## Decisions needed

1. **The SEP licence:** open an issue asking the author. It is public, so it waits for the
   maintainer.
2. **The carrier source** for the built documents.
3. **Which Gap B sets**, and how many items from each, so Gap B doesn't outweigh the attacks.
4. **The gated sets:** the maintainer accepts prodnull's terms and xlam's form.
5. **The suite v0.3 false-positive set.**

## Plan

As in the 11-05 note, everything runs on the box:
1. Licence checks.
2. The maintainer's forms.
3. Filters against the suite and the garak seeds.
4. The two judges, a paid step that waits for the maintainer.
5. Retraining from scratch, then the gate and a new holdout measurement.
