# 0012: The v0.2 classifier

- **Status:** accepted, 2026-11-04. The maintainer's choices are recorded below; the answers
  to the open questions of the first draft are under *Answers*.
- **Builds on:** [0006](0006-evaluation-rules.md) (evaluation rules),
  [0009](0009-evaluation-harness-v0.1.md) (the evaluation harness),
  [0010](0010-proxy-v0.1.md) (the proxy's classifier slot)

## Why

v0.1 published its weak spot: indirect and adaptive prompt injection (LLMail-Inject,
BIPIA) is still hard for every detector we measured. The open classifiers that do best,
PIGuard and ProtectAI v2, trained on sets that overlap the public benchmarks, and the
maintained permissive options are few. v0.2 trains our own: small enough for a CPU, with
its training data listed source by source and its numbers from sources it never saw. It
also covers harmful requests, so the proxy can offer protection beyond injection.

## Decision

**One model, two outputs.** Each output is an independent yes/no (a sigmoid, read as
log-odds), so the proxy can threshold and act on each separately:

| Output | Yes when the text… | Examples |
|---|---|---|
| **attack** | tries to make the model follow someone else's instructions or switch its rules off | prompt injection (direct, or inside an email, page, document, tool result or retrieved chunk); jailbreak wrappers, persuasive ones included |
| **harmful** | asks for something harmful | a plain harmful request; the request inside a jailbreak |

A plain harmful request is harmful but not an attack. A jailbreak that wraps one is both. A
jailbreak template whose request is a placeholder is an attack whose harmful label is
unknown. Text *about* attacks, and documents that give their reader ordinary
instructions, are neither. Where a source cannot say whether a text is harmful, that
label is left unknown and the harmful loss skips it.

**Two base models; keep the better one.** Both are MIT-licensed encoders with 384-wide
layers:

| | DeBERTa-v3-xsmall | mmBERT-small |
|---|---|---|
| Layers | 12 | 22 |
| Vocabulary | 128k | 256k |
| Context | 512 tokens | 8,192 tokens |
| Languages | English | multilingual |
| Architecture | DeBERTa-v2 | ModernBERT |

How they are trained:
- **Input length:** 512 tokens, the same length the harness scores at. That is DeBERTa's
  limit.
- **Precision:** weights in float32, bf16 for the computation.
- **Learning rate:** a small sweep (2e-5 and 5e-5), one seed each, judged on validation.
- **Seeds:** the best setting is trained with three seeds, and models are compared by the
  mean; two runs within a few points of each other are not different.
- **Selection:** the epoch, setting and model with the best mean of the two outputs'
  validation recall at 1% false positives, if neither output raises false positives on the
  hard benign sets. Ties go to lower CPU latency, measured as INT8 ONNX P50/P99 at 128 and
  512 tokens, batch size 1, hardware stated.

**The evaluation suite stays held out: training uses other sources only.** None of the
suite's 11 sources is used in any split, not even the splits the suite doesn't use (BIPIA's
training attacks, LLMail-Inject phase 1, deepset's train split). Training on them would make
their families in-distribution, and a "held-out family" number would no longer mean that.
More rules:
- **Near duplicates of suite texts** are dropped: the same MinHash test as the suite
  (Jaccard ≥ 0.8 on character 5-grams).
- **Templates reused inside longer texts** are dropped too, through 8-word shingles. An
  audit found jailbreak templates with a new question attached that MinHash missed.
- **Model selection and early stopping** use a validation split of the training sources.
- **The suite scores each final candidate once.**
- **The sources**, with their licences and both labels, are in
  [training-data.md](../training-data.md).

**Measuring the harmful output.** The v0.1 suite has no harmful-request positives. Two of
its sources have them in parts the suite left out:
- XSTest's 200 unsafe prompts;
- OR-Bench's toxic set (or-bench-toxic, 655 prompts).

Both are CC-BY-4.0, both sources are held out from training already, and the suite's hard
benign sets (XSTest safe, OR-Bench hard-1k) measure over-blocking on the same topics. They
are added to the suite as harmful-request families before the final evaluation, with the
harmful output reported separately.

**Synthetic data from Claude on Amazon Bedrock**, where public data is thinnest: indirect
injection and hard benign text. One call writes several clean carrier documents for a
stated genre, language and setting:
- genres: email, web page, review, support ticket, README, source code, chat log, JSON tool
  output, calendar invite, PDF text;
- with each document, an injection that fits it, with a goal and a technique drawn from a
  fixed list.

The code then inserts the injection into the document to make the attack. The clean
document becomes the attack's contrastive benign twin, which teaches the model the
injection rather than the genre. A second prompt writes standalone hard benign text:
documents with legitimate instructions, security writing, and prompts full of trigger
words. More rules:
- No suite text is shown to the generator: its prompts are written from the lists of goals
  and techniques only.
- Each item records the model and prompt version that made it.
- The synthetic items go through the same filters as every other source.

**What ships.**
- An INT8 ONNX model with both outputs and its tokenizer, Apache-2.0, on Hugging Face under
  `gantrly`, pinned by commit.
- A model card: held-out numbers per output, family and language; latency with hardware;
  the data ledger with attributions (ODC-BY and CC-BY sources); known limits.
- The synthetic set, published with the model if the terms for Claude's outputs allow it.
- Support in the proxy's classifier slot, with a threshold per output.

**Compute and gates.**
- Training and scoring run on the marker-bench box (NVIDIA L4), inside `~/mobius-guard` only.
- Gated sets are downloaded where the maintainer's Hugging Face login is (his Mac); only the
  data files go to the box, never a token.
- Every step runs first on small random samples, which are audited: automatic checks plus
  random items read by hand. Each long or paid step waits for the maintainer's go.

## Label cleaning (2026-11-05)

The dress rehearsal's model was used to find label noise: of the 200 training items it most
disagreed with on each output, many were mislabelled at the source. Examples:
- in-the-wild prompts are labelled by the community they were posted in;
- SaTML labels every turn of an attack chat as an attack;
- Salad-Data's base set labels by topic;
- WildJailbreak's generator sometimes got its own label wrong.

So the labels were checked by LLM judges, measured first.

**Calibration** (300 items: 100 hard, 200 random; about $0.80):
- *Referee.* Claude Sonnet 4.6 labelled every disputed item blind (text and policy only). It
  is the newest Claude model this account can call, and was used as the reference.
- *Noise.* On the random items, the source labels were about 23% wrong. The worst were
  WildJailbreak (attack side) 47%, Salad-Data base 45% and SaTML 35%; WildChat, UltraChat and
  JailbreakBench's harmful items were clean.
- *Judges.* On the random items, Kimi K2.5 was right 95% (attack) / 93% (harmful), DeepSeek
  v3.2 92% / 91%, and GPT-OSS-Safeguard 120B 81% / 89%: Safeguard was too strict and was
  not used.

**Judging:**
- Kimi K2.5 and DeepSeek v3.2 (Bedrock, Mumbai, flex tier) labelled all 192,591 items with
  the policy in `mobiusguard_eval/judge.py`: $39.58, 25 minutes.
- Where they disagreed on attack, the item was dropped (15,151).

**Spot check of the flips** (299, Sonnet 4.6, blind, $0.86):
- right 100% for Salad-Data's attack flips and the base set's harmful flips;
- **wrong for HackAPrompt** (the source was right 93%: those inputs only look harmless out
  of their game);
- 37–88% elsewhere.

**The rule** (`judge.RULE_2026_11_05`):
- keep those two kinds of flips;
- revert HackAPrompt to its source label;
- drop every other item whose attack label the judges flipped;
- make every other changed harmful label unknown.

The result is **157,113 items** (141,497 train, 15,616 val, 35% attacks); each item keeps
its source labels in `meta`. Noise the judges agreed with cannot be found this way. The
evaluation suite was never judged: it stays the honest test.

## Label cleaning of the added sources (2026-11-06)

The nine sources added for the retrain ([training-data.md](../training-data.md#added-2026-11-06-indirect-injection-and-hard-benign-text))
were labelled by the same two judges ($13.38 for 55,127 items). Their labels are of
different kinds, so the rule starts from what each source's label is:
- **Constructed attack labels** (BrowseSafe++, Nemotron, rgeada): every injected window was
  checked to hold its injection, so the judges' disagreements were spot-checked, not
  applied.
- **Human harmful labels** (Aegis 2.0) and PHTest's: checked the same way.

**Spot check** (231 disputed items, Claude Sonnet 4.6, blind, $0.72):

| Disputed | Referee sides with | Applied |
|---|---|---|
| BrowseSafe++ Markdown attack labels (40) | the construction 37 | constructed labels kept |
| rgeada attack labels (25) | the construction 21 | kept |
| BrowseSafe++ HTML attack labels (40) | the construction only 14 | pairs either judge disputes dropped (4,613 items): one fragment of an injection scattered through HTML is often a harmless-looking piece |
| Aegis 2.0 harmful labels both judges overrule (50) | the judges 46 | the judges' label where both agree; the human label where they split |
| Aegis rows both judges call attacks (30) | attack 27 | kept as attacks (its jailbreak prompts) |
| PHTest harmful labels (17), clean twins called harmful (9) | split | unknown where both judges overrule; the source's label where they split |
| CyberSecEval MITRE harmful labels (20) | the judges 14 | the default rule: unknown |

On the older sources the rule is the 2026-11-05 one: the 156,523 items carried over keep
identical labels and splits. The cleaned set has **206,438 items**, 33% attacks, and it
passed a final audit: no duplicate IDs, no text shared between train and val or with the
suite, no twins split across them.

## Status of the synthetic data (2026-11-05)

The synthetic generator was not built in this round. The first training run uses the cleaned
public data only, and its held-out numbers will show what the missing indirect-injection data
costs. Published, permissively licensed indirect-injection datasets that are not in the
evaluation suite are being looked at as an alternative. They would go through the ledger, the
maintainer's check and the same filters. The cost estimate below is kept for reference.

## Order of training (2026-11-05)

- **Baseline first.** The first full run trains on the cleaned public data above: the
  learning-rate sweep, then three seeds of each base's best rate.
- **Then the indirect-injection data.** The published sets in the
  [research note](../research/2026-11-05-indirect-injection-datasets.md) are added after
  their licence checks, through the same ledger, filters and judges. The model is trained
  **from scratch on everything together**, not fine-tuned further on the new data alone,
  which would erode what it learned before and could not be rebuilt from one dataset. That
  run reuses the baseline's chosen settings and trains the three seeds only.
- **Decided before the baseline is scored:** the indirect data is added whatever the
  baseline scores on the suite, so the suite does not steer the data.
- **Which seed is exported:** of each base's three seeds, the one with the best validation
  selection score; the bases are compared by their three-seed mean.
- **The INT8 gate stays as it is.** If a model fails it, standard fixes are tried on the
  trained model and judged against the same gate: leaving the most sensitive layers in
  float32, or calibrated static INT8. A model that still fails is not shipped as INT8, and
  the results note says so.

## Cost of the synthetic data

| | Calls | Input | Output | Sonnet 4.6 | Haiku 4.5 |
|---|---|---|---|---|---|
| **Small run** (60 attack/twin pairs + 50 hard benign, per model) | 15 per model | 23k | 34k | $0.58 | $0.19 |
| **Full run** (8,000 attack/twin pairs + 4,000 hard benign) | 1,734 | 2.6M | 4.0M | $67 ($34 at half price) | $22 ($11 at half price) |

How the estimate is built:
- Tokens: about 1,500 input per call (instructions plus the lists), six pairs or ten
  benign texts per call, about 280 output tokens per document.
- Prices: Bedrock list prices per million tokens, input/output: Sonnet 4.6 $3/$15, Haiku
  4.5 $1/$5.
- "Half price" is Bedrock batch inference, if its job limits fit; to be confirmed before
  the full run.
- The small run tries both models on the same specifications. The full run uses the one
  whose output reads better by hand, and Haiku if they are equal.
- Region: `eu.*` inference profiles in eu-central-1. On 2026-11-04 both models are listed as
  authorized; the first call of the small run confirms access.

## Answers (2026-11-04)

1. **The training data:** accepted as listed, with WildJailbreak's attack side kept and the
   harmful-request sets added for the second output.
2. **Gated sets:** terms accepted for HackAPrompt and WildJailbreak; logged in on the Mac.
   AdvBench (gated) is not used; JailbreakBench covers the same kind of requests openly.
3. **The small synthetic run:** approved (under $1). Languages: English half, and German,
   French, Spanish, Portuguese, Hindi, Chinese, Japanese, Arabic and Russian.
4. **Publishing the synthetic set:** yes, after the terms check.
5. **Where the weights live:** a `gantrly` organisation on Hugging Face.
6. **The runtime:** loading the ONNX model needs `onnxruntime` and `tokenizers`, not torch: a
   lighter extra (`mobiusguard[onnx]`), decided when the model exists.
7. **Input length and settings:** no shortcuts. 512 tokens, a learning-rate sweep, three
   seeds.

## Considered

- **Leaving WildJailbreak's attack side out** (first proposal): its persuasive framings
  push the model to judge harm. With a separate harmful output, the attack output learns the
  framing and the harmful output learns the harm, so both are kept.
- **One output for attacks and harmful requests together:** simpler, but one threshold
  would serve two jobs, and harmless-but-scary prompts would raise false positives on
  injection.
- **Also training on the suite sources' other splits:** more in-distribution data, but the
  suite would stop being held out for those families.
- **Distilling PIGuard or ProtectAI scores:** cheap labels, but the student inherits the
  teachers' training sets, which overlap the benchmarks.
- **Larger bases (DeBERTa-v3-base, mmBERT-base):** possibly more accurate, at roughly three to
  four times the CPU cost. Revisit only if both small models fall short.
- **Labelling the noisy sets with Claude:** not needed. In a hand check of 200 Mosscap
  prompts, 3–4% were not attacks, under the 10% threshold.
