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
