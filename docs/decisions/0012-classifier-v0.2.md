# 0012: The v0.2 classifier

- **Status:** proposed, 2026-11-04. The maintainer's choices of 2026-11-03 are recorded
  below; the questions at the end need his answers before training starts.
- **Builds on:** [0006](0006-evaluation-rules.md) (evaluation rules),
  [0009](0009-evaluation-harness-v0.1.md) (the evaluation harness),
  [0010](0010-proxy-v0.1.md) (the proxy's classifier slot)

## Why

v0.1 published its weak spot: indirect and adaptive prompt injection (LLMail-Inject,
BIPIA) is still hard for every detector we measured. The open classifiers that do best,
PIGuard and ProtectAI v2, trained on sets that overlap the public benchmarks, and the
maintained permissive options are few. v0.2 trains our own: small enough for a CPU, with
its training data listed source by source and its numbers from sources it never saw.

## Decision

**What it detects.** The positive class is text that tries to make the model follow
someone else's instructions instead of its developer's or user's:
- prompt injection, direct (typed by the user) or indirect (inside an email, web page,
  document, tool result or retrieved chunk);
- jailbreak wrappers that try to switch the model's rules off.

Not positive:
- a harmful request on its own ("how do I pick a lock");
- text *about* injection;
- a document that gives its reader ordinary instructions.

These are the evaluation suite's labels too. Harmful-request sets (AdvBench, JBB-Behaviors,
Salad-Data's base set) would teach "harmful = attack" and raise false positives on XSTest
and OR-Bench, so they are left out.

**Two base models; keep the better one.** Both are MIT-licensed encoders with 384-wide
layers:

| | DeBERTa-v3-xsmall | mmBERT-small |
|---|---|---|
| Layers | 12 | 22 |
| Vocabulary | 128k | 256k |
| Context | 512 tokens | 8,192 tokens |
| Languages | English | multilingual |
| Architecture | DeBERTa-v2 | ModernBERT |

Each is fine-tuned with three seeds, and the runs are compared by their mean: two runs
within a few points of each other are not different. The winner is the one with the
better held-out recall at 1% false positives across attack families, if it does not
raise false positives on the hard benign sets. Ties go to lower CPU latency, measured as
INT8 ONNX P50/P99 at 128 and 512 tokens, batch size 1, hardware stated.

**The evaluation suite stays held out: training uses other sources only.** None of the
suite's 11 sources is used in any split, not even the splits the suite doesn't use (BIPIA's
training attacks, LLMail-Inject phase 1, deepset's train split). Training on them would make
their families in-distribution, and a "held-out family" number would no longer mean that.
More rules:
- Every training text that is a near duplicate of a suite text is dropped: the same
  MinHash test as the suite (Jaccard ≥ 0.8 on character 5-grams).
- Model selection and early stopping use a validation split of the training sources.
- The suite scores each final candidate once.
- The sources, licences and planned use are in [training-data.md](../training-data.md);
  each needs the maintainer's OK.

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
- A small run comes first and its output is read by hand; the full run needs the
  maintainer's approval of its cost (below).

**What ships.**
- An INT8 ONNX model and its tokenizer, Apache-2.0.
- A model card: held-out numbers per family and language, latency with hardware, the data
  ledger with attributions (ODC-BY and CC-BY sources), and known limits.
- Support in the proxy's existing classifier slot.

**Compute.**
- Training and scoring run on the marker-bench box (NVIDIA L4), inside `~/mobius-guard` only.
- Gated sets are downloaded on the maintainer's Mac with his Hugging Face login; only the
  data files go to the box, never a token.

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
- "Half price" is Bedrock batch inference, if its job limits fit; it is to be confirmed
  before the full run.
- The small run tries both models on the same specifications. The full run uses the one
  whose output reads better by hand, and Haiku if they are equal.
- Region: `eu.*` inference profiles in eu-central-1. On 2026-11-04, both models are listed
  as authorized; the first call of the small run confirms access.

## Open questions

1. **The training data:** keep or drop each source in [training-data.md](../training-data.md).
2. **Gated sets:** accept the terms of HackAPrompt and WildJailbreak on Hugging Face, and
   log in on the Mac (`uvx hf auth login`).
3. **The small synthetic run:** approve it (under $1), and choose the languages. Proposed:
   English half, and German, French, Spanish, Portuguese, Hindi, Chinese, Japanese, Arabic
   and Russian for the other half.
4. **Publishing the synthetic set:** release it with the model (useful to others, and
   reproducible), or keep it private. The terms that apply to Claude's outputs on Bedrock
   are for the maintainer to check before release.
5. **Where the weights live:** a Hugging Face organisation (for example `gantrly`), pinned by
   commit like the baselines.
6. **The runtime:** loading the ONNX model needs `onnxruntime` and `tokenizers`, not torch.
   This would be a new, lighter extra (`mobiusguard[onnx]`), decided when the model exists.

## Considered

- **Also training on the suite sources' other splits:** more in-distribution data, but the
  suite would stop being held out for those families. If wanted, that could be a second
  model, reported separately.
- **Distilling PIGuard or ProtectAI scores:** cheap labels, but the student inherits the
  teachers' training sets, which overlap the benchmarks.
- **Larger bases (DeBERTa-v3-base, mmBERT-base):** possibly more accurate, at roughly three to
  four times the CPU cost. Revisit only if both small models fall short.
- **Labelling the noisy sets (Mosscap, whose prompts are not all attacks) with Claude:** paid,
  so heuristics and a manual sample come first, as described in
  [training-data.md](../training-data.md).
