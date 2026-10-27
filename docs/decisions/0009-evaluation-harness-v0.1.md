# 0009: The v0.1 evaluation harness

- **Status:** accepted, 2026-10-27
- **Builds on:** [0006](0006-evaluation-rules.md) (evaluation rules)

## Decision

**What it measures.** Two things: prompt-injection detection, and the streaming redactor.

**Datasets: a permissive starter set** that downloads without sign-up, every licence
checked against the source on 2026-10-27 and recorded in the ledger
([`sources.py`](../../packages/mobiusguard-eval/src/mobiusguard_eval/sources.py),
summarised in [datasets.md](../datasets.md)). Files are pinned to a commit (Hugging Face)
or a SHA-256 (GitHub), fetched into a local cache, and never committed.

| Role | Sets |
|---|---|
| Attacks | deepset, Gandalf, jackhhao (jailbreaks), SPML, BIPIA test attacks, LLMail-Inject (fixed 3,000 sample) |
| Hard benign | NotInject, XSTest (safe prompts), OR-Bench hard-1k, LLMail-Inject's benign emails |
| Ordinary traffic | oasst1 user messages (35 languages) |

AgentDojo is left for later: its attacks are templates in code, not a list of strings.
Gated sets (HackAPrompt, WildJailbreak, PINT) and Llama Prompt Guard 2 are out of v0.1.

**Thresholds come from ordinary traffic.** Half of the oasst1 messages (split by
near-duplicate cluster) sets each detector's threshold for a target false-positive rate of
0.1%, 1% or 5%. Every attack set and every hard benign set is reported out of sample. This
is how a deployment would calibrate (on its own normal traffic), and it means a detector
can't look good on NotInject by tuning to NotInject.

**Families are sources plus obfuscations.** An attack family is its source dataset, plus
five deterministic obfuscations applied to 1,000 test attacks spread across sources:
spaced letters, look-alike letters from other scripts, zero-width characters, leetspeak and
base64. No model calls. A technique taxonomy (role-play, payload splitting, ...) is v0.2.

**Duplicates.** Exact repeats inside a source are dropped; texts labelled both attack and
benign are dropped everywhere. Near duplicates (estimated Jaccard >= 0.8 on character
5-grams, MinHash) form clusters, and a cluster always lands in one split.

**Baselines.**

- *keyword*: ten well-known injection phrases. The floor.
- *tfidf*: character TF-IDF + logistic regression, trained leave-one-source-out: the
  items of a source are scored by a model trained on every other source, minus near
  duplicates, so no score comes from a model that saw its source.
- *protectai-v2* (Apache-2.0) and *piguard* (MIT), pinned to a commit, inputs cut to 512
  tokens as their model cards do. PIGuard's model class is re-implemented locally from its
  29-line remote code, so the harness never runs downloaded code
  (`trust_remote_code=False` everywhere).

Each table marks with † a set the detector is known to have trained on (PIGuard: deepset
train, jackhhao, XSTest prompts; ProtectAI: jackhhao, XSTest). ProtectAI also trained on 15
unnamed datasets, so its other cells may be contaminated too; the ledger says so.

**The redactor** is measured two ways: how often each of the 245 patterns fires on the
suite's ~57k public texts (a firing rate with every finding written out for review, not a
false-positive rate, because people do paste real emails), and recall on synthetic values
of every curated type placed in real messages and streamed in random chunks, including
near misses that must not be redacted.

**Where it runs.** Scoring and reporting are separate commands, so model scoring runs on
the GPU box and the report is computed from score files. Latency is measured on CPU, batch
size 1, at 64/256/512 tokens, with the CPU model, thread count and library versions
recorded; v0.1's numbers come from the GPU box's CPU (AWS g6.xlarge, 4 vCPU).

**Outputs** (all under the git-ignored `runs/`): `items.jsonl` + `manifest.json` (suite,
with a hash of every item ID so two builds can be compared), per-detector `scores.jsonl`
and `run.json` (what ran, where, which commit), and the report (`report.md`,
`metrics.json`, and `scored_items.jsonl` with one reviewable row per item).

**Runs resume.** Every step saves its work as it goes and skips what is already done for
the same inputs, so a crash, a fix or a new detector never means starting again. A
checkpoint is an append-only file whose first line is a key: everything that decides the
result (detector and model revision, the suite's item IDs, the pattern set, the settings).
A different key sets the old file aside instead of reusing it; a line cut short by a crash
is ignored. Scoring is saved per 2,048 items (per source for TF-IDF), the redactor
evaluation per 2,000 texts and per pattern, and the suite, finished scores and latency
files are skipped when their key matches. `mobiusguard-eval pipeline` runs every step in
order, carries on past a failed step and reports it at the end; running it again resumes.
`--force` redoes a step.

## Why

Every choice here answers the same question: would the number survive someone trying to
reproduce or attack it? Pinned inputs, out-of-sample thresholds, leave-one-source-out
training and contamination marks are what make the comparison with existing classifiers
fair.

## Considered

- **Thresholds per benign set**: lower reported false positives everywhere, but each number
  would be tuned to the set it is reported on.
- **A random row split for TF-IDF**: higher scores, but they measure memorising a
  dataset's style, which is the contamination problem we are trying to show.
- **Gated sets and Prompt Guard 2 now**: more coverage, but sign-ups and a licence that
  forbids bundling. Planned as optional loaders.

## Known limits

- oasst1 is not perfectly benign: a few users pasted jailbreak prompts, which then count as
  false positives in calibration.
- Inputs longer than 512 tokens are truncated for the transformer baselines, which can hide
  an attack at the end of a long email.
- Obfuscated copies come from all attack sources, including sets marked † for a detector.
- The LLMail-Inject sample contains attack *attempts*, not only successful attacks.
