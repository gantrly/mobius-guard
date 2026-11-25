# Results: per-role thresholds and windows for long inputs (2026-11-25)

This is step A of the improvement plan ([ROADMAP](../ROADMAP.md), *Fortress: the improvement
plan*). It changes how the proxy scores texts, not the model, so both v1 and v3
([results](2026-11-25-fortress-v3.md)) are measured the same way.

**Setup:**
- **Scoring:** suite v0.2 plus the extended harmless sets, scored as the proxy runs them
  (every view, highest score).
- **Thresholds:** each model's own 1% user threshold, set on oasst1's calibration half.
- **Hardware and code:** NVIDIA L4, commit `1b27b1c`. Scores and counts only.

## What was measured

- **Windows** ([decision 0018](../decisions/0018-long-inputs-in-windows.md)): a text over
  512 tokens is scored in overlapping windows of 512 tokens (128 shared), and the highest
  score counts.
- **Per-role thresholds** ([decision 0019](../decisions/0019-per-role-thresholds.md)): the
  suite's document sources (LLMail, BIPIA, LLMail's harmless emails) arrive in deployment
  as tool results. They are judged against a threshold set at 1% on harmless documents,
  not against the user threshold. Measured with `role-offset`, which is equivalent at the 1%
  operating point.
- **The harmless documents** (`doc-calibration`): 1,145 items, never trained on by either
  model. They are the validation split of the v3 data minus anything in v1's training set:
  browsesafe HTML 303, browsesafe Markdown 324, Nemotron 122 and SEP 396.

**The thresholds:**

| | v1 | v3 |
|---|---:|---:|
| User threshold (ordinary messages, 1%, every view) | 2.960 | 3.310 |
| Document threshold (harmless documents, 1%) | −1.719 | −2.242 |

## Results

| | v1 now | v3 now | v1 + windows | v3 + windows | v1 + roles | v3 + roles | v1 + both | v3 + both |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| LLMail caught | 43.6 | 43.4 | 49.9 | 49.0 | 68.4 | 64.7 | 75.1 | 72.1 |
| BIPIA caught | 14.4 | 12.0 | 14.4 | 12.0 | 20.8 | 15.2 | 20.8 | 15.2 |
| LLMail harmless emails blocked (160) | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| jackhhao harmless prompts blocked | 1.3 | 3.2 | 1.3 | 4.1 | 1.3 | 3.2 | 1.3 | 4.1 |
| oasst1 test half blocked | 0.9 | 1.0 | 0.9 | 1.0 | 0.9 | 1.0 | 0.9 | 1.0 |
| NotInject blocked | 6.8 | 7.1 | 6.8 | 7.1 | 6.8 | 7.1 | 6.8 | 7.1 |
| Developer check (of 8) blocked | 5 | 2 | 5 | 2 | 5 | 2 | 5 | 2 |

**Is the document threshold too strict?** A two-fold check (`doc_fp_check.py`) set the
threshold on one half of the 1,145 documents (split by near-duplicate cluster) and counted
false positives on the other half, then swapped the halves:

| | v1 | v3 |
|---|---:|---:|
| Fold 1: held-out harmless documents blocked | 6 / 581 = 1.03% (95% 0.5–2.2%) | 6 / 581 = 1.03% (0.5–2.2%) |
| Fold 2: held-out harmless documents blocked | 5 / 564 = 0.89% (0.4–2.1%) | 5 / 564 = 0.89% (0.4–2.1%) |
| Threshold per fold | −1.719 / −1.610 | −2.242 / −2.156 |

- **The threshold generalises within these sources** and holds the 1% target.
- **Where the false positives fall:** most are browsesafe HTML pages (2–3% there), none are
  SEP documents, and almost none are Markdown pages.
- **What is not yet tested:** these documents come from the same sources as training. Other
  kinds of tool output, such as API JSON, search results or code, are not covered here.

## Real tool output (added the same day): the document threshold is too strict

The documents above are web pages, Markdown, emails and SEP data. A test on real tool
output followed: 2,236 harmless tool outputs (API and function responses from glaive_fc,
hermes_fc, toolace and toucan) and 16,585 harmless user requests to use tools. Neither
model trained on them: v3's recipe leaves the tool-call sources out, and v1 never had them.

| Harmless text | v1 | v3 |
|---|---:|---:|
| Tool outputs at the document threshold | 4.38% | 3.09% |
| … toucan only (665) | 11.3% | 6.5% |
| Tool outputs at the user threshold | 1.07% | 0.89% |
| User requests to use tools, at the user threshold | 0.57% | 0.39% |

So the document threshold blocks about 3% of real tool output, three times its target. The
LLMail gain above (65–68%) carries that cost.

**Set fairly** (`tool_mix.py`): the threshold is set at 1% on the documents plus half the
tool outputs, split by cluster, and tested on the other half.

| | v1, fold 1 / 2 | v3, fold 1 / 2 |
|---|---|---|
| Tool threshold | 1.50 / 1.91 | 0.22 / 1.86 |
| Held-out tool outputs blocked | 1.76% / 1.36% | 2.46% / 1.00% |
| LLMail caught | 51.6% / 49.0% | 56.5% / 50.6% |
| BIPIA caught | 18.4% / 17.6% | 14.4% / 13.6% |

- **The gain shrinks:** set this way, the per-role gain is about 7–13 points on LLMail,
  close to what windows give.
- **The threshold is unstable:** it swings between folds (0.22 against 1.86 for v3).
  2,236 tool outputs from four sources are too few to fix a 1% threshold.
- **Decision:** the tool threshold stays off by default
  ([decision 0019](../decisions/0019-per-role-thresholds.md)). The lasting fix is to train
  on tool outputs as harmless text, with each text's role marked (B1 in the ROADMAP).

## Reading the results

- **Per-role thresholds help both models with no retraining, but less than the table
  above shows.** Against the web and email documents alone, LLMail goes from 43–44% to
  65–68%. Measured fairly, with real tool output, the gain is about 7–13 points, at 1–2.5%
  of tool outputs blocked.
- **Windows add about 6 points on LLMail.** For v3 they also raise the harmless jackhhao
  prompts blocked from 3.2% to 4.1%, and each extra window is one more model call.
- **The fixes help both models equally,** so v3 against v1 is unchanged.
  - With the fairer look-alike check (decision 0017, 2026-11-25), every pairing fails the
    same three checks: the developer check (2 of 8, bar 1; v1 blocks 5), the harmless
    jackhhao prompts and OR-Bench hard in the harmful output (51.0% against 50.9%).
  - **v3 with both fixes, against v1 as shipped today:** 38 of 41 checks pass, with LLMail
    at 72.1% against 43.6%.
- **v1 does better than v3 at the same setting on LLMail and BIPIA** (68.4 against 64.7, and
  20.8 against 15.2, with per-role thresholds).
