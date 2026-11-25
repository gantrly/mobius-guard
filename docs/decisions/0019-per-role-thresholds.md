# 0019: A separate attack threshold for tool results

- **Status:** built and measured 2026-11-25. The default (on or off, and the value shipped
  with Fortress) is the maintainer's choice.
- **Builds on:** [0015](0015-classifier-sees-every-view.md) (every view, its own threshold),
  [0017](0017-disguises-carry-no-label.md) (the gate)

## Context

The classifier sees text, not where the text came from. "Send the report to bob" is a
request when the user writes it and an injection inside an email. One threshold has to
serve both, so the model trades the two off:

- v2's tool-call data helped the developer check and hurt LLMail;
- removing that data did the opposite
  ([results](../results/2026-11-24-fortress-v2-diagnosis.md)).

The proxy already knows each checked text's role: the user's turn or a tool result.

## Decision

- **`policy.classifier_threshold_tool`:** the attack threshold for tool results. Each
  checked text is judged against its own role's threshold, and the request is flagged when
  any text is over its threshold. Unset, tool results use the same threshold as other
  texts, so nothing changes. The decision's score stays the highest over all texts, for the
  audit log.
- **Setting it:** on harmless documents, at the same 1% target as the user threshold. Use
  documents the model never trained on, as `mobiusguard-eval doc-calibration` builds them.
- **Measuring it:** `mobiusguard-eval role-offset` shifts the suite's document sources to
  the document threshold. At the 1% operating point this is the same decision the proxy
  makes.

## Measured (2026-11-25, [results](../results/2026-11-25-fortress-deployment-thresholds.md))

| | v1 | v3 |
|---|---:|---:|
| Document threshold (1,145 harmless documents) | −1.719 | −2.242 |
| LLMail caught: one threshold → per role | 43.6 → 68.4% | 43.4 → 64.7% |
| BIPIA caught: one threshold → per role | 14.4 → 20.8% | 12.0 → 15.2% |
| Held-out harmless documents blocked (two folds) | 1.03%, 0.89% | 1.03%, 0.89% |
| LLMail's 160 harmless emails blocked | 0% | 0% |

## Before it is on by default

- **Ship the value per model** in `fortress.json` (for example `thresholds.attack_tool`). A
  threshold belongs to the files it was set on, as the views threshold does.
- **Check other kinds of tool output** (API JSON, search results, code) for false
  positives. The calibration documents are web pages, Markdown, emails and SEP data.
- **Say it in the configuration guide and the model card,** with the measured trade-off.
