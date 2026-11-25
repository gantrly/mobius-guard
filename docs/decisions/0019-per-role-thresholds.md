# 0019: A separate attack threshold for tool results

- **Status:** built and measured 2026-11-25. **Off by default** (the maintainer's choice of
  the same day, after the tool-output check below). It can be set by hand.
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

## Real tool output (2026-11-25)

Harmless API and function responses (2,236, never trained on by either model) are blocked
at 3.1% (v3) and 4.4% (v1) at the document threshold: three times its target. Tool output
scores higher than web pages and emails.

Set fairly, at 1% on documents plus half the tool outputs and tested on the other half:

| | v1 | v3 |
|---|---|---|
| Tool threshold (two folds) | 1.50–1.91 | 0.22–1.86 |
| Held-out tool outputs blocked | 1.4–1.8% | 1.0–2.5% |
| LLMail caught (from 43–44%) | 49–52% | 51–57% |

The threshold is unstable with this little tool output. So it stays off by default. The
next model is trained on tool outputs as harmless text, with roles marked (ROADMAP B1), and
its tool threshold is set on a larger tool-output set.

## Before it is on by default

- **Ship the value per model** in `fortress.json` (for example `thresholds.attack_tool`). A
  threshold belongs to the files it was set on, as the views threshold does.
- **Set it on real tool output as well as documents:** enough of it, from enough sources,
  that the threshold holds steady between folds.
- **Say it in the configuration guide and the model card,** with the measured trade-off.
