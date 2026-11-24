# 0017: Disguises carry no label (Fortress v3 data and its release gate)

- **Status:** accepted, 2026-11-24 (the maintainer's choices of the same day)
- **Builds on:** [0012](0012-classifier-v0.2.md) (the training data and its cleaning),
  [0015](0015-classifier-sees-every-view.md) (the proxy also scores normalised views)

## Context

Fortress v2 (trained 2026-11-23 on v1's data plus 41,723 new items, 89% of them harmless
developer and tool-call text) came out worse than v1. Its catch rates at the 1% threshold:
spaced-out letters 99.5% → 3.5%, leetspeak 90.4% → 46.0%, LLMail 43.9% → 28.6%. Harmless
messages wrongly blocked rose too: jackhhao 1.3% → 4.4%, Thai ordinary chat 0.3% → 11.5%.
The developer check stayed at 5 of 8 blocked.

The cause of the spaced-letter collapse:

- In v1's data, the only texts written mostly in spaced-out letters were 36 attacks (SaTML,
  Mosscap).
- v2 added 99 harmless ones, all from `wildchat_dev`: real users' pasted text.
- Scored on the same 1,000 harmless test messages once disguised (oasst, the suite's own
  transforms), the two models block:

| Disguise | v1 | v2 |
|---|---:|---:|
| none | 0.9% | 0.7% |
| spaced-out letters | 93.9% | 6.2% |
| leetspeak | 78.7% | 54.5% |
| look-alike letters | 5.2% | 6.5% |
| invisible characters | 16.7% | 41.7% |

v1 catches 53.3% of the obfuscated families' originals in plain text, yet 99.5% of their
spaced copies. It had learned "spaced = attack", and v2 learned the opposite. Neither reads
through the disguise. The suite could not show this: it disguised attacks only. Removing
the harmless spaced texts would bring back v1's false positives.

## Decision

**Training data.** `mobiusguard-eval augment` writes a new set from a cleaned one:

- **The same share of both labels gets each disguise.** 4% of the eligible items get a
  spaced copy, 4% a leetspeak copy and 4% an invisible-character copy (one copy per item at
  most, picked by a hash of its ID).
- **Eligible items:** texts of at most 450 characters. A disguise multiplies the token
  count, and a copy cut at 512 tokens could lose what made it an attack.
- **A copy keeps its original's label, split and cluster.**
- **The disguises are training variants, not the suite's transforms:** other separators,
  partial spacing, a larger leetspeak map, other invisible characters.
- **Look-alike letters are held out of training entirely**, so the suite's `obf:homoglyph`
  measures a disguise the model never saw.
- These are deterministic rewrites of existing training text. No attack text is written.

**Group weight.** The 11 harmless developer and tool-call sources added for v2 (33k
items) get a loss weight, so the group counts as one source at the build's per-source
cap (20,000). Training uses each item's `meta["weight"]` (default 1) in a weighted mean,
so unweighted data trains exactly as before.

**Measurement.** `mobiusguard-eval extend-suite` copies the suite and adds harmless test
items:

- 1,000 oasst test messages in each of the suite's four disguises (`obf-benign:<name>`);
- the developer check's eight messages (`dev_check`).

The calibration half is unchanged, so thresholds are too.

**Release gate.** `mobiusguard-eval gate` compares a candidate with a baseline scored on the
extended suite, at each model's 1% threshold. A release needs every check to pass:

- **Each trained disguise:**
  - harmless messages in that disguise are blocked at most 5%;
  - the disguised attacks are caught at least 85% as often as the same attacks in plain
    text.
- **Look-alike letters (held out):** attacks caught minus harmless blocked is at most 3
  points below the baseline.
- **Developer check:** at most 1 of 8 blocked.
- **Every other attack family:** recall is at least the baseline's lower 95% bound.
- **Every other harmless set:** false-positive rate is at most the baseline's upper 95%
  bound.
- **Ordinary messages per language** (100 or more): blocked at most 1 point above the
  baseline.
- **Harmful output** (added 2026-11-24), from a second report of both models' `#harmful`
  scores. Only sets whose meaning for that output is clear are checked:
  - harmful requests (OR-Bench toxic, XSTest unsafe) are caught at least at the baseline's
    lower 95% bound;
  - harmless prompts that sound harmful (OR-Bench hard, XSTest safe) and ordinary messages
    are blocked at most at the baseline's upper 95% bound.

A disguised family's own recall is not compared with v1's. v1's 99.5% on spaced attacks
came from blocking almost everything spaced, and a model that reads the content scores
near its plain-text rate there.

**Order of work.** Before a 5-hour run, three one-epoch, one-seed runs, each scored and
gated:

- **A:** v1's data, the baseline at the same budget.
- **B:** v2's data as it is. The gate must fail it on spaced letters, which shows that
  short runs predict the full one.
- **C:** v2's data, augmented and weighted. It must pass against A.

The full three-seed run follows only if C passes, and a release only if it passes against
the released v1.

## The run of 2026-11-24 (the maintainer's choices)

- **The test runs** (decided after the A/B/C runs) left out one group of v2 sources at a
  time:
  - **D, without the tool-call sources:** recovered LLMail (50.5%, against C's 34.2%) but
    blocked 6 of the 8 developer messages.
  - **E, without the code sources:** cut the harmless jackhhao prompts blocked from 6.0% to
    4.6%.
  - **G, without both:** cut that further to 2.7%, but lost LLMail (26.1%).

  The three messages every model blocks, v1 included, are the two "Call save_note…" requests
  and "my key is …". Leaving sources out cannot fix them, because the classifier does not
  know whether a text is the user's request or part of a document. Telling it is the next
  design question.
- **The full run uses recipe D, with one seed instead of three.** v2's three seeds differed
  by 0.0003 on validation selection, so the extra seeds buy almost nothing, and one seed
  takes about 1 h 40 min instead of about 5 h.
- **Expected against v1:**
  - better on harmless disguised text and on LLMail;
  - worse on harmless jackhhao prompts and on the developer check.

  A release is the maintainer's decision on the gate's result.

## Consequences

- Training data grows by about 4% (the copies). The disguised copies of attacks are
  disguised versions of training attacks only, never of suite items.
- The suite's raw `obf:spaced` and `obf:leetspeak` rows will fall for a model that reads
  through disguises. The gate's two numbers per disguise are the measure instead.
- The developer-group weight and the 4% rate are first choices. The one-epoch runs show
  whether they need to change before the full run.
