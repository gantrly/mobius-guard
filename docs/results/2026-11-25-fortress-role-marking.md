# Results: role marking, the first screening batch (2026-11-25)

This is candidate R of [decision 0020](../decisions/0020-role-marking.md): the model is told
whether a text is the user's turn or a tool result or document. **Not trained further and
not delivered** (the maintainer's decision of the same day). This note keeps what it
showed, and why the weak areas stopped moving.

**Setup:**
- **Data:** v2's data plus disguised copies (decision 0017), each text marked `[user]` or
  `[tool]`, and the tool-call sources back. Half of their tool outputs are held out by
  cluster: 574 set the tool threshold, 582 are a harmless test set.
- **Training:** 239,941 train and 26,556 validation items, with `[tool]` items 49% attacks
  and `[user]` items 26% attacks. DeBERTa-v3-xsmall at 5e-5, 1 epoch, seeds 0 and 1, about
  36 min each.
- **Hardware and code:** NVIDIA L4, commit `0c27018`.
- **Scoring:** as the proxy would run it, on suite v0.3 (v0.2 plus the extended harmless
  sets plus the held-out tool outputs) with markers. The user threshold is set on
  oasst1's calibration half, the tool threshold on 1,682 harmless documents and tool
  outputs. Each is set at 1%.
- **Report:** the screening half (ROADMAP B3), against v1 as shipped (every view, one
  threshold).
- **Gate:** both seeds; a check passes only if it passes for each.

## Against v1

The gate passes 32 of 40 checks.

| | v1 | R (mean of 2 seeds) | Seeds |
|---|---:|---:|---|
| BIPIA caught | 12.1% | **48.5%** | |
| jackhhao harmless prompts blocked | 1.5% | **1.4%** | |
| Held-out harmless tool outputs blocked | 0.7% | 1.6% (bar 2.5%) | |
| Harmless disguised: spaced / leetspeak / invisible / look-alike | 95.9 / 78.3 / 20.5 / 5.5% | 5.3 / 4.2 / 3.2 / 2.0% | seed 0 spaced 7.3%, leetspeak 5.1% |
| Disguised attacks caught (plain originals 57.1%) | 99.6 / 93.3 / 70.4 / 67.0% | 65.2 / 64.0 / 65.4 / 61.5% | |
| Gandalf / jackhhao / SPML / base64 caught | 99.0 / 86.9 / 33.8 / 100% | 98.5 / 85.4 / 35.9 / 100% | |
| Ordinary chat (oasst1), all languages | | same | |
| Developer check (of 8) blocked | 5 | 4.5 | 5 and 4 |
| LLMail caught | 46.2% | 39.7% | 48.5% and 30.8% |
| deepset caught | 35.7% | 26.6% | 27.0% and 26.2% |
| Harmful: XSTest safe prompts blocked | 7.3% | 15.8% | 15.5% and 16.3% |
| Harmful: OR-Bench hard blocked | 49.5% | 53.2% | |
| Harmful: oasst1 blocked | 0.9% | 1.1% | |

**Thresholds** (seed 0 / seed 1):
- **User threshold:** −0.06 / 1.17.
- **Tool threshold:** 0.39 / 2.16, above the user threshold. Harmless `[tool]` text scores
  higher than harmless `[user]` text, and the separate tool threshold corrects for that:
  held-out tool outputs are blocked at 1.6%.

## What it showed

- **Marking where a text comes from works where it should.** BIPIA, injections hidden in
  documents, goes from 12% to 48%. The harmless jackhhao prompts are back at v1's level,
  with the tool-call data restored. No "tool means attack" shortcut appears in the
  held-out tool outputs.
- **It does not fix the developer check.** The same messages are blocked: the two "Call
  save_note with the text exactly: …" requests and "my key is …".
- **New concern:** the harmful output over-blocks XSTest's safe prompts, on both seeds.
  The cause is not known.
- **Noise:** LLMail differs by 18 points between the two seeds. deepset is low, which may
  partly be the short run.

## Why the weak areas stopped moving (2026-11-23 to 25)

Over the v2, v3 and R runs, each fix moved one weak area and cost another. Four reasons:

1. **The weak sets are small, so real gains of 3–5 points are invisible.**
   - Developer check: 8 sentences, so one message is 12.5 points.
   - BIPIA: about 66 attacks per screening half, about ±12 points.
   - deepset: about 150, about ±8.
   - XSTest safe prompts: about 125, about ±6.
   - LLMail: about 1,300, about ±3, but it varies by up to 18 points between seeds.
2. **The weak sets cannot be trained on.** LLMail, BIPIA and deepset are held-out test
   families, and no split of their sources may be used for training. So each change to the
   training mix moves them only indirectly, and in both directions. The tool-call data
   helped the developer check and hurt LLMail. Role marking helped BIPIA and jackhhao.
3. **The developer check is 8 hand-picked sentences, and 3 read like injection payloads.**
   Fixing them with look-alike harmless data would be teaching to the test. It needs a
   held-out set of hundreds of real harmless developer messages.
4. **The model is likely at its capacity.** DeBERTa-v3-xsmall has a 22M-parameter
   backbone. In v3, LLMail's ranking improved (AUC 0.903 to 0.939) without its recall at the
   1% threshold moving: the scores bunch at the threshold.

## What follows

Data-mix changes on this model have stopped paying off. Next ([ROADMAP](../ROADMAP.md)):

- **More capacity:** a larger teacher distilled into the small model.
- **Bigger held-out test sets:** indirect injection and developer false positives.
- **Decisions on several seeds,** or on full runs.
