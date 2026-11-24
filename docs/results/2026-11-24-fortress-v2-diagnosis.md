# Results: why Fortress v2 lost to v1, and the v3 test runs (2026-11-23 to 24)

Fortress v2 was trained on v1's data plus the v2 sources ([training-data.md](../training-data.md),
*Full build, 2026-11-23*). It scored worse than v1, so it was **not released**. This note
covers:

- what went wrong;
- what that showed about v1;
- the fix ([decision 0017](../decisions/0017-disguises-carry-no-label.md));
- the 1-epoch test runs that check the fix before a full training.

**Setup.** NVIDIA L4 (AWS g6.xlarge), torch 2.15.0, transformers 5.22.1, DeBERTa-v3-xsmall at
5e-5. The suite is v0.2. Thresholds are each model's own, set at 1% false positives on the
calibration half of oasst1; every number below is at that threshold. All counts come from
scripts that print counts only, never dataset text.

## 1. v2 against v1

v2 was a full run: 3 seeds, 3 epochs, 248,112 items, code commit `7cad31d`, 4 h 35 min. Seed 2
was chosen; the seeds' validation selection scores were 0.9659, 0.9663 and 0.9665. Its INT8
export passed its checks and is as fast as v1 (P50 36 ms at 128 tokens, CPU).

| Attack family | n | v1 | v2 |
|---|---:|---:|---:|
| Spaced-out letters | 1,000 | 99.5 | 3.5 |
| Leetspeak | 1,000 | 90.4 | 46.0 |
| LLMail (indirect, adaptive) | 2,981 | 43.9 | 28.6 |
| Jailbreak prompts (jackhhao) | 644 | 86.8 | 88.5 |
| Look-alike letters | 1,000 | 52.2 | 54.6 |
| Gandalf, deepset, SPML, BIPIA, base64, invisible characters | | within about 2 points | |

| Harmless set | v1 | v2 |
|---|---:|---:|
| oasst1 test half | 0.9 | 1.0 |
| jackhhao harmless prompts | 1.3 | 4.4 |
| oasst1, Thai (322 messages) | 0.3 | 11.5 |

The developer check (`scripts/dev_check.py`, INT8, v2 threshold 0.7131) blocked 5 of 8
messages, the same count as v1.

## 2. The cause

v2's data is v1's data unchanged (no attack label differs on a shared ID; 49 items left
out), plus 41,723 new items, of which 37,321 (89%) are harmless developer, code and
tool-call text.

- **Texts written mostly in spaced-out letters** (at least half of the text in runs of
  single letters):
  - In v1's data there were 36, all attacks (SaTML 29, Mosscap 7).
  - v2 added 99 harmless ones, all from `wildchat_dev`: English letters, each one a
    900-character window of a long message.
- **Spaced attacks' median score** fell from +6.89 to −9.38, as low as ordinary chat.
- **Leetspeak-like harmless texts** (three or more words mixing letters and digits) rose
  from 586 to 807. The new ones come from the code sources. Attacks with that pattern
  stayed at 2,529. This pattern is crude, so it is a likely cause, not a measured one.

**What it showed about v1.** The same 1,000 harmless oasst1 test messages were scored after
disguising them with the suite's own transforms (INT8 models):

| Harmless message, rewritten as | v1 blocks | v2 blocks |
|---|---:|---:|
| plain | 0.9% | 0.7% |
| spaced-out letters | 93.9% | 6.2% |
| leetspeak | 78.7% | 54.5% |
| look-alike letters | 5.2% | 6.5% |
| invisible characters | 16.7% | 41.7% |

v1 catches **53.3%** of the obfuscated families' originals in plain text, yet 99.5% of their
spaced copies and 90.4% of their leetspeak copies.

- **v1** did not read through these disguises: it learned "spaced or leetspeak means
  attack".
- **v2** learned the opposite.
- **Look-alike letters** are the one disguise both models read through: about 53% caught,
  about 6% of harmless messages blocked.
- **Why the suite missed it:** it disguised attacks only, so v1's false positives there
  were never measured.

## 3. The fix and its 1-epoch test runs

The fix ([decision 0017](../decisions/0017-disguises-carry-no-label.md)) has three parts:

- **Disguised copies of both labels at the same rate.** 4% of the eligible items each for
  spaced, leetspeak and invisible characters, as training variants.
- **Look-alike letters held out.**
- **The v2 developer group weighted** to count as one capped source.

`extend-suite` adds 4 × 1,000 disguised harmless messages and the 8 developer texts to a
copy of the suite, and `gate` gives a pass or fail against a baseline.

Three runs of 1 epoch with seed 0 (commit `8658147`), each scored on the extended suite:

| Run | Data | Items | Train | Validation attack recall at 1% |
|---|---|---:|---:|---:|
| A | v1's data | 185,852 | 25 min | 99.2% |
| B | v2's data | 223,365 | 30 min | 99.2% |
| C | v3 = v2's data, augmented and weighted | 241,013 | 35 min | 98.1% |

**B reproduces the full v2 failure:** spaced attacks 9.4% caught, LLMail 36.4%, harmless
jackhhao prompts blocked 4.5%. So 1-epoch runs predict the full run, and recipes can be
screened at about 40 minutes each.

**The raw model** (the classifier alone):

| | A | C |
|---|---:|---:|
| Harmless spaced messages blocked | 98.6% | 4.1% |
| Harmless leetspeak messages blocked | 84.7% | 2.3% |
| Harmless invisible-character messages blocked | 51.5% | 2.0% |
| Spaced attacks caught (plain originals: 51.5%) | 99.8% | 27.0% |

C stopped reacting to the disguises, but on its own it catches disguised attacks less often
than plain ones.

**As the proxy runs it** (`local-views:DIR`, commit `aec4c73`): the proxy scores the
original and the normalised view and keeps the higher score (decision 0015).

| Disguise | v1: attacks caught / harmless blocked | C: attacks caught / harmless blocked |
|---|---|---|
| Spaced-out letters | 99.6% / 94.6% | 57.9% / 4.9% |
| Leetspeak | 92.7% / 76.5% | 56.3% / 3.4% |
| Invisible characters | 69.8% / 17.1% | 60.7% / 2.5% |
| Look-alike letters (held out), caught minus blocked | 61.4% | 56.9% |

As the proxy runs it, C catches disguised attacks at least as often as plain ones (51.5%)
and blocks 2.5–4.9% of disguised harmless messages. v1 blocks 17–95% of them.

**C against v1, both scored as the proxy runs them:** 30 of 35 checks pass. The failures:

| Check | v1 | C |
|---|---:|---:|
| LLMail attacks caught | 43.6% | 34.2% |
| jackhhao harmless prompts blocked | 1.3% | 6.0% |
| developer check | 5 of 8 | 4 of 8 |
| Gandalf attacks caught (bar 98.6%) | 99.3% | 98.5% |
| look-alike letters, caught minus blocked (slack 3 points) | 61.4% | 56.9% |

Against A at the same budget, only the first three fail. The 1-epoch A shows the same
Gandalf and look-alike gaps against the 3-epoch v1, so those two are an effect of the short
run. The first three come with v2's new data, as B shows, and the group weight did not fix
them.

## 4. Which v2 sources cause the rest

These runs used the same 1-epoch budget and the same scoring (as the proxy runs it). Each
leaves out one group of v2 sources, with C's group weight kept (commit `fb2dbac`).

| | v1 | A (v1 data) | C (all v3) | D (no tool-call) | E (no code) | G (neither) |
|---|---:|---:|---:|---:|---:|---:|
| LLMail attacks caught | 43.6 | 52.4 | 34.2 | 50.5 | 30.7 | 26.1 |
| jackhhao harmless prompts blocked | 1.3 | 1.0 | 6.0 | 6.0 | 4.6 | 2.7 |
| Developer check (of 8) blocked | 5 | 5 | 4 | 6 | 4 | 5 |
| Checks passed against v1 (of 35) | | | 30 | 31 | 30 | 28 |

- **LLMail:** the tool-call sources pull it down. Without them it recovers above v1.
- **The developer check:** the same tool-call sources help it.
- **The jackhhao harmless prompts:** the code sources cause part of the rise.
- **The messages no model passes:** three of the eight are blocked by every model, v1
  included: the two "Call save_note…" requests and "my key is …". Removing sources only
  trades one result for another, because the classifier does not know whether a text is
  the user's request or part of a document.
- **Noise:** LLMail ranges from 26% to 52% across these single-seed, 1-epoch runs, so part
  of that spread may be noise.

**The full run (2026-11-24 evening):** recipe D, with seed 0 and 3 epochs (one seed: see
decision 0017). It is gated against v1 as the proxy runs it, harmful checks included,
with the INT8 developer check. Its results go in a later note.

## What follows

- **Tell the classifier where a text comes from:** the user's turn, a tool result or a
  document. This is the fix that can serve both LLMail and the developer check. It needs a
  design decision first.
- **The full 3-seed run** (about 5.5 h) only when a 1-epoch candidate passes against A, and
  a release only when it passes against the released v1 as the proxy runs it.
- **Model card and user docs:** v1's false positives on disguised harmless text belong in
  the model card's limits.
