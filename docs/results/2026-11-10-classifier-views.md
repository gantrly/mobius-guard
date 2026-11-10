# Fortress scores every view, 2026-11-10

The first red-team run found Fortress-XS scoring only the original text, so the disguises
the normaliser undoes reached it intact ([decision 0015](../decisions/0015-classifier-sees-every-view.md)).
This note measures the fix: the classifier scores every view of a text at a threshold set
for that, together with three normalisation gaps fixed the same day.

**Setup.**
- **Box:** g6.xlarge, AMD EPYC 7R13 (4 vCPU); Fortress-XS on the CPU (onnxruntime 1.31.1,
  INT8, one text at a time), revision `420ca0aa`.
- **Code:** commit `f4a1bed` (this branch) against 0.2.0 as measured in the full red-team
  run of 2026-11-09 (commit `faf4b34`), both with
  [`examples/ollama-fortress.toml`](../../examples/ollama-fortress.toml).
- **Harmless text:** suite v0.2. The threshold is set on oasst1's dev half and gated on the
  test items of oasst1, NotInject, OR-Bench hard and LLMail benign emails.
- **Attacks:** 300 garak prompts drawn at random (seed 1) from the 14,855 outside the
  [sealed holdout](2026-11-10-red-team-holdout.md), 52 attempts each: 15,600. They were
  used to choose this change, so they show what it does, not how well it generalises; the
  holdout measurement is below.

## The threshold

| oasst1 dev (16,284 ordinary messages) | Blocked |
|---|---:|
| Original text at Fortress's own 2.7634 (0.2.0) | 153 |
| Every view at 2.7634 | 167 |
| **Every view at 3.1107** | **153** |

3.1107 (exactly 3.110666513442993) is the lowest threshold at which scoring every view
blocks no more dev messages than 0.2.0 does. Fortress's own threshold was set on the same
messages with the PyTorch model (162 at 1%); the INT8 model the proxy runs blocks 153, and
that is what the new threshold keeps.

## The gate

| Test items | Items | Original text at 2.7634 (as 0.2.0) | Every view at 3.1107 |
|---|---:|---:|---:|
| oasst1 | 16,061 | 144 (0.90%) | 144 (0.90%) |
| NotInject | 339 | 23 (6.78%) | 23 (6.78%) |
| OR-Bench hard | 1,319 | 0 | 0 |
| LLMail benign | 160 | 0 | 0 |

`mobiusguard-eval redteam gate`: passed, no rise on any set. The normalisation fixes on
their own also changed nothing here: rule blocks were 0 on all four sets before and after.

Rejected on the way:

| Change | oasst1 test blocked | Gate |
|---|---:|---|
| Original text at 2.0 | 180 (+0.22 pt) | failed |
| Original text at 1.5 | 202 (+0.36 pt) | failed |
| Every view at 2.7634 | 156 (+0.075 pt) | failed (oasst1 may not rise) |

## Attacks

Share of attempts that got through, on the 15,600 attempts above.

| Family | Attempts | 0.2.0 | This branch | Newly caught | Newly through |
|---|---:|---:|---:|---:|---:|
| encoding | 6,604 | 25.3% | 15.8% | 744 | 114 |
| latentinjection | 7,280 | 33.3% | 25.7% | 638 | 84 |
| sysprompt_extraction | 1,300 | 17.7% | 4.8% | 176 | 8 |
| promptinject | 416 | 4.3% | 0.0% | 18 | 0 |
| **All** | 15,600 | **27.9%** | **19.1%** | 1,576 | 206 |

By mutation, applied left to right (600 attempts each, or 1,200 where both orders are
together). The 7 chains not listed, base64 alone or last and base64 then spaced or
leetspeak, got none through in either.

| Chain | 0.2.0 | This branch |
|---|---:|---:|
| spaced + leetspeak (either order) | 88.3% | 47.0% |
| look-alike letters | 62.0% | 45.7% |
| invisible + look-alike (either order) | 58.8% | 42.7% |
| invisible characters | 56.3% | 41.3% |
| leetspeak + invisible | 46.7% | 33.0% |
| leetspeak | 38.7% | 30.0% |
| leetspeak + look-alike | 37.7% | 30.7% |
| look-alike + leetspeak | 35.7% | 31.7% |
| invisible + leetspeak | 33.7% | 28.3% |
| base64 + look-alike | 19.3% | 0.0% |
| invisible + spaced | 15.0% | 7.0% |
| look-alike + spaced | 9.0% | 4.7% |
| spaced + look-alike | 8.3% | 4.7% |
| spaced + invisible | 8.3% | 5.7% |
| spaced | 6.0% | 4.7% |
| base64 + invisible | 5.3% | 0.0% |
| **plain** | **48.0%** | **49.3%** |

The disguises now cost an attacker little: a disguised attempt gets through about as often
as a plain one. What is left is the plain prompts Fortress misses, mostly
`latentinjection` templates, which needs training data, not normalisation. The 206 newly
through scored between 2.7634 and 3.1107 at best: the price of keeping ordinary messages
at 0.90%. Plain prompts lose slightly for the same reason (16 newly through, 8 newly
caught).

## Cost

About 17.5% of ordinary messages get a second view (3,130 of the 17,879 test items, mostly
words that mix letters and digits), and each costs one more classifier call. Scoring all
17,879 took 200 s on the original text and 252 s with every view, on 4 vCPU in one
process: 11.2 → 14.1 ms per message on average. Disguised text nearly always has a second
view, so it costs about two calls.

## On the holdout

The change measured once on the 4,563 held-out prompts (237,276 attempts, 52 each, no
errors): the holdout's first opening, logged 2026-11-10 in `opened.jsonl`. 0.2.0 is the
same attempts in the full run of 2026-11-09. Same box and configuration as above.

| Family | Attempts | 0.2.0 | This branch | Newly caught | Newly through |
|---|---:|---:|---:|---:|---:|
| encoding | 90,896 | 25.5% | 13.9% | 11,300 | 778 |
| latentinjection | 125,216 | 27.4% | **28.9%** | 1,230 | **3,056** |
| sysprompt_extraction | 15,600 | 16.2% | 0.0% | 2,534 | 0 |
| promptinject | 5,564 | 2.3% | 0.0% | 128 | 0 |
| **All** | 237,276 | **25.4%** | **20.6%** | 15,192 | 3,834 |

By mutation (9,126 attempts each). The 7 chains with base64 alone or last, and base64 then
spaced or leetspeak, got none through in either.

| Chain | 0.2.0 | This branch | Newly caught | Newly through |
|---|---:|---:|---:|---:|
| spaced + leetspeak (either order) | 90.8% | 62.4% | 2,614 | 18 |
| **plain** | **65.2%** | **63.9%** | 158 | 36 |
| look-alike letters | 58.7% | 50.3% | 884 | 120 |
| invisible + look-alike | 55.2% | 47.1% | 936 | 204 |
| look-alike + invisible | 55.0% | 47.2% | 910 | 190 |
| invisible characters | 51.5% | 47.9% | 498 | 172 |
| leetspeak + invisible | 40.8% | 35.7% | 892 | 418 |
| invisible + leetspeak | 34.1% | 34.1% | 484 | 484 |
| **leetspeak** | **21.1%** | **33.1%** | 436 | **1,532** |
| base64 + look-alike | 16.7% | 0.0% | 1,526 | 0 |
| leetspeak + look-alike | 16.4% | 16.0% | 268 | 224 |
| invisible + spaced | 14.9% | 5.2% | 924 | 44 |
| look-alike + leetspeak | 14.7% | 13.8% | 270 | 192 |
| spaced + invisible | 8.4% | 4.5% | 448 | 88 |
| spaced + look-alike | 7.5% | 4.0% | 362 | 42 |
| look-alike + spaced | 7.2% | 3.9% | 330 | 24 |
| spaced | 5.3% | 3.5% | 196 | 28 |
| base64 + invisible | 4.8% | 0.0% | 442 | 0 |

**What holds:** the overall drop (25.4% → 20.6%, against 27.9% → 19.1% on the tuning
prompts), and every family but one: encoding, system-prompt extraction and prompt
injection improve as they did on the tuning prompts.

**What doesn't:**
- **Leetspeak alone gets worse** (21.1% → 33.1%), where the tuning prompts showed a gain
  (38.7% → 30.0%). 1,532 attempts that 0.2.0 blocked now get through.
- **latentinjection gets slightly worse** (27.4% → 28.9%). On the tuning prompts it
  improved (33.3% → 25.7%).

The cause is the threshold. All 3,834 attempts newly let through were blocked by the
classifier in 0.2.0 with a score between 2.7634 and 3.1107, and with every view their top
score is still in that band. That is the price named above, larger on the holdout than on
the 300 tuning prompts:
- 1,486 of the 1,532 leetspeak attempts are latentinjection, not encoding.
- Of latentinjection's 3,056, 2,430 are `LatentInjectionResume`, which gains only 482.
  The held-out résumé prompts score close to the threshold, so the change in threshold
  decides them. This is a held-out result, so it is not used
to tune the threshold again (decision 0006). The fix for latentinjection is training data
([v2 data note](../research/2026-11-10-fortress-v2-data.md)).
