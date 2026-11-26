# Bigger held-out test sets: candidates for decision 0021, Phase 1 (2026-11-26)

**Why:** the weak test sets are too small to show real gains of 3 to 5 points
([results 2026-11-25](../results/2026-11-25-fortress-role-marking.md)):
- the developer check is 8 sentences;
- BIPIA has about 66 attacks per screening half;
- LLMail has about 1,300.

[Decision 0021](../decisions/0021-capacity-and-measurement.md) Phase 1 asks for larger
held-out sets: indirect injection, and real harmless developer messages.

**How:**
- **Research:** web only, from dataset cards, repositories and papers. No data was downloaded.
- **What was checked:** each candidate was compared with what Fortress already trains on
  ([`train_sources.py`](../../packages/mobiusguard-eval/src/mobiusguard_eval/train_sources.py))
  and what the suite already holds
  ([`sources.py`](../../packages/mobiusguard-eval/src/mobiusguard_eval/sources.py)).
- **Licences and counts** are as stated by the source. They are checked again when a loader is
  written.

**Bigger sets cut sampling noise only.** LLMail's 18-point gap between seeds is the model's
own variance. The noise floor (three seeds) is still needed.

## Recommended

### 1. LLMail-Inject: much more of what the suite already samples

- **What the suite holds now:** 3,000 attacks from phase 2's labelled unique submissions
  (`labelled_unique_submissions_phase2.json`), plus the 203 harmless test emails.
  Fortress never trains on LLMail.
- **Available, as the card states:**
  - **Phase 2:** 37,303 labelled unique submissions (69 MB). The file is already pinned in
    `sources.py`.
  - **Phase 1:** 160,741 (448 MB). It was run against the older defenses, so it is a
    different and easier population.
  - The raw files (462k rows) are not needed.
- **Licence:** MIT, not gated.
- **Format:** an email (`subject` + `body`) read by a mail assistant, so these are indirect
  injections. `team_id` (224 teams) and `scenario` (40 levels) come with every submission.
- **Risks:**
  - **Near duplicates:** each team iterated on its own attack. Split screening from final
    **by team**, and count confidence intervals by team or cluster, not by row.
  - **Copies in training:** some of our training sources may contain LLMail copies. A
    near-duplicate check against the training set is required.
- **Plan:** all of phase 2, filtered as now to entries judged as attacks, then near-duplicates
  removed and split by team. That is roughly 10× today's set. Phase 1 is an optional second
  set.

### 2. Developer false positives: WildChat-4.8M files never used for training

- **What training uses now:** `wildchat_dev` takes 4,000 messages from files 5, 33, 49, 53,
  62 and 65 of the 86 files. `wildchat` takes file 0 of WildChat-1M.
- **Available:** 80 unused files, about 15 GB in total for all 86. Filtered the same way as
  `wildchat_dev`:
  - first user turns;
  - two or more developer terms;
  - not toxic, not flagged.

  A few files should give thousands of messages.
- **Licence:** ODC-BY. The non-toxic set is open.
- **Risks:**
  - **The 1M overlap:** most of WildChat-1M (about 759k conversations by `conversation_hash`,
    per a secondary source) is inside 4.8M. Drop any held-out message whose text or hash is
    in training.
  - **Duplicates:** WildChat has many repeated first turns. Remove duplicates on normalised
    text.
  - **Real attacks:** some "harmless" rows are real jailbreak attempts. Before this becomes a
    bar, review the flagged rows by ID and count only (texts not printed), and decide how
    to handle them.
- **Plan:** 4 unused files, chosen by a fixed seed, with their indices recorded in the source.
  The 8-sentence developer check stays as a smoke test.

### 3. BIPIA: test attacks put inside documents

- **What the suite holds now:** the 125 test attack instructions on their own (75 text, 50
  code), with no documents. This is why BIPIA is so small.
- **Available:** the repository's builder places each test attack at the start, middle or
  end of a test context. The three tasks that ship their contexts:
  - Email QA: 50 contexts, 11,250 prompts;
  - Table QA: 100 contexts, 22,500 prompts;
  - Code QA: 50 contexts, 7,500 prompts.

  That is 41,250 prompts, and the 200 clean contexts are a harmless set. Web QA (NewsQA)
  and Summarization (XSum) need separate downloads under their own terms: leave them out.
- **Licence:**
  - The code is MIT.
  - Email contexts come from OpenAI Evals (MIT).
  - Tables come from WikiTableQuestions, and code from Stack Exchange (CC BY-SA 4.0).

  We use them for evaluation and do not redistribute them, as with the suite now.
- **Limit:** there are still only 125 distinct attacks. More rows measure robustness to
  position and context, not variety of attack. The confidence interval has to be counted by
  attack instruction, so it narrows less than the row count suggests.
- **Plan:** email, table and code, scored as `[tool]`. Split screening from final by attack
  instruction.

## Not usable as held-out sets

| Set | Why |
|---|---|
| BrowseSafe++ train split | Already training data (`browsesafe_md`, `browsesafe_html`) |
| BrowseSafe++ test split | The evaluation licence allows scoring only through the authors' leaderboard. Labels are withheld, so we can't measure it ourselves |
| BrowseSafe-Bench (MIT, 3,680 test) | 6,488 BrowseSafe++ pairs are built from it, so it overlaps our training. Its test split also appears to share templates with train. At most a secondary check after near-duplicate removal |
| SEP, InjecAgent | Already training sources |
| AgentDojo (MIT) | An environment, not a dataset: its text has to be generated by running agents. Possible later |
| deepset/prompt-injections | Already in the suite; 116 test rows |
| Tensor Trust | Direct injection, not indirect; licence unclear |
| Qualifire benchmark | CC-BY-NC-4.0 (non-commercial) |
| Lakera PINT | The dataset is private |

## What this gives, per screening half (after splitting)

| Set | Today | With Phase 1 (estimate) |
|---|---:|---:|
| LLMail attacks | ~1,300 | ~15,000, from ~110 teams |
| BIPIA attacks | ~66 (bare) | ~20,000 placements of ~60 instructions |
| Developer harmless messages | 8 (smoke test) | thousands |

The estimates come before near-duplicate removal, and the final counts come from the box.

## Built 2026-11-26: the loaders

In [`sources.py`](../../packages/mobiusguard-eval/src/mobiusguard_eval/sources.py), with
tests on made-up files. Not run on real data yet. Two findings changed the plan:
- **LLMail has no team field** in the labelled file (only `attack_attempt` and `reason`), so
  the halves are split by near-duplicate cluster, as for every other set. A team split
  would need a join with the 264 MB raw file. The file also marks about 2,000 attempts as
  the boolean `true` rather than the string `"True"`; `llmail_full` takes both (`llmail`'s
  3,000 sample takes only the string, unchanged).
- **BIPIA gives every document every attack,** so a split by document would put all 125
  attacks in both halves. `bipia_embedded` puts documents and attacks each in one of two
  groups and keeps only pairs from the same group (about half). Each group is one half
  (`meta["half"]`, which the screening split follows), so the halves share neither
  documents nor attacks.

**Intervals:** the report's 95% intervals counted rows. On `bipia_embedded`, 10,000 rows
per half come from about 62 attacks, so they were too narrow. Since
[decision 0023](../decisions/0023-intervals-by-unit.md) the gate uses an interval by unit
(here, the attack).

## Built on the box 2026-11-26: `runs/suite-p1`

The suite was built with `build --sources oasst llmail_benign llmail_full bipia_embedded
wildchat_dev_test`, which took 164 s on marker-bench at commit `2960a45`. It holds 77,232
items, after 7,412 repeats inside a source were removed.

| Set | Items | Screening half (test) |
|---|---:|---:|
| `llmail_full` | 20,357 attacks (21,007 attempts, less repeats) | 9,744 |
| `bipia_embedded` | 14,785 attacks + 178 clean documents | 8,595 |
| `wildchat_dev_test` | 4,407 (5,000 sample, less repeats) | 2,106 |
| `llmail_benign` | 160 | 79 |
| `oasst` | 16,277 calibration + 16,068 test | 8,092 test |
| Disguised copies (5 disguises) | 1,000 each | 548 each |

- **BIPIA: fewer attacks than planned (20,600).** In a document with no sentence break (most
  tables), the middle placement lands at the start, so it repeats the start placement and
  is removed. BIPIA's own builder can do the same.
- **v1 on the screening half** (as shipped: every view, one threshold, at 1%):

| Set | v1 | 95% interval by row | by unit |
|---|---:|---|---|
| LLMail caught | 40.3% | 39.3–41.2 | 33.4–46.9 (5,135 clusters) |
| BIPIA inside documents caught | 6.3% | 5.8–6.8 | 2.8–10.6 (79 attacks) |
| Real developer messages blocked | **9.8%** | 8.6–11.1 | 7.9–11.8 |
| Ordinary chat (oasst1) blocked | 0.9% | 0.7–1.1 | 0.7–1.1 |

**Readings:**
- **v1 blocks about 1 in 10 real developer messages,** 10× its rate on ordinary chat. That
  is the developer bar of decision 0021: a candidate may block no more.
- **The interval by unit matters.** LLMail's near-duplicate clusters widen ±1 point to about
  ±7.
- **Near-duplicate check against training: clean.** Against recipe R's build, 3 of 4,407
  developer messages are near duplicates, all via `wildchat_dev`; there are no exact
  matches, and none anywhere else
  ([results](../results/2026-11-26-fortress-phase1.md)).

## Next steps

1. **Done:** the near-duplicate check, and the scores of v1, R-xsmall and the teacher
   ([results](../results/2026-11-26-fortress-phase1.md)).
2. **The noise floor:** three xsmall seeds, or a second teacher seed.
