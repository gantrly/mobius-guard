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

## Next steps (not started)

All are box work. Nothing is downloaded or processed on the Mac.
1. **Loaders** in `sources.py`: `llmail_full` (phase 2, team split), `bipia_embedded`
   (email/table/code), `wildchat_dev_test` (4 unused files). Ledger entries and tests go
   with them.
2. **On the box:** fetch, build, near-duplicate check against `runs/train-*`, then counts
   only.
3. **Score v1 and v3** on the new sets, and run the three noise-floor seeds.
