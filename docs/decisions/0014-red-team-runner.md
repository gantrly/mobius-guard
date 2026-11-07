# 0014: The red-team runner and reviewed patches

- **Status:** proposed, 2026-11-07
- **Builds on:** [0001](0001-what-mobius-guard-is-for.md) (contribution 3: a red-team →
  reviewed-patch loop gated on benign text), [0006](0006-evaluation-rules.md) (rule 7: no
  re-testing on patched attacks), [0009](0009-evaluation-harness-v0.1.md) (the harness),
  [0013](0013-releasing-fortress-v0.2.md) (Fortress-XS)

## Decision

**What it does.** It attacks a Mobius Guard configuration and groups the attempts that get
through. From those groups it proposes threshold and rule changes for a person to review.
Every proposal must pass a gate on harmless text, and its effect is measured on attacks it
was not tuned on.

**Where it lives.**
- Inside `mobiusguard-eval`, as `mobiusguard-eval redteam run | findings | propose`, so it
  reuses the suite, metrics, ledger, near-duplicate clustering and resumable checkpoints.
- PyRIT is an optional extra, `[pyrit]` (69 more packages). A default install does not
  change.
- garak cannot be an extra: it pins transformers below 5.20, and the training extras need
  5.22. It runs in its own environment, and `redteam/garak_export.py` (standard library and
  garak only, run with garak's Python) writes its prompts to a seeds file the runner reads.

**Targets.**
- **In-process:** a `Guard` built from any config, with no network. This is the loop's
  default, and the fastest.
- **HTTP:** a running proxy, through OpenAI Chat Completions, OpenAI Responses or
  Anthropic Messages, so users can red-team their own deployment.
  - A block is the proxy's 403 `prompt_blocked`.
  - An allowed request reaches the proxy's upstream model, so the runner prints the number
    of requests before it starts.
- Either way the runner tests the firewall, not the model: an attempt **gets through** when
  the guard allows it.

**Attack sources. We do not write attacks.**
- **garak 0.17.1** probes (Apache-2.0) and **PyRIT 1.1.0** converters (MIT).
- The first garak families are the static, injection-focused ones (maintainer, 2026-11-07):
  `latentinjection` (injections hidden in documents, emails, resumes and translations),
  `promptinject`, `encoding` and `sysprompt_extraction`. That is 19,418 prompts once
  duplicates across probe classes are dropped. The export turns garak's 256-prompt sample
  off and fixes its random seed, so it is complete and repeatable.
- Not yet: community jailbreaks (garak's `dan`: they target model safety more than
  injection, and their licences are unclear), and probes that need a generator model,
  which come with the adaptive attacks.
  - They are read at run time from the installed package and never copied into git.
  - Each probe set used gets a provenance-ledger entry: its licence, the dataset it comes
    from, and the known models trained on that dataset.
- **Mutations:** the harness's five obfuscation transforms (base64, spaced letters,
  leetspeak, look-alike letters, invisible characters), alone or two different ones
  stacked in order: 25 chains, plus the plain prompt. PyRIT's converters can be added as
  steps, but only ones that call no model. A mutated attack keeps its parent's label.
- **Delivery:** each variant goes once as the user's message and once as a tool result
  after a neutral request, the way an indirect injection arrives.
- **Volume:** every chain for every prompt (maintainer, 2026-11-07): 52 attempts per
  prompt, about 1.0 million for the four families, a few hours on the box's CPU in
  process. A small run comes first.
- **Adaptive attacks:** PyRIT's multi-turn attackers, which rewrite an attempt after each
  block.
  - During development the attacker is a **local model on the box** (Ollama), so the code
    is built at no API cost.
  - The measured run uses a **paid model**. A small run gives its cost first, and the run
    waits for the maintainer's approval.

**Runs.**
- Resumable and seeded, on the box, never on a developer's machine.
- **On the CPU, with the runtime the proxy ships.** On 2,000 attempt texts, the same
  INT8 file under onnxruntime-gpu 1.31.1 (NVIDIA L4) flipped 30 attack verdicts (1.5%)
  against the CPU runtime: scores differed by up to 2.35 log-odds (p99 0.89), and it was
  only about twice as fast, because many nodes fall back to the CPU. A 1.5% shift would
  move the bypass rates being measured, so the GPU is not used.
- Each distinct text is scored once and its score reused (a user message and a tool
  result carrying the same variant are the same text to the classifier). Texts are still
  scored one at a time, so the cache changes the run's length, not its result: about
  466,000 distinct texts, roughly 12 hours on the box's two cores.
- One row per attempt: attempt ID, parent item ID, source, mutation chain, target, decision,
  the layer that caught it (rule ID, `classifier` or `harmful`), scores, milliseconds.
- Attack text stays in the run files on the box. Reports, chat and git show counts and IDs
  only.

**Findings.** The attempts that got through, grouped by source family, mutation chain and
near-duplicate cluster (the harness's MinHash). Each group shows its size, its bypass rate
and a few example IDs.

**Patches.** These are never applied automatically. The tool writes a patch file and a
report; a person opens the pull request.
- **Thresholds:** computed automatically. For each classifier output, the report shows the
  threshold that would catch each group and what it costs in false positives on the gate
  sets.
- **Rules:** written by a person. The tool measures a candidate rule on the findings and on
  the gate, and the patch is a diff to `rules.py`.
- **Training data:** findings also become a training source for Fortress v2. They get
  their own ledger entry and never enter the evaluation suite.

**The gate.** A patch passes only if false positives do not rise on the four harmless-text
sets: ordinary messages (oasst1), NotInject, OR-Bench hard and LLMail benign emails. Patches
are tuned on the dev split and gated on the test split.

**Measurement (0006 rule 7).**
- **Sealed holdout:** before any patch is tuned, a share of the attack groups is set aside,
  split by source family and cluster. The SHA-256 of its sorted item IDs is committed in
  `docs/results/` before its first use. It is opened once per release and never used for
  tuning.
- A patch's effect is reported on a **fresh run** (new seed, new adaptive attempts) and on
  the holdout. It is never reported on the findings it was tuned on.

**The order of work.** Each part is tested and reviewed before the next.
1. Target adapters.
2. garak and PyRIT adapters, the mutation chains, and the ledger entries.
3. The runner.
4. A small run on the box: fixed probes, then the local attacker.
5. Findings.
6. Patch proposals.
7. The gate and the sealed holdout.
8. The CLI, a user guide and tests.
9. The first measured run against 0.2.0 with Fortress, with a results note.

## Open, for the maintainer

- **Confirming adaptive attempts:** an attacker model's rewrite can drift into something
  harmless, and then "got through" means nothing. Proposal: a judge model confirms each
  adaptive attempt that got through before it counts. Unconfirmed ones are reported
  separately. The judge is paid in the measured run, under the same approval.
- **Gate tolerance:** proposal: no rise at all on oasst1 (the threshold set) and at most
  0.5 percentage points on each of the other three sets, configurable.
- **Holdout share:** proposal: 20% of the attack groups.

## Considered

- **Our own attack library:** rejected. It duplicates garak and PyRIT, and decision 0001
  asks us to contribute what is missing, which is the gated loop, not more attacks.
- **Rules drafted by a model:** rejected for now. Regex rules drafted from a cluster tend to
  be brittle, and drafting them costs model calls. The tool computes thresholds; a person
  writes the rules.
- **A fourth package, `mobiusguard-redteam`:** rejected. It would duplicate the harness's
  suite, metrics, clustering and checkpoints, or depend on all of them anyway.
- **Applying patches automatically:** rejected. Decision 0001 promises *reviewed* patches,
  and an automatic patch re-tested on its own findings is the result decision 0006 forbids.
- **promptfoo's red team:** its closed loop is in the paid Enterprise edition, and its
  open-source red team is a Node tool. An adapter can come later if users ask.
