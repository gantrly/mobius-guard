# Red-teaming a Mobius Guard configuration

`mobiusguard-eval redteam` attacks a Mobius Guard configuration with an existing attack
tool's prompts, many times over in mutated forms, and reports what got through. Its
findings become threshold or rule changes that a person reviews, and a change is accepted
only if it does not block more harmless text. The design is
[decision 0014](decisions/0014-red-team-runner.md).

It tests the **firewall, not the model**: an attempt *gets through* when the guard lets it
through. What a model would then do is out of scope.

## What you need

- `pip install "mobiusguard-eval[pyrit]"` for PyRIT's prompt converters (optional), and
  `mobiusguard[onnx]` if the configuration uses Fortress-XS or Fortress-Base.
- [garak](https://github.com/NVIDIA/garak) 0.17.1 **in its own environment**. garak pins
  transformers below 5.20, which the harness's training extras cannot use:

  ```bash
  uv venv venv-garak && VIRTUAL_ENV=venv-garak uv pip install garak==0.17.1
  ```

- A machine to run on. A full run sends about a million attempts; on a 4-vCPU box with
  Fortress-XS on the CPU it takes about 12–14 hours. Use a server, not a laptop.

## 1. Export the attack prompts

```bash
venv-garak/bin/python packages/mobiusguard-eval/src/mobiusguard_eval/redteam/garak_export.py \
    --out runs/redteam/seeds latentinjection promptinject encoding sysprompt_extraction
```

This writes `seeds.jsonl` (one prompt per line, as garak would send it) and
`manifest.json` (garak's version, prompts per probe, the commit of every dataset a probe
read). Every probe class of the named modules is loaded with garak's prompt cap off and
its random seed fixed, so an export is complete and gives the same file every time. The
four modules above are the static, injection-focused ones: 19,418 prompts with garak
0.17.1. garak and the datasets it reads are registered with their licences in
`mobiusguard_eval/redteam/seeds.py`.

Seeds stay on the machine that runs the attacks. Never commit them.

## 2. Run

```bash
mobiusguard-eval redteam run --seeds runs/redteam/seeds/seeds.jsonl \
    --config mobiusguard.toml --out runs/redteam/run-1 --sample 50   # the small run first
mobiusguard-eval redteam run --seeds runs/redteam/seeds/seeds.jsonl \
    --config mobiusguard.toml --out runs/redteam/run-2 --shard 0/2 &  # then the full run,
mobiusguard-eval redteam run --seeds runs/redteam/seeds/seeds.jsonl \
    --config mobiusguard.toml --out runs/redteam/run-2 --shard 1/2 &  # one process per shard
```

- **Each prompt becomes 52 attempts:** plain, and through 25 mutation chains (spaced
  letters, look-alike letters, invisible characters, leetspeak and base64, alone or two
  stacked in order), each sent once as the user's message and once as a tool result after
  a neutral request, the way an indirect injection arrives. `--chains` and `--deliveries`
  pick a subset.
- **`--config`** runs the configuration's guard in the same process, with no network.
  **`--http URL`** sends real requests to a running proxy instead (`--api chat`,
  `responses` or `anthropic`). Each request the proxy allows goes on to its upstream model
  and may cost a model call; the run prints how many did.
- **Resume.** Run the same command again after a crash or a stop: finished prompts are
  skipped, and attempts the target gave no verdict for are sent again. A directory holds
  one run; a run with different settings is refused.
- **Score cache.** With `--config`, Fortress scores each distinct text once. Texts are
  still scored one at a time, as the proxy does, so the cache shortens the run without
  changing its result.
- **CPU only.** The same INT8 file on onnxruntime-gpu changed 1.5% of attack verdicts
  compared with the CPU runtime the proxy ships, so runs use the CPU (decision 0014).

`mobiusguard-eval redteam summary --out runs/redteam/run-2` prints counts across shards.

Each run directory holds `run.json` (its settings), `attempts-<shard>.jsonl` (one row per
attempt: IDs, chain, delivery and the verdict, with **no attack text**), `done-<shard>.jsonl`
(finished prompts) and `scores-<shard>.jsonl` (the score cache).

## 3. Seal the holdout, before looking for patches

```bash
mobiusguard-eval redteam seal --seeds runs/redteam/seeds/seeds.jsonl --out runs/redteam/holdout
```

Prompts are grouped by near-duplicate text within their family (the suite's MinHash), and
20% of each family's groups are set aside, chosen from the group names alone, never from
results. The command prints the SHA-256 of the held-out prompt IDs: **commit it in
`docs/results/` before the holdout is first used.** `redteam verify-holdout` checks that a
holdout still matches its seeds. A holdout is sealed once and never overwritten; patches
are never tuned on it, and measuring one on it is logged (decision 0006, rule 7).

## 4. Findings

```bash
mobiusguard-eval redteam findings --out runs/redteam/run-2 \
    --seeds runs/redteam/seeds/seeds.jsonl --holdout runs/redteam/holdout/holdout.json \
    --report runs/redteam/findings
```

`findings.json` and `findings.md` give, for every group and chain that something got
through: how many attempts, how many got through, the rate, which layer caught the rest,
and the classifier scores of those that got through (what a threshold change would need).
Totals are broken down by family, chain, number of stacked mutations and delivery. Reports
carry counts, rates, scores and IDs only.

## 5. Gate a patch

A patch is a changed config (a threshold) or a new rule. Before it is proposed:

```bash
mobiusguard-eval redteam gate --suite runs/suite-v0.2 \
    --base mobiusguard.toml --patched patched.toml --report runs/redteam/gate-1
```

Both configs are run on the test items of the suite's four harmless-text sets. The patch
passes only if blocks do not rise at all on ordinary messages (oasst1, where the threshold
is set) and rise by at most 0.5 percentage points on NotInject, OR-Bench hard and LLMail
benign emails. The command exits with 1 when the gate fails. A patch that passes is
proposed as a pull request with its findings and gate report; it is never applied
automatically, and its effect is reported on a fresh run and on the holdout, never on the
findings it was tuned on.

## 6. Adaptive attacks

The fixed run tries mutations decided in advance. In an adaptive run an attacker model
rewrites each prompt and tries again, guided by the guard's answer, and a second model
judges whether the rewrite still asks for the same thing
([decision 0016](decisions/0016-adaptive-attacks.md)).

```bash
pip install "mobiusguard-eval[pyrit]"
mobiusguard-eval redteam adapt --seeds runs/redteam/seeds/seeds.jsonl \
    --holdout runs/redteam/holdout/holdout.json --out runs/redteam/adapt-1 \
    --target v0.2.0=original.toml --target patched=mobiusguard.toml \
    --endpoint http://127.0.0.1:11434/v1 --attacker mistral:7b-instruct \
    --judge qwen2.5:7b-instruct --per-family 5
mobiusguard-eval redteam adapt-summary --out runs/redteam/adapt-1
```

- **The attack** is PyRIT's PAIR: one stream of up to `--max-tries` rewrites per prompt
  (10 by default). The attacker's instructions are PyRIT's; its objective is the garak
  prompt. It stops at the first confirmed bypass.
- **What the attacker sees:** whether the guard blocked the rewrite and why, and the attack
  score with the threshold. A real proxy shows only a 403, so this is a worst case;
  `--verdict-only` hides the score.
- **A bypass** is a rewrite the guard lets through *and* the judge calls the same request.
  One it lets through but the judge rejects is *drift*. An answer the judge gives that
  can't be read is counted and never a bypass. The judge must be a different model.
- **Prompts** come only from outside the sealed holdout: `--per-family` of each family by
  a fixed seed, or `--ids`. A held-out ID is refused, and so is a holdout that no longer
  matches its seeds.
- **The attacker and the judge** are any models behind an OpenAI-compatible endpoint:
  local ones through Ollama during development, paid ones only for a measured run after
  its cost is approved. Their Ollama digests go into the run's key.
- **Output:** `tries.jsonl` (one row per try, no text), `done.jsonl` (finished prompt and
  target pairs; a run resumes) and `bypasses.jsonl`, the text of each confirmed bypass for
  the person who writes a rule from it. Keep it on the machine that ran the attack.
