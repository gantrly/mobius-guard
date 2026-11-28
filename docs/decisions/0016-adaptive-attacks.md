# 0016: Adaptive attacks

- **Status:** accepted, 2026-11-10 (the maintainer's choices of the same day)
- **Builds on:** [0014](0014-red-team-runner.md) (the red team: firewall not model, a
  local attacker in development and a paid one for the measured run, a judge confirms
  bypasses, the gate and the holdout), [0015](0015-classifier-sees-every-view.md) (the
  patched proxy)

## Decision

**What it measures.** How often an attacker who rewrites a prompt and tries again gets it
past the guard, while it still asks for the same thing. The fixed-probe run tries 26
mutations decided in advance; here the attacker reacts to each verdict.

**The attack.** PyRIT's PAIR (`PAIRAttack`, PyRIT 1.1.0): one stream of up to 10 rewrites
per prompt, each guided by the previous verdict. The attacker's instructions are PyRIT's
own; its objective is the garak prompt as exported. Mobius Guard writes no attack text and
no attack instructions. TAP (a tree of rewrites) and multi-turn attacks come later.

**The target.** The in-process guard, wrapped as a PyRIT target. A rewrite replaces the
prompt's payload message and is sent as the user's message. The target's reply to the
attacker is a status line: blocked or let through, and, because the attacker sees the
score (the maintainer's choice), the attack score and the threshold. A real proxy shows
only a 403, so these results are a **worst case** and are reported as one.

**Feedback to the attacker** (the objective scorer, 0 to 1):
- blocked: how close the score came to the threshold, at most 0.8;
- let through but not judged the same request: 0.2, so drifting away earns nothing;
- let through and judged the same request: 1.0, which ends the attack.

**The judge.** A different local model from the attacker answers one question about the
pair: does the rewrite ask for the same thing as the original? It sees no verdict and no
score. A pass the judge rejects is counted as *drift*, not as a bypass. An answer it can't
read counts as not the same, and is counted separately.

**Models.** In development, both run on the box's GPU through Ollama: the attacker
Mistral-7B-Instruct, the judge Qwen2.5-7B-Instruct (both Apache-2.0), pinned by their
Ollama digests in the run's key. The measured run swaps in paid models, with the
maintainer's approval of its cost.

**Targets compared.** The same prompts against 0.2.0's behaviour (`classifier_views =
"original"`) and against the patched proxy, so the effect of decision 0015 on an adaptive
attacker is measured, not assumed.

**Prompts.** Only prompts outside the sealed holdout: the runner refuses a held-out one.
The first small run takes 20, five per garak family, chosen by a fixed seed.

**Records.** One row per try: prompt ID, target, try number, verdict, attack score, judge
answer, time. No text in rows or reports. The text of each confirmed bypass goes to a
separate file on the machine that ran it, for the person who writes a rule from it; it is
never committed or put in a report. A run resumes after a crash; finished prompts are
skipped.

**Reported.** Per target and family: prompts attacked, confirmed bypasses, drift, judge
failures, and tries until the first bypass.

## Considered

- **Verdict only, no score.** Realistic, and the reported black-box number later; the
  maintainer chose the stronger worst case for the first runs.
- **Writing our own attacker loop.** It would mean writing attack instructions. PyRIT's
  PAIR has them, published and reviewed.
- **The attacker as its own judge.** Simpler, but it would grade its own work.
- **Multi-turn first** (Crescendo, chunked requests). It needs a model's replies, so it
  tests the firewall and the model together; later.
