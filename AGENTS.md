# Notes for coding agents

Mobius Guard: an open-source LLM firewall proxy (Python) whose contributions are streaming
redaction that rewrites rather than terminates, honest held-out evaluation, a red-team →
reviewed-patch loop, and a permissively licensed CPU classifier. Read
[README.md](README.md), then [docs/ROADMAP.md](docs/ROADMAP.md) for what is done and what
is next, and [docs/decisions/](docs/decisions/) before changing anything they cover.

## Layout

- `packages/mobiusguard-redact`: streaming redaction. **No runtime dependencies**; keep it
  that way so gateways can embed it.
- `packages/mobiusguard`: the proxy (rules, classifier, decision policy, audit).
- `packages/mobiusguard-eval`: the evaluation harness.
- `docs/decisions/NNNN-*.md`: one record per design decision, numbered.
- `docs/research/`: dated research notes with sources.
- Each package carries a copy of `LICENSE` and `NOTICE` (wheels must include them). If you
  change the root files, change the copies too.

## Commands

```bash
make check      # lint + strict type check + tests (what CI runs)
make fmt        # format and auto-fix
uv run pytest packages/mobiusguard-redact -q
```

## Rules

- **Surface design decisions before building them.** Anything that changes what is
  measured, what it costs, the public API, or an existing convention goes to the
  maintainer as options first, then into `docs/decisions/`.
- **Evaluation honesty** (decision 0006): never report numbers on the attacks a patch or
  model was tuned on; use held-out families and the false-positive sets; state hardware for
  latency. A big swing between runs on the same input is a bug signature, not a result.
- **Small run first.** Before any training, batch eval, GPU job or paid model call, run
  the smallest sample that covers every code path. Report its time, cost and output, then
  ask before the full run. GPU training happens on a remote box, never in CI.
- **No datasets, models or secrets in git.** Every data source goes in the provenance
  ledger with its licence and which known models trained on it.
- **Commits:** sign off (`git commit -s`), with a clear message about what changed and why.
  Push only when asked.
- `make check` must pass before saying something is done. Say plainly what was and wasn't
  tested.
