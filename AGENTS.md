# Notes for coding agents

Mobius Guard: an open-source LLM firewall proxy (Python) whose contributions are streaming
redaction that rewrites rather than terminates, honest held-out evaluation, a red-team →
reviewed-patch loop, and a permissively licensed CPU classifier. Read
[README.md](README.md), then [docs/ROADMAP.md](docs/ROADMAP.md) for what is done and what
is next, and [docs/decisions/](docs/decisions/) before changing anything they cover.

## Layout

- `packages/mobiusguard-redact`: streaming redaction. **One runtime dependency (`regex`)**;
  keep it that small so gateways can embed it.
- `packages/mobiusguard`: the proxy (rules, classifier, decision policy, audit).
- `packages/mobiusguard-eval`: the evaluation harness.
- `docs/decisions/NNNN-*.md`: one record per design decision, numbered.
- `docs/research/`: dated research notes with sources.
- `docs/results/`: dated measurements from the harness, with hardware.
- User guides: `docs/quickstart.md`, `configuration.md`, `rules.md`, `redaction.md`,
  `audit-log.md`, `deploy.md`; maintainers: `docs/releasing.md`. Keep them true when you
  change behaviour, settings or numbers.
- Each package carries a copy of `LICENSE` and `NOTICE` (wheels must include them). If you
  change the root files, change the copies too.

## Commands

```bash
make check      # lint + strict type check + tests (what CI runs)
make fmt        # format and auto-fix
uv run pytest packages/mobiusguard-redact -q
make test-stress   # property tests with 5,000 examples each; run after changing a pattern
make bench         # redactor latency and holdback
uv run python fuzz/redactor.py --hypothesis   # the fuzz property; Atheris itself runs in CI
uv build --all-packages && scripts/check_dist.sh dist   # wheels in a clean environment
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
  Push only when asked. `main` is protected: work on a branch and open a pull request; it
  is squash-merged once CI, CodeQL and the sign-off check pass. Label it (`detection`,
  `redaction`, `proxy`, `evaluation`, `security`, `bug`, `enhancement`, `documentation`), since the
  labels group the generated release notes.
- **Workflows:** pin every action to a full commit SHA with its version in a comment, and
  give each job only the permissions it needs; Dependabot keeps the pins current.
- **Releases** follow [docs/releasing.md](docs/releasing.md): the three packages share one
  version, set in each `__init__.py`; a test fails if the versions or the ranges between
  the packages disagree. Add a `CHANGELOG.md` entry for anything users notice, under
  `## Unreleased`: **dating the section for the current version and merging releases it**
  (tag-release.yml tags and starts the release, which then waits for approval).
- `make check` must pass before saying something is done. Say plainly what was and wasn't
  tested.

## Traps

- **Streaming changes what a regex may do.** No variable-length lookbehinds (use
  `not_after`); a body that can run on to a later terminator holds back everything after a
  match (private keys did; the body may not contain `-----END`). gitleaks rules changed for
  streaming live in `STREAMING_FIXES` / `STREAMING_PREFIXES` in `patterns.py`; say why in
  decision 0007.
- **The keyword prefilter** skips a gitleaks rule until one of its keywords arrives. A rule
  whose match needs text before its keyword, or whose secret starts before it, must be in
  `KEYWORDS_UNSAFE`; `test_keywords_are_a_safe_filter` checks every rule. After changing
  patterns or upgrading gitleaks, run the stress profile: it found the one such leak so far.
- **Training data (v0.2):** never add an evaluation-suite source, or another split of one,
  to `train_sources.py`; a test checks. Build and audit small random samples
  (`--sample-seed`) before a full build, and read items by hand. Twins with opposite
  labels on purpose go in `CONTRAST`, or the conflict rule drops them.
- **Ruff formats Python code blocks inside Markdown**, so run `make fmt` after editing docs,
  or `make check` fails at lint before the tests run.
