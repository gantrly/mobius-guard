# Development

Requires [uv](https://docs.astral.sh/uv/). Read [CONTRIBUTING.md](../CONTRIBUTING.md) and
[AGENTS.md](../AGENTS.md) first.

```sh
make install       # .venv and the pre-commit hook
make check         # ruff, pyright strict, pytest (in parallel) with coverage: what CI runs
make test-stress   # property tests with 5,000 examples each, in parallel (a few minutes)
make bench         # redactor latency per chunk and how much is held back
uv build --all-packages && scripts/check_dist.sh dist   # the wheels in a clean environment
```

## Fuzzing

`fuzz/redactor.py` fuzzes the redactor's main guarantee: the same output however the text
is split. It is built from pieces of what the patterns look for. Atheris (coverage-guided)
drives the property through Hypothesis, so a failing input is shrunk to a small example.
The *Fuzz* workflow runs it for 3 minutes on pull requests that touch the redactor, and
for 20 minutes every week.

```sh
uv sync --group fuzz && uv run python fuzz/redactor.py -max_total_time=300  # Linux x86_64
uv run python fuzz/redactor.py --hypothesis   # anywhere: the same property, without Atheris
```

## The evaluation harness

Scoring can run on a GPU machine and the report anywhere; every step saves its progress and
skips finished work, so a crash or a fix never means starting over.

```sh
uv sync --all-packages --all-extras                        # adds scikit-learn, torch, transformers
uv run mobiusguard-eval sources                            # the provenance ledger
uv run mobiusguard-eval build --out runs/suite             # fetch pinned data, build the suite
uv run mobiusguard-eval score --suite runs/suite --detector piguard --device cuda --out runs/piguard
uv run mobiusguard-eval report --suite runs/suite --runs runs/piguard --out runs/report
uv run mobiusguard-eval redaction --suite runs/suite --out runs/redaction
uv run mobiusguard-eval pipeline --out runs --device cuda  # all of it; run again to resume
```

Training data and fine-tuning for the v0.2 classifier
([decision 0012](decisions/0012-classifier-v0.2.md), [training-data.md](training-data.md)):

```sh
uv sync --all-packages --all-extras                  # includes the train extra
uv run mobiusguard-eval train-sources                # the training ledger (never the suite's)
uv run mobiusguard-eval train-data --suite runs/suite --out runs/train-small --cap 300 \
    --sample-seed 1                                  # a small random sample, to audit first
uv run mobiusguard-eval train-data --suite runs/suite --out runs/train     # the full set
uv run mobiusguard-eval train --data runs/train --base mmbert-small --seed 0 \
    --out runs/model-mmbert-s0 --device cuda         # one run; resumes after a stop
uv run mobiusguard-eval score --suite runs/suite --detector "local:runs/model-mmbert-s0/best#harmful" \
    --out runs/score-mmbert-harmful --device cuda    # #attack (default) or #harmful
```

Two gated sources (HackAPrompt, WildJailbreak) need a Hugging Face login that has accepted
their terms. Download them where that login is, and copy the cached *files* (not the
token) to the training machine. Each step runs on small random samples first, and those are
audited before anything long.

How it measures: [decision 0009](decisions/0009-evaluation-harness-v0.1.md) and the rules in
[decision 0006](decisions/0006-evaluation-rules.md). Datasets and their licences:
[datasets.md](datasets.md).

## Layout

```text
packages/mobiusguard-redact   streaming redaction: patterns, validators, StreamRedactor
packages/mobiusguard          the proxy: APIs, normalisation, rules, policy, redaction, audit
packages/mobiusguard-eval     the evaluation harness: ledger, suite, detectors, metrics, CLI
scripts/                      gitleaks rule import, live check, wheel check, README images
benchmarks/                   redactor latency
fuzz/                         the redactor fuzz target (Atheris)
examples/                     settings for Ollama, Compose with a local model
Dockerfile                    the proxy's container image
docs/                         guides, results, roadmap, architecture, threat model,
                              datasets, decision records
```

## README images

`.github/assets/hero*.svg` and the result charts are generated, not drawn by hand:
`uv run python scripts/brand/hero.py` replays the real redactor chunk by chunk, and
`uv run python scripts/brand/charts.py` draws the numbers from the dated results pages.
Change a chart's numbers only together with the results page they come from.

## Built with

[regex](https://pypi.org/project/regex/) (partial matching) · rules from
[gitleaks](https://github.com/gitleaks/gitleaks) (MIT) · Starlette, httpx and uvicorn ·
[Hypothesis](https://hypothesis.works) · NumPy and PyArrow · scikit-learn · PyTorch and
Transformers (baselines and the optional classifier) · uv · Ruff · Pyright · pytest.
