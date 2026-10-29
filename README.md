<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/lockup-dark.png">
    <img src=".github/assets/lockup.png" alt="Mobius Guard" width="400">
  </picture>
</p>

<h3 align="center">An open-source firewall for LLM apps.</h3>

<p align="center">
  Rewrites secrets and personal data in a streamed reply without stopping the stream,<br>
  and measures every detection claim on data the detector never saw.
</p>

<p align="center">
  <a href="#licence"><img alt="Licence: Apache-2.0" src="https://img.shields.io/badge/licence-Apache--2.0-1b1e23?style=flat-square"></a>
  <img alt="Status: pre-alpha" src="https://img.shields.io/badge/status-pre--alpha-f5b301?style=flat-square">
  <img alt="Python 3.11 to 3.13" src="https://img.shields.io/badge/Python-3.11%20%C2%B7%203.12%20%C2%B7%203.13-3776ab?style=flat-square&logo=python&logoColor=white">
  <img alt="Pyright strict" src="https://img.shields.io/badge/types-pyright%20strict-3178c6?style=flat-square">
  <img alt="Property-based tests" src="https://img.shields.io/badge/tests-Hypothesis-1e7f4a?style=flat-square">
  <a href="https://github.com/gantrly/gantrly"><img alt="A Gantrly project" src="https://img.shields.io/badge/a-Gantrly%20project-f5b301?style=flat-square"></a>
</p>

<p align="center">
  <a href="#what-it-does">What it does</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#run-it">Run it</a> ·
  <a href="docs/ROADMAP.md">Roadmap</a> ·
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/hero-dark.svg">
    <img src=".github/assets/hero.svg" alt="A model's reply streams in token-sized chunks; an API key and a database password split across chunks come out replaced with labels, and the rest of the text flows through" width="880">
  </picture>
</p>

<p align="center"><sub>Drawn by <a href="scripts/brand/hero.py"><code>scripts/brand/hero.py</code></a> from the redactor's real output, chunk by chunk, holdback included.</sub></p>

> **Pre-alpha.** Parts 0–2 of the [roadmap](docs/ROADMAP.md) are done: the streaming
> redactor, the evaluation harness and the proxy, with results in [docs/results](docs/results/).
> Next is the v0.1 release. Nothing is on PyPI yet.

## What it does

|  |  |
|---|---|
| **Redaction that keeps the stream going** | Secrets and personal data in a model's reply are replaced as it streams, even when a secret is split across chunks: `"sk-proj-Q7w"` + `"E9rT…"` becomes `[REDACTED:openai_api_key]`. Text that can't be part of a secret is passed on at once; only a possible match is held back (about one word). |
| **245 patterns** | 24 curated ones with checks that cut false positives (Luhn for cards, mod-97 for IBANs, Verhoeff for Aadhaar), plus all 221 [gitleaks](https://github.com/gitleaks/gitleaks) rules with gitleaks' own entropy and allowlist rules. Any can be switched off by ID. |
| **Proven chunk-safe** | The output is the same however the input is split. Property tests split every test input at every point, one character at a time and at random, for every pattern. |
| **Honest evaluation** | Detectors are scored as recall at a fixed false-positive rate, with thresholds set on ordinary traffic, never on the sets reported. Datasets are pinned, with their licence and which models trained on them, and those cells are marked. Five obfuscation families (spaced letters, look-alike letters, invisible characters, leetspeak, base64). |
| **Baselines in every table** | Keyword rules, TF-IDF trained leave-one-source-out, ProtectAI v2 and PIGuard, with CPU latency stated with the hardware. |
| **The proxy** | In front of any model, speaking OpenAI Chat Completions, OpenAI Responses and Anthropic Messages, streamed or not: input clean-up (invisible characters, look-alike and spaced-out letters, leetspeak, base64) and named rules on the way in, the redactor on the way out, an audit log and OpenTelemetry spans. |
| **A closed loop** *(v0.2)* | Attacks that get through become reviewed rule or threshold changes, gated on a benign canary set; our own small, permissively licensed CPU classifier. |

## Why another guardrail?

Lots of tools already screen prompts. Mobius Guard focuses on four things that, as of
October 2026, no mature open-source project does well
([the research behind this](docs/research/2026-10-27-landscape-and-eval.md)):

1. **Streaming redaction that rewrites instead of killing the stream.** Others block the
   whole reply or don't look inside streams at all.
2. **Honest numbers.** Most public prompt-injection datasets were used to train the
   classifiers that report scores on them, and attackers who adapt beat most published
   defences.
3. **Red-team findings become reviewed patches** (v0.2), applied only after they pass a
   benign canary set and a person approves them.
4. **A maintained, permissively licensed classifier** (v0.2), small enough to run on a CPU
   in milliseconds, trained on data whose source and licence are on record.

## How it works

```text
client ──► /v1/chat/completions · /v1/responses · /v1/messages
             │
        request path   normalise → rules + classifier → policy (allow / block, with reasons)
             │
        upstream LLM (any OpenAI-compatible API)
             │ streamed reply
        response path  mobiusguard-redact: rewrite secrets and PII in the stream
             │
           client      audit log + OpenTelemetry GenAI spans
```

More in [docs/architecture.md](docs/architecture.md). Every design choice is a numbered
record in [docs/decisions/](docs/decisions/): streaming semantics in
[0007](docs/decisions/0007-streaming-redaction-semantics.md), the evaluation harness in
[0009](docs/decisions/0009-evaluation-harness-v0.1.md).

## Run it

Requires [uv](https://docs.astral.sh/uv/). Until the packages are published, run from this
repository:

```sh
make install   # .venv and the pre-commit hook
make check     # lint, strict type check and tests: what CI runs
```

**Redact a stream** (`mobiusguard-redact`, one dependency):

```python
from mobiusguard_redact import StreamRedactor, redact

r = StreamRedactor()  # curated + gitleaks patterns
for chunk in model_stream:
    send(r.feed(chunk))  # safe to show now
send(r.flush())  # end of the reply
# r.findings: pattern, category and position of each redaction, never the secret itself

redact("key AKIAQWERTYUIOPASDFGH")  # 'key [REDACTED:aws_access_key_id]'
```

**Evaluate a detector** (`mobiusguard-eval`; scoring can run on a GPU machine, the report
anywhere):

```sh
uv sync --all-packages --all-extras                       # adds scikit-learn, torch, transformers
uv run mobiusguard-eval sources                           # the provenance ledger
uv run mobiusguard-eval build --out runs/suite            # fetch pinned data, build the suite
uv run mobiusguard-eval score --suite runs/suite --detector piguard --device cuda --out runs/piguard
uv run mobiusguard-eval report --suite runs/suite --runs runs/piguard --out runs/report
uv run mobiusguard-eval redaction --suite runs/suite --out runs/redaction
uv run mobiusguard-eval pipeline --out runs --device cuda  # all of it; run again to resume
```

Every step saves its progress and skips finished work, so a crash or a fix never means
starting over.

### Checks

```sh
make check         # ruff, pyright strict, pytest with coverage
make test-stress   # property tests with 5,000 examples each (about 5 minutes)
make bench         # redactor latency per chunk and how much is held back
```

## Built with

[regex](https://pypi.org/project/regex/) (partial matching) · rules from
[gitleaks](https://github.com/gitleaks/gitleaks) (MIT) · [Hypothesis](https://hypothesis.works) ·
NumPy and PyArrow · scikit-learn · PyTorch and Transformers (baselines only) ·
uv · Ruff · Pyright · pytest.

## Layout

```
packages/mobiusguard-redact   streaming redaction: patterns, validators, StreamRedactor
packages/mobiusguard-eval     the evaluation harness: ledger, suite, detectors, metrics, CLI
packages/mobiusguard          the proxy: APIs, normalisation, rules, policy, redaction, audit
scripts/                      gitleaks rule import, brand and README images
benchmarks/                   redactor latency
docs/                         roadmap, architecture, threat model, datasets, decision records
```

Working notes for contributors and coding agents: [AGENTS.md](AGENTS.md).

## Part of Gantrly

Mobius Guard is built by the people behind [Gantrly](https://github.com/gantrly/gantrly),
open-source project tracking for teams that build. Gantrly's AI agent will run behind it
(the proxy is built; wiring Gantrly to it comes next); Mobius Guard has no dependency on Gantrly and is meant for any LLM
app. It lives in its own repository with its own licence.

## Contributing

Issues and pull requests are welcome: read [CONTRIBUTING.md](CONTRIBUTING.md) first.
Found a way past the guard you'd rather not publish? Report it privately
([SECURITY.md](SECURITY.md)). Everyone taking part follows the
[code of conduct](CODE_OF_CONDUCT.md).

## Licence

[Apache-2.0](LICENSE). Contributions are signed off under the
[Developer Certificate of Origin](https://developercertificate.org/), no CLA
([decision 0008](docs/decisions/0008-home-in-the-gantrly-org.md)). The gitleaks rules are
MIT, credited in [NOTICE](NOTICE). Evaluation datasets are not included; the harness
downloads them, and their licences are listed in [docs/datasets.md](docs/datasets.md).
