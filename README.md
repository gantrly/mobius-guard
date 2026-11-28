<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/lockup-dark.png">
    <img src=".github/assets/lockup.png" alt="Mobius Guard" width="400">
  </picture>
</p>

<h3 align="center">An open-source firewall for LLM apps.</h3>

<p align="center">
  Rewrites secrets in a streamed reply without stopping the stream,<br>
  and measures every claim on data the detector never saw.
</p>

<p align="center">
  <a href="#licence"><img alt="Licence: Apache-2.0" src="https://img.shields.io/badge/licence-Apache--2.0-1b1e23?style=flat-square"></a>
  <a href="https://pypi.org/project/mobiusguard/"><img alt="PyPI version" src="https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fpypi.org%2Fpypi%2Fmobiusguard%2Fjson&query=%24.info.version&prefix=v&label=PyPI&color=f5b301&style=flat-square&cacheSeconds=600"></a>
  <a href="https://github.com/gantrly/mobius-guard/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/gantrly/mobius-guard/ci.yml?branch=main&style=flat-square&label=CI"></a>
  <a href="https://www.bestpractices.dev/projects/16287"><img alt="OpenSSF Best Practices" src="https://www.bestpractices.dev/projects/16287/badge"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/gantrly/mobius-guard"><img alt="OpenSSF Scorecard" src="https://img.shields.io/ossf-scorecard/github.com/gantrly/mobius-guard?style=flat-square&label=OpenSSF%20Scorecard"></a>
  <img alt="Python 3.11 to 3.13" src="https://img.shields.io/badge/Python-3.11%20%C2%B7%203.12%20%C2%B7%203.13-3776ab?style=flat-square&logo=python&logoColor=white">
  <img alt="Pyright strict" src="https://img.shields.io/badge/types-pyright%20strict-3178c6?style=flat-square">
  <img alt="Property-based tests" src="https://img.shields.io/badge/tests-Hypothesis-1e7f4a?style=flat-square">
  <a href="https://github.com/gantrly"><img alt="A Gantrly project" src="https://img.shields.io/badge/a-Gantrly%20project-f5b301?style=flat-square"></a>
</p>

<p align="center">
  <a href="#how-it-works">How it works</a> ·
  <a href="#results">Results</a> ·
  <a href="#quickstart">Quickstart</a> ·
  <a href="#documentation">Docs</a> ·
  <a href="#roadmap">Roadmap</a> ·
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/hero-dark.svg">
    <img src=".github/assets/hero.svg" alt="A model's reply streams in token-sized chunks; an API key and a database password split across chunks come out replaced with labels, and the rest of the text flows through" width="880">
  </picture>
</p>

<p align="center"><sub>The real redactor, replayed chunk by chunk by <a href="scripts/brand/hero.py"><code>hero.py</code></a>.</sub></p>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/stats-dark.svg">
    <img src=".github/assets/stats.svg" alt="0 of 15,000 secrets leaked; 0 of 23,221 benign texts blocked; 0.15 ms per streamed token; about one word of delay" width="880">
  </picture>
</p>

## Why Mobius Guard

| | |
|---|---|
| **Redacts mid-stream** | Secrets and personal data are replaced as the reply streams, even when split across chunks. The stream never stops. |
| **Handles what models really write** | Tokens with characters added or dropped, keys in backticks, URLs without a host: still caught. |
| **Honest numbers** | Recall at a fixed false-positive rate, on pinned datasets the models were not trained on, with the weak spots published. |
| **Its own classifiers** | [Fortress-XS](https://huggingface.co/gantrly/fortress-xs), the default: prompt injection and harmful requests, 81 MB, 183 ms on a CPU at 512 tokens. [Try it in your browser](https://huggingface.co/spaces/gantrly/fortress-xs). [Fortress-Base](https://huggingface.co/gantrly/fortress-base), opt-in: 5× more injections caught inside documents, at 2.9× the CPU time. Both Apache-2.0. |
| **Red-teamed** | A million mutated garak attacks against a configuration, a sealed holdout, and a gate that refuses a fix which blocks more harmless text ([guide](docs/red-team.md)). |
| **Drop-in proxy** | OpenAI Chat Completions, OpenAI Responses and Anthropic Messages, streamed or not. Change one base URL. |

## How it works

```mermaid
sequenceDiagram
    autonumber
    participant App as Your app<br/>(any OpenAI or Anthropic SDK)
    participant MG as Mobius Guard
    participant LLM as Model API
    App->>MG: request
    Note over MG: normalise (invisible chars, look-alikes,<br/>spaced letters, base64), then 8 rules<br/>and the Fortress classifier (optional)
    alt attack
        MG-->>App: 403 in the API's own error format, with the rule IDs
    else allowed
        MG->>LLM: the request, unchanged
        LLM-->>MG: streamed reply
        MG-->>App: the same stream, secrets replaced by [REDACTED:…]
    end
    Note over MG: one audit line: decision, rules, redaction counts (no text)
```

User messages and tool results are checked; your own system prompt is not. Nothing is
logged in plain text unless you ask. Details: [architecture](docs/architecture.md),
[threat model](docs/threat-model.md).

## Results

### Fortress-XS, our classifier

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/fortress-speed-dark.svg">
  <img src="docs/assets/fortress-speed-light.svg" alt="Average recall over 9 held-out attack families at 1% false positives against CPU latency at 512 tokens: Fortress-XS 66.0% at 183 ms, PIGuard 44.1% at 1,151 ms, ProtectAI v2 28.8% at 1,151 ms, keyword rules 19.4% at 0.21 ms" width="760">
</picture>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/fortress-recall-dark.svg">
  <img src="docs/assets/fortress-recall-light.svg" alt="Recall at 1% false positives per attack family for Fortress-XS, PIGuard, ProtectAI v2 and keyword rules; the numbers are in the table below" width="760">
</picture>

| Recall at 1% false positives (%) | **Fortress-XS** | PIGuard | ProtectAI v2 | Keyword rules |
|---|---:|---:|---:|---:|
| Gandalf (direct injection) | **99.3** | 91.7 | 90.9 | 72.7 |
| LLMail-Inject (indirect, adaptive) | 43.9 | 28.3 | 2.1 | **59.4** |
| BIPIA (indirect) | 15.2 | **53.6** | 0.8 | 0.0 |
| SPML (system-prompt chatbots) | 34.1 | 21.3 | **91.9** | 28.2 |
| Obfuscated: base64 / spaced / leetspeak | **100** / **99.5** / 90.4 | **100** / 0.8 / **97.1** | 45.5 / 0.0 / 0.3 | 0.0 / 0.0 / 0.2 |
| Obfuscated: look-alike / invisible characters | **52.2** / **59.0** | 4.1 / 0.2 | 16.6 / 11.2 | 8.6 / 5.9 |
| **Average of these 9** | **66.0** | 44.1 | 28.8 | 19.4 |
| False positives: NotInject / OR-Bench hard | 6.8 / 0.0 | 8.3 / 11.1 | 4.7 / 0.8 | 2.1 / 0.0 |
| CPU latency at 512 tokens, size | **183 ms, 81 MB** | 1,151 ms | 1,151 ms | 0.2 ms |

- **Held out:** every number is on test sets no compared detector trained on, scored once.
  Thresholds are set so that 1% of ordinary user messages are flagged.
- **Where each detector wins:** Fortress-XS leads on obfuscation and direct injection. On
  the four non-obfuscated families it is level with PIGuard (48.1 vs 48.7). PIGuard wins
  BIPIA and ProtectAI v2 wins SPML.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/fortress-false-positives-dark.svg">
  <img src="docs/assets/fortress-false-positives-light.svg" alt="False positives at the same threshold: ordinary messages about 1% for every classifier; NotInject Fortress-XS 6.8%, PIGuard 8.3%, ProtectAI v2 4.7%, keyword rules 2.1%; OR-Bench hard Fortress-XS 0.0%, PIGuard 11.1%, ProtectAI v2 0.8%; LLMail benign emails 0% for all" width="760">
</picture>

| False positives at the same threshold (%) | **Fortress-XS** | PIGuard | ProtectAI v2 | Keyword rules |
|---|---:|---:|---:|---:|
| Ordinary messages (oasst1 test half, 16,061) | 0.9 | 1.0 | 0.9 | 0.3 |
| NotInject: harmless text with attack trigger words (339) | 6.8 | 8.3 | **4.7** | 2.1 |
| OR-Bench hard: harmless prompts that sound harmful (1,319) | **0.0** | 11.1 | 0.8 | 0.0 |
| LLMail-Inject benign emails (160) | 0.0 | 0.0 | 0.0 | 0.0 |
| English ordinary messages (7,668) | 1.3 | 0.6 | **0.1** | 0.5 |

**The second output: harmful requests.** Same threshold rule. It isn't compared with other
detectors: none of the three above has this output.

| Fortress-XS harmful output, at 1% false positives (%) | |
|---|---:|
| Caught: OR-Bench toxic (655) | 90.4 |
| Caught: XSTest unsafe (200) | 84.0 |
| Flagged by mistake: XSTest safe prompts (250) | 8.0 |
| Flagged by mistake: OR-Bench hard, harmless but sounding harmful (1,319) | **48.2** |
| The attack output firing on these harmful requests | 0.0 |

The harmful output over-blocks prompts that only sound harmful, so the proxy only logs it
unless you set `harmful = "block"`.

- **More:** the full scorecard, training data and limits are in the
  [model card](https://huggingface.co/gantrly/fortress-xs) and the
  [results note](docs/results/2026-11-07-classifier-v0.2-retrain.md). You can try it in the
  [demo](https://huggingface.co/spaces/gantrly/fortress-xs): the model runs in your browser.

### Fortress-Base, for documents, email and developer traffic

A larger, opt-in model (DeBERTa-v3-base): `classifier = "fortress-base"`. It reads each
text with its role in front, user or tool result, and each role has its own threshold.

| At 1% false positives (%) | Fortress-XS | **Fortress-Base** |
|---|---:|---:|
| LLMail-Inject, injections in emails (10,613) | 47.4 | **68.5** |
| BIPIA, injections inside documents (6,273) | 12.9 | **70.5** |
| deepset (135) / SPML (6,265) | 40.0 / 34.1 | **51.1 / 39.5** |
| Gandalf, direct injection (482) | 99.6 | **100.0** |
| Blocked by mistake: real developer messages (2,301) | 10.6 | **6.0** |
| Blocked by mistake: harmless text spaced out / in leetspeak (493 each) | 93.3 / 74.6 | **3.4 / 3.0** |
| Blocked by mistake: ordinary messages (7,975) / held-out tool outputs (299) | 1.0 / **2.0** | **0.9** / 3.0 |
| Harmful output, flagged by mistake: OR-Bench hard (672) | **47.0** | 50.6 |
| CPU, 4 threads, 128 / 512 tokens; size | **35 / 183 ms; 81 MB** | 104 / 525 ms; 308 MB |

- **How it was measured:** on the final halves of the test data (suite v0.3 and larger
  held-out sets of LLMail-Inject, BIPIA and real WildChat developer messages), scored once
  after the model was chosen. Fortress-XS runs as shipped. These sets differ from the table
  above, so Fortress-XS's numbers differ too. Intervals are in the
  [results note](docs/results/2026-11-28-fortress-base-release.md).
- **It passed every check** of the release gate against Fortress-XS: 45 of 45.
- **Its weak spots:** its harmful output flags about a third of harmless spaced-out or
  leetspeak text (it only logs by default). It is one trained model, not the best of
  several seeds. It costs 2.9× Fortress-XS's CPU time. All of this is in the
  [model card](https://huggingface.co/gantrly/fortress-base).

### Red-teaming

`mobiusguard-eval redteam` attacks a configuration with garak's prompt-injection probes in
26 mutated forms, each sent as a user message and as a tool result
([guide](docs/red-team.md), [decision 0014](docs/decisions/0014-red-team-runner.md)).
- **Against 0.2.0 with Fortress-XS:** 1,009,736 attempts, 27.1% got through.
- **What changed:** the findings led to the classifier scoring every view of a text and to
  three normalisation fixes, each checked by the gate on harmless text.
- **Checked once on a sealed holdout** of 4,563 prompts that no fix saw: 25.4% got through
  before, 20.6% after. Leetspeak alone got worse, 21.1% → 33.1%
  ([results](docs/results/2026-11-10-classifier-views.md#on-the-holdout)).
- **Not yet measured:** Fortress-Base under the red team, and the adaptive runner
  (`redteam adapt`, PyRIT's PAIR) at full scale.

### The proxy and the redactor

<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/assets/obfuscation-dark.svg">
  <img src=".github/assets/obfuscation.svg" alt="Recall at 1% false positives on spaced, look-alike and invisible-character attacks rises from 0–17% to 38–61% with Mobius Guard's normalisation in front of PIGuard and ProtectAI v2" width="880">
</picture>

- **Redaction:** 0 of 15,000 secrets leaked, exact or garbled, streamed in random chunks
  through real messages ([2026-11-02](docs/results/2026-11-02-redactor.md)).
- **Request rules:** no false blocks on 23,221 benign texts, under a millisecond each
  ([2026-10-29](docs/results/2026-10-29-proxy.md)).
- **Live:** 20 of 20 checks with the official OpenAI and Anthropic SDKs against a real model
  ([2026-10-30](docs/results/2026-10-30-live-check.md)).
- **Still hard for every detector:** indirect and adaptive attacks (LLMail-Inject, BIPIA).
  Fortress-XS raised LLMail-Inject from 12% to 44%; BIPIA-style injections are its
  weakest family. Fortress-Base catches 68.5% of LLMail-Inject and 70.5% of BIPIA's
  injections inside documents.

## Quickstart

```sh
pip install "mobiusguard[onnx]"   # Python 3.11 or newer; [onnx] adds the Fortress classifier
mobiusguard serve --port 8787 --config mobiusguard.toml
```

```toml
# mobiusguard.toml
[policy]
classifier = "fortress-xs"   # or "fortress-base": more accurate on documents, 2.9× the CPU
harmful = "log"              # harmful requests: log (default), block or off
```

```python
from openai import OpenAI

client = OpenAI(base_url="http://127.0.0.1:8787/v1")  # your usual key; that's all
```

<details>
<summary>The redactor on its own, or the proxy in a container</summary>

```python
from mobiusguard_redact import StreamRedactor

r = StreamRedactor()
for chunk in model_stream:
    send(r.feed(chunk))  # what is safe to show now
send(r.flush())
```

```sh
docker build -t mobiusguard . && docker run -p 127.0.0.1:8787:8787 mobiusguard
```

</details>

| Package | What | Depends on |
|---|---|---|
| `mobiusguard-redact` | Streaming redaction, for any gateway or app | `regex` only |
| `mobiusguard` | The proxy | the redactor, Starlette, httpx; `[onnx]` adds onnxruntime and tokenizers for Fortress |
| `mobiusguard-eval` | The evaluation harness | both, plus NumPy and PyArrow |

## Documentation

[Quickstart](docs/quickstart.md) · [Configuration](docs/configuration.md) ·
[Rules](docs/rules.md) · [Redaction](docs/redaction.md) · [Audit log](docs/audit-log.md) ·
[Deploy](docs/deploy.md) · [Red-teaming](docs/red-team.md) ·
[Architecture](docs/architecture.md) · [Threat model](docs/threat-model.md) ·
[Training data](docs/training-data.md) · [Results](docs/results/) ·
[Decisions](docs/decisions/) · [Development](docs/development.md)

## Roadmap

```mermaid
timeline
    v0.1 · released : Streaming redactor : Evaluation harness : Proxy for three APIs
    v0.2 · released : Fortress-XS, our own CPU classifier
    v0.3 · released : Fortress-Base, opt-in : Red-team and adaptive-attack runners : Role marks and every-view scoring
    next : Red-team Fortress-Base : A faster distilled model, under study
    v0.4 : Dashboard : Tool, RAG and MCP screening : LiteLLM and Presidio adapters
```

More in [ROADMAP.md](docs/ROADMAP.md) and the [changelog](CHANGELOG.md).

## Part of Gantrly

Built by the people behind [Gantrly](https://github.com/gantrly), whose AI agent will
run behind it. Mobius Guard has no dependency on Gantrly and works with any LLM app.

## Contributing

Issues and pull requests are welcome: start with [CONTRIBUTING.md](CONTRIBUTING.md).
Questions and ideas: [Discussions](https://github.com/gantrly/mobius-guard/discussions).
Found a way past the guard? Report it privately ([SECURITY.md](SECURITY.md)).

## Licence

[Apache-2.0](LICENSE), with contributions signed off under the
[DCO](https://developercertificate.org/) (no CLA). The gitleaks rules are MIT
([NOTICE](NOTICE)). Datasets are not included; their licences are in
[datasets.md](docs/datasets.md).
