# Mobius Guard

An open-source firewall for LLM apps. It sits in front of any OpenAI-compatible API,
screens prompts before they reach the model, and rewrites leaked secrets and personal data
in the streamed reply **without stopping the stream**.

A [Gantrly](https://github.com/gantrly) project. Gantrly will run its AI agents behind it, but
Mobius Guard is licensed (Apache-2.0) and built separately, for any LLM app to use.

> **Status: pre-alpha.** Nothing is ready to use yet. This README describes what we are
> building; [docs/ROADMAP.md](docs/ROADMAP.md) shows what is done.

## Why another guardrail?

Lots of tools already screen prompts. Mobius Guard focuses on four things that, as of
October 2026, no mature open-source project does well
([the research behind this](docs/research/2026-10-27-landscape-and-eval.md)):

1. **Streaming redaction that rewrites instead of killing the stream.** A secret split
   across two chunks (`"AKIA"` … `"IOSFODNN7EXAMPLE"`) is still caught, and the reply keeps
   flowing with the secret replaced. We test this by splitting every test input at every
   possible point.
2. **Honest numbers.** Most public prompt-injection datasets were used to train the
   classifiers that report scores on them, and attackers who adapt beat most published
   defences. We report recall at a fixed false-positive rate on attack families held out
   from training, false positives on hard benign text, and CPU latency with the hardware
   stated.
3. **Red-team findings become reviewed patches** (v0.2). Attacks that get through become a
   proposed rule or threshold change. It is applied only after it passes a benign "canary"
   set and a person approves it.
4. **A maintained, permissively licensed classifier** (v0.2), small enough to run on a CPU
   in milliseconds, trained on data whose source and licence are on record.

## Packages

| Package | What it is |
|---|---|
| [`mobiusguard-redact`](packages/mobiusguard-redact) | Streaming redaction library with no dependencies. Usable on its own in any app or gateway. |
| [`mobiusguard`](packages/mobiusguard) | The proxy: rules, classifier, decision policy, audit log. |
| [`mobiusguard-eval`](packages/mobiusguard-eval) | The evaluation harness. |

## Developing

Requires [uv](https://docs.astral.sh/uv/).

```bash
make install   # create .venv and install the pre-commit hook
make check     # lint, type check and tests: the same as CI
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Design decisions are recorded in
[docs/decisions/](docs/decisions/).

## Security

Please report vulnerabilities in Mobius Guard privately: see [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE).
