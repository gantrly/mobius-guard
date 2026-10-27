# 0005: One repo, three distributions

- **Status:** accepted, 2026-10-27

## Decision

A uv workspace with three packages under `packages/`:

| Distribution | Import | Runtime dependencies |
|---|---|---|
| `mobiusguard-redact` | `mobiusguard_redact` | none |
| `mobiusguard` | `mobiusguard` | redact, server, ONNX Runtime |
| `mobiusguard-eval` | `mobiusguard_eval` | data and metrics libraries |

Tooling: hatchling builds, ruff (lint and format), pyright strict, pytest with Hypothesis,
pre-commit, GitHub Actions on Linux and macOS for Python 3.11 to 3.13.

## Why

Gateways and apps should be able to embed the redactor without pulling in a web server or
ML stack. The eval harness needs heavy data libraries that the proxy must not carry.

## Considered

- **One package with extras** (`mobiusguard[eval]`): simpler to publish, but the redactor
  would still drag the proxy's import tree and versioning along.
