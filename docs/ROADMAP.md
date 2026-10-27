# Roadmap

Each part is finished, tested and reviewed before the next one starts.

## v0.1: redaction, evaluation, proxy

| Part | What | Status |
|---|---|---|
| 0 | Foundation: uv workspace, CI, community files, decision records, threat model | **done** (2026-10-27) |
| 1 | `mobiusguard-redact`: streaming redactor, 24 curated + 221 gitleaks patterns, split-at-every-point property tests, latency benchmark | **done** (2026-10-27); keyword prefilter for CPU cost still to do |
| 2 (next) | `mobiusguard-eval`: provenance ledger, dataset loaders, held-out families, false-positive sets, metrics (recall at fixed FPR, AUC, latency), baselines | planned |
| 3 | `mobiusguard` proxy: OpenAI-compatible `/v1/chat/completions` (streaming and not), input normalisation, rules layer, pluggable classifier (PIGuard baseline), decision policy, audit log, OpenTelemetry GenAI spans | planned |
| 4 | Release v0.1: docs, published numbers from the harness, PyPI release, make the repository public | planned |

## v0.2: closed loop and our own model

- Red-team runner (mutation families, with garak/PyRIT adapters rather than re-writing them).
- Patch proposals (rules or threshold changes) as reviewable diffs, gated on the benign
  canary set and a sealed holdout.
- Train a small permissive classifier (DeBERTa-v3-xsmall / mmBERT-small class) on the GPU
  box; INT8 ONNX; model card with held-out numbers.

## v0.3: reach

- Dashboard.
- Tool-output / RAG / MCP screening (integrate with existing MCP gateways rather than
  compete).
- Adapters: LiteLLM guardrail, Presidio streaming.
