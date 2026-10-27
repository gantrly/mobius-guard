# Architecture

This describes the target for v0.1. Parts not built yet are marked *(planned)*: as of
2026-10-27 the redactor and the evaluation harness exist; the proxy is Part 3.

```text
client ──► POST /v1/chat/completions                    (proxy: planned)
             │
             ▼
        ┌─────────────────────────── request path ───────────────────────────┐
        │ normalise   decode/strip what attackers use to hide text           │
        │             (zero-width, homoglyphs, spaced letters, base64, …)    │
        │ rules       fast deterministic patterns           ┐ run together   │
        │ classifier  small local ONNX model, score 0–1     ┘                │
        │ policy      combine into ALLOW / BLOCK (with reasons)              │
        └────────────────────────────────────────────────────────────────────┘
             │ BLOCK → 403 with a machine-readable reason, audit record
             │ ALLOW
             ▼
        upstream LLM (any OpenAI-compatible API)
             │ streamed reply (SSE)
             ▼
        ┌─────────────────────────── response path ──────────────────────────┐
        │ redactor    rewrites secrets/PII in the stream; holds back only    │
        │             text where a pattern might still be matching           │
        └────────────────────────────────────────────────────────────────────┘
             │
             ▼
           client           audit log + OpenTelemetry GenAI spans (async)
```

## Components

**`mobiusguard-redact`** depends only on `regex` and is usable without the proxy. Its core
is a streaming transformer: feed it text chunks, get back text that is safe to emit now. It
holds back text only from the earliest point where some pattern might still be matching
(partial matching), so ordinary text passes through with about one word of delay. The
defining property, tested for every pattern: **the output is the same however the input is
split into chunks.** Semantics, limits and measured cost are in
[decision 0007](decisions/0007-streaming-redaction-semantics.md).

**`mobiusguard`** is the proxy. Detectors share one interface (`text → Finding[]` with a
score and reason), so rules, our classifier and third-party classifiers are interchangeable
and can be compared in the eval harness. The policy is configuration, not code: thresholds
and which detectors block or only log.

**`mobiusguard-eval`** runs any detector (ours or a baseline) over registered datasets and
writes per-item results that a person can review, plus the summary metrics. Every dataset
is registered in a provenance ledger with its source, licence, and which known models were
trained on it, so contaminated comparisons are visible ([datasets.md](datasets.md)).
It works in three steps that can run on different machines: `build` (fetch pinned data,
remove duplicates, split, add obfuscated attacks), `score` (one detector, CPU or GPU, one
score per item) and `report` (thresholds from ordinary traffic, recall per family, false
positives per benign set, AUC). See [decision 0009](decisions/0009-evaluation-harness-v0.1.md).

## Principles

- **Fail closed on the request path, keep streaming on the response path.** If a detector
  errors, the request is blocked (configurable). Redaction never stops a reply; it replaces
  the matched text.
- **No prompt or reply text in logs by default.** The audit log stores decisions, scores,
  rule IDs and hashes; storing full text is an explicit opt-in.
- **Measure, don't claim.** Latency targets and detection rates are published from the
  harness, with hardware stated.
