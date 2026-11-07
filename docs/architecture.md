# Architecture

The v0.1 design, as built (updated 2026-11-02): the redactor, the evaluation harness and the
proxy ([decision 0010](decisions/0010-proxy-v0.1.md)), packaged as described in
[decision 0011](decisions/0011-releasing-v0.1.md).

```text
client ──► /v1/chat/completions · /v1/responses · /v1/messages
             │
             ▼
        ┌─────────────────────────── request path ───────────────────────────┐
        │ normalise   decode/strip what attackers use to hide text           │
        │             (zero-width, homoglyphs, spaced letters, base64, …)    │
        │ rules       8 named regex rules, high or medium severity           │
        │ classifier  optional: Fortress-XS (attack + harmful), PIGuard, ... │
        │             Fortress ships its thresholds; the others have none    │
        │ policy      ALLOW / BLOCK with reasons; high rules block; attack   │
        │             scores over the threshold block, harmful ones log      │
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
split into chunks.** gitleaks rules run only where one of their keywords is in the unsent
text, as in gitleaks itself, which makes it about three times faster. Semantics, limits,
the three gitleaks rules changed for streaming, and measured cost are in
[decision 0007](decisions/0007-streaming-redaction-semantics.md).

**`mobiusguard`** is the proxy, a Starlette app that forwards requests with httpx. For each
of the three APIs it knows where the text is (`apis.py`): which parts of a request the model
reads, where the reply text and tool-call arguments sit in each streamed event, and the
API's own error format. The request check (`guard.py`) looks at user messages and tool
results only, in up to three views each (`normalize.py`), with the named rules
(`rules.py`) and an optional classifier; the policy is configuration, not code. The reply
is redacted per stream: per choice, output item or content block (`outbound.py`). Every
request ends with one audit line (`audit.py`). The evaluation harness wraps the same rules
and normalisation as detectors (`mobiusguard-eval`'s `detectors/proxy.py`), so the numbers
published are those of the shipped code.

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
