# 0002: Python for the core

- **Status:** accepted, 2026-10-27

## Decision

The redactor, proxy and evaluation harness are written in Python (3.11+), with an async
ASGI server for streaming and ONNX Runtime for the classifier.

## Why

Training, evaluation and the security-ML ecosystem (garak, PyRIT, Presidio, LiteLLM,
Hugging Face) are Python, so contributors and adapters share one language. ONNX Runtime in
Python meets the latency budget; the model, not the language, dominates request time.

## Considered

- **Rust:** best latency and a single binary, but slower to build and fewer contributors.
  The redactor could be ported later behind the same API if profiling shows a need.
- **Go:** single binary, but ONNX needs cgo, and it would compete head-on with Pipelock.
- **TypeScript / Next.js** (the prototype's plan): one stack with the dashboard, but unusual
  for a security proxy and further from the ML tooling. Kept as an option for the v0.3
  dashboard only.
