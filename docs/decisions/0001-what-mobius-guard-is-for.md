# 0001: What Mobius Guard is for

- **Status:** accepted, 2026-10-27
- **Context:** [research note](../research/2026-10-27-landscape-and-eval.md)

## Decision

Rebuild the prototype from scratch as an open-source tool that contributes what existing
projects don't, rather than another prompt-screening proxy. The proxy is how it is
delivered; the contributions are:

1. Streaming redaction that rewrites split secrets instead of terminating the stream.
2. Honest, held-out evaluation, published with every number we claim.
3. A red-team → reviewed-patch loop gated on benign text (v0.2).
4. A maintained, permissively licensed CPU classifier (v0.2).

## Why

As of October 2026, inline prompt screening is well covered (LiteLLM, Kong, agentgateway,
Plano, Pipelock), and MCP gateways are crowded. But LiteLLM (#41611) and Presidio (#2312)
leak secrets split across chunks; NeMo Guardrails and Pipelock can only block or end a
stream; AWS Bedrock can't mask while streaming. Closed-loop patching exists only in
promptfoo Enterprise, without an automatic false-positive gate. ProtectAI's widely used
classifier is archived, and Prompt Guard 2 is under the Llama licence.

## Considered

- **Build the blueprint as written** (Next.js proxy, red team, auto-patch, dashboard at
  once). It overlaps heavily with existing tools, and its headline result (Run #2 catches
  100%) re-tests the attacks it just patched.
