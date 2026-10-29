# 0010: The v0.1 proxy

- **Status:** accepted, 2026-10-29
- **Builds on:** [0003](0003-v0.1-scope.md) (scope), [0007](0007-streaming-redaction-semantics.md)
  (redaction), [0009](0009-evaluation-harness-v0.1.md) (evaluation)

## Decision

**Starlette and httpx.** A small async stack: we write the routes ourselves, stream with
httpx, and serve with uvicorn. No request models that copy each provider's schema: the
proxy reads the fields it needs and passes the rest through untouched.

**Three APIs from the start:**

| Route | Upstream | Streamed events the redactor rewrites |
|---|---|---|
| `POST /v1/chat/completions` | OpenAI-compatible | `choices[].delta.content`, tool-call arguments |
| `POST /v1/responses` | OpenAI-compatible | `response.output_text.delta`, function-call arguments |
| `POST /v1/messages` | Anthropic | `content_block_delta` (`text_delta`, `input_json_delta`) |

`GET /v1/models` is passed through so SDKs that list models keep working. Anything else is
404: the proxy only forwards what it understands.

**Keys.** By default the caller's own key (`Authorization` or `x-api-key`) is forwarded and
never stored or logged. A deployment can instead hold the upstream key itself (named by an
environment variable in the config) and require its own client tokens.

**Request path.** Every piece of text the model will read (system prompt, messages, tool
results, instructions) is extracted per API, then:

1. **Normalised**: invisible characters removed, look-alike letters folded to Latin,
   spaced-out letters joined, leetspeak undone for matching, base64 runs decoded and
   checked too. Detection sees both the original and the normalised text. The forwarded
   request is never changed.
2. **Rules**: named regex rules (with IDs and a category) over both texts.
3. **Classifier**: optional plug-in; none by default. PIGuard and ProtectAI v2 are
   available as an extra (`mobiusguard[classifier]`); our own ONNX model replaces them in
   v0.2.
4. **Policy** (configuration, not code): by default, a high-severity rule hit **blocks**
   with the rule IDs; classifier scores are **logged only** until a threshold is set from the
   deployment's own traffic. Blocks use each API's own error format, HTTP 403, with a
   machine-readable reason. If a detector fails, the request is blocked (fail closed;
   configurable).

**Which text is checked.** User messages and tool results, where attacks arrive (tool
results carry indirect injection). System and developer prompts are the deployment's own;
checking them would block legitimate prompts such as "never reveal the system prompt".

**Rules are written before they are measured.** The first rule set was written from
published attack patterns and measured once with the harness (Part 3e). A rule changed after
seeing results says so, and is measured on sets it was not tuned on (decision 0006). Each
rule has a severity: `high` rules (instruction overrides, chat-template tokens, markdown
exfiltration) block under the default policy; `medium` ones are logged.

**Response path.** The streaming redactor runs on each text and argument stream
separately (a stream per choice, per output item, per content block), so a secret split
across events is still caught. Non-streamed replies are redacted in place. Event
framing, IDs and everything else pass through unchanged. Anthropic thinking blocks are
left alone: they carry a signature that any change would break.

**Audit and telemetry.** One JSON line per request: time, API, model, decision, rule IDs,
scores, redaction counts by pattern, timings and a hash of the prompt, never its text unless
`include_text` is set. OpenTelemetry spans with the GenAI semantic conventions when the
optional `opentelemetry` extra is installed.

**Configuration** is a TOML file (Python reads it without a dependency), with every
setting overridable from the environment.

## Why

The evaluation showed spaced letters, look-alike letters and invisible characters beating
every baseline, so normalisation comes first and is measured with the same harness (Part
3e). Blocking on rules but only logging classifier scores keeps false blocks low until a
deployment calibrates; the results showed 1–11% false positives on hard benign text at a
threshold that looked like 1% on ordinary traffic.

## Considered

- **FastAPI**: OpenAPI docs and models, but heavier and the models would duplicate three
  providers' schemas.
- **A LiteLLM guardrail instead of a proxy**: instant reach, but we would inherit the
  streaming limits this project exists to fix. An adapter is planned for v0.3.
- **Chat Completions only**: a third of the protocol work, but Responses and Anthropic
  Messages are where agent traffic is going.
- **A classifier in every install**: detection out of the box, but torch (~1 GB) and about a
  second per long prompt on a CPU.
