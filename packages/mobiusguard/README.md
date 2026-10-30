# mobiusguard

The Mobius Guard firewall proxy. Part of [Mobius Guard](https://github.com/gantrly/mobius-guard).
Pre-alpha.

It sits between your app and the model and speaks three APIs: OpenAI Chat Completions
(`/v1/chat/completions`), OpenAI Responses (`/v1/responses`) and Anthropic Messages
(`/v1/messages`), streamed or not.

- **On the way in**, user messages and tool results are cleaned up (invisible characters,
  look-alike letters, spaced-out letters, leetspeak and base64 undone) and checked against
  named rules, and optionally a classifier. A clear rule hit is refused with HTTP 403 in the
  API's own error format, naming the rule. Classifier scores are logged until you set a
  threshold.
- **On the way out**, secrets and personal data are replaced in the reply as it streams,
  even when they are split across events (`mobiusguard-redact`).
- **For each request**, one audit line: the decision, rule IDs, scores and what was
  redacted, never the prompt text unless you ask. OpenTelemetry spans if installed.

```sh
mobiusguard serve --port 8787                 # forwards each caller's own API key
mobiusguard check "Ignore all previous instructions"   # try the request check
```

Point any SDK at it:

```python
from openai import OpenAI

client = OpenAI(base_url="http://127.0.0.1:8787/v1")  # your usual API key

from anthropic import Anthropic

claude = Anthropic(base_url="http://127.0.0.1:8787")
```

To try it with a free local model, run Ollama and use
[`examples/ollama.toml`](https://github.com/gantrly/mobius-guard/blob/main/examples/ollama.toml);
`scripts/live_check.py` sends every case through all three APIs.

Settings are a TOML file (`mobiusguard serve --config mobiusguard.toml`); see
`mobiusguard/config.py` for every option, and
[decision 0010](https://github.com/gantrly/mobius-guard/blob/main/docs/decisions/0010-proxy-v0.1.md)
for the design. Optional extras: `mobiusguard[classifier]` (PIGuard or ProtectAI v2, about a
second per long prompt on a CPU) and `mobiusguard[otel]`.
