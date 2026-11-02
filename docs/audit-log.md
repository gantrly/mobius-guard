# The audit log

The proxy writes one JSON line per request to `[audit] path` (default
`mobiusguard-audit.jsonl`; `""` turns it off). It records what was decided and why, never
the prompt, the reply, the secrets or the API keys, unless you set `include_text = true`.

A blocked request (from the live check, where the attack was spaced out letter by letter):

```json
{"time": "2026-10-30T05:44:57.179+00:00", "api": "chat", "model": "qwen2.5:3b", "stream": false,
 "decision": "block", "ms": 0.5, "reason": "rule",
 "rules": [{"id": "override_instructions", "severity": "high", "view": "normalized", "where": "messages[0].content"},
           {"id": "reveal_instructions", "severity": "medium", "view": "normalized", "where": "messages[0].content"}],
 "score": null, "checked": 1, "prompt_sha256": "b662f3b33ae0829278584599f04b4c41"}
```

An allowed request whose reply had two secrets redacted:

```json
{"time": "2026-10-30T05:44:57.495+00:00", "api": "chat", "model": "qwen2.5:3b", "stream": false,
 "decision": "allow", "ms": 314.1, "reason": "", "rules": [], "score": null, "checked": 1,
 "prompt_sha256": "acdae0104c9eb06308d1dc58c2b1dd22",
 "redacted": {"aws_access_key_id": 1, "connection_string_password": 1}, "upstream_status": 200}
```

## Fields

| Field | Meaning |
|---|---|
| `time` | When the request finished (UTC) |
| `api` | `chat` (Chat Completions), `responses` or `anthropic` (Messages) |
| `model` | The `model` field of the request |
| `stream` | Whether the reply was streamed |
| `decision` | `allow` or `block` |
| `ms` | Time in the proxy, upstream included |
| `reason` | Why it was blocked: `rule`, `classifier` or `detector_error`; empty when allowed |
| `rules` | Every rule hit: its ID, severity, the view it matched in (`original`, `normalized`, `base64`) and where in the request (`messages[2].content`, `input[0].content[1]`, …) |
| `score` | The highest classifier score over the checked texts (log-odds), or `null` without a classifier |
| `checked` | How many texts were checked (user messages and tool results) |
| `prompt_sha256` | A hash of the checked texts, to match repeats without storing them |
| `error` | The detector error, when one failed |
| `redacted` | Redactions in the reply, counted per pattern ID |
| `upstream_status` | The upstream's HTTP status |
| `upstream_error` | Why the upstream could not be reached (the proxy then answers 502) |
| `texts` | The checked texts; only with `include_text = true` |

Requests refused before they are checked (a missing client token, a body over the size
limit, invalid JSON) are not logged.

## Useful queries

```sh
# What was blocked, and by which rule
jq -c 'select(.decision == "block") | [.time, .reason, [.rules[].id]]' mobiusguard-audit.jsonl

# Which patterns redact most on your traffic
jq -r '.redacted // {} | to_entries[] | .key' mobiusguard-audit.jsonl | sort | uniq -c | sort -rn
```

The classifier scores in this log are also how to choose a classifier threshold
([configuration.md](configuration.md#choosing-the-threshold)).

## Keeping it

The file only grows; rotate it with your usual tool (`logrotate` with `copytruncate`, or a
log shipper reading the file). With `include_text = true` it holds user prompts: treat it
as sensitive data, with matching access control and retention.
