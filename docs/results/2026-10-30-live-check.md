# Live check: the proxy with real SDKs and a real model (2026-10-30)

The proxy's tests use a fake upstream. This check puts it in front of a real model and
talks to it with the official `openai` and `anthropic` Python libraries, to confirm that the
three APIs, streaming, blocking and redaction work end to end with clients as people use
them.

**Setup.** Ollama 0.40.13 (Docker, image pinned by digest) on an NVIDIA L4, serving
`qwen2.5:3b`, which answers Chat Completions, Responses and Anthropic Messages. Mobius
Guard `serve` in front of it with [`examples/ollama.toml`](../../examples/ollama.toml).
Script: [`scripts/live_check.py`](../../scripts/live_check.py). Fake secrets only; no paid
API was called.

## Result: 20 of 20

| API | Ordinary question | Spaced-out injection | Model echoes a key and a password |
|---|---|---|---|
| Chat Completions | answered (not streamed, streamed) | 403, `PermissionDeniedError` | both redacted |
| Responses | answered (not streamed, streamed) | 403, `PermissionDeniedError` | both redacted |
| Anthropic Messages | answered (not streamed, streamed) | 403, `PermissionDeniedError` | both redacted |
| Chat Completions, tool call | | | token in the arguments redacted (not streamed, streamed) |

- The injection (`i g n o r e   a l l   p r e v i o u s …`) was refused in about 2 ms with
  `override_instructions` and `reveal_instructions`, found in the normalised view; the
  official SDKs raised their usual permission error and exposed the rule IDs.
- The same echo sent straight to the model (no proxy) contained the key and the password,
  so the `[REDACTED:…]` labels in the proxied replies are the proxy's work.
- The audit log had one line per request (20), with the decisions and redaction counts
  (`aws_access_key_id` 10, `connection_string_password` 10, `github_token` 2) and no prompt
  text, secret or key.

## Two redactor gaps found and fixed

The first run passed 16 of 20. Both failures were models not echoing a secret exactly:

1. **A password in a URL without its host.** Asked to repeat
   `postgres://app:Sup3rS3cret!@db:5432/prod`, the model wrote
   `postgres://app:Sup3rS3cret!/db/prod`. The pattern only knew `user:password@host`, so the
   password went out. It now also treats a "port" that isn't a number as a password
   (`localhost:5432` is still left alone).
2. **A token with extra characters.** The model repeated a GitHub token with four characters
   added. The pattern required exactly 36 characters after `ghp_`, so the real token, inside
   the longer string, went out. It now takes 36 or more.

Both fixes have regression tests. On the changed patterns, the full test suite (389 tests) and
the 5,000-example stress tests passed again, and the redactor evaluation came out the same:
4,800 of 4,800 synthetic secrets redacted, and no new firing on the 57,064 public texts, so
the wider patterns add no false positives there. Lesson for the evaluation: synthetic secrets are inserted
exactly, but models garble what they echo; the redactor evaluation should also include
garbled echoes.
