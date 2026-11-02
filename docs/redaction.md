# Redaction

The proxy runs every reply through `mobiusguard-redact`: secrets and personal data are
replaced with a label naming what they were, as the reply streams. The same redactor is a
separate package with one dependency, for use in any gateway or app.

```text
in:   my key is AKIAQWERTYUIOPASDFGH and the db is postgres://app:Sup3rS3cret!@db:5432/prod
out:  my key is [REDACTED:aws_access_key_id] and the db is postgres://app:[REDACTED:connection_string_password]@db:5432/prod
```

## What is redacted

**24 curated patterns**, written for chat text, with checks that cut false positives. They
win when two patterns cover the same text.

| ID | Kind | What |
|---|---|---|
| `aws_access_key_id` | secret | AWS access key ID |
| `aws_secret_access_key` | secret | AWS secret access key next to an AWS or secret-key label |
| `github_token` | secret | GitHub personal, OAuth, app or refresh token |
| `github_fine_grained_token` | secret | GitHub fine-grained personal access token |
| `gitlab_token` | secret | GitLab personal access token |
| `openai_api_key` | secret | OpenAI API key |
| `anthropic_api_key` | secret | Anthropic API key |
| `google_api_key` | secret | Google API key |
| `huggingface_token` | secret | Hugging Face access token |
| `slack_token` | secret | Slack token |
| `slack_webhook_url` | secret | Slack incoming webhook URL |
| `stripe_secret_key` | secret | Stripe secret or restricted key |
| `npm_token` | secret | npm access token |
| `json_web_token` | secret | JSON Web Token |
| `private_key` | secret | PEM private key block |
| `connection_string_password` | secret | Password inside a database or broker URL, also when the model dropped the `@host` part |
| `bearer_token` | secret | Bearer token, in an `Authorization` header or on its own |
| `email` | personal | Email address |
| `payment_card` | personal | Payment card number (issuer prefix, length and Luhn check) |
| `iban` | personal | International bank account number (mod-97 check) |
| `us_ssn` | personal | US Social Security number (dashed form only) |
| `in_aadhaar` | personal | Indian Aadhaar number (Verhoeff check) |
| `in_pan` | personal | Indian PAN (permanent account number) |
| `phone_international` | personal | Phone number in international format (+country code, 8–15 digits) |

**All 221 [gitleaks](https://github.com/gitleaks/gitleaks) rules** (v8.30.1, MIT), with
gitleaks' own entropy, allowlist and keyword checks: cloud providers, payment and messaging
APIs, CI tokens, `<name>_api_key = …` assignments and more. Their IDs are gitleaks' own
(`generic-api-key`, `twilio-api-key`, …).

Only the secret is replaced, not what surrounds it: `api_key = sk_live_…` becomes
`api_key = [REDACTED:stripe_secret_key]`. Token patterns accept a few characters more or
less than the exact length, because models repeating a token add or drop characters and
the rest of it would still be exposed.

## In streamed replies

- **The output is the same however the reply is split into chunks**, including a secret
  split across two events. Property tests check this at every split point for every
  shipped pattern.
- **About one word of delay.** Text that cannot be part of a secret is passed on at once;
  only where a secret might be starting is text held back (3 characters at the median and
  41 at P99 on this repository's own docs and code; up to a few lines after the word `curl`,
  where gitleaks looks ahead for an auth header).
- In the proxy, each text and each tool-call argument stream is redacted separately: per
  choice in Chat Completions, per output item in Responses, per content block in Anthropic
  Messages. Anthropic thinking blocks are left untouched, because they carry a signature
  that any change would break.
- At most 8,192 characters are held back. If a possible match grows past that, the held
  text is replaced with `[REDACTED:holdback_overflow]`: on overflow it redacts rather than
  leaks.

## Switching patterns off

In the proxy:

```toml
[redaction]
exclude = ["email", "generic-api-key"]
```

`enabled = false` turns redaction off. The audit log counts redactions per pattern ID,
which shows which ones fire on your traffic.

## On its own

```sh
pip install mobiusguard-redact
```

```python
from mobiusguard_redact import StreamRedactor, default_patterns, redact

r = StreamRedactor()  # or StreamRedactor(default_patterns(exclude={"email"}))
for chunk in model_stream:
    send(r.feed(chunk))  # whatever is safe to show now
send(r.flush())  # at the end of the reply
r.findings  # pattern ID, category and position; never the secret

redact("key AKIAQWERTYUIOPASDFGH")  # 'key [REDACTED:aws_access_key_id]'
```

Also `redact_stream(iterable)` and `aredact_stream(async_iterable)`. One
`StreamRedactor` handles one stream. Custom patterns are `Pattern(id=…, category=…,
source=…, regex=…)`; run them through the same property tests before relying on the
chunking guarantee ([decision 0007](decisions/0007-streaming-redaction-semantics.md)).

## Limits

- It finds what the patterns describe. Free-form personal data (names, street addresses)
  needs a named-entity model and is not covered in v0.1.
- A private key with no END line is redacted when the reply ends there; in the middle of a
  reply, it is held until the 8,192-character limit and then replaced together with the
  text after it.
- A secret the model rewrites beyond recognition (spelled out, split by spaces, translated)
  is not caught.
- Generic rules fire on some ordinary text. How often each pattern fires on 57,000 public
  prompts and messages is measured in the [redactor evaluation](results/), so you can
  switch off the ones that are noisy for you.
