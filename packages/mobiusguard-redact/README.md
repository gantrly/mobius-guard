# mobiusguard-redact

Streaming redaction for LLM output. It rewrites secrets and personal data in text that
arrives in chunks, including a secret split across two chunks, **without stopping the
stream** and without buffering the whole reply. Part of
[Mobius Guard](https://github.com/imtiaj-007/adaptive-llm-firewall). Pre-alpha.

```python
from mobiusguard_redact import StreamRedactor

r = StreamRedactor()  # curated patterns + all gitleaks rules
for chunk in llm_stream:  # e.g. "my key is AKIA", "QWERTYUIOPASDFGH ok"
    send(r.feed(chunk))  # emits text as soon as it is safe
send(r.flush())  # "my key is [REDACTED:aws_access_key_id] ok"
r.findings  # pattern IDs and positions, never the secrets
```

- **Same output however the text is split.** For every shipped pattern, property tests
  check this at every split point.
- **About one word of delay.** Only text where a secret might be starting is held back.
- **Patterns:** 24 curated (API keys, tokens, private keys, emails, payment cards with Luhn,
  IBAN, US SSN, Aadhaar with Verhoeff, PAN, phone numbers) plus all 221 regex rules from
  [gitleaks](https://github.com/gitleaks/gitleaks) v8.30.1 with its entropy and allowlist
  checks. Drop any by ID: `default_patterns(exclude={"generic-api-key"})`.
- Also `redact(text)`, `redact_stream(iterable)` and `aredact_stream(async_iterable)`.

How it works and its limits: [decision 0007](../../docs/decisions/0007-streaming-redaction-semantics.md).
