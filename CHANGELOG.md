# Changelog

All notable changes, per release. The three packages (`mobiusguard-redact`, `mobiusguard`,
`mobiusguard-eval`) are released together with one version number. Versions follow
[Semantic Versioning](https://semver.org); before 1.0, a minor version may change the API.

## Unreleased

- SECURITY.md: response times, coordinated disclosure, safe harbour, scope and supported
  versions. OpenSSF Best Practices badge in the README.
- `serve` names the upstream, not the variable, when a held key's variable is not set.

## 0.1.0 (2026-11-03)

The first release.

### mobiusguard-redact

- Streaming redaction: secrets and personal data are rewritten in text that arrives in
  chunks, with the same output however the text is split (property-tested at every split
  point), about one word of delay, and at most 8,192 characters held back.
- 24 curated patterns (API keys and tokens, private keys, connection-string passwords,
  bearer tokens, emails, payment cards with Luhn, IBAN with mod-97, US SSN, Aadhaar with
  Verhoeff, PAN, international phone numbers) and all 221 gitleaks v8.30.1 rules with their
  entropy, allowlist and keyword checks.
- Private keys: the block ends at its END line, so the text after a key flows on at once;
  a key cut off before its END line (a model reaching its token limit) is still redacted.
- gitleaks' curl rules follow a command onto the next line only after a continuation
  character, so the lines after the word "curl" are no longer held back.
- Tolerates the ways models garble what they echo: tokens a few characters longer or
  shorter (Stripe keys too), values wrapped in quotes or markdown, passwords in URLs without a host.
- Keyword prefilter: 177 gitleaks rules run only where one of their keywords is present or
  arriving (same output, checked on every public text in the evaluation).

### mobiusguard

- Proxy for OpenAI Chat Completions, OpenAI Responses and Anthropic Messages, streamed or
  not, in front of any compatible upstream.
- Request check on user messages and tool results: normalisation (invisible characters,
  look-alike letters, spaced-out letters, leetspeak, base64), eight named rules with
  severities, an optional PIGuard or ProtectAI v2 classifier, and a policy that blocks with
  HTTP 403 in each API's own error format. Fails closed.
- Streaming redaction of replies and tool-call arguments, per choice, output item and
  content block.
- Audit log (one JSON line per request, no prompt text by default) and OpenTelemetry spans.
- Forwarded or held API keys, with client tokens; start-up warnings for risky key settings.
- `mobiusguard serve`, `mobiusguard check`, and a container image.

### mobiusguard-eval

- Provenance ledger of 11 pinned public datasets with licences and known training use.
- Suite builder with near-duplicate clusters and five obfuscation families; recall at a
  fixed false-positive rate from thresholds set on ordinary traffic, AUC, Wilson intervals
  and CPU latency.
- Baselines: keyword rules, TF-IDF trained leave-one-source-out, ProtectAI v2, PIGuard.
- Redactor evaluation: firing rates on public text, synthetic and garbled secrets in real
  messages, near misses.
- Every step checkpointed; `mobiusguard-eval pipeline` resumes where it stopped.
