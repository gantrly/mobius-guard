# Changelog

All notable changes, per release. The three packages (`mobiusguard-redact`, `mobiusguard`,
`mobiusguard-eval`) are released together with one version number. Versions follow
[Semantic Versioning](https://semver.org); before 1.0, a minor version may change the API.

## Unreleased

- Fix: of two IBANs written in groups of four with only a space between them, the second
  was not redacted; nor was the second of two such American Express numbers (#20). The
  first number's match ran on into the second and was cut back to pass its check, but the
  search then went on from inside the second number. It now goes on from the end of the
  accepted number, in one-shot and streaming redaction alike.

## 0.1.1 (2026-11-04)

- SECURITY.md: response times, coordinated disclosure, safe harbour, scope and supported
  versions. OpenSSF Best Practices badge in the README.
- `serve` names the upstream, not the variable, when a held key's variable is not set.
- The redactor no longer rescans all the held text on every chunk while a possible secret
  is open, such as a private key whose END line hasn't arrived yet. Each pattern resumes
  where its last scan left off. With 6,000–8,000 characters held, a chunk takes 3.5 ms
  instead of 66 ms with all patterns (#17). The output is unchanged.
- The benchmark measures this case: `benchmarks/redact_stream.py --held`.
- `mobiusguard` and `mobiusguard-eval` now require `mobiusguard-redact>=0.1.1`, so upgrading
  the proxy brings this fix.
- Dependencies in the lockfile updated to their latest releases; no known
  vulnerabilities.
- Releases: each GitHub release also carries its build provenance as files, a Sigstore
  bundle and an in-toto envelope, so a download can be checked offline
  (`gh attestation verify <file> --bundle …`). The provenance now covers only the wheels
  and sdists (0.1.0's also listed a stray `.gitignore`). Uploads use
  `pypa/gh-action-pypi-publish`, which adds PEP 740 attestations on PyPI.
- A fuzz target for the redactor (`fuzz/redactor.py`, Atheris), run on pull requests that
  touch the redactor and weekly.

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
