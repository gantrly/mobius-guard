# 0007: How streaming redaction behaves

- **Status:** accepted, 2026-10-27

## Decision

**Holdback by partial matching.** The redactor emits everything that cannot be part of a
secret and holds back only from the earliest point where some pattern *might* be matching.
It uses the [`regex`](https://pypi.org/project/regex/) library's partial matching for this,
so `mobiusguard-redact` has one runtime dependency. Ordinary text passes through with no
added delay.

A match is held, not emitted, while it could still change with more input:

- a partial match (the text so far could become a match);
- a full match that could still grow: the text from its start to the end of the buffer is
  itself a match or the start of one (`fullmatch(..., partial=True)`). This catches
  regexes that settle for a shorter match while a longer one is still arriving, such as
  `+1 (415)` before `555-0132` arrives;
- any match that overlaps the held region (otherwise re-scanning would lose it).

**A `regex` quirk we work around.** Partial matching misreports lazy quantifiers followed
by a literal: `regex.search(r"\w*?abc", "Hello there", partial=True)` claims a partial
match at 0, which would hold back all text. Lazy and greedy quantifiers accept the same
strings, so each pattern also gets a greedy copy (`_probe.make_greedy`) that is used only to
find where a match might start; the original pattern still decides what is redacted.

**Delay is about one word.** gitleaks' keyword rules (`<word>_api_key = …`) can start at
any word, so the last unfinished word is held. Measured on this repo's docs and code in
4-character chunks (Apple M1 Pro, Python 3.12, all 245 patterns): output trails input by
3 characters at P50, 25 at P99, 65 at most.

**The guarantee:** for every shipped pattern, the redacted output is the same however the
input is split into chunks. This is enforced by property tests that split every test input
at every point, every single-character split, random splits and generated matches for every
pattern Hypothesis can sample. The could-grow check above is what makes cases like `a+b|a`
safe, but we only claim what the tests cover: custom patterns should be run through the
same property tests.

**Patterns: as many as we can ship, from two sources.**

1. *Curated*: our own high-precision secrets and PII, with checks that cut false positives
   (Luhn for cards, mod-97 for IBAN, Verhoeff for Aadhaar). These win when two patterns
   cover the same text.
2. *gitleaks* (v8.30.1, MIT, attributed in NOTICE): all 221 regex rules, generated into a
   Python module by `scripts/import_gitleaks.py` from a pinned, hash-checked copy of
   `gitleaks.toml`. We keep gitleaks' semantics where they apply to text: the secret is the
   `secretGroup` or the first non-empty capture group; a match is skipped when its Shannon
   entropy is at or below the rule's threshold, or when a global or rule allowlist matches.
   Path and commit conditions have no meaning in a chat stream: path-scoped rules run
   everywhere, path-only allowlists are dropped, and `line` allowlist targets use the match
   instead.

Many gitleaks rules were built for scanning code, so some will fire on chat text. Their
false-positive rate on benign text is measured in the evaluation harness (Part 2), and
any rule can be switched off by ID.

**What gets replaced.** Only the secret, not the surrounding match: `api_key = sk_live_…`
becomes `api_key = [REDACTED:stripe_secret_key]`. Overlapping secrets are merged into one
replacement, labelled by the leftmost, longest match (curated first). The label format is
configurable.

**Limits.**

- At most 8,192 characters are held back (configurable). If a possible match grows past
  that, the held text is replaced with `[REDACTED:holdback_overflow]`: on overflow we
  redact rather than leak.
- At the end of the stream, everything left is matched as complete text and emitted.

**Findings** record the pattern ID, category, source and the position in the input
stream, never the secret itself.

**CPU cost (to improve).** Same run: 0.34 ms per chunk at P50 and 1.2 ms at P99 with all
patterns, 0.03 ms with the curated set alone (`benchmarks/redact_stream.py`). Fine for one
stream, but a proxy with many concurrent streams needs less. Next step: skip a gitleaks
rule unless one of its keywords (or the start of one, at the end of the buffer) is in the
unemitted text.

## Considered

- **Fixed window** (hold the last N characters): standard library only and simple, but
  every reply's first text waits for N characters, which hurts time to first token.
- **Word-boundary holdback**: low delay, but patterns that span spaces (card numbers,
  PEM keys) each need special handling.
- **Curated only** or **secrets only**: fewer false positives, but much less coverage. We
  measure instead of guessing.
