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

**A second quirk: variable-length lookbehinds.** With one in a pattern, partial
`fullmatch` can report a finished match as still growing, so everything after it is held
until the holdback overflows. Found by the evaluation harness on a 23,000-character email
(2026-10-27), after the email pattern gained `(?<!://[^\s:/@]{1,256}:)`. Patterns must not
use variable-length lookbehinds; a pattern's `not_after` regex does the same job when a
match is accepted, outside partial matching. A regression test covers the case.

**Delay is about one word.** gitleaks' keyword rules (`<word>_api_key = …`) can start at
any word, so the last unfinished word is held. Measured on this repo's docs and code in
4-character chunks (2026-11-03, AWS g6.xlarge CPU, Python 3.12, all 245 patterns): output
trails input by 3 characters at P50, 36 at P99 and 169 at most.

**The curl rules follow continued lines only (2026-11-02).** gitleaks' `curl-auth-header`
and `curl-auth-user` looked up to five lines past the word `curl` for the header or user
option, so the redactor held up to 500 characters after any "curl" in the text. A curl
command only continues on the next line after a continuation character (`\` in shells, `^`
in cmd, a backtick in PowerShell), so later lines are now followed only after one; the rest
of both regexes is gitleaks' own (`STREAMING_PREFIXES` in `patterns.py`). A header on an
uncontinued next line is still caught by `generic-api-key`.

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

**Garbled echoes (2026-11-02).** Models do not repeat a secret exactly: the live check saw
a token with four characters added and a connection string with its host dropped, and the
redactor evaluation's garbled families (wrapped in quotes or markdown, 1-4 characters
added, 1-3 dropped, other surroundings) found more. Curated token patterns therefore accept
a few characters more or less than the exact length (`ghp_` + 30 or more instead of 36,
AWS key IDs 12-24 after the prefix, ...), the AWS secret key also follows a plain "secret
key" label and brackets, a bearer token is found without its `Authorization:` header, and a
connection string may have an empty user (`redis://:password@host`). These changes were made
after seeing those results; their false-positive cost is measured on the public texts,
which they were not tuned on.

**Private keys end at their END line (2026-11-02).** Both private-key patterns (ours and
gitleaks') allowed any text in the body, so after a complete key the match could still run on
to a later END line: everything after a key was held back until the holdback limit and then
replaced. Found by the benchmark once its input contained a PEM block. The body may no
longer contain `-----END`; gitleaks' `private-key` regex is changed accordingly
(`STREAMING_FIXES` in `patterns.py`); with the two curl rules below, the only rules we run
differently from gitleaks. Our
pattern also ends at the end of the reply, so a key cut off before its END line (a model
reaching its token limit) is redacted instead of passed on.

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

**CPU cost: a keyword prefilter (2026-11-02).** Running every pattern on every chunk cost
0.44 ms per chunk at P50 and 2.1 ms at P99 (same run). gitleaks runs a rule only when one
of its keywords is in the text; the redactor now does the same on text it has not sent:
a rule runs while one of its keywords is in that text, or the text ends with the start of
one (a keyword may be arriving). That is safe only when every match contains a keyword, the
secret does not start before it, and the rule still finds the same secret when the text
before the keyword has already been sent. `test_keywords_are_a_safe_filter` checks these on
200 generated matches per rule; the 44 rules that fail or cannot be generated always run
(`KEYWORDS_UNSAFE`, among them `lob-api-key`, which needs "lob" before its keyword and
leaked in a stress run until it was listed). Result: 0.15 ms per chunk at P50 and 0.40 ms at
P99 (3x and 5x faster; curated set alone 0.04 ms), and the same output with and without the
prefilter on all 57,064 public texts of the evaluation. The index of keywords is built once
per pattern set.

## Considered

- **Fixed window** (hold the last N characters): standard library only and simple, but
  every reply's first text waits for N characters, which hurts time to first token.
- **Word-boundary holdback**: low delay, but patterns that span spaces (card numbers,
  PEM keys) each need special handling.
- **Curated only** or **secrets only**: fewer false positives, but much less coverage. We
  measure instead of guessing.
