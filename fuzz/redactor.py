"""Fuzz the streaming redactor: its output must not depend on how the text is split.

Atheris (coverage-guided, libFuzzer) drives the property through Hypothesis, so any input it
finds is shrunk and printed as a Hypothesis example. The text is built from pieces of what
the patterns look for (prefixes, separators, PEM lines, continued commands), so the fuzzer
reaches partial and overlapping matches quickly. No whole fake secret is written here.

    uv sync --group fuzz          # Linux x86_64, Python 3.12+: Atheris has no other wheels
    uv run python fuzz/redactor.py -max_total_time=300

Without Atheris, ``uv run python fuzz/redactor.py --hypothesis`` runs the same property as
an ordinary Hypothesis test.
"""

from __future__ import annotations

import sys

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from mobiusguard_redact import StreamRedactor, default_patterns, redact

PIECES = [
    "-----BEGIN RSA PRIVATE KEY-----\n",
    "\n-----END RSA PRIVATE KEY-----",
    "-----BEGIN ",
    "PRIVATE KEY-----",
    "AKIA",
    "ghp_",
    "github_pat_",
    "glpat-",
    "sk-proj-",
    "sk-ant-api03-",
    "sk_live_",
    "xoxb-",
    "hf_",
    "AIza",
    "Bearer ",
    "Authorization: ",
    "curl -H '",
    " \\\n",
    "postgres://app:",
    "@db:5432/x",
    "api_key = '",
    "password=",
    "token: ",
    "secret",
    "GB82 WEST ",
    "4111 1111 ",
    "+1 415 555 ",
    "@example.com",
    "\n",
    " ",
    "=",
    "'",
    '"',
]
BODY = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_."
PATTERNS = default_patterns()

texts = st.lists(
    st.one_of(st.sampled_from(PIECES), st.text(BODY, max_size=48), st.text(max_size=8)),
    max_size=40,
).map("".join)


@settings(database=None, deadline=None, max_examples=200, suppress_health_check=list(HealthCheck))
@given(texts, st.lists(st.integers(1, 64), max_size=64))
def split_invariance(text: str, sizes: list[int]) -> None:
    r = StreamRedactor(PATTERNS)
    out: list[str] = []
    pos = 0
    for size in sizes:
        out.append(r.feed(text[pos : pos + size]))
        pos += size
        assert r.held <= 8192
    out.append(r.feed(text[pos:]))
    out.append(r.flush())
    assert "".join(out) == redact(text, PATTERNS, prefilter=False)


def main() -> None:
    if "--hypothesis" in sys.argv:
        split_invariance()
        return
    import atheris

    atheris.instrument_all()
    atheris.Setup(sys.argv, split_invariance.hypothesis.fuzz_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
