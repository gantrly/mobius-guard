"""The keyword prefilter skips a pattern only where it could not have matched."""

from __future__ import annotations

import re
import warnings

import pytest
import regex
from hypothesis import HealthCheck, Phase, given, settings
from hypothesis import strategies as st
from mobiusguard_redact import StreamRedactor, redact
from mobiusguard_redact._gitleaks_rules import RULES
from mobiusguard_redact.patterns import KEYWORDS_UNSAFE, Pattern, gitleaks_patterns

KEYED = [p for p in gitleaks_patterns() if p.keywords]
SLOW = [HealthCheck.too_slow, HealthCheck.filter_too_much, HealthCheck.data_too_large]


def _generator(p: Pattern) -> str | None:
    gen = regex.sub(r"\(\?<?[=!](?:[^()]|\([^()]*\))*\)", "", p.regex)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            re.compile(gen)
    except (re.error, DeprecationWarning, FutureWarning):
        return None
    return gen


def test_most_gitleaks_rules_use_their_keywords() -> None:
    assert all(r.keywords for r in RULES)
    assert len(KEYED) == len(RULES) - len(KEYWORDS_UNSAFE)
    assert {r.id for r in RULES} >= KEYWORDS_UNSAFE


@pytest.mark.parametrize("pattern", KEYED, ids=lambda p: p.id)
def test_keywords_are_a_safe_filter(pattern: Pattern) -> None:
    """Every generated match contains a keyword, its secret does not start before it, and
    it is still found when the text before the keyword has already been sent.

    A rule that fails goes into ``KEYWORDS_UNSAFE`` and always runs.
    """
    gen = _generator(pattern)
    assert gen is not None, f"{pattern.id}: cannot be checked, add it to KEYWORDS_UNSAFE"

    @settings(max_examples=200, derandomize=True, deadline=None, database=None,
              phases=[Phase.generate], suppress_health_check=SLOW)  # fmt: skip
    @given(st.from_regex(gen, fullmatch=True))
    def check(s: str) -> None:
        m = pattern.compiled.fullmatch(s)
        if m is None:  # the generator drops look-arounds
            return
        # Lower-case one character at a time so positions still line up ("İ" -> 2 chars).
        low = "".join(c if len(c.lower()) != 1 else c.lower() for c in s)
        at = [low.find(k) for k in pattern.keywords if k in low]
        assert at, f"{pattern.id}: a match without a keyword: {s!r}"
        k = min(at)
        secret = pattern.secret_span(m)
        assert secret[0] >= k, f"{pattern.id}: secret first: {s!r}"
        # Before the keyword arrives the rule is skipped, so the text before it may already
        # have been sent; the scan then starts later. It must still find the same secret
        # (the "lob" in "lob=live_..." must not be required, for example).
        for start in range(k + 1):
            again = pattern.compiled.search(s, start)
            assert again is not None, f"{pattern.id}: lost when scanning from {start}: {s!r}"
            assert pattern.secret_span(again) == secret, f"{pattern.id}: from {start}: {s!r}"

    check()


def test_a_keyword_split_across_chunks_is_still_caught() -> None:
    token = "glpat-" + "Ab3dE5gH7jK9mN1pQ3sT"
    text = f"token {token} ok"
    for cut in range(1, len(text)):
        r = StreamRedactor()
        out = r.feed(text[:cut]) + r.feed(text[cut:]) + r.flush()
        assert token not in out, cut
        assert out == redact(text, prefilter=False), cut


def test_context_before_the_keyword_is_not_lost() -> None:
    # Found by the stress run (2026-11-02): "lob=" was sent before "live_" arrived, and the
    # rule, which needs "lob", could no longer match. Such rules always run now.
    text = "lob=live_" + "0" * 35 + ";"
    expected = redact(text, prefilter=False)
    assert "[REDACTED:lob-api-key]" in expected
    for cut in range(1, len(text)):
        r = StreamRedactor()
        assert r.feed(text[:cut]) + r.feed(text[cut:]) + r.flush() == expected, cut


def test_patterns_without_keywords_always_run() -> None:
    custom = Pattern(id="ticket", category="secret", source="test", regex=r"TCK-\d{6}")
    assert redact("see TCK-123456", [custom]) == "see [REDACTED:ticket]"
