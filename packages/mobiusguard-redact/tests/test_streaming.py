"""The redactor's core promise: output does not depend on how the input is chunked."""

from __future__ import annotations

import asyncio
import re
import warnings
from collections.abc import AsyncIterator, Sequence

import pytest
import regex
from hypothesis import given
from hypothesis import strategies as st
from mobiusguard_redact import (
    Pattern,
    StreamRedactor,
    aredact_stream,
    default_patterns,
    redact,
    redact_stream,
)
from mobiusguard_redact.curated import CURATED
from samples import POSITIVES

ALL = default_patterns()


def chunked(text: str, cuts: Sequence[int], patterns: Sequence[Pattern] = ALL) -> str:
    r = StreamRedactor(patterns)
    points = sorted({c for c in cuts if 0 < c < len(text)})
    out: list[str] = []
    prev = 0
    for c in [*points, len(text)]:
        out.append(r.feed(text[prev:c]))
        prev = c
    out.append(r.flush())
    return "".join(out)


@pytest.mark.parametrize(("pattern_id", "text", "secret"), POSITIVES)
def test_every_two_way_split_matches_one_shot(pattern_id: str, text: str, secret: str) -> None:
    sentence = f"Here it is: {text}. Thanks!"
    expected = redact(sentence, ALL, prefilter=False)
    assert secret not in expected
    for cut in range(1, len(sentence)):
        assert chunked(sentence, [cut]) == expected, (pattern_id, cut)


@pytest.mark.parametrize(("pattern_id", "text", "secret"), POSITIVES)
def test_one_character_chunks_match_one_shot(pattern_id: str, text: str, secret: str) -> None:
    sentence = f"> {text}\nnext line"
    expected = redact(sentence, ALL, prefilter=False)
    assert chunked(sentence, range(len(sentence))) == expected, pattern_id


# Fragments the property tests build text from: plain words, separators and secrets.
_SECRETS = [text for _, text, _ in POSITIVES]
_WORDS = [
    "the",
    "key",
    "api_key",
    "=",
    "token:",
    "AKIA",
    "ghp_",
    "sk-",
    "4111",
    "+91",
    "@",
    "-----BEGIN",
    "glpat-",
    "xoxb-",
    "twilio",
    "adafruit_key",
    "secret",
]
_SEPS = [" ", "\n", ", ", '"', "'", "`", ". ", "\t", " = ", ": "]

fragments = st.lists(
    st.one_of(
        st.sampled_from(_SECRETS),
        st.sampled_from(_WORDS),
        st.sampled_from(_SEPS),
        st.text(alphabet="abcXYZ019_-./+= \n", max_size=12),
    ),
    max_size=12,
).map("".join)


@given(text=fragments, cuts=st.lists(st.integers(min_value=1, max_value=400), max_size=12))
def test_random_splits_match_one_shot(text: str, cuts: list[int]) -> None:
    # One-shot without the keyword prefilter is the reference.
    assert chunked(text, cuts) == redact(text, ALL, prefilter=False)


def _regex_samples() -> list[tuple[Pattern, st.SearchStrategy[str]]]:
    """A Hypothesis strategy for every shipped pattern that the stdlib ``re`` can parse.

    Hypothesis generates from ``re`` syntax; look-arounds are dropped from the generator
    (the redactor still applies them), and patterns using ``regex``-only syntax such as
    mid-pattern flags are skipped.
    """
    out: list[tuple[Pattern, st.SearchStrategy[str]]] = []
    for p in ALL:
        generator = regex.sub(r"\(\?<?[=!](?:[^()]|\([^()]*\))*\)", "", p.regex)
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error")
                re.compile(generator)
        except (re.error, DeprecationWarning, FutureWarning):
            continue
        out.append((p, st.from_regex(generator, fullmatch=True)))
    return out


SAMPLED = _regex_samples()


def test_most_patterns_can_be_sampled() -> None:
    assert len(SAMPLED) >= 0.8 * len(ALL)


BENIGN = [
    "Hello there, how are you today? I hope the weather is nice where you are.",
    "To configure the client, set the timeout and retries in config.yaml, then restart.",
    "def add(a, b):\n    return a + b  # simple helper\n",
    "The meeting moved to 3pm; bring the Q3 numbers and the roadmap draft.",
]


@pytest.mark.parametrize("text", BENIGN)
def test_hold_points_are_real(text: str) -> None:
    """Every reported hold point is a genuine possible match start (no bogus partials)."""
    for p in ALL:
        start = p.partial_start(text, 0)
        if start is None:
            continue
        m = p.compiled.match(text, pos=start, partial=True)
        assert m is not None, (p.id, start, text[start:])
        assert m.partial or m.end() == len(text), (p.id, start)


def _last_word(text: str) -> int:
    return len(text) - len(text.rstrip(".,;:!?").rsplit(None, 1)[0]) if " " in text else len(text)


@pytest.mark.parametrize("text", BENIGN)
def test_benign_prose_holds_at_most_the_last_word(text: str) -> None:
    # gitleaks' keyword rules ("<word>_api_key = ...") can start at any word, so the last
    # unfinished word is held: about one word of delay (decision 0007).
    r = StreamRedactor(ALL)
    out = r.feed(text)
    assert r.held <= _last_word(text) + 1, (r.held, text[len(out) :])


@given(data=st.data())
def test_generated_matches_split_anywhere(data: st.DataObject) -> None:
    pattern, strategy = data.draw(st.sampled_from(SAMPLED))
    body = data.draw(strategy)
    text = (
        data.draw(st.sampled_from(["", "x ", "said: ", "\n"]))
        + body
        + data.draw(st.sampled_from(["", " y", ".", "\n", '"']))
    )
    cuts = data.draw(st.lists(st.integers(min_value=1, max_value=max(1, len(text))), max_size=8))
    assert chunked(text, cuts) == redact(text, ALL, prefilter=False), pattern.id


# ---------------------------------------------------------------- behaviour


def test_plain_text_is_not_held_back() -> None:
    r = StreamRedactor(CURATED)
    assert r.feed("Hello there, how are you today? ") == "Hello there, how are you today? "
    r = StreamRedactor(ALL)
    assert r.feed("Hello there, how are you today?\n").startswith("Hello there, how are you")


def test_possible_secret_is_held_until_it_resolves() -> None:
    r = StreamRedactor(CURATED)
    first = r.feed("my token is ghp_Zx9Q")
    assert "ghp_" not in first
    rest = r.feed("Zx9Q" * 8 + " ok") + r.flush()
    assert "[REDACTED:github_token]" in first + rest
    assert "Zx9Q" not in first + rest


def test_findings_hold_positions_not_secrets() -> None:
    r = StreamRedactor(CURATED)
    text = "a jo@example.com b 123-45-6789"
    r.feed(text)
    r.flush()
    spans = [(f.pattern_id, text[f.start : f.end]) for f in r.findings]
    assert spans == [("email", "jo@example.com"), ("us_ssn", "123-45-6789")]
    assert all("@" not in repr(f) for f in r.findings)


def test_overflow_redacts_instead_of_leaking() -> None:
    r = StreamRedactor(CURATED, max_holdback=64)
    out = r.feed("-----BEGIN RSA PRIVATE KEY-----\n" + "A" * 200)
    assert "AAAA" not in out
    assert "[REDACTED:holdback_overflow]" in out
    assert r.findings[0].pattern_id == "holdback_overflow"


def test_flush_twice_and_feed_after_flush() -> None:
    r = StreamRedactor(CURATED)
    r.feed("x")
    assert r.flush() == "x"
    assert r.flush() == ""
    with pytest.raises(RuntimeError):
        r.feed("y")


def test_custom_label() -> None:
    assert redact("jo@example.com", CURATED, label="<{id}>") == "<email>"


def test_iterator_helpers() -> None:
    chunks = ["mail jo@exa", "mple.com", " now"]
    assert "".join(redact_stream(chunks, CURATED)) == "mail [REDACTED:email] now"

    async def gen() -> AsyncIterator[str]:
        for c in chunks:
            yield c

    async def collect() -> str:
        return "".join([c async for c in aredact_stream(gen(), CURATED)])

    assert asyncio.run(collect()) == "mail [REDACTED:email] now"


_PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    + "\n".join(["MIIEow" + "A" * 58] * 6)
    + "\n-----END RSA PRIVATE KEY-----"
)


def test_text_after_a_private_key_is_not_held_back() -> None:
    # Found by the benchmark (2026-11-02): both private-key patterns could run on to a
    # later END line, so everything after a key was held until the holdback limit.
    text = f"here:\n{_PEM}\n" + "The reply goes on. " * 600
    r = StreamRedactor()
    out = [r.feed(text[: len(_PEM) + 40])]
    for i in range(len(_PEM) + 40, len(text), 4):
        out.append(r.feed(text[i : i + 4]))
        assert r.held < 40, (i, r.held)
    out.append(r.flush())
    assert "".join(out) == redact(text, ALL, prefilter=False)
    assert "".join(out).startswith("here:\n[REDACTED:private_key]\nThe reply")


def test_a_private_key_without_its_end_line_does_not_leak() -> None:
    text = "key:\n" + _PEM[:200] + "\n" + "more text. " * 900
    r = StreamRedactor()
    out = "".join(r.feed(text[i : i + 4]) for i in range(0, len(text), 4)) + r.flush()
    assert "MIIEow" not in out


@pytest.mark.parametrize("cut", [1, 5, 40, 100, 300])
def test_a_private_key_cut_off_at_the_end_of_the_reply_does_not_leak(cut: int) -> None:
    # A model that hits its token limit mid-key: no END line, then the stream ends.
    text = "key:\n" + _PEM[:200]
    expected = redact(text, ALL, prefilter=False)
    assert expected == "key:\n[REDACTED:private_key]"
    assert chunked(text, [cut]) == expected


def test_the_lines_after_the_word_curl_are_not_held_back() -> None:
    # The curl rules looked five lines ahead for a header, so several lines after "curl"
    # were held (benchmark, 2026-11-02). Now only a continued command is followed.
    text = "Use curl for that.\n" + "Another line of ordinary text here.\n" * 20
    r = StreamRedactor()
    r.feed(text[:24])
    for i in range(24, len(text), 4):
        r.feed(text[i : i + 4])
        assert r.held < 40, (i, r.held)
    r.flush()
