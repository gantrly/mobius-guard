"""Streaming redaction: rewrite secrets in text that arrives in chunks.

The redactor emits everything that cannot be part of a match and holds back only from the
earliest point where some pattern might still be matching. See decision 0007.
"""

from __future__ import annotations

from collections.abc import AsyncIterable, AsyncIterator, Iterable, Iterator, Sequence
from dataclasses import dataclass

import regex

from .patterns import Category, Pattern, default_patterns

DEFAULT_LABEL = "[REDACTED:{id}]"
OVERFLOW_ID = "holdback_overflow"


@dataclass(frozen=True, slots=True)
class Finding:
    """One redacted span. Positions are character offsets in the input stream.

    The secret itself is never stored.
    """

    pattern_id: str
    category: Category | None  # None for a holdback overflow
    source: str
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class _Candidate:
    match_start: int
    match_end: int
    secret_start: int
    secret_end: int
    accepted: bool
    pattern: Pattern


class StreamRedactor:
    """Redact one stream of text.

    Call :meth:`feed` with each chunk and send what it returns; call :meth:`flush` once at the
    end and send that too. The concatenated output is the same however the input was split
    (for the shipped patterns; see decision 0007). One instance handles one stream.

    With ``prefilter`` (the default), a pattern that has keywords runs only while one of
    them is in the text not yet sent, or the text ends with the start of one. Patterns
    without keywords always run.
    """

    def __init__(
        self,
        patterns: Sequence[Pattern] | None = None,
        *,
        label: str = DEFAULT_LABEL,
        max_holdback: int = 8192,
        context: int = 1024,
        prefilter: bool = True,
    ) -> None:
        self._patterns = tuple(default_patterns() if patterns is None else patterns)
        self._keywords = _keywords_for(self._patterns) if prefilter else None
        self._label = label
        self._max_holdback = max_holdback
        self._context = context
        self._ctx = ""  # already-emitted input kept for look-behind
        self._buf = ""  # input not emitted yet
        self._offset = 0  # stream offset of _buf[0]
        self._closed = False
        self.findings: list[Finding] = []

    @property
    def held(self) -> int:
        """Characters received but not yet emitted."""
        return len(self._buf)

    def feed(self, chunk: str) -> str:
        if self._closed:
            raise RuntimeError("feed() after flush()")
        self._buf += chunk
        return self._process(final=False)

    def flush(self) -> str:
        if self._closed:
            return ""
        out = self._process(final=True)
        self._closed = True
        return out

    # ------------------------------------------------------------------ internals

    def _process(self, *, final: bool) -> str:
        text = self._ctx + self._buf
        base = len(self._ctx)
        n = len(text)

        hold = n
        candidates: list[_Candidate] = []
        skip = self._keywords.skipped(text[base:], final=final) if self._keywords else ()
        for i, p in enumerate(self._patterns):
            if i in skip:
                continue
            for m in p.compiled.finditer(text, pos=base):
                if not final and p.could_grow(m):
                    hold = min(hold, m.start())
                    break
                span = p.accepted_span(m)
                s0, s1 = span or p.secret_span(m)
                candidates.append(_Candidate(m.start(), m.end(), s0, s1, span is not None, p))
            if not final:
                start = p.partial_start(text, base)
                if start is not None:
                    hold = min(hold, start)

        if not final:
            # A finished match that crosses the hold point must be held too, or the next
            # scan (which starts at the hold point) would never see it again.
            changed = True
            while changed:
                changed = False
                for c in candidates:
                    if c.match_start < hold < c.match_end:
                        hold = c.match_start
                        changed = True

        emitted = self._render(text, base, hold, candidates)
        consumed = hold - base
        if not final and n - hold > self._max_holdback:
            # A possible match grew past the limit: redact rather than leak (decision 0007).
            start = self._offset + consumed
            self.findings.append(Finding(OVERFLOW_ID, None, "redactor", start, start + n - hold))
            emitted += self._label.format(id=OVERFLOW_ID)
            consumed = n - base
        self._ctx = (self._ctx + self._buf[:consumed])[-self._context :] if self._context else ""
        self._buf = self._buf[consumed:]
        self._offset += consumed
        return emitted

    def _render(self, text: str, base: int, hold: int, candidates: list[_Candidate]) -> str:
        spans = sorted(
            (c for c in candidates if c.accepted and c.match_end <= hold),
            key=lambda c: (c.secret_start, -(c.secret_end - c.secret_start), c.pattern.priority),
        )
        merged: list[tuple[int, int, Pattern]] = []
        for c in spans:
            if c.secret_start == c.secret_end:
                continue
            if merged and c.secret_start < merged[-1][1]:
                s, e, p = merged[-1]
                merged[-1] = (s, max(e, c.secret_end), p)
            else:
                merged.append((c.secret_start, c.secret_end, c.pattern))

        out: list[str] = []
        pos = base
        for s, e, p in merged:
            out.append(text[pos:s])
            out.append(self._label.format(id=p.id))
            self.findings.append(
                Finding(
                    p.id, p.category, p.source, self._offset + s - base, self._offset + e - base
                )
            )
            pos = e
        out.append(text[pos:hold])
        return "".join(out)


class _Keywords:
    """Which patterns with keywords can be skipped for a piece of text."""

    def __init__(self, patterns: Sequence[Pattern]) -> None:
        keyed = {i: p.keywords for i, p in enumerate(patterns) if p.keywords}
        self._keyed = frozenset(keyed)
        words = sorted({k for ks in keyed.values() for k in ks}, key=len, reverse=True)
        # Longest first, so at each position the regex finds the longest keyword there;
        # every keyword inside it is present too.
        self._find = regex.compile("|".join(map(regex.escape, words))) if words else None
        self._present = {
            w: frozenset(i for i, ks in keyed.items() if any(k in w for k in ks)) for w in words
        }
        self._starts: dict[str, set[int]] = {}
        for i, ks in keyed.items():
            for k in ks:
                for n in range(1, len(k)):
                    self._starts.setdefault(k[:n], set()).add(i)
        self._longest = max(map(len, words), default=0)

    def skipped(self, text: str, *, final: bool) -> frozenset[int]:
        if self._find is None:
            return frozenset()
        low = text.lower()
        run: set[int] = set()
        for m in self._find.finditer(low, overlapped=True):
            run |= self._present[m.group()]
        if not final:  # a keyword may be arriving: its start is at the end of the text
            for n in range(1, min(self._longest, len(low) + 1)):
                run |= self._starts.get(low[-n:], set())
        return self._keyed - run


_KEYWORDS: dict[tuple[int, ...], tuple[tuple[Pattern, ...], _Keywords]] = {}


def _keywords_for(patterns: tuple[Pattern, ...]) -> _Keywords:
    """The keyword index for a pattern set, built once (it takes about 10 ms).

    Keyed by the patterns' identities; the entry keeps the patterns alive, so an identity
    cannot be reused while it is cached.
    """
    key = tuple(map(id, patterns))
    hit = _KEYWORDS.get(key)
    if hit is None:
        if len(_KEYWORDS) >= 32:
            _KEYWORDS.clear()
        hit = _KEYWORDS[key] = (patterns, _Keywords(patterns))
    return hit[1]


def redact(
    text: str,
    patterns: Sequence[Pattern] | None = None,
    *,
    label: str = DEFAULT_LABEL,
    prefilter: bool = True,
) -> str:
    """Redact a complete string."""
    r = StreamRedactor(patterns, label=label, prefilter=prefilter)
    return r.feed(text) + r.flush()


def redact_stream(
    chunks: Iterable[str], patterns: Sequence[Pattern] | None = None
) -> Iterator[str]:
    """Redact an iterable of chunks, yielding output as soon as it is safe."""
    r = StreamRedactor(patterns)
    for chunk in chunks:
        out = r.feed(chunk)
        if out:
            yield out
    tail = r.flush()
    if tail:
        yield tail


async def aredact_stream(
    chunks: AsyncIterable[str], patterns: Sequence[Pattern] | None = None
) -> AsyncIterator[str]:
    """Async version of :func:`redact_stream`."""
    r = StreamRedactor(patterns)
    async for chunk in chunks:
        out = r.feed(chunk)
        if out:
            yield out
    tail = r.flush()
    if tail:
        yield tail
