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
        # What the last scan settled, reused while the text only grows at the end (see
        # _process): per pattern, where to resume scanning and the matches before that.
        self._scans: list[tuple[int, list[_Candidate]] | None] = [None] * len(self._patterns)
        self._kw_seen = 0  # how far the keyword scan has read
        self._kw_run: set[int] = set()
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

        # While nothing has been emitted since the last call, the text is the last text plus
        # the new chunk, so each pattern resumes where its last scan stopped being able to
        # change (issue #17). Matches before that point are final, and no match can start
        # in the text between them: either would have shown as a match that could grow or
        # as a partial match, the same rule that lets text be emitted at all. That holds for
        # any earlier scan of this stream, so a pattern the prefilter skips keeps its place.
        hold = n
        candidates: list[_Candidate] = []
        scans = self._scans  # a skipped pattern keeps its place for later
        skip = self._skipped(text, base, final=final)
        for i, p in enumerate(self._patterns):
            if i in skip:
                continue
            resume, found = scans[i] or (base, [])  # the list is replaced below
            grows: int | None = None
            for m in p.compiled.finditer(text, pos=resume):
                if not final and p.could_grow(m):
                    grows = m.start()
                    break
                span = p.accepted_span(m)
                s0, s1 = span or p.secret_span(m)
                found.append(_Candidate(m.start(), m.end(), s0, s1, span is not None, p))
            candidates += found
            if final:
                continue
            start = p.partial_start(text, resume)
            if start is not None:
                grows = start if grows is None else min(grows, start)
            if grows is None:
                scans[i] = (n, found)
            else:
                hold = min(hold, grows)
                if not found or found[-1].match_end <= grows:  # matches are in order
                    scans[i] = (grows, found)
                else:  # resume at a finished match that runs past the possible one
                    again = min(grows, *(c.match_start for c in found if c.match_end > grows))
                    scans[i] = (again, [c for c in found if c.match_start < again])

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
        if consumed:  # the text now starts elsewhere: scan afresh next time
            self._scans = [None] * len(self._patterns)
            self._kw_seen = 0
            self._kw_run = set()
        return emitted

    def _skipped(self, text: str, base: int, *, final: bool) -> frozenset[int]:
        """The patterns the keyword prefilter skips, reading only text it has not read."""
        kw = self._keywords
        if kw is None:
            return frozenset()
        # Reread the last few characters too: a keyword may have arrived across the cut.
        start = max(base, base + self._kw_seen - kw.longest + 1)
        self._kw_run |= kw.present(text[start:])
        self._kw_seen = len(text) - base
        run = self._kw_run if final else self._kw_run | kw.starting(text[base:])
        return kw.keyed - run

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
        self.keyed = frozenset(keyed)
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
        self.longest = max(map(len, words), default=0)

    def present(self, text: str) -> set[int]:
        """The patterns that have one of their keywords in the text."""
        run: set[int] = set()
        if self._find is not None:
            for m in self._find.finditer(text.lower(), overlapped=True):
                run |= self._present[m.group()]
        return run

    def starting(self, text: str) -> set[int]:
        """The patterns that have a keyword whose start ends the text: it may be arriving."""
        low = text[-self.longest :].lower()
        run: set[int] = set()
        for n in range(1, min(self.longest, len(low) + 1)):
            run |= self._starts.get(low[-n:], set())
        return run

    def skipped(self, text: str, *, final: bool) -> frozenset[int]:
        run = self.present(text) if final else self.present(text) | self.starting(text)
        return self.keyed - run


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
