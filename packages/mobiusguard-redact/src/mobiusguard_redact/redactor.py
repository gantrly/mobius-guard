"""Streaming redaction: rewrite secrets in text that arrives in chunks.

The redactor emits everything that cannot be part of a match and holds back only from the
earliest point where some pattern might still be matching. See decision 0007.
"""

from __future__ import annotations

from collections.abc import AsyncIterable, AsyncIterator, Iterable, Iterator, Sequence
from dataclasses import dataclass

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
    """

    def __init__(
        self,
        patterns: Sequence[Pattern] | None = None,
        *,
        label: str = DEFAULT_LABEL,
        max_holdback: int = 8192,
        context: int = 1024,
    ) -> None:
        self._patterns = tuple(default_patterns() if patterns is None else patterns)
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
        for p in self._patterns:
            for m in p.compiled.finditer(text, pos=base):
                if not final and p.could_grow(m):
                    hold = min(hold, m.start())
                    break
                s0, s1 = p.secret_span(m)
                candidates.append(_Candidate(m.start(), m.end(), s0, s1, p.accepts(m), p))
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


def redact(
    text: str, patterns: Sequence[Pattern] | None = None, *, label: str = DEFAULT_LABEL
) -> str:
    """Redact a complete string."""
    r = StreamRedactor(patterns, label=label)
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
