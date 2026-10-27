"""Pattern definitions and the built-in pattern sets."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from functools import cache
from typing import Literal

import regex

from ._gitleaks_rules import GLOBAL_ALLOWLIST, RULES
from ._gitleaks_types import Allowlist
from ._probe import make_greedy
from .validators import shannon_entropy

Category = Literal["secret", "pii"]


@dataclass(frozen=True, slots=True)
class Pattern:
    """One thing the redactor looks for.

    ``group`` picks what gets replaced: a group number or name, ``0`` for the whole match,
    or ``None`` for the first non-empty capture group (falling back to the whole match).
    A match is redacted only if it passes ``validator``, has entropy above
    ``min_entropy``, is not excused by an allowlist, and is not preceded by ``not_after``.

    ``not_after`` is a regex for text that must not come right before a match (checked on
    the 300 characters before it). It does the job of a variable-length lookbehind, which
    the ``regex`` library's partial matching gets wrong: a match can be reported as still
    growing, which would hold back everything after it (decision 0007).
    """

    id: str
    category: Category
    source: str
    regex: str
    description: str = ""
    group: int | str | None = 0
    validator: Callable[[str], bool] | None = None
    min_entropy: float = 0.0
    allowlists: tuple[Allowlist, ...] = ()
    priority: int = 0  # lower wins when two matches cover the same text
    not_after: str = ""
    compiled: regex.Pattern[str] = field(init=False, repr=False, compare=False)
    probe: regex.Pattern[str] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "compiled", _compile(self.regex))
        object.__setattr__(self, "probe", _compile(make_greedy(self.regex)))

    def partial_start(self, text: str, pos: int) -> int | None:
        """Earliest index >= pos where a match might start but needs more text, if any."""
        n = len(text)
        while pos < n:
            m = self.probe.search(text, pos, partial=True)
            if m is None:
                return None
            if m.partial:
                return m.start() if m.start() < n else None
            pos = m.start() + 1  # a full match here; a longer one may start later
        return None

    def could_grow(self, m: regex.Match[str]) -> bool:
        """Whether more input could change this match.

        True when the text from the match start to the end of the buffer is itself a match
        or the start of one. This catches what partial matching alone misses: a regex that
        settles for a shorter match (``a+b|a`` on ``"aa"``) when a longer one is still
        arriving.
        """
        return self.probe.fullmatch(m.string, m.start(), partial=True) is not None

    def secret_span(self, m: regex.Match[str]) -> tuple[int, int]:
        """The part of a match that gets replaced."""
        if self.group is None:
            for i in range(1, (m.re.groups or 0) + 1):
                if m.group(i):
                    return m.span(i)
            return m.span()
        return m.span(self.group)

    def accepted_span(self, m: regex.Match[str]) -> tuple[int, int] | None:
        """The span to redact for a match, or None if it isn't a finding.

        A pattern with a validator (cards, IBANs, phone numbers) can match one piece too
        many: "IBAN GB82...32 5." takes in the " 5" and fails its check. Then the match is
        tried again without its last space- or hyphen-separated piece, up to three times.
        Cutting only at a separator keeps the pattern's boundary rules true, and the result
        depends only on the matched text, so it is the same however the stream is split.
        """
        if self.accepts(m):
            return self.secret_span(m)
        if self.validator is None or self.group not in (0, None) or m.re.groups:
            return None
        text = m.group()
        for _ in range(3):
            cut = max(text.rfind(" "), text.rfind("-"))
            if cut <= 0:
                return None
            text = text[:cut].rstrip(" -")
            if self.compiled.fullmatch(text) and self._accepts_text(text, text):
                return (m.start(), m.start() + len(text))
        return None

    def accepts(self, m: regex.Match[str]) -> bool:
        """Whether a regex match is a real finding (validators, entropy, allowlists)."""
        start, end = self.secret_span(m)
        secret = m.string[start:end]
        if not secret:
            return False
        if self.not_after and _compile(f"(?:{self.not_after})\\Z").search(
            m.string, max(0, m.start() - 300), m.start()
        ):
            return False
        return self._accepts_text(secret, m.group())

    def _accepts_text(self, secret: str, match: str) -> bool:
        if self.validator is not None and not self.validator(secret):
            return False
        if self.min_entropy and shannon_entropy(secret) <= self.min_entropy:
            return False
        return not any(_allowed(a, secret, match) for a in self.allowlists)


@cache
def _compile(pattern: str) -> regex.Pattern[str]:
    return regex.compile(pattern)


def _allowed(a: Allowlist, secret: str, match: str) -> bool:
    target = secret if a.target == "secret" else match
    checks: list[bool] = []
    if a.regexes:
        checks.append(any(_compile(r).search(target) for r in a.regexes))
    if a.stopwords:
        lowered = secret.lower()
        checks.append(any(w in lowered for w in a.stopwords))
    return all(checks) if a.require_all else any(checks)


def gitleaks_patterns() -> tuple[Pattern, ...]:
    """All gitleaks regex rules, with gitleaks' entropy and allowlist semantics."""
    global_allow = (GLOBAL_ALLOWLIST,) if GLOBAL_ALLOWLIST else ()
    return tuple(
        Pattern(
            id=r.id,
            category="secret",
            source="gitleaks",
            regex=r.regex,
            description=r.description,
            group=r.secret_group or None,
            min_entropy=r.entropy,
            allowlists=global_allow + r.allowlists,
            priority=10,
        )
        for r in RULES
    )


def default_patterns(*, exclude: Iterable[str] = ()) -> tuple[Pattern, ...]:
    """Curated patterns first, then every gitleaks rule. ``exclude`` drops IDs."""
    from .curated import CURATED

    skip = set(exclude)
    return tuple(p for p in (*CURATED, *gitleaks_patterns()) if p.id not in skip)
