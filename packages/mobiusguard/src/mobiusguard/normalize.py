"""Undo the tricks that hide an attack from detectors, for detection only.

The evaluation (docs/results/2026-10-27-baselines.md) showed spaced-out letters, look-alike
letters and invisible characters beating every baseline. Detection therefore looks at
several *views* of each text: the original, a normalised copy (invisible characters
removed, compatibility forms and look-alike letters folded, spaced letters joined, leetspeak
undone) and the decoded contents of any base64 run. The request sent to the model is never
changed.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass

# Characters that render as nothing: zero-width, joiners, bidi controls, soft hyphen,
# variation selectors and Unicode tag characters (used for "ASCII smuggling").
_INVISIBLE = re.compile("[­᠎​-‏‪-‮⁠-⁤⁦-⁩﻿︀-️\U000e0000-\U000e007f]")

# Cyrillic and Greek letters that look like Latin ones in most fonts.
_CONFUSABLES = str.maketrans(
    "асеіјорѕхукмнтвАВСЕНІЈКМОРЅТХУαορυνιΑΒΕΖΗΙΚΜΝΟΡΤΥΧ",
    "aceijopsxykmhtbABCEHIJKMOPSTXYaopuviABEZHIKMNOPTYX",
)
_CONFUSABLE_SET = frozenset(chr(c) for c in _CONFUSABLES)
_WORD = re.compile(r"\w+")

_LEET = str.maketrans({"4": "a", "@": "a", "3": "e", "1": "i", "!": "i", "0": "o",
                       "5": "s", "$": "s", "7": "t", "+": "t"})  # fmt: skip
_LEET_WORD = re.compile(r"[A-Za-z@$!+]*[0-9@$!+][A-Za-z0-9@$!+]*")

# Three or more single characters, each followed by one to three spaces: "i g n o r e".
_SPACED = re.compile(r"(?<!\S)(?:\S {1,3}){3,}\S(?!\S)")
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}|[A-Za-z0-9_-]{16,}={0,2}")


@dataclass(frozen=True, slots=True)
class View:
    kind: str  # original | normalized | base64
    text: str


def strip_invisible(text: str) -> str:
    return _INVISIBLE.sub("", text)


def fold_confusables(text: str) -> str:
    """Fold look-alike letters, but only in words that mix them with Latin letters or are
    made only of look-alikes; ordinary Russian or Greek words are left as they are."""

    def fold(m: re.Match[str]) -> str:
        w = m.group()
        has_confusable = any(c in _CONFUSABLE_SET for c in w)
        if not has_confusable:
            return w
        has_latin = any("a" <= c.lower() <= "z" for c in w)
        only_confusable = all(c in _CONFUSABLE_SET or not c.isalpha() for c in w)
        return w.translate(_CONFUSABLES) if has_latin or only_confusable else w

    return _WORD.sub(fold, text)


def join_spaced(text: str) -> str:
    """'i g n o r e   a l l' -> 'ignore all' (a wider gap is a word break)."""

    def join(m: re.Match[str]) -> str:
        return " ".join(word.replace(" ", "") for word in re.split(r" {2,}", m.group()))

    return _SPACED.sub(join, text)


def unleet(text: str) -> str:
    """Undo leetspeak in words that mix letters with digits or symbols ('1gn0r3')."""
    return _LEET_WORD.sub(
        lambda m: m.group().translate(_LEET) if re.search("[A-Za-z]", m.group()) else m.group(),
        text,
    )


def normalize(text: str) -> str:
    out = unicodedata.normalize("NFKC", strip_invisible(text))
    out = fold_confusables(out)
    out = join_spaced(out)
    return unleet(out)


def decoded_base64(text: str, *, min_printable: float = 0.9) -> list[str]:
    """Text hidden in base64 runs, when it decodes to mostly printable UTF-8."""
    found: list[str] = []
    for m in _B64.finditer(text):
        run = m.group()
        try:
            raw = base64.b64decode(
                run + "=" * (-len(run) % 4),
                altchars=b"-_" if "-" in run or "_" in run else None,
                validate=True,
            )
        except (binascii.Error, ValueError):
            continue
        try:
            s = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if len(s) >= 8 and sum(c.isprintable() or c in "\n\t" for c in s) / len(s) >= min_printable:
            found.append(s)
    return found


def views(text: str) -> list[View]:
    """Every view of a text that detection should look at, without duplicates."""
    out = [View("original", text)]
    norm = normalize(text)
    if norm != text:
        out.append(View("normalized", norm))
    for s in decoded_base64(text):
        out.append(View("base64", s))
        n = normalize(s)
        if n != s:
            out.append(View("base64", n))
    return out
