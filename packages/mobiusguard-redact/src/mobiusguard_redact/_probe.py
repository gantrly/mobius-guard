"""Greedy copies of patterns, used only to find where a match might be starting.

``regex`` partial matching misreports lazy quantifiers followed by a literal:
``regex.search(r"\\w*?abc", "Hello there", partial=True)`` claims a partial match at 0.
Greedy and lazy quantifiers accept exactly the same strings, so a greedy copy answers
"could a match start here?" correctly. The original pattern still decides what is
redacted. See decision 0007.
"""

from __future__ import annotations

_QUANT = "*+?}"


def make_greedy(pattern: str) -> str:
    """Drop the ``?`` that makes a quantifier lazy, outside escapes and character classes."""
    out: list[str] = []
    i, n = 0, len(pattern)
    in_class = False
    prev_quant = False  # the last emitted token was a quantifier
    while i < n:
        c = pattern[i]
        if c == "\\":
            out.append(pattern[i : i + 2])
            i += 2
            prev_quant = False
            continue
        if in_class:
            out.append(c)
            if c == "]":
                in_class = False
            i += 1
            continue
        if c == "[":
            in_class = True
            out.append(c)
            i += 1
            # A ']' right after '[' or '[^' is a literal.
            if i < n and pattern[i] == "^":
                out.append("^")
                i += 1
            if i < n and pattern[i] == "]":
                out.append("]")
                i += 1
            prev_quant = False
            continue
        if c == "?" and prev_quant:
            i += 1  # lazy marker: drop it
            prev_quant = False
            continue
        if c == "(" and i + 1 < n and pattern[i + 1] == "?":
            out.append("(?")  # group syntax, not a quantifier
            i += 2
            prev_quant = False
            continue
        if c == "{":
            j = pattern.find("}", i)
            body = pattern[i + 1 : j] if j != -1 else ""
            if j != -1 and body and all(ch.isdigit() or ch == "," for ch in body):
                out.append(pattern[i : j + 1])
                i = j + 1
                prev_quant = True
                continue
        out.append(c)
        prev_quant = c in _QUANT and c != "}"
        i += 1
    return "".join(out)
