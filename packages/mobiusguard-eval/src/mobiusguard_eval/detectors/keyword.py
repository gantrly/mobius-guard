"""The 'rules alone' baseline: a short list of well-known injection phrases.

Deliberately naive. It is the floor every other detector should beat, and it shows how many
attacks in a set are the textbook kind.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

import regex

from ..items import Item
from . import chunks

PHRASES: tuple[str, ...] = (
    r"\b(?:ignore|disregard|forget|override|skip)\b.{0,40}\b(?:instructions?|rules?|prompts?|"
    r"directions?|guidelines?|everything|above|previous|prior)\b",
    r"\b(?:system|initial|original|hidden|secret)\s+(?:prompt|instructions?|message)\b",
    r"\byou\s+are\s+now\b",
    r"\b(?:act|behave|pretend|respond)\s+as\b",
    r"\b(?:jailbreak|DAN|developer\s+mode|do\s+anything\s+now)\b",
    r"\bnew\s+(?:instructions?|rules?|task)\b",
    r"\b(?:reveal|print|repeat|show|tell\s+me)\b.{0,30}\b(?:password|secret|prompt|"
    r"instructions?|key)\b",
    r"\bno\s+(?:restrictions?|limits?|filters?|rules?)\b",
    r"\b(?:send|forward|email|post)\b.{0,40}\b(?:to|at)\b.{0,20}@",
    r"</?(?:system|user|assistant|im_start|im_end)>|\[/?INST\]|<\|[a-z_]+\|>",
)
_COMPILED = tuple(regex.compile(p, regex.IGNORECASE | regex.DOTALL) for p in PHRASES)


class KeywordDetector:
    name = "keyword"

    def info(self) -> dict[str, str]:
        return {"phrases": str(len(PHRASES))}

    def score_text(self, text: str) -> float:
        """How many of the phrase patterns appear (0 to len(PHRASES))."""
        return float(sum(1 for p in _COMPILED if p.search(text)))

    def fingerprint(self) -> dict[str, str]:
        return {"phrases": hashlib.sha256("\n".join(PHRASES).encode()).hexdigest()}

    def groups(self, items: Sequence[Item]) -> list[tuple[str, list[int]]]:
        return chunks(len(items))

    def score_group(self, items: Sequence[Item], idx: Sequence[int]) -> list[float]:
        return [self.score_text(items[i].text) for i in idx]
