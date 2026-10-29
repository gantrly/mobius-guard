"""Named rules for prompt injection, run over every view of every checked text.

Written from published attack patterns before being measured (decision 0010); changes made
after looking at evaluation results must say so, and are measured on sets they were not
tuned on (decision 0006).

``severity``: ``high`` rules block under the default policy, ``medium`` ones are logged.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

import regex

from .normalize import View

Severity = Literal["high", "medium"]


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    severity: Severity
    description: str
    pattern: str
    compiled: regex.Pattern[str] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "compiled", regex.compile(self.pattern, regex.I | regex.S))


_NOT = r"(?<!\b(?:not|never|don'?t|do\s+not|won'?t|cannot|can'?t)\s+)"

RULES: tuple[Rule, ...] = (
    Rule(
        "override_instructions",
        "high",
        "Tells the model to ignore, forget or replace its earlier instructions",
        _NOT + r"\b(?:ignore|disregard|forget|override|bypass)\b\W+(?:\w+\W+){0,3}?"
        r"(?:all\W+|any\W+|the\W+|your\W+|my\W+)?(?:previous|prior|above|earlier|preceding|"
        r"original|initial|system|existing)\W+(?:\w+\W+){0,2}?"
        r"(?:instructions?|rules?|prompts?|directions?|guidelines?|messages?|context)\b",
    ),
    Rule(
        "chat_template_injection",
        "high",
        "Contains a chat-template control token that fakes a new turn or a system message",
        r"<\|(?:im_start|im_end|system|user|assistant|endoftext|start_header_id|"
        r"end_header_id|eot_id)\|>|\[/?INST\]|<<\s*/?SYS\s*>>",
    ),
    Rule(
        "fake_system_turn",
        "medium",
        "Claims to be a system or developer message inside user text",
        r"(?:^|\n)\s*(?:#{1,3}\s*)?(?:system|developer)\s*(?:message|prompt|override|update)?"
        r"\s*[:>\]]\s*\S",
    ),
    Rule(
        "reveal_instructions",
        "medium",
        "Asks the model to reveal its system prompt or hidden instructions",
        _NOT + r"\b(?:reveal|print|repeat|show|output|display|tell\s+me|give\s+me|leak|dump)\b"
        r"\W+(?:\w+\W+){0,4}?(?:system\s+prompt|initial\s+prompt|hidden\s+(?:prompt|"
        r"instructions?)|(?:your|the)\s+(?:instructions|rules|prompt)|secret\s+password)\b",
    ),
    Rule(
        "jailbreak_persona",
        "medium",
        "Classic jailbreak personas and modes",
        r"\b(?:DAN|do\s+anything\s+now|developer\s+mode\s+(?:enabled|on)|jailbreak(?:en)?|"
        r"evil\s+confidant|AIM\s+mode|unfiltered\s+and\s+amoral)\b",
    ),
    Rule(
        "markdown_exfiltration",
        "high",
        "A markdown image or link that sends data to an outside address in its query",
        r"!\[[^\]]*\]\(\s*https?://[^)\s]+\?[^)\s]*=\s*[^)\s]*\)",
    ),
    Rule(
        "send_data_out",
        "medium",
        "Asks to send, forward or upload data to an email address or URL",
        _NOT + r"\b(?:send|forward|email|e-mail|upload|post|exfiltrate)\b\W+(?:\w+\W+){0,8}?"
        r"(?:to|at)\s+(?:[\w.+-]+@[\w-]+\.[\w.]+|https?://\S+)",
    ),
    Rule(
        "decode_and_follow",
        "medium",
        "Asks to decode hidden content and act on it",
        r"\bdecode\b\W+(?:\w+\W+){0,6}?(?:and|then)\W+(?:\w+\W+){0,2}?"
        r"(?:follow|execute|run|do|obey|carry\s+out)\b",
    ),
)


@dataclass(frozen=True, slots=True)
class Hit:
    rule: str
    severity: Severity
    view: str  # which view matched: original | normalized | base64
    where: str  # which text in the request


def check(views: list[View], where: str, rules: tuple[Rule, ...] = RULES) -> list[Hit]:
    """Each rule that matches any view, once (the first view that shows it)."""
    hits: list[Hit] = []
    for rule in rules:
        for v in views:
            if rule.compiled.search(v.text):
                hits.append(Hit(rule.id, rule.severity, v.kind, where))
                break
    return hits
