"""The request check: views of each text, rules, the optional classifier, then the policy.

Only text the deployment doesn't control is checked by default: user messages and tool
results. System and developer prompts are the deployment's own; checking them would block
legitimate prompts such as "never reveal the system prompt".
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

import anyio

from .apis import Api, Json, Text
from .config import Config
from .normalize import views
from .rules import RULES, Hit, Rule, check

CHECKED_ROLES = ("user", "tool")

Scorer = Callable[[Sequence[str]], list[float]]


@dataclass(slots=True)
class Decision:
    action: str = "allow"  # allow | block
    hits: list[Hit] = field(default_factory=list[Hit])
    score: float | None = None  # highest classifier score over the checked texts
    reason: str = ""
    error: str = ""
    checked: int = 0  # how many texts were checked
    prompt_hash: str = ""

    def details(self) -> Json:
        out: Json = {"rules": sorted({h.rule for h in self.hits})}
        if self.score is not None:
            out["score"] = round(self.score, 3)
        return out


def prompt_hash(texts: Sequence[Text]) -> str:
    h = hashlib.sha256()
    for t in texts:
        h.update(t.role.encode() + b"\0" + t.text.encode() + b"\0")
    return h.hexdigest()[:32]


class Guard:
    def __init__(
        self,
        cfg: Config,
        *,
        rules: tuple[Rule, ...] = RULES,
        scorer: Scorer | None = None,
        roles: tuple[str, ...] = CHECKED_ROLES,
    ) -> None:
        self.cfg = cfg
        self.rules = rules
        self.roles = roles
        self.scorer = scorer if scorer is not None else _load_scorer(cfg)

    def decide(self, texts: Sequence[Text]) -> Decision:
        """The decision for one request (synchronous; the classifier may take a while)."""
        pol = self.cfg.policy
        checked = [t for t in texts if t.role in self.roles]
        d = Decision(checked=len(checked), prompt_hash=prompt_hash(checked))
        try:
            if pol.rules != "off":
                for t in checked:
                    d.hits += check(views(t.text), t.where, self.rules)
            if self.scorer is not None and checked:
                d.score = max(self.scorer([t.text for t in checked]))
        except Exception as e:
            d.error = f"{type(e).__name__}: {e}"
            if pol.on_error == "block":
                d.action, d.reason = "block", "detector_error"
            return d
        if pol.rules == "block" and any(h.severity == "high" for h in d.hits):
            d.action, d.reason = "block", "rule"
        elif (
            pol.classifier_threshold is not None
            and d.score is not None
            and d.score >= pol.classifier_threshold
        ):
            d.action, d.reason = "block", "classifier"
        return d

    async def check(self, api: Api, body: Json, state: Json) -> Json | None:
        texts = api.texts(body)
        d = await anyio.to_thread.run_sync(self.decide, texts)
        state["guard"] = d
        if d.action != "block":
            return None
        if d.reason == "detector_error":
            msg = "Blocked by Mobius Guard: the request could not be checked."
        elif d.reason == "classifier":
            msg = "Blocked by Mobius Guard: the prompt looks like an injection attempt."
        else:
            rules = ", ".join(sorted({h.rule for h in d.hits if h.severity == "high"}))
            msg = f"Blocked by Mobius Guard: the prompt matched {rules}."
        return {"status": 403, "message": msg, "code": "prompt_blocked", "details": d.details()}


def _load_scorer(cfg: Config) -> Scorer | None:
    name = cfg.policy.classifier
    if not name:
        return None
    from .classifier import HF_MODELS, HFClassifier

    if name not in HF_MODELS:
        raise ValueError(f"unknown classifier {name!r}; choose from {sorted(HF_MODELS)}")
    model: Any = HFClassifier(HF_MODELS[name])
    return model.score_texts  # type: ignore[no-any-return]
