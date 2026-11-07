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

# Per text, an attack score, or (attack, harmful) from a model with both outputs (Fortress).
Score = float | tuple[float, float]
Scorer = Callable[[Sequence[str]], Sequence[Score]]


@dataclass(slots=True)
class Decision:
    action: str = "allow"  # allow | block
    hits: list[Hit] = field(default_factory=list[Hit])
    score: float | None = None  # highest attack score over the checked texts
    harmful: float | None = None  # highest harmful-request score (Fortress only)
    flagged: list[str] = field(default_factory=list[str])  # over a threshold: classifier, harmful
    reason: str = ""
    error: str = ""
    checked: int = 0  # how many texts were checked
    prompt_hash: str = ""

    def details(self) -> Json:
        out: Json = {"rules": sorted({h.rule for h in self.hits})}
        if self.score is not None:
            out["score"] = round(self.score, 3)
        if self.harmful is not None:
            out["harmful"] = round(self.harmful, 3)
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
        thresholds: dict[str, float] | None = None,
        roles: tuple[str, ...] = CHECKED_ROLES,
    ) -> None:
        self.cfg = cfg
        self.rules = rules
        self.roles = roles
        if scorer is None:
            scorer, thresholds = _load_scorer(cfg)
        self.scorer = scorer
        pol, own = cfg.policy, thresholds or {}
        # A threshold in the config wins; otherwise the model's own; a model without one only
        # logs scores.
        self.attack_threshold = (
            pol.classifier_threshold if pol.classifier_threshold is not None else own.get("attack")
        )
        self.harmful_threshold = (
            pol.harmful_threshold if pol.harmful_threshold is not None else own.get("harmful")
        )

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
                scores = self.scorer([t.text for t in checked])
                d.score = max(s[0] if isinstance(s, tuple) else s for s in scores)
                pairs = [s[1] for s in scores if isinstance(s, tuple)]
                if pairs and pol.harmful != "off":
                    d.harmful = max(pairs)
        except Exception as e:
            d.error = f"{type(e).__name__}: {e}"
            if pol.on_error == "block":
                d.action, d.reason = "block", "detector_error"
            return d
        attack_th, harmful_th = self.attack_threshold, self.harmful_threshold
        if attack_th is not None and d.score is not None and d.score >= attack_th:
            d.flagged.append("classifier")
        if harmful_th is not None and d.harmful is not None and d.harmful >= harmful_th:
            d.flagged.append("harmful")
        if pol.rules == "block" and any(h.severity == "high" for h in d.hits):
            d.action, d.reason = "block", "rule"
        elif "classifier" in d.flagged and pol.classifier_action == "block":
            d.action, d.reason = "block", "classifier"
        elif "harmful" in d.flagged and pol.harmful == "block":
            d.action, d.reason = "block", "harmful"
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
        elif d.reason == "harmful":
            msg = "Blocked by Mobius Guard: the prompt asks for harmful content."
        else:
            rules = ", ".join(sorted({h.rule for h in d.hits if h.severity == "high"}))
            msg = f"Blocked by Mobius Guard: the prompt matched {rules}."
        return {"status": 403, "message": msg, "code": "prompt_blocked", "details": d.details()}


def _load_scorer(cfg: Config) -> tuple[Scorer | None, dict[str, float]]:
    """The configured classifier's scorer and its own thresholds (none for the published
    classifiers, which only log scores until ``classifier_threshold`` is set)."""
    name = cfg.policy.classifier
    if not name:
        return None, {}
    from .classifier import HF_MODELS, ONNX_MODELS, HFClassifier, OnnxClassifier

    if name in ONNX_MODELS:
        onnx = OnnxClassifier(ONNX_MODELS[name], directory=cfg.policy.classifier_dir)
        return onnx.score_texts, onnx.thresholds
    if name not in HF_MODELS:
        known = sorted([*ONNX_MODELS, *HF_MODELS])
        raise ValueError(f"unknown classifier {name!r}; choose from {known}")
    model: Any = HFClassifier(HF_MODELS[name])
    return model.score_texts, {}
