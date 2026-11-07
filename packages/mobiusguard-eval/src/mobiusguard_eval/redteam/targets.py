"""What the red-team runner attacks, and what came back (decision 0014).

- :class:`GuardTarget`: a :class:`~mobiusguard.guard.Guard` built from any config, run in
  this process with no network. The loop's default.
- :class:`HttpTarget`: a running proxy, through OpenAI Chat Completions, OpenAI Responses or
  Anthropic Messages, so users can red-team their own deployment. An allowed request goes on
  to the proxy's upstream model, so each one may cost a model call; requests ask for one
  output token (Responses: 16, its minimum).

An attempt is a list of messages, ``{"role": ..., "content": ...}``, with roles ``system``,
``user``, ``assistant`` and ``tool``. A ``tool`` message is text the model reads back from a
tool (an email, a web page, a document): each target turns it into that API's own
tool-call/tool-result pair, which is where indirect injections arrive.

An attempt **gets through** when the guard allows it. What the model would reply is not
judged: the runner tests the firewall, not the model.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol, cast

import httpx
import mobiusguard
from mobiusguard.apis import APIS, Api, Json
from mobiusguard.config import load
from mobiusguard.guard import Decision, Guard
from mobiusguard.rules import RULES

ApiName = Literal["chat", "responses", "anthropic"]
Message = Mapping[str, str]
API_NAMES: tuple[ApiName, ...] = ("chat", "responses", "anthropic")
ROLES = ("system", "user", "assistant", "tool")
TOOL_NAME = "read_document"  # the tool a "tool" message comes back from

# The proxy's block messages (mobiusguard.guard.Guard.check), by reason. The 403 body says
# which rules matched but not why the request was blocked, so the HTTP target reads it from
# the message; a test checks this table against the proxy itself.
REASON_BY_MESSAGE = {
    "the prompt looks like an injection attempt": "classifier",
    "the prompt asks for harmful content": "harmful",
    "the request could not be checked": "detector_error",
    "the prompt matched": "rule",
}


@dataclass(frozen=True, slots=True)
class Verdict:
    """What a target did with one attempt.

    ``blocked`` with ``reason`` rule, classifier, harmful or detector_error. An allowed
    attempt has ``reason`` "" unless the guard failed open (``detector_error``).
    ``flagged`` lists scores over a threshold that only logs. ``error`` means the target
    gave no verdict at all (network failure, an unexpected status): such an attempt counts
    neither as caught nor as got through.
    """

    blocked: bool
    reason: str = ""
    rules: tuple[str, ...] = ()
    score: float | None = None
    harmful: float | None = None
    flagged: tuple[str, ...] = ()
    ms: float = 0.0
    error: str = ""

    def to_json(self) -> Json:
        return {
            "blocked": self.blocked,
            "reason": self.reason,
            "rules": list(self.rules),
            "score": self.score,
            "harmful": self.harmful,
            "flagged": list(self.flagged),
            "ms": round(self.ms, 2),
            "error": self.error,
        }


class Target(Protocol):
    name: str

    def info(self) -> dict[str, str]:
        """What a run records about the target, so two runs can be compared."""
        ...

    def send(self, messages: Sequence[Message]) -> Verdict: ...


def _check(messages: Sequence[Message]) -> None:
    if not messages:
        raise ValueError("an attempt needs at least one message")
    for m in messages:
        if m.get("role") not in ROLES:
            raise ValueError(f"role must be one of {ROLES}, not {m.get('role')!r}")
        if not isinstance(m.get("content"), str):
            raise ValueError("content must be a string")


def request_body(api: ApiName, messages: Sequence[Message], model: str = "redteam") -> Json:
    """The request an SDK would send for this attempt, in the API's own format."""
    _check(messages)
    if api == "chat":
        out: list[Json] = []
        for i, m in enumerate(messages):
            if m["role"] == "tool":
                call = f"call_rt_{i}"
                out.append({"role": "assistant", "content": None, "tool_calls": [
                    {"id": call, "type": "function",
                     "function": {"name": TOOL_NAME, "arguments": "{}"}}]})  # fmt: skip
                out.append({"role": "tool", "tool_call_id": call, "content": m["content"]})
            else:
                out.append({"role": m["role"], "content": m["content"]})
        return {"model": model, "messages": out, "max_tokens": 1}
    if api == "responses":
        items: list[Json] = []
        for i, m in enumerate(messages):
            if m["role"] == "tool":
                call = f"call_rt_{i}"
                items.append({"type": "function_call", "call_id": call, "name": TOOL_NAME,
                              "arguments": "{}"})  # fmt: skip
                items.append({"type": "function_call_output", "call_id": call,
                              "output": m["content"]})  # fmt: skip
            else:
                items.append({"role": m["role"], "content": m["content"]})
        return {"model": model, "input": items, "max_output_tokens": 16}
    system = [m["content"] for m in messages if m["role"] == "system"]
    msgs: list[Json] = []
    for i, m in enumerate(messages):
        if m["role"] == "tool":
            use = f"toolu_rt_{i}"
            msgs.append({"role": "assistant", "content": [
                {"type": "tool_use", "id": use, "name": TOOL_NAME, "input": {}}]})  # fmt: skip
            msgs.append({"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": use,
                 "content": [{"type": "text", "text": m["content"]}]}]})  # fmt: skip
        elif m["role"] != "system":
            msgs.append({"role": m["role"], "content": m["content"]})
    body: Json = {"model": model, "messages": msgs, "max_tokens": 1}
    if system:
        body["system"] = "\n\n".join(system)
    return body


def _api(name: ApiName) -> Api:
    return next(a for a in APIS if a.name == name)


def verdict_from_decision(d: Decision, ms: float = 0.0) -> Verdict:
    blocked = d.action == "block"
    reason = d.reason if blocked else ("detector_error" if d.error else "")
    return Verdict(
        blocked=blocked,
        reason=reason,
        rules=tuple(sorted({h.rule for h in d.hits})),
        score=d.score,
        harmful=d.harmful,
        flagged=tuple(d.flagged),
        ms=ms,
    )


def _rules_hash() -> str:
    src = "\n".join(f"{r.id}|{r.severity}|{r.pattern}" for r in RULES)
    return hashlib.sha256(src.encode()).hexdigest()[:16]


@dataclass
class GuardTarget:
    """A guard in this process. ``api`` picks the request format the texts are read from."""

    guard: Guard
    api: ApiName = "chat"
    name: str = "guard"
    config: str = ""

    @classmethod
    def from_config(cls, path: str | Path | None, *, api: ApiName = "chat") -> GuardTarget:
        cfg = load(Path(path) if path else None)
        return cls(Guard(cfg), api=api, config=str(path or ""))

    def info(self) -> dict[str, str]:
        pol = self.guard.cfg.policy
        return {
            "target": "guard",
            "api": self.api,
            "config": self.config,
            "mobiusguard": mobiusguard.__version__,
            "rules": _rules_hash(),
            "rules_action": pol.rules,
            "classifier": pol.classifier,
            "classifier_action": pol.classifier_action,
            "attack_threshold": str(self.guard.attack_threshold),
            "harmful": pol.harmful,
            "harmful_threshold": str(self.guard.harmful_threshold),
        }

    def send(self, messages: Sequence[Message]) -> Verdict:
        texts = _api(self.api).texts(request_body(self.api, messages))
        t0 = time.perf_counter()
        d = self.guard.decide(texts)
        return verdict_from_decision(d, (time.perf_counter() - t0) * 1000)


def _reason(message: str) -> str:
    low = message.lower()
    return next((r for key, r in REASON_BY_MESSAGE.items() if key in low), "")


def _num(v: object) -> float | None:
    return float(v) if isinstance(v, int | float) and not isinstance(v, bool) else None


def _dict(v: object) -> Json:
    return cast("Json", v) if isinstance(v, dict) else {}


def verdict_from_response(status: int, body: object, ms: float = 0.0) -> Verdict:
    """A proxy's answer to one request: 2xx allowed, 403 prompt_blocked blocked, else error."""
    if 200 <= status < 300:
        return Verdict(blocked=False, ms=ms)
    b = _dict(body)
    err = _dict(b.get("error"))
    mg = _dict(err.get("mobiusguard"))
    code = err.get("code") or mg.get("code")
    if status == 403 and code == "prompt_blocked":
        rules = mg.get("rules")
        return Verdict(
            blocked=True,
            reason=_reason(str(err.get("message", ""))),
            rules=tuple(sorted(str(r) for r in cast("list[object]", rules)))
            if isinstance(rules, list)
            else (),
            score=_num(mg.get("score")),
            harmful=_num(mg.get("harmful")),
            ms=ms,
        )
    text = err.get("message") or (json.dumps(b)[:200] if b else "")
    return Verdict(blocked=False, ms=ms, error=f"HTTP {status}: {text}"[:300])


@dataclass
class HttpTarget:
    """A running proxy at ``base_url`` (without /v1), reached through one of its APIs.

    ``requests`` counts what was sent, so a run can say how many reached the upstream model.
    Pass ``client`` to use your own ``httpx.Client`` (tests do).
    """

    base_url: str
    api: ApiName = "chat"
    model: str = "redteam"
    key: str = "redteam"
    timeout: float = 60.0
    client: httpx.Client | None = None
    name: str = "http"
    requests: int = field(default=0, init=False)
    allowed: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        self._http = self.client or httpx.Client(
            base_url=self.base_url.rstrip("/"), timeout=self.timeout
        )

    def info(self) -> dict[str, str]:
        return {"target": "http", "url": self.base_url, "api": self.api, "model": self.model}

    def _headers(self) -> dict[str, str]:
        if self.api == "anthropic":
            return {"x-api-key": self.key, "anthropic-version": "2023-06-01"}
        return {"authorization": f"Bearer {self.key}"}

    def send(self, messages: Sequence[Message]) -> Verdict:
        body = request_body(self.api, messages, self.model)
        self.requests += 1
        t0 = time.perf_counter()
        try:
            r = self._http.post(_api(self.api).path, json=body, headers=self._headers())
        except httpx.HTTPError as e:
            ms = (time.perf_counter() - t0) * 1000
            return Verdict(blocked=False, ms=ms, error=f"{type(e).__name__}: {e}"[:300])
        ms = (time.perf_counter() - t0) * 1000
        try:
            parsed: Any = r.json()
        except ValueError:
            parsed = {}
        v = verdict_from_response(r.status_code, parsed, ms)
        if not v.blocked and not v.error:
            self.allowed += 1
        return v

    def close(self) -> None:
        self._http.close()
