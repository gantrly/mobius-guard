"""The hooks a real deployment runs: the guard on requests, redaction on replies."""

from __future__ import annotations

import time
from collections.abc import AsyncIterator

from starlette.requests import Request

from . import sse
from .apis import Api, Json
from .app import Hooks
from .audit import AuditLog, emit_span, record
from .config import Config
from .guard import Guard
from .outbound import Redactors, patterns_for, redact_body, redact_events


class ProxyHooks(Hooks):
    def __init__(self, cfg: Config, *, guard: Guard | None = None) -> None:
        self.cfg = cfg
        self.guard = guard or Guard(cfg)
        self.patterns = patterns_for(cfg.redaction.exclude)
        self.audit = AuditLog(cfg.audit.path)

    async def check(self, api: Api, body: Json, request: Request, state: Json) -> Json | None:
        state["started_ns"] = time.time_ns()
        if self.cfg.audit.include_text:
            state["texts"] = [t.text for t in api.texts(body) if t.role in self.guard.roles]
        return await self.guard.check(api, body, state)

    def finish(self, api: Api, state: Json) -> None:
        if state.get("finished"):
            return
        state["finished"] = True
        rec = record(state)
        self.audit.write(rec)
        emit_span(rec, int(state.get("started_ns", time.time_ns())))

    def _redactors(self, state: Json) -> Redactors:
        red = state.get("redactors")
        if not isinstance(red, Redactors):
            red = state["redactors"] = Redactors(self.patterns)
        return red

    def rewrite_json(self, api: Api, body: Json, state: Json) -> Json:
        if not self.cfg.redaction.enabled:
            return body
        return redact_body(api, body, self._redactors(state))

    def rewrite_events(
        self, api: Api, events: AsyncIterator[sse.Event], state: Json
    ) -> AsyncIterator[sse.Event]:
        if not self.cfg.redaction.enabled:
            return events
        return redact_events(api, events, self._redactors(state))
