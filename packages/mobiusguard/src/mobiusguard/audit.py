"""The audit log and telemetry: what was decided for each request, never the text by default.

One JSON line per request: when, which API and model, the decision and why (rule IDs,
severity, which view matched), the classifier score, what was redacted (pattern IDs and
counts), timings and a hash of the checked prompt. Prompt text is written only when
``[audit] include_text = true``. API keys are never written.

OpenTelemetry spans (GenAI semantic conventions) are emitted when ``opentelemetry-api`` is
installed (``mobiusguard[otel]``) and an SDK is configured by the host.
"""

from __future__ import annotations

import importlib
import json
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .apis import Json
from .guard import Decision
from .outbound import Redactors

SYSTEM = {"chat": "openai", "responses": "openai", "anthropic": "anthropic"}


def record(state: Json) -> Json:
    """The audit record for one request, from the state the handler collected."""
    d = state.get("guard")
    red = state.get("redactors")
    out: Json = {
        "time": datetime.now(UTC).isoformat(timespec="milliseconds"),
        "api": state.get("api"),
        "model": state.get("model", ""),
        "stream": bool(state.get("stream")),
        "decision": state.get("decision", "allow"),
        "ms": round(
            (time.perf_counter() - float(state.get("started", time.perf_counter()))) * 1000, 1
        ),
    }
    if isinstance(d, Decision):
        out["reason"] = d.reason
        out["rules"] = [{"id": h.rule, "severity": h.severity, "view": h.view, "where": h.where}
                        for h in d.hits]  # fmt: skip
        out["score"] = None if d.score is None else round(d.score, 4)
        out["checked"] = d.checked
        out["prompt_sha256"] = d.prompt_hash
        if d.error:
            out["error"] = d.error
    if isinstance(red, Redactors):
        out["redacted"] = dict(red.found)
    for key in ("upstream_status", "upstream_error"):
        if key in state:
            out[key] = state[key]
    if "texts" in state:
        out["texts"] = state["texts"]
    return out


class AuditLog:
    def __init__(self, path: str) -> None:
        self.path = Path(path) if path else None
        self._lock = threading.Lock()

    def write(self, rec: Json) -> None:
        if self.path is None:
            return
        line = json.dumps(rec, ensure_ascii=False, default=str) + "\n"
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line)


def emit_span(rec: Json, started_ns: int) -> None:
    """A span for the request, if OpenTelemetry is installed; otherwise nothing."""
    try:
        trace: Any = importlib.import_module("opentelemetry.trace")
    except ImportError:
        return
    tracer: Any = trace.get_tracer("mobiusguard")
    api = str(rec.get("api", ""))
    span: Any = tracer.start_span(f"mobiusguard {api}", start_time=started_ns)
    attrs: Json = {
        "gen_ai.operation.name": "chat",
        "gen_ai.system": SYSTEM.get(api, api),
        "gen_ai.request.model": rec.get("model", ""),
        "mobiusguard.decision": rec.get("decision", ""),
        "mobiusguard.rules": [r["id"] for r in rec.get("rules", [])],
        "mobiusguard.redacted": sum(rec.get("redacted", {}).values()),
    }
    if rec.get("score") is not None:
        attrs["mobiusguard.score"] = rec["score"]
    if "upstream_status" in rec:
        attrs["http.response.status_code"] = rec["upstream_status"]
    for k, v in attrs.items():
        span.set_attribute(k, v)
    span.end()
