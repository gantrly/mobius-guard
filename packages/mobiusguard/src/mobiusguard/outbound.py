"""Redaction on the way back, for each API's replies, streamed or not (decision 0010).

Each text the model writes gets its own streaming redactor: per choice in Chat Completions,
per output item and content part in Responses, per content block in Anthropic Messages, and
separately for tool-call arguments. Whatever a redactor still holds when its text ends is
sent in one extra delta event just before the event that ends it. Event framing, IDs and
every other field pass through unchanged.

Not redacted: Anthropic "thinking" blocks, which carry a signature that a change would
break, and reasoning content that providers return encrypted.
"""

from __future__ import annotations

import copy
import json
from collections import Counter
from collections.abc import AsyncIterator, Callable, Sequence
from typing import Any, cast

from mobiusguard_redact import Pattern, StreamRedactor, default_patterns

from . import sse
from .apis import Api, Json

Key = tuple[Any, ...]


class Redactors:
    """One streaming redactor per text being written, and the counts of what they found."""

    def __init__(self, patterns: Sequence[Pattern]) -> None:
        self.patterns = patterns
        self.live: dict[Key, StreamRedactor] = {}
        self.found: Counter[str] = Counter()

    def feed(self, key: Key, text: str) -> str:
        r = self.live.get(key)
        if r is None:
            r = self.live[key] = StreamRedactor(self.patterns)
        return r.feed(text)

    def flush(self, key: Key) -> str:
        r = self.live.pop(key, None)
        if r is None:
            return ""
        tail = r.flush()
        self.found.update(f.pattern_id for f in r.findings)
        return tail

    def whole(self, text: str) -> str:
        r = StreamRedactor(self.patterns)
        out = r.feed(text) + r.flush()
        self.found.update(f.pattern_id for f in r.findings)
        return out

    def open_keys(self, prefix: Callable[[Key], bool] = lambda _: True) -> list[Key]:
        return [k for k in self.live if prefix(k)]


def _d(v: object) -> Json:
    return cast("Json", v) if isinstance(v, dict) else {}


def _l(v: object) -> list[Any]:
    return cast("list[Any]", v) if isinstance(v, list) else []


def _redact_strings(value: Any, red: Redactors) -> Any:
    """Every string inside a JSON value (tool inputs given as objects)."""
    if isinstance(value, str):
        return red.whole(value)
    if isinstance(value, list):
        return [_redact_strings(v, red) for v in cast("list[Any]", value)]
    if isinstance(value, dict):
        return {k: _redact_strings(v, red) for k, v in cast("Json", value).items()}
    return value


# ------------------------------------------------------------------------------ whole replies


def redact_body(api: Api, body: Json, red: Redactors) -> Json:
    out = copy.deepcopy(body)
    if api.name == "chat":
        for choice in _l(out.get("choices")):
            msg = _d(_d(choice).get("message"))
            if isinstance(msg.get("content"), str):
                msg["content"] = red.whole(msg["content"])
            for call in _l(msg.get("tool_calls")):
                fn = _d(_d(call).get("function"))
                if isinstance(fn.get("arguments"), str):
                    fn["arguments"] = red.whole(fn["arguments"])
    elif api.name == "responses":
        _redact_response_object(out, red)
    else:
        for block in _l(out.get("content")):
            _redact_anthropic_block(_d(block), red)
    return out


def _redact_response_item(item: Json, red: Redactors) -> None:
    if item.get("type") == "function_call" and isinstance(item.get("arguments"), str):
        item["arguments"] = red.whole(item["arguments"])
    for part in _l(item.get("content")):
        p = _d(part)
        if p.get("type") == "output_text" and isinstance(p.get("text"), str):
            p["text"] = red.whole(p["text"])


def _redact_response_object(resp: Json, red: Redactors) -> None:
    for item in _l(resp.get("output")):
        _redact_response_item(_d(item), red)
    if isinstance(resp.get("output_text"), str):
        resp["output_text"] = red.whole(resp["output_text"])


def _redact_anthropic_block(block: Json, red: Redactors) -> None:
    if block.get("type") == "text" and isinstance(block.get("text"), str):
        block["text"] = red.whole(block["text"])
    elif block.get("type") == "tool_use" and "input" in block:
        block["input"] = _redact_strings(block["input"], red)


# ------------------------------------------------------------------------------ streams


def _with_data(ev: sse.Event, data: Json) -> sse.Event:
    return sse.Event(json.dumps(data, ensure_ascii=False, separators=(",", ":")), ev.event,
                     ev.extra)  # fmt: skip


async def redact_events(
    api: Api, events: AsyncIterator[sse.Event], red: Redactors
) -> AsyncIterator[sse.Event]:
    rewrite = {"chat": _chat_event, "responses": _responses_event, "anthropic": _anthropic_event}
    step = rewrite[api.name]
    last: Json = {}
    async for ev in events:
        if ev.data == "[DONE]":
            for out in _chat_flush_all(last, red):
                yield out
            yield ev
            continue
        try:
            data = json.loads(ev.data) if ev.data else None
        except json.JSONDecodeError:
            data = None
        if not isinstance(data, dict):
            yield ev
            continue
        data_d = cast("Json", data)
        if api.name == "chat":
            last = data_d
        for out in step(ev, data_d, red):
            yield out
    # A stream that ends without its closing events still releases what was held.
    if api.name == "chat":
        for out in _chat_flush_all(last, red):
            yield out
    else:
        for out in _final_flush(api, red):
            yield out


def _final_flush(api: Api, red: Redactors) -> list[sse.Event]:
    out: list[sse.Event] = []
    for key in red.open_keys():
        tail = red.flush(key)
        if not tail:
            continue
        if api.name == "responses" and key[0] == "text":
            kind = "response.output_text.delta"
            data: Json = {"type": kind, "item_id": key[1], "content_index": key[2], "delta": tail}
        elif api.name == "responses":
            kind = "response.function_call_arguments.delta"
            data = {"type": kind, "item_id": key[1], "delta": tail}
        else:
            kind = "content_block_delta"
            dt, field = ("text_delta", "text") if key[0] == "text" else ("input_json_delta",
                                                                        "partial_json")  # fmt: skip
            data = {"type": kind, "index": key[1], "delta": {"type": dt, field: tail}}
        out.append(sse.Event(json.dumps(data, ensure_ascii=False, separators=(",", ":")), kind))
    return out


def _chat_event(ev: sse.Event, data: Json, red: Redactors) -> list[sse.Event]:
    before: list[sse.Event] = []
    changed = False
    for choice in _l(data.get("choices")):
        c = _d(choice)
        i = c.get("index", 0)
        delta = _d(c.get("delta"))
        if isinstance(delta.get("content"), str):
            delta["content"] = red.feed(("content", i), delta["content"])
            changed = True
        for call in _l(delta.get("tool_calls")):
            tc = _d(call)
            fn = _d(tc.get("function"))
            if isinstance(fn.get("arguments"), str):
                fn["arguments"] = red.feed(("args", i, tc.get("index", 0)), fn["arguments"])
                changed = True
        if c.get("finish_reason"):
            before += _chat_flush_choice(data, i, red)
    return [*before, _with_data(ev, data) if changed or before else ev]


def _chat_flush_choice(template: Json, i: Any, red: Redactors) -> list[sse.Event]:
    """Extra delta events carrying what choice ``i``'s redactors still hold."""
    out: list[sse.Event] = []
    for key in red.open_keys(lambda k: k[0] in ("content", "args") and k[1] == i):
        tail = red.flush(key)
        if not tail:
            continue
        if key[0] == "content":
            delta: Json = {"content": tail}
        else:
            delta = {"tool_calls": [{"index": key[2], "function": {"arguments": tail}}]}
        data = {k: v for k, v in template.items() if k != "choices" and k != "usage"}
        data["choices"] = [{"index": i, "delta": delta, "finish_reason": None}]
        out.append(sse.Event(json.dumps(data, ensure_ascii=False, separators=(",", ":"))))
    return out


def _chat_flush_all(template: Json, red: Redactors) -> list[sse.Event]:
    out: list[sse.Event] = []
    for i in sorted({k[1] for k in red.open_keys()}, key=str):
        out += _chat_flush_choice(template, i, red)
    return out


def _responses_event(ev: sse.Event, data: Json, red: Redactors) -> list[sse.Event]:
    kind = str(data.get("type", ev.event))
    if kind == "response.output_text.delta":
        key = ("text", data.get("item_id"), data.get("content_index", 0))
        data["delta"] = red.feed(key, str(data.get("delta", "")))
        return [_with_data(ev, data)]
    if kind == "response.function_call_arguments.delta":
        data["delta"] = red.feed(("args", data.get("item_id")), str(data.get("delta", "")))
        return [_with_data(ev, data)]
    if kind == "response.output_text.done":
        key = ("text", data.get("item_id"), data.get("content_index", 0))
        tail = red.flush(key)
        if isinstance(data.get("text"), str):
            data["text"] = red.whole(data["text"])
        extra: list[sse.Event] = []
        if tail:
            delta = {k: data[k] for k in ("item_id", "output_index", "content_index")
                     if k in data}  # fmt: skip
            extra.append(sse.Event(
                json.dumps({"type": "response.output_text.delta", **delta, "delta": tail},
                           ensure_ascii=False, separators=(",", ":")),
                "response.output_text.delta", ev.extra))  # fmt: skip
        return [*extra, _with_data(ev, data)]
    if kind == "response.function_call_arguments.done":
        tail = red.flush(("args", data.get("item_id")))
        if isinstance(data.get("arguments"), str):
            data["arguments"] = red.whole(data["arguments"])
        extra: list[sse.Event] = []
        if tail:
            extra.append(sse.Event(
                json.dumps({"type": "response.function_call_arguments.delta",
                            **{k: data[k] for k in ("item_id", "output_index") if k in data},
                            "delta": tail}, ensure_ascii=False, separators=(",", ":")),
                "response.function_call_arguments.delta", ev.extra))  # fmt: skip
        return [*extra, _with_data(ev, data)]
    # Events that repeat whole objects: parts, items and the final response.
    changed = False
    if isinstance(data.get("part"), dict):
        part = _d(data["part"])
        if part.get("type") == "output_text" and isinstance(part.get("text"), str):
            part["text"] = red.whole(part["text"])
            changed = True
    if isinstance(data.get("item"), dict):
        _redact_response_item(_d(data["item"]), red)
        changed = True
    if isinstance(data.get("response"), dict):
        _redact_response_object(_d(data["response"]), red)
        changed = True
    return [_with_data(ev, data) if changed else ev]


def _anthropic_event(ev: sse.Event, data: Json, red: Redactors) -> list[sse.Event]:
    kind = str(data.get("type", ev.event))
    if kind == "content_block_delta":
        delta = _d(data.get("delta"))
        i = data.get("index", 0)
        if delta.get("type") == "text_delta" and isinstance(delta.get("text"), str):
            delta["text"] = red.feed(("text", i), delta["text"])
            return [_with_data(ev, data)]
        if delta.get("type") == "input_json_delta" and isinstance(delta.get("partial_json"), str):
            delta["partial_json"] = red.feed(("json", i), delta["partial_json"])
            return [_with_data(ev, data)]
        return [ev]  # thinking and signature deltas are left alone
    if kind == "content_block_stop":
        i = data.get("index", 0)
        extra: list[sse.Event] = []
        for key, delta_type, field in (("text", "text_delta", "text"),
                                       ("json", "input_json_delta", "partial_json")):  # fmt: skip
            tail = red.flush((key, i))
            if tail:
                extra.append(sse.Event(
                    json.dumps({"type": "content_block_delta", "index": i,
                                "delta": {"type": delta_type, field: tail}},
                               ensure_ascii=False, separators=(",", ":")),
                    "content_block_delta", ev.extra))  # fmt: skip
        return [*extra, ev]
    if kind == "content_block_start" and isinstance(data.get("content_block"), dict):
        block = _d(data["content_block"])
        if block.get("type") == "text" and block.get("text"):
            block["text"] = red.feed(("text", data.get("index", 0)), str(block["text"]))
            return [_with_data(ev, data)]
    return [ev]


def patterns_for(exclude: Sequence[str]) -> tuple[Pattern, ...]:
    return default_patterns(exclude=exclude)
