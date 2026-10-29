"""Part 3c: replies are redacted in each API's format, however the stream is split."""

from __future__ import annotations

import asyncio
import json
import random
from collections.abc import AsyncIterator, Sequence
from typing import Any

import httpx
import pytest
from mobiusguard import sse
from mobiusguard.apis import AnthropicMessages, ChatCompletions, Responses
from mobiusguard.app import create_app
from mobiusguard.config import Audit, Config, Upstream
from mobiusguard.hooks import ProxyHooks
from mobiusguard.outbound import Redactors, patterns_for, redact_body, redact_events
from mobiusguard_redact import redact
from starlette.testclient import TestClient

KEY = "AKIAQWERTYUIOPASDFGH"
REPLY = f"Use key {KEY} and postgres://app:Sup3rS3cret!@db:5432/prod then restart."
EXPECTED = redact(REPLY)
ARGS = json.dumps({"token": "ghp_" + "Zx9Q" * 9, "repo": "x"})
PATTERNS = patterns_for(())


def pieces(text: str, rng: random.Random) -> list[str]:
    out: list[str] = []
    i = 0
    while i < len(text):
        n = rng.randint(1, 9)
        out.append(text[i : i + n])
        i += n
    return out


async def _aiter(events: Sequence[sse.Event]) -> AsyncIterator[sse.Event]:
    for ev in events:
        yield ev


def run(api: Any, events: list[sse.Event]) -> tuple[list[sse.Event], Redactors]:
    red = Redactors(PATTERNS)

    async def go() -> list[sse.Event]:
        return [ev async for ev in redact_events(api, _aiter(events), red)]

    return asyncio.run(go()), red


def data(ev: sse.Event) -> dict[str, Any]:
    return json.loads(ev.data)


def chat_stream(text_parts: list[str], arg_parts: list[str]) -> list[sse.Event]:
    evs = [
        sse.Event(json.dumps({"id": "c", "choices": [{"index": 0, "delta": {"content": p}}]}))
        for p in text_parts
    ]
    evs += [
        sse.Event(
            json.dumps(
                {
                    "id": "c",
                    "choices": [
                        {
                            "index": 0,
                            "delta": {"tool_calls": [{"index": 0, "function": {"arguments": p}}]},
                        }
                    ],
                }
            )
        )
        for p in arg_parts
    ]
    evs.append(
        sse.Event(
            json.dumps({"id": "c", "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]})
        )
    )
    evs.append(sse.Event("[DONE]"))
    return evs


@pytest.mark.parametrize("seed", range(25))
def test_chat_stream(seed: int) -> None:
    rng = random.Random(seed)
    out, red = run(ChatCompletions(), chat_stream(pieces(REPLY, rng), pieces(ARGS, rng)))
    assert out[-1].data == "[DONE]"
    text = args = ""
    finish_seen = False
    for ev in out[:-1]:
        for c in data(ev)["choices"]:
            assert not finish_seen, "nothing may follow the finishing event"
            text += c["delta"].get("content", "")
            for tc in c["delta"].get("tool_calls", []):
                args += tc["function"]["arguments"]
            finish_seen = c.get("finish_reason") == "stop"
    assert text == EXPECTED
    assert KEY not in text
    assert args == redact(ARGS)
    assert red.found["aws_access_key_id"] == 1


def responses_stream(text_parts: list[str], arg_parts: list[str]) -> list[sse.Event]:
    def ev(kind: str, **fields: Any) -> sse.Event:
        return sse.Event(json.dumps({"type": kind, **fields}), kind)

    evs = [
        ev("response.output_text.delta", item_id="m1", output_index=0, content_index=0, delta=p)
        for p in text_parts
    ]
    evs.append(
        ev("response.output_text.done", item_id="m1", output_index=0, content_index=0, text=REPLY)
    )
    evs += [
        ev("response.function_call_arguments.delta", item_id="f1", output_index=1, delta=p)
        for p in arg_parts
    ]
    evs.append(ev("response.function_call_arguments.done", item_id="f1", arguments=ARGS))
    evs.append(
        ev(
            "response.completed",
            response={
                "output": [
                    {"type": "message", "content": [{"type": "output_text", "text": REPLY}]},
                    {"type": "function_call", "arguments": ARGS},
                ]
            },
        )
    )
    return evs


@pytest.mark.parametrize("seed", range(25))
def test_responses_stream(seed: int) -> None:
    rng = random.Random(seed)
    out, _ = run(Responses(), responses_stream(pieces(REPLY, rng), pieces(ARGS, rng)))
    events = [data(e) for e in out]
    text = "".join(e["delta"] for e in events if e["type"] == "response.output_text.delta")
    args = "".join(
        e["delta"] for e in events if e["type"] == "response.function_call_arguments.delta"
    )
    done = next(e for e in events if e["type"] == "response.output_text.done")
    final = next(e for e in events if e["type"] == "response.completed")["response"]["output"]
    assert text == done["text"] == final[0]["content"][0]["text"] == EXPECTED
    assert args == final[1]["arguments"] == redact(ARGS)
    assert all(e.event == data(e)["type"] for e in out)


def anthropic_stream(text_parts: list[str], json_parts: list[str]) -> list[sse.Event]:
    def ev(kind: str, **fields: Any) -> sse.Event:
        return sse.Event(json.dumps({"type": kind, **fields}), kind)

    evs = [
        ev("message_start", message={"id": "m"}),
        ev("content_block_start", index=0, content_block={"type": "thinking", "thinking": ""}),
        ev(
            "content_block_delta",
            index=0,
            delta={"type": "thinking_delta", "thinking": f"the key is {KEY}"},
        ),
        ev("content_block_stop", index=0),
        ev("content_block_start", index=1, content_block={"type": "text", "text": ""}),
    ]
    evs += [
        ev("content_block_delta", index=1, delta={"type": "text_delta", "text": p})
        for p in text_parts
    ]
    evs.append(ev("content_block_stop", index=1))
    evs.append(ev("content_block_start", index=2, content_block={"type": "tool_use", "input": {}}))
    evs += [
        ev("content_block_delta", index=2, delta={"type": "input_json_delta", "partial_json": p})
        for p in json_parts
    ]
    evs += [ev("content_block_stop", index=2), ev("message_stop")]
    return evs


@pytest.mark.parametrize("seed", range(25))
def test_anthropic_stream(seed: int) -> None:
    rng = random.Random(seed)
    out, _ = run(AnthropicMessages(), anthropic_stream(pieces(REPLY, rng), pieces(ARGS, rng)))
    events = [data(e) for e in out]
    deltas = [e for e in events if e["type"] == "content_block_delta"]
    text = "".join(e["delta"].get("text", "") for e in deltas if e["index"] == 1)
    js = "".join(e["delta"].get("partial_json", "") for e in deltas if e["index"] == 2)
    assert text == EXPECTED
    assert js == redact(ARGS)
    thinking = next(e for e in deltas if e["index"] == 0)
    assert KEY in thinking["delta"]["thinking"]  # signed thinking is never altered
    # every block's deltas come before its stop event
    for idx in (1, 2):
        stop = next(
            i for i, e in enumerate(events) if e == {"type": "content_block_stop", "index": idx}
        )
        assert all(
            i < stop
            for i, e in enumerate(events)
            if e["type"] == "content_block_delta" and e["index"] == idx
        )


def test_streams_cut_short_still_release_held_text() -> None:
    stream = [sse.Event(json.dumps({"choices": [{"index": 0, "delta": {"content": "id " + KEY}}]}))]
    out, _ = run(ChatCompletions(), stream)
    assert "".join(data(e)["choices"][0]["delta"].get("content", "") for e in out) == redact(
        "id " + KEY
    )


def test_whole_replies_are_redacted_in_each_format() -> None:
    red = Redactors(PATTERNS)
    chat = redact_body(
        ChatCompletions(),
        {
            "choices": [
                {"message": {"content": REPLY, "tool_calls": [{"function": {"arguments": ARGS}}]}}
            ]
        },
        red,
    )
    msg = chat["choices"][0]["message"]
    assert msg["content"] == EXPECTED
    assert msg["tool_calls"][0]["function"]["arguments"] == redact(ARGS)

    resp = redact_body(
        Responses(),
        {"output": [{"type": "message", "content": [{"type": "output_text", "text": REPLY}]}]},
        red,
    )
    assert resp["output"][0]["content"][0]["text"] == EXPECTED

    ant = redact_body(
        AnthropicMessages(),
        {
            "content": [
                {"type": "text", "text": REPLY},
                {"type": "tool_use", "input": {"token": "ghp_" + "Zx9Q" * 9, "n": 3}},
            ]
        },
        red,
    )
    assert ant["content"][0]["text"] == EXPECTED
    assert ant["content"][1]["input"] == {"token": "[REDACTED:github_token]", "n": 3}


def test_through_the_proxy_streamed_and_not() -> None:
    stream = b"".join(e.encode() for e in chat_stream(pieces(REPLY, random.Random(1)), []))

    def upstream(request: httpx.Request) -> httpx.Response:
        if json.loads(request.content).get("stream"):
            return httpx.Response(
                200, content=stream, headers={"content-type": "text/event-stream"}
            )
        return httpx.Response(200, json={"choices": [{"message": {"content": REPLY}}]})

    cfg = Config(openai=Upstream("https://oa.test/v1"), audit=Audit(path=""))
    app = create_app(cfg, hooks=ProxyHooks(cfg), transport=httpx.MockTransport(upstream))
    body = {"model": "m", "messages": [{"role": "user", "content": "hi"}]}
    with TestClient(app) as c:
        whole = c.post("/v1/chat/completions", json=body)
        assert whole.json()["choices"][0]["message"]["content"] == EXPECTED
        with c.stream("POST", "/v1/chat/completions", json={**body, "stream": True}) as r:
            raw = b"".join(r.iter_bytes())

    async def parse() -> list[sse.Event]:
        async def one() -> AsyncIterator[bytes]:
            yield raw

        return [e async for e in sse.parse(one())]

    events = asyncio.run(parse())
    text = "".join(
        c["delta"].get("content", "")
        for e in events
        if e.data != "[DONE]"
        for c in data(e)["choices"]
    )
    assert text == EXPECTED
    assert KEY.encode() not in raw
