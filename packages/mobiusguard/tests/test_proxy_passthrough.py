"""Part 3a: the proxy forwards the three APIs faithfully, against a fake upstream."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from mobiusguard import sse
from mobiusguard.apis import Api, Json
from mobiusguard.app import Hooks, create_app
from mobiusguard.config import Config, Upstream, load
from starlette.requests import Request
from starlette.testclient import TestClient

CHAT_SSE = (
    b'data: {"id":"c1","choices":[{"index":0,"delta":{"role":"assistant","content":"Hel"}}]}\n\n'
    b'data: {"id":"c1","choices":[{"index":0,"delta":{"content":"lo"}}]}\n\n'
    b"data: [DONE]\n\n"
)
ANTHROPIC_SSE = (
    b'event: message_start\ndata: {"type":"message_start","message":{"id":"m1"}}\n\n'
    b'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,'
    b'"delta":{"type":"text_delta","text":"Hi"}}\n\n'
    b'event: message_stop\ndata: {"type":"message_stop"}\n\n'
)


class Upstreams:
    """A fake OpenAI and Anthropic that record what they were sent."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if path.endswith("/models"):
            return httpx.Response(200, json={"data": [{"id": "m"}]})
        body = json.loads(request.content)
        if body.get("model") == "broken":
            return httpx.Response(429, json={"error": {"message": "slow down"}},
                                  headers={"retry-after": "3"})  # fmt: skip
        if body.get("stream"):
            data = ANTHROPIC_SSE if path.endswith("/messages") else CHAT_SSE
            return httpx.Response(200, content=data, headers={"content-type": "text/event-stream",
                                                              "x-request-id": "req-1"})  # fmt: skip
        return httpx.Response(200, json={"id": "x", "path": path},
                              headers={"x-request-id": "req-1", "set-cookie": "a=b"})  # fmt: skip


@pytest.fixture
def up() -> Upstreams:
    return Upstreams()


def client(up: Upstreams, cfg: Config | None = None, hooks: Hooks | None = None) -> TestClient:
    cfg = cfg or Config(openai=Upstream("https://oa.test/v1"),
                        anthropic=Upstream("https://an.test/v1"))  # fmt: skip
    return TestClient(create_app(cfg, hooks=hooks, transport=httpx.MockTransport(up)))


@pytest.fixture
def tc(up: Upstreams) -> Iterator[TestClient]:
    with client(up) as c:
        yield c


def test_chat_is_forwarded_with_the_callers_key_only(tc: TestClient, up: Upstreams) -> None:
    r = tc.post("/v1/chat/completions", json={"model": "m", "messages": []},
                headers={"authorization": "Bearer sk-caller", "cookie": "s=1"})  # fmt: skip
    assert r.status_code == 200
    assert r.json() == {"id": "x", "path": "/v1/chat/completions"}
    assert r.headers["x-request-id"] == "req-1"
    assert "set-cookie" not in r.headers
    sent = up.requests[0]
    assert str(sent.url) == "https://oa.test/v1/chat/completions"
    assert sent.headers["authorization"] == "Bearer sk-caller"
    assert "cookie" not in sent.headers


@pytest.mark.parametrize(("path", "upstream"), [
    ("/v1/responses", "https://oa.test/v1/responses"),
    ("/v1/messages", "https://an.test/v1/messages"),
])  # fmt: skip
def test_responses_and_messages_go_to_their_upstream(
    tc: TestClient, up: Upstreams, path: str, upstream: str
) -> None:
    r = tc.post(path, json={"model": "m"}, headers={"x-api-key": "k", "anthropic-version": "v"})
    assert r.status_code == 200
    assert str(up.requests[0].url) == upstream
    assert up.requests[0].headers["x-api-key"] == "k"


@pytest.mark.parametrize(("path", "expected"), [
    ("/v1/chat/completions", CHAT_SSE),
    ("/v1/messages", ANTHROPIC_SSE),
])  # fmt: skip
def test_streams_pass_through_event_for_event(tc: TestClient, path: str, expected: bytes) -> None:
    with tc.stream("POST", path, json={"model": "m", "stream": True}) as r:
        assert r.headers["content-type"].startswith("text/event-stream")
        body = b"".join(r.iter_bytes())
    assert body == expected


def test_upstream_errors_come_back_as_they_were(tc: TestClient) -> None:
    r = tc.post("/v1/chat/completions", json={"model": "broken"})
    assert r.status_code == 429
    assert r.json() == {"error": {"message": "slow down"}}
    assert r.headers["retry-after"] == "3"


def test_unreachable_upstream_is_a_502_in_the_apis_format(up: Upstreams) -> None:
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route", request=request)

    with TestClient(create_app(Config(), transport=httpx.MockTransport(down))) as c:
        r = c.post("/v1/messages", json={"model": "m"})
    assert r.status_code == 502
    assert r.json()["type"] == "error"
    assert r.json()["error"]["type"] == "api_error"


def test_bad_bodies_are_refused_before_the_upstream(tc: TestClient, up: Upstreams) -> None:
    assert tc.post("/v1/chat/completions", content=b"{not json").status_code == 400
    assert tc.post("/v1/chat/completions", json=[1, 2]).status_code == 400
    assert up.requests == []


def test_body_limit(up: Upstreams) -> None:
    from mobiusguard.config import Limits

    cfg = Config(limits=Limits(max_body_bytes=50))
    with client(up, cfg) as c:
        r = c.post("/v1/chat/completions", json={"model": "m", "messages": ["x" * 100]})
    assert r.status_code == 413
    assert up.requests == []


def test_held_key_and_client_tokens(up: Upstreams, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OA_KEY", "sk-held")
    monkeypatch.setenv("AN_KEY", "an-held")
    cfg = Config(openai=Upstream("https://oa.test/v1", "OA_KEY"),
                 anthropic=Upstream("https://an.test/v1", "AN_KEY"),
                 client_tokens=("tok-1",))  # fmt: skip
    with client(up, cfg) as c:
        assert c.post("/v1/chat/completions", json={"model": "m"}).status_code == 401
        bad = c.post("/v1/messages", json={"model": "m"}, headers={"x-api-key": "nope"})
        assert bad.status_code == 401
        assert bad.json()["error"]["type"] == "authentication_error"
        ok = c.post("/v1/chat/completions", json={"model": "m"},
                    headers={"authorization": "Bearer tok-1"})  # fmt: skip
        assert ok.status_code == 200
        c.post("/v1/messages", json={"model": "m"}, headers={"x-api-key": "tok-1"})
    assert up.requests[0].headers["authorization"] == "Bearer sk-held"  # the token never leaves
    assert up.requests[1].headers["x-api-key"] == "an-held"
    assert "authorization" not in up.requests[1].headers


class Blocker(Hooks):
    async def check(self, api: Api, body: Json, request: Request, state: Json) -> Json | None:
        return {"status": 403, "message": "Blocked by Mobius Guard: rule r1.",
                "code": "prompt_blocked", "details": {"rules": ["r1"]}}  # fmt: skip


@pytest.mark.parametrize("path", ["/v1/chat/completions", "/v1/responses", "/v1/messages"])
def test_a_block_never_reaches_the_upstream(up: Upstreams, path: str) -> None:
    with client(up, hooks=Blocker()) as c:
        r = c.post(path, json={"model": "m"})
    assert r.status_code == 403
    assert up.requests == []
    body: dict[str, Any] = r.json()
    err = body["error"]
    assert err["type"] == "permission_error"
    assert err["mobiusguard"]["rules"] == ["r1"]
    if path == "/v1/messages":
        assert body["type"] == "error"
    else:
        assert err["code"] == "prompt_blocked"


def test_models_and_health(tc: TestClient) -> None:
    assert tc.get("/v1/models").json() == {"data": [{"id": "m"}]}
    assert tc.get("/healthz").json() == {"status": "ok"}
    assert tc.post("/v1/embeddings", json={}).status_code == 404


async def _chunks(data: bytes, size: int) -> AsyncIterator[bytes]:
    for i in range(0, len(data), size):
        yield data[i : i + size]


@pytest.mark.parametrize("size", [1, 2, 3, 7, 64, 10_000])
def test_sse_parse_is_the_same_however_bytes_are_split(size: int) -> None:
    import asyncio

    async def collect() -> list[sse.Event]:
        return [ev async for ev in sse.parse(_chunks(ANTHROPIC_SSE.replace(b"\n", b"\r\n"), size))]

    events = asyncio.run(collect())
    assert [e.event for e in events] == ["message_start", "content_block_delta", "message_stop"]
    assert b"".join(e.encode() for e in events) == ANTHROPIC_SSE


def test_config_from_toml_and_env(tmp_path: Path) -> None:
    f = tmp_path / "mg.toml"
    f.write_text(
        '[upstream.openai]\nbase_url = "http://local:8000/v1"\napi_key_env = "K"\n'
        '[policy]\nrules = "log"\nclassifier = "piguard"\nclassifier_threshold = 2.5\n'
        '[redaction]\nexclude = ["email"]\n[audit]\npath = ""\n'
    )
    cfg = load(f, env={"MOBIUSGUARD_ANTHROPIC_BASE_URL": "http://a/v1",
                       "MOBIUSGUARD_CLIENT_TOKENS": "a, b"})  # fmt: skip
    assert cfg.openai == Upstream("http://local:8000/v1", "K")
    assert cfg.anthropic.base_url == "http://a/v1"
    assert cfg.policy.rules == "log"
    assert cfg.policy.classifier_threshold == 2.5
    assert cfg.redaction.exclude == ("email",)
    assert cfg.audit.path == ""
    assert cfg.client_tokens == ("a", "b")
    assert load(None, env={}) == Config()
    f.write_text('[policy]\nrules = "maybe"\n')
    with pytest.raises(ValueError, match="block, log or off"):
        load(f, env={})
