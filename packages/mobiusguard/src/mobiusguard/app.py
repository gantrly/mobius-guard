"""The proxy: one handler for the three APIs, a pass-through for model lists.

Order for each request: caller check, size and JSON check, the request check (rules,
classifier, policy), then the upstream call; the reply is redacted on its way back. A block
or an error is answered in the API's own error format.
"""

from __future__ import annotations

import json
import time
from collections.abc import AsyncGenerator, AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

import httpx
from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from . import sse
from .apis import APIS, Api, Json
from .config import Config

# Headers passed on to the upstream; everything else (cookies, host, hop-by-hop) is dropped.
FORWARD = {
    "authorization", "x-api-key", "anthropic-version", "anthropic-beta", "openai-organization",
    "openai-project", "openai-beta", "user-agent", "accept", "idempotency-key",
}  # fmt: skip
# Headers passed back from the upstream.
RETURN_PREFIXES = ("x-request-id", "request-id", "openai-", "anthropic-", "x-ratelimit-",
                   "retry-after")  # fmt: skip


class Hooks:
    """What runs inside a request. Part 3a passes everything through; the guard (3b) and
    the redaction (3c) replace these."""

    async def check(self, api: Api, body: Json, request: Request, state: Json) -> Json | None:
        """None to forward the request, or ``{"status", "message", "code", "details"}``."""
        return None

    def rewrite_json(self, api: Api, body: Json, state: Json) -> Json:
        return body

    def rewrite_events(
        self, api: Api, events: AsyncIterator[sse.Event], state: Json
    ) -> AsyncIterator[sse.Event]:
        return events

    def finish(self, api: Api, state: Json) -> None:
        """Called once the reply has been sent (audit)."""


def _forward_headers(request: Request, api: Api, cfg: Config) -> dict[str, str]:
    headers = {k.lower(): v for k, v in request.headers.items()}
    out = {k: v for k, v in headers.items() if k in FORWARD or k.startswith("x-stainless-")}
    key = api.upstream(cfg).api_key()
    if key:
        api.set_key(out, key)
    out["accept-encoding"] = "identity"  # we read the stream as it arrives
    out["content-type"] = "application/json"
    return out


def _return_headers(resp: httpx.Response) -> dict[str, str]:
    return {k: v for k, v in resp.headers.items() if k.lower().startswith(RETURN_PREFIXES)}


def create_app(
    cfg: Config, *, hooks: Hooks | None = None, transport: httpx.AsyncBaseTransport | None = None
) -> Starlette:
    hooks = hooks or Hooks()
    clients: dict[str, httpx.AsyncClient] = {}

    @asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncGenerator[None]:
        clients["http"] = httpx.AsyncClient(
            timeout=httpx.Timeout(cfg.limits.timeout_seconds, connect=10), transport=transport
        )
        try:
            yield
        finally:
            await clients["http"].aclose()

    def fail(
        api: Api, status: int, message: str, code: str, details: Json | None = None
    ) -> Response:
        return JSONResponse(api.error(status, message, code, details), status_code=status)

    def handler(api: Api) -> Callable[[Request], Awaitable[Response]]:
        async def handle(request: Request) -> Response:
            state: Json = {"started": time.perf_counter(), "api": api.name}
            if cfg.client_tokens:
                headers = {k.lower(): v for k, v in request.headers.items()}
                if api.caller_key(headers) not in cfg.client_tokens:
                    return fail(api, 401, "Missing or unknown Mobius Guard client token.",
                                "unauthorized")  # fmt: skip
            raw = await request.body()
            if len(raw) > cfg.limits.max_body_bytes:
                return fail(api, 413, "Request body too large for Mobius Guard.", "too_large")
            try:
                body = json.loads(raw)
            except json.JSONDecodeError:
                return fail(api, 400, "Request body is not valid JSON.", "invalid_json")
            if not isinstance(body, dict):
                return fail(api, 400, "Request body must be a JSON object.", "invalid_json")
            body_d: Json = body  # pyright: ignore[reportUnknownVariableType]
            state["model"] = str(body_d.get("model", ""))
            state["stream"] = api.is_stream(body_d)

            blocked = await hooks.check(api, body_d, request, state)
            if blocked is not None:
                state["decision"] = "block"
                hooks.finish(api, state)
                return fail(api, int(blocked["status"]), str(blocked["message"]),
                            str(blocked["code"]), blocked.get("details"))  # fmt: skip
            state.setdefault("decision", "allow")

            up = api.upstream(cfg)
            url = f"{up.base_url.rstrip('/')}/{api.upstream_path}"
            client = clients["http"]
            req = client.build_request("POST", url, content=raw,
                                       headers=_forward_headers(request, api, cfg))  # fmt: skip
            try:
                resp = await client.send(req, stream=True)
            except httpx.HTTPError as e:
                state["upstream_error"] = type(e).__name__
                hooks.finish(api, state)
                return fail(
                    api, 502, f"Upstream unreachable: {type(e).__name__}.", "upstream_error"
                )
            state["upstream_status"] = resp.status_code
            ctype = resp.headers.get("content-type", "")

            if resp.status_code == 200 and ctype.startswith("text/event-stream"):
                events = hooks.rewrite_events(api, sse.parse(resp.aiter_bytes()), state)

                async def body_iter() -> AsyncIterator[bytes]:
                    async for ev in events:
                        yield ev.encode()

                def done() -> None:
                    hooks.finish(api, state)

                async def close() -> None:
                    await resp.aclose()
                    done()

                return StreamingResponse(body_iter(), media_type="text/event-stream",
                                         headers=_return_headers(resp),
                                         background=BackgroundTask(close))  # fmt: skip

            content = await resp.aread()
            await resp.aclose()
            if resp.status_code == 200 and ctype.startswith("application/json"):
                try:
                    data = json.loads(content)
                except json.JSONDecodeError:
                    data = None
                if isinstance(data, dict):
                    out = hooks.rewrite_json(api, data, state)  # pyright: ignore[reportUnknownArgumentType]
                    hooks.finish(api, state)
                    return JSONResponse(out, status_code=200, headers=_return_headers(resp))
            hooks.finish(api, state)
            # Errors and anything we don't understand go back as they came.
            return Response(content, status_code=resp.status_code, media_type=ctype or None,
                            headers=_return_headers(resp))  # fmt: skip

        return handle

    async def models(request: Request) -> Response:
        api = APIS[0]
        url = f"{cfg.openai.base_url.rstrip('/')}/models"
        resp = await clients["http"].get(url, headers=_forward_headers(request, api, cfg))
        return Response(resp.content, status_code=resp.status_code,
                        media_type=resp.headers.get("content-type"),
                        headers=_return_headers(resp))  # fmt: skip

    async def health(_: Request) -> Response:
        return JSONResponse({"status": "ok"})

    routes = [Route(api.path, handler(api), methods=["POST"]) for api in APIS]
    routes += [Route("/v1/models", models, methods=["GET"]), Route("/healthz", health)]
    return Starlette(routes=routes, lifespan=lifespan)
