"""The three APIs the proxy speaks: where their text is, and how they report an error.

The proxy never rebuilds a request. It reads the text fields the model will see (for the
request path) and the text and argument deltas the model writes (for the response path),
and passes everything else through as it came.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, cast

from .config import Config, Upstream

Role = str


@dataclass(frozen=True, slots=True)
class Text:
    """One piece of text the model will read, and where it is in the request."""

    role: Role  # system | user | assistant | tool | developer
    text: str
    where: str  # e.g. "messages[2].content[0]"


Json = dict[str, Any]


def _as_dict(v: object) -> Json:
    return cast("Json", v) if isinstance(v, dict) else {}


def _as_list(v: object) -> list[Any]:
    return cast("list[Any]", v) if isinstance(v, list) else []


class Api:
    name: Literal["chat", "responses", "anthropic"]
    path: str  # route on the proxy
    upstream_path: str  # appended to the upstream base URL

    def upstream(self, cfg: Config) -> Upstream:
        return cfg.openai

    def texts(self, body: Json) -> list[Text]:
        raise NotImplementedError

    def is_stream(self, body: Json) -> bool:
        return body.get("stream") is True

    def error(self, status: int, message: str, code: str, details: Json | None = None) -> Json:
        """An error body in this API's own format (OpenAI style by default)."""
        err: Json = {"message": message, "type": _openai_type(status), "param": None, "code": code}
        body: Json = {"error": err}
        if details:
            err["mobiusguard"] = details
        return body

    def set_key(self, headers: dict[str, str], key: str) -> None:
        headers.pop("x-api-key", None)
        headers["authorization"] = f"Bearer {key}"

    def caller_key(self, headers: dict[str, str]) -> str:
        auth = headers.get("authorization", "")
        return auth[7:].strip() if auth.lower().startswith("bearer ") else ""


def _openai_type(status: int) -> str:
    names = {400: "invalid_request_error", 401: "authentication_error",
             403: "permission_error", 413: "invalid_request_error"}  # fmt: skip
    return names.get(status, "api_error")


def _parts(content: object, where: str, role: Role, kinds: tuple[str, ...]) -> list[Text]:
    """Text from a string or a list of typed parts ({"type": "text", "text": ...})."""
    if isinstance(content, str):
        return [Text(role, content, where)] if content else []
    out: list[Text] = []
    for j, part in enumerate(_as_list(content)):
        p = _as_dict(part)
        if p.get("type") in kinds and isinstance(p.get("text"), str) and p["text"]:
            out.append(Text(role, p["text"], f"{where}[{j}]"))
    return out


class ChatCompletions(Api):
    name = "chat"
    path = "/v1/chat/completions"
    upstream_path = "chat/completions"

    def texts(self, body: Json) -> list[Text]:
        out: list[Text] = []
        for i, msg in enumerate(_as_list(body.get("messages"))):
            m = _as_dict(msg)
            role = str(m.get("role", "user"))
            out += _parts(m.get("content"), f"messages[{i}].content", role, ("text",))
        return out


class Responses(Api):
    name = "responses"
    path = "/v1/responses"
    upstream_path = "responses"

    def texts(self, body: Json) -> list[Text]:
        out: list[Text] = []
        if isinstance(body.get("instructions"), str) and body["instructions"]:
            out.append(Text("system", body["instructions"], "instructions"))
        inp = body.get("input")
        if isinstance(inp, str):
            return [*out, Text("user", inp, "input")] if inp else out
        kinds = ("input_text", "output_text", "text")
        for i, item in enumerate(_as_list(inp)):
            it = _as_dict(item)
            where = f"input[{i}]"
            if it.get("type") == "function_call_output":
                output = it.get("output")
                if isinstance(output, str) and output:
                    out.append(Text("tool", output, f"{where}.output"))
                else:
                    out += _parts(output, f"{where}.output", "tool", kinds)
            elif "content" in it:
                out += _parts(
                    it.get("content"), f"{where}.content", str(it.get("role", "user")), kinds
                )
        return out


class AnthropicMessages(Api):
    name = "anthropic"
    path = "/v1/messages"
    upstream_path = "messages"

    def upstream(self, cfg: Config) -> Upstream:
        return cfg.anthropic

    def texts(self, body: Json) -> list[Text]:
        out = _parts(body.get("system"), "system", "system", ("text",))
        for i, msg in enumerate(_as_list(body.get("messages"))):
            m = _as_dict(msg)
            role = str(m.get("role", "user"))
            content = m.get("content")
            out += _parts(content, f"messages[{i}].content", role, ("text",))
            for j, block in enumerate(_as_list(content)):
                b = _as_dict(block)
                if b.get("type") == "tool_result":
                    out += _parts(b.get("content"), f"messages[{i}].content[{j}].content", "tool",
                                  ("text",))  # fmt: skip
        return out

    def error(self, status: int, message: str, code: str, details: Json | None = None) -> Json:
        err: Json = {"type": _anthropic_type(status), "message": message}
        if details:
            err["mobiusguard"] = {"code": code, **details}
        return {"type": "error", "error": err}

    def set_key(self, headers: dict[str, str], key: str) -> None:
        headers.pop("authorization", None)
        headers["x-api-key"] = key

    def caller_key(self, headers: dict[str, str]) -> str:
        return headers.get("x-api-key", "") or super().caller_key(headers)


def _anthropic_type(status: int) -> str:
    return {400: "invalid_request_error", 401: "authentication_error",
            403: "permission_error", 413: "request_too_large"}.get(status, "api_error")  # fmt: skip


APIS: tuple[Api, ...] = (ChatCompletions(), Responses(), AnthropicMessages())
