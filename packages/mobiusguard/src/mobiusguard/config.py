"""Configuration: a TOML file, with environment overrides for what differs per deployment.

    [upstream.openai]            # serves /v1/chat/completions, /v1/responses, /v1/models
    base_url = "https://api.openai.com/v1"
    api_key_env = ""             # set to hold the key here instead of forwarding the caller's

    [upstream.anthropic]         # serves /v1/messages
    base_url = "https://api.anthropic.com/v1"

    [policy]
    rules = "block"              # block | log | off
    classifier = ""              # "", "piguard" or "protectai-v2" (needs mobiusguard[classifier])
    classifier_threshold = ""    # a log-odds score; empty = log scores only
    on_error = "block"           # block | allow: what a failing detector does

    [redaction]
    enabled = true
    exclude = []                 # pattern IDs to switch off

    [audit]
    path = "mobiusguard-audit.jsonl"   # "" = no audit log
    include_text = false

    [limits]
    max_body_bytes = 4_000_000
    timeout_seconds = 600

Environment: ``MOBIUSGUARD_OPENAI_BASE_URL``, ``MOBIUSGUARD_ANTHROPIC_BASE_URL``,
``MOBIUSGUARD_CLIENT_TOKENS`` (comma-separated tokens callers must present when the proxy
holds the upstream keys).
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, cast

Action = Literal["block", "log", "off"]


@dataclass(frozen=True, slots=True)
class Upstream:
    base_url: str
    api_key_env: str = ""  # name of the env var holding the key; "" = forward the caller's

    def api_key(self) -> str:
        return os.environ.get(self.api_key_env, "") if self.api_key_env else ""


@dataclass(frozen=True, slots=True)
class Policy:
    rules: Action = "block"
    classifier: str = ""
    classifier_threshold: float | None = None
    on_error: Literal["block", "allow"] = "block"


@dataclass(frozen=True, slots=True)
class Redaction:
    enabled: bool = True
    exclude: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Audit:
    path: str = "mobiusguard-audit.jsonl"
    include_text: bool = False


@dataclass(frozen=True, slots=True)
class Limits:
    max_body_bytes: int = 4_000_000
    timeout_seconds: float = 600


@dataclass(frozen=True, slots=True)
class Config:
    openai: Upstream = field(default_factory=lambda: Upstream("https://api.openai.com/v1"))
    anthropic: Upstream = field(default_factory=lambda: Upstream("https://api.anthropic.com/v1"))
    policy: Policy = field(default_factory=Policy)
    redaction: Redaction = field(default_factory=Redaction)
    audit: Audit = field(default_factory=Audit)
    limits: Limits = field(default_factory=Limits)
    client_tokens: tuple[str, ...] = ()  # required from callers when non-empty


def _section(data: dict[str, Any], *path: str) -> dict[str, Any]:
    cur = data
    for key in path:
        nxt: object = cur.get(key, {})
        cur = cast("dict[str, Any]", nxt) if isinstance(nxt, dict) else {}
    return cur


ACTIONS: dict[str, Action] = {"block": "block", "log": "log", "off": "off"}


def _action(value: object, name: str) -> Action:
    if isinstance(value, str) and value in ACTIONS:
        return ACTIONS[value]
    raise ValueError(f"{name} must be block, log or off, not {value!r}")


def load(path: Path | None = None, env: dict[str, str] | None = None) -> Config:
    """Read the TOML file (if any), then apply environment overrides."""
    env = dict(os.environ) if env is None else env
    data: dict[str, Any] = tomllib.loads(path.read_text()) if path else {}
    up_o, up_a = _section(data, "upstream", "openai"), _section(data, "upstream", "anthropic")
    pol, red = _section(data, "policy"), _section(data, "redaction")
    aud, lim = _section(data, "audit"), _section(data, "limits")

    threshold = pol.get("classifier_threshold", "")
    on_error = pol.get("on_error", "block")
    if on_error != "block" and on_error != "allow":
        raise ValueError(f"policy.on_error must be block or allow, not {on_error!r}")
    tokens = env.get("MOBIUSGUARD_CLIENT_TOKENS", "")
    return Config(
        openai=Upstream(
            env.get("MOBIUSGUARD_OPENAI_BASE_URL")
            or str(up_o.get("base_url", "https://api.openai.com/v1")),
            str(up_o.get("api_key_env", "")),
        ),
        anthropic=Upstream(
            env.get("MOBIUSGUARD_ANTHROPIC_BASE_URL")
            or str(up_a.get("base_url", "https://api.anthropic.com/v1")),
            str(up_a.get("api_key_env", "")),
        ),
        policy=Policy(
            rules=_action(pol.get("rules", "block"), "policy.rules"),
            classifier=str(pol.get("classifier", "")),
            classifier_threshold=None if threshold in ("", None) else float(threshold),
            on_error=on_error,
        ),
        redaction=Redaction(
            enabled=bool(red.get("enabled", True)),
            exclude=tuple(str(x) for x in red.get("exclude", ())),
        ),
        audit=Audit(
            path=str(aud.get("path", "mobiusguard-audit.jsonl")),
            include_text=bool(aud.get("include_text", False)),
        ),
        limits=Limits(
            max_body_bytes=int(lim.get("max_body_bytes", 4_000_000)),
            timeout_seconds=float(lim.get("timeout_seconds", 600)),
        ),
        client_tokens=tuple(t.strip() for t in tokens.split(",") if t.strip()),
    )
