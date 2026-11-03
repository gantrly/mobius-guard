"""Settings: the TOML file, environment overrides and the start-up warnings."""

from __future__ import annotations

from pathlib import Path

import pytest
from mobiusguard.config import load, warnings


def test_defaults_without_a_file() -> None:
    cfg = load(None, env={})
    assert cfg.openai.base_url == "https://api.openai.com/v1"
    assert cfg.policy.rules == "block"
    assert cfg.client_tokens == ()
    assert warnings(cfg, {}) == []


def test_file_and_environment(tmp_path: Path) -> None:
    f = tmp_path / "mg.toml"
    f.write_text('[policy]\nrules = "log"\nclassifier_threshold = 2.5\n'
                 '[upstream.openai]\nbase_url = "http://a/v1"\n')  # fmt: skip
    cfg = load(f, env={"MOBIUSGUARD_OPENAI_BASE_URL": "http://b/v1"})
    assert cfg.policy.rules == "log"
    assert cfg.policy.classifier_threshold == 2.5
    assert cfg.openai.base_url == "http://b/v1"  # the environment wins


def test_bad_values_are_refused(tmp_path: Path) -> None:
    f = tmp_path / "mg.toml"
    f.write_text('[policy]\nrules = "deny"\n')
    with pytest.raises(ValueError, match="block, log or off"):
        load(f, env={})


def _held(tmp_path: Path, both: bool = True) -> Path:
    f = tmp_path / "mg.toml"
    body = '[upstream.openai]\napi_key_env = "OPENAI_KEY"\n'
    if both:
        body += '[upstream.anthropic]\napi_key_env = "ANTHROPIC_KEY"\n'
    f.write_text(body)
    return f


def test_a_held_key_without_client_tokens_is_warned_about(tmp_path: Path) -> None:
    env = {"OPENAI_KEY": "k", "ANTHROPIC_KEY": "k"}
    assert any("anyone who can reach it" in w for w in warnings(load(_held(tmp_path), env), env))


def test_client_tokens_without_held_keys_are_warned_about(tmp_path: Path) -> None:
    env = {"OPENAI_KEY": "k", "MOBIUSGUARD_CLIENT_TOKENS": "t1"}
    assert any(
        "sent to that upstream" in w for w in warnings(load(_held(tmp_path, False), env), env)
    )


def test_held_keys_with_client_tokens_are_fine(tmp_path: Path) -> None:
    env = {"OPENAI_KEY": "k", "ANTHROPIC_KEY": "k", "MOBIUSGUARD_CLIENT_TOKENS": "t1, t2"}
    cfg = load(_held(tmp_path), env=env)
    assert cfg.client_tokens == ("t1", "t2")
    assert warnings(cfg, env) == []


def test_a_missing_key_variable_is_warned_about(tmp_path: Path) -> None:
    env = {"MOBIUSGUARD_CLIENT_TOKENS": "t1"}
    found = warnings(load(_held(tmp_path), env), env)
    assert "the OpenAI upstream's api_key_env variable is not set" in found
    assert "the Anthropic upstream's api_key_env variable is not set" in found
