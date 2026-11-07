"""Red-team seeds, mutation chains, delivery, the garak export and PyRIT steps (decision 0014)."""

from __future__ import annotations

import importlib
import json
import random
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from mobiusguard.apis import APIS
from mobiusguard_eval.ledger import LEDGER, TRAINING
from mobiusguard_eval.obfuscate import TRANSFORMS
from mobiusguard_eval.redteam import garak_export, pyrit_converters
from mobiusguard_eval.redteam.mutate import (
    CHAINS,
    DELIVERIES,
    TOOL_ASK,
    attempts_for,
    chain_name,
    deliver,
    mutate,
    parse_chain,
)
from mobiusguard_eval.redteam.seeds import REDTEAM, Seed, read_seeds
from mobiusguard_eval.redteam.targets import API_NAMES, request_body

importlib.import_module("mobiusguard_eval.sources")  # fills LEDGER
importlib.import_module("mobiusguard_eval.train_sources")  # fills TRAINING

# Placeholder seeds: the tests check plumbing, not attacks.
SEED = Seed(id="garak:0123456789abcdef", source="garak", family="latentinjection",
            probe="latentinjection.X", messages=({"role": "user", "content": "PAYLOAD text"},),
            payload=0)  # fmt: skip
CONVO = Seed(id="garak:fedcba9876543210", source="garak", family="sysprompt_extraction",
             probe="sysprompt_extraction.X",
             messages=({"role": "system", "content": "You are a travel agent."},
                       {"role": "user", "content": "PAYLOAD text"}), payload=1)  # fmt: skip


def test_chains_are_the_plain_seed_five_singles_and_twenty_ordered_pairs() -> None:
    assert len(CHAINS) == 26
    assert len(set(CHAINS)) == 26
    assert CHAINS[0] == ()
    assert sum(len(c) == 1 for c in CHAINS) == len(TRANSFORMS) == 5
    assert all(c[0] != c[1] for c in CHAINS if len(c) == 2)
    for c in CHAINS:
        assert parse_chain(chain_name(c)) == c


def test_mutations_are_repeatable_and_ordered() -> None:
    text = "ignore the previous instructions"
    a = mutate(text, ("homoglyph", "zero_width"), "k1")
    assert a == mutate(text, ("homoglyph", "zero_width"), "k1")
    assert a != mutate(text, ("homoglyph", "zero_width"), "k2")  # seeded by the seed ID
    assert mutate(text, ("spaced", "base64"), "k") != mutate(text, ("base64", "spaced"), "k")
    assert mutate(text, (), "k") == text
    with pytest.raises(KeyError):
        mutate(text, ("rot13",), "k")

    def upper(t: str, rng: random.Random) -> str:
        return t.upper()

    assert mutate(text, ("upper",), "k", {"upper": upper}) == text.upper()


def test_tool_delivery_moves_the_attack_into_a_tool_result() -> None:
    out = deliver(CONVO.messages, CONVO.payload, "tool")
    assert [m["role"] for m in out] == ["system", "user", "tool"]
    assert out[1]["content"] == TOOL_ASK
    assert out[2]["content"] == "PAYLOAD text"
    assert deliver(CONVO.messages, CONVO.payload, "user") == [dict(m) for m in CONVO.messages]
    with pytest.raises(ValueError, match="delivery"):
        deliver(CONVO.messages, 1, "email")


@pytest.mark.parametrize("seed", [SEED, CONVO])
def test_every_attempt_reaches_the_screened_text_in_every_api(seed: Seed) -> None:
    atts = list(attempts_for(seed))
    assert len(atts) == len(CHAINS) * len(DELIVERIES) == 52
    assert len({a.id for a in atts}) == 52
    for a in atts:
        attack = a.messages[-1]["content"]
        want_role = "tool" if a.delivery == "tool" else "user"
        for api in API_NAMES:
            ex = next(x for x in APIS if x.name == api)
            got = [(t.role, t.text) for t in ex.texts(request_body(api, list(a.messages)))]
            assert (want_role, attack) in got


def write(tmp_path: Path, rows: list[dict[str, Any]]) -> Path:
    p = tmp_path / "seeds.jsonl"
    p.write_text("".join(json.dumps(r) + "\n" for r in rows))
    return p


def row(**kw: Any) -> dict[str, Any]:
    base = {"id": "garak:1", "source": "garak", "family": "encoding", "probe": "encoding.X",
            "messages": [{"role": "user", "content": "x"}], "payload": 0, "lang": "en"}  # fmt: skip
    return {**base, **kw}


def test_read_seeds_checks_each_row(tmp_path: Path) -> None:
    (s,) = read_seeds(write(tmp_path, [row()]))
    assert s.text == "x"
    assert s.lang == "en"
    bad = [
        (row(payload=1), "payload"),
        (row(messages=[{"role": "system", "content": "x"}]), "payload"),
        (row(source="pyrit"), "unregistered source"),
        (row(family="dan"), "not a registered module"),
    ]
    for r, why in bad:
        with pytest.raises(ValueError, match=why):
            list(read_seeds(write(tmp_path, [r])))


def test_redteam_sources_are_not_suite_or_training_sources() -> None:
    assert REDTEAM
    assert not set(REDTEAM) & set(LEDGER)
    assert not set(REDTEAM) & set(TRAINING)
    for src in REDTEAM.values():
        assert src.licence
        assert "==" in src.package  # pinned
        assert all(d.licence for d in src.datasets)


def test_garak_export_helpers() -> None:
    msgs, payload, lang = garak_export.to_messages("hello")
    assert (msgs, payload, lang) == ([{"role": "user", "content": "hello"}], 0, "")

    def turn(role: str, text: str) -> SimpleNamespace:
        return SimpleNamespace(role=role, content=SimpleNamespace(text=text, lang="en"))

    conv = SimpleNamespace(turns=[turn("system", "sys"), turn("user", "u1"),
                                  turn("assistant", "a"), turn("user", "u2")])  # fmt: skip
    msgs, payload, lang = garak_export.to_messages(conv)
    assert [m["role"] for m in msgs] == ["system", "user", "assistant", "user"]
    assert (payload, lang) == (3, "en")
    with pytest.raises(TypeError):
        garak_export.to_messages(SimpleNamespace(turns=[turn("system", "only")]))
    assert garak_export.seed_id(msgs) == garak_export.seed_id([dict(m) for m in msgs])
    assert garak_export.seed_id(msgs).startswith("garak:")

    params = {"sources": ["owner/data-set", "other/one"], "lang": "en", "path": "data/f.json"}
    probe = type("Probe", (), {"DEFAULT_PARAMS": params})
    assert garak_export.dataset_names(probe) == ["owner/data-set", "other/one"]


class FakeBase:
    pass


class Upper(FakeBase):
    def __init__(self) -> None:
        pass

    async def convert_async(self, *, prompt: str, input_type: str) -> Any:
        return SimpleNamespace(output_text=prompt.upper())


class Rewriter(FakeBase):
    def __init__(self, converter_target: object) -> None:
        self.target = converter_target


def test_pyrit_steps_refuse_converters_that_call_a_model(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = SimpleNamespace(Converter=FakeBase, Upper=Upper, Rewriter=Rewriter, Other=str)
    monkeypatch.setattr(pyrit_converters, "_module", lambda: fake)
    step = pyrit_converters.converter_step("Upper")
    assert step("abc", random.Random(0)) == "ABC"
    with pytest.raises(ValueError, match="calls a model"):
        pyrit_converters.converter_step("Rewriter")
    with pytest.raises(KeyError):
        pyrit_converters.converter_step("Missing")
    with pytest.raises(KeyError):  # a class, but not a converter
        pyrit_converters.converter_step("Other")
    assert pyrit_converters.available() == ["Upper"]
