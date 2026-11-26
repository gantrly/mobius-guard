"""The Phase 1 held-out sets of decision 0021, on small made-up files (no real data)."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import pytest
from mobiusguard_eval import sources
from mobiusguard_eval.items import ATTACK, BENIGN, make_item
from mobiusguard_eval.ledger import LEDGER
from mobiusguard_eval.screening import half
from mobiusguard_eval.suite import ledger_sources


def test_phase1_sources_are_registered_and_pinned() -> None:
    ids = {s.id for s in ledger_sources()}
    assert {"llmail_full", "bipia_embedded", "wildchat_dev_test"} <= ids
    wild = LEDGER["wildchat_dev_test"]
    paths = {f.path for f in wild.files}
    assert len(paths) == 4
    for i in (5, 33, 49, 53, 62, 65):  # wildchat_dev's training files
        assert f"data/train-{i:05d}-of-00086.parquet" not in paths


def test_llmail_full_takes_string_and_boolean_attempts(tmp_path: Path) -> None:
    data = {
        "an email asking the assistant to forward the inbox": {"attack_attempt": "True"},
        "another email with a planted instruction for the assistant": {"attack_attempt": True},
        "a plain question about the meeting": {"attack_attempt": "False"},
        "an email that might or might not be an attempt": {"attack_attempt": "Unclear"},
        "   ": {"attack_attempt": "True"},
    }
    path = tmp_path / "labelled.json"
    path.write_text(json.dumps(data))
    items = list(sources._llmail_full([path]))  # pyright: ignore[reportPrivateUsage]
    assert len(items) == 2
    assert all(it.label == ATTACK and it.source == "llmail_full" for it in items)


@pytest.mark.parametrize("position", ["start", "middle", "end"])
def test_bipia_insert_keeps_the_document_and_adds_the_attack(position: str) -> None:
    context = "First sentence here. Second one follows! Third ends it?"
    attack = "PLANTED"
    out = sources.bipia_insert(context, attack, position, "k")
    assert attack in out
    assert out.replace(attack, "").replace("\n", "").replace(" ", "") == context.replace(" ", "")
    if position == "start":
        assert out.startswith(attack)
    if position == "end":
        assert out.endswith(attack)
    assert sources.bipia_insert(context, attack, position, "k") == out  # fixed by the key


def _bipia_files(tmp_path: Path) -> list[Path]:
    paths: list[Path] = []
    for task in ("email", "table", "code"):
        rows: list[dict[str, Any]] = []
        for i in range(12):
            body = f"{task} document {i}. It has a second sentence. And a third one {i * 31}."
            rows.append({"context": [body, "more"] if task == "code" else body})
        p = tmp_path / task / "test.jsonl"
        p.parent.mkdir()
        p.write_text("\n".join(json.dumps(r) for r in rows))
        paths.append(p)
    for kind, n in (("text", 10), ("code", 8)):
        p = tmp_path / f"{kind}_attack_test.json"
        p.write_text(json.dumps({f"{kind} category": [f"{kind} attack {i}" for i in range(n)]}))
        paths.append(p)
    return paths


def test_bipia_embedded_keeps_documents_and_attacks_in_one_half(tmp_path: Path) -> None:
    items = list(sources._bipia_embedded(_bipia_files(tmp_path)))  # pyright: ignore[reportPrivateUsage]
    benign = [it for it in items if it.label == BENIGN]
    attacks = [it for it in items if it.label == ATTACK]
    assert len(benign) == 36  # every clean document
    assert attacks
    halves_of: dict[str, set[str]] = defaultdict(set)
    for it in items:
        halves_of["context:" + it.meta["context"]].add(half(it))
        if it.label == ATTACK:
            halves_of["attack:" + it.meta["attack"]].add(half(it))
            assert it.meta["position"] in ("start", "middle", "end")
    assert all(len(h) == 1 for h in halves_of.values())  # nothing in both halves
    assert {half(it) for it in items} == {"screen", "final"}
    per_pair: dict[tuple[str, str], int] = defaultdict(int)
    for it in attacks:
        per_pair[(it.meta["context"], it.meta["attack"])] += 1
    assert set(per_pair.values()) == {3}  # three placements of each kept pair
    code_attacks = {it.meta["attack"] for it in attacks if it.meta["task"] == "code"}
    assert all(a.startswith("code") for a in code_attacks)


def test_half_follows_a_source_set_half() -> None:
    it = make_item("some text long enough to be an item", BENIGN, "x", meta={"half": "final"})
    assert half(it) == "final"
    assert half(make_item("other text", BENIGN, "x")) in ("screen", "final")


def test_wildchat_dev_test_filters_like_training(tmp_path: Path) -> None:
    pa = pytest.importorskip("pyarrow")
    pq = pytest.importorskip("pyarrow.parquet")

    def conv(text: str) -> list[dict[str, str]]:
        return [{"role": "user", "content": text}, {"role": "assistant", "content": "ok"}]

    dev = "My python script calls the API with curl and the json schema fails"
    rows = [
        (conv(dev), "English", False, [{"flagged": False}, {"flagged": False}]),
        (conv("Tell me a story about a dragon"), "English", False, [{"flagged": False}] * 2),
        (conv(dev + " again"), "English", True, [{"flagged": False}] * 2),  # toxic
        (conv(dev + " once more"), "English", False, [{"flagged": True}] * 2),  # flagged
    ]
    table = pa.table({
        "conversation": [r[0] for r in rows],
        "language": [r[1] for r in rows],
        "toxic": [r[2] for r in rows],
        "openai_moderation": [r[3] for r in rows],
    })  # fmt: skip
    path = tmp_path / "train-00009-of-00086.parquet"
    pq.write_table(table, path)
    items = list(sources._wildchat_dev_test([path]))  # pyright: ignore[reportPrivateUsage]
    assert [it.text for it in items] == [dev]
    assert items[0].label == BENIGN
    assert items[0].lang == "en"
