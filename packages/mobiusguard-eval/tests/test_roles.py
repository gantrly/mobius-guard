"""Per-role thresholds: documents are scored against a threshold set on harmless documents."""

from __future__ import annotations

import json
from pathlib import Path

from mobiusguard_eval import roles
from mobiusguard_eval.items import Item, read_jsonl, write_jsonl


def _it(i: str, source: str, label: int = 0, split: str = "test") -> Item:
    return Item(id=i, text="x", label=label, source=source, family=source,  # type: ignore[arg-type]
                split=split)  # type: ignore[arg-type]  # fmt: skip


def _run(d: Path, name: str, scores: dict[str, float]) -> Path:
    d.mkdir(parents=True)
    (d / "run.json").write_text(json.dumps({"detector": name, "info": {}}))
    with (d / "scores.jsonl").open("w") as f:
        f.writelines(json.dumps({"id": k, "score": v}) + "\n" for k, v in scores.items())
    return d


def test_documents_are_shifted_to_the_document_threshold(tmp_path: Path) -> None:
    suite = tmp_path / "suite"
    suite.mkdir()
    cal = [_it(f"o{i}", "oasst", split="dev") for i in range(200)]
    items = [*cal, _it("mail", "llmail", 1), _it("chat", "gandalf", 1)]
    write_jsonl(suite / "items.jsonl", items)
    scores = {f"o{i}": i / 100 for i in range(200)}  # user threshold at 1%: 1.98
    scores |= {"mail": 1.0, "chat": 1.0}
    run = _run(tmp_path / "run", "m", scores)
    docs = _run(tmp_path / "docs", "m", {f"d{i}": i / 200 for i in range(200)})  # 0.99
    info = roles.role_offset(run, docs, suite, tmp_path / "out")
    assert info["user_threshold"] > info["document_threshold"]
    got = {json.loads(line)["id"]: json.loads(line)["score"]
           for line in (tmp_path / "out" / "scores.jsonl").open()}  # fmt: skip
    assert got["chat"] == 1.0  # a user's text keeps its score
    shift = info["document_threshold"] - info["user_threshold"]
    assert got["mail"] == 1.0 - shift  # the email is judged against the document threshold
    meta = json.loads((tmp_path / "out" / "run.json").read_text())
    assert meta["detector"] == "m+roles"


def test_calibration_takes_harmless_documents_not_trained_on(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    val = [_it("a", "sep", split="val"), _it("b", "browsesafe_md", split="val"),
           _it("c", "sep", 1, split="val"), _it("d", "wildchat", split="val"),
           _it("e", "nemotron_ipi", split="val")]  # fmt: skip
    write_jsonl(data / "val.jsonl", val)
    other = tmp_path / "other_train.jsonl"
    write_jsonl(other, [_it("e", "nemotron_ipi", split="train")])
    m = roles.document_calibration(data, [other], tmp_path / "cal")
    assert m["items"] == 2  # a and b: c is an attack, d is not a document, e was trained on
    assert m["by_source"] == {"sep": 1, "browsesafe_md": 1}


def _src_item(i: int, source: str, turn: str = "", label: int = 0, split: str = "train",
              cluster: str = "") -> Item:  # fmt: skip
    meta = {"turn": turn} if turn else {}
    return Item(id=f"{source}:{i}", text=f"text {i}", label=label, source=source,  # type: ignore[arg-type]
                family=source, split=split, cluster=cluster or f"{source}:{i}", meta=meta)  # type: ignore[arg-type]  # fmt: skip


def test_roles_by_source_and_turn() -> None:
    assert roles.role_of(_src_item(1, "browsesafe_md")) == "tool"
    assert roles.role_of(_src_item(1, "toucan", turn="tool")) == "tool"
    assert roles.role_of(_src_item(1, "toucan", turn="user")) == "user"
    assert roles.role_of(_src_item(1, "wildchat")) == "user"
    assert roles.role_of(_src_item(1, "llmail", label=1)) == "tool"
    assert roles.role_of(_src_item(1, "obf-benign:spaced")) == "user"


def test_mark_roles_marks_every_text_and_holds_out_half_the_tool_outputs(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    tools = [_src_item(i, "glaive_fc", turn="tool") for i in range(400)]
    copies = [
        Item(id=f"{t.id}~aug:spaced", text="t e x t", label=0, source="glaive_fc",
             family="glaive_fc", split="train", cluster=t.cluster,
             meta={"turn": "tool", "augmented": "spaced", "original": t.id})
        for t in tools[:100]
    ]  # fmt: skip
    users = [_src_item(i, "glaive_fc", turn="user") for i in range(400, 450)]
    docs = [_src_item(i, "sep", label=i % 2) for i in range(20)]
    write_jsonl(data / "train.jsonl", tools + copies + users + docs)
    write_jsonl(data / "val.jsonl", [])
    (data / "summary.json").write_text(json.dumps({"ids_sha256": "x", "rule": "r"}))
    s = roles.mark_roles(data, tmp_path / "out", tmp_path / "held")
    kept = list(read_jsonl(tmp_path / "out" / "train.jsonl"))
    cal = list(read_jsonl(tmp_path / "held" / "calibration" / "items.jsonl"))
    test = list(read_jsonl(tmp_path / "held" / "test" / "items.jsonl"))
    assert all(it.text.startswith(("[user]\n", "[tool]\n")) for it in kept)
    assert all(it.text.startswith("[tool]\n") for it in kept if it.source == "sep")
    assert 120 < len(cal) + len(test) < 280  # about half of the 400 tool outputs
    held = {it.id for it in cal + test}
    trained_copies = {it.meta["original"] for it in kept if it.meta.get("augmented")}
    assert held
    assert trained_copies  # some copies train (their originals do too)
    assert not held & trained_copies  # no held-out output's disguised copy is trained on
    assert all(it.source == "tool_outputs" and it.split == "test" for it in cal + test)
    assert all(not it.text.startswith("[") for it in cal + test)  # stored unmarked
    assert s["role_marker"] is True
