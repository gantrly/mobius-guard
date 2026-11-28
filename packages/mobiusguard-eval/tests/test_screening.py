"""The screening split keeps clusters whole and both halves keep calibration and fixed checks."""

from __future__ import annotations

from pathlib import Path

from mobiusguard_eval.items import Item, read_jsonl, write_jsonl
from mobiusguard_eval.screening import split_suite


def _it(i: int, split: str = "test", source: str = "gandalf", cluster: str = "") -> Item:
    return Item(id=f"{source}:{i}", text="x", label=1, source=source, family=source,
                split=split, cluster=cluster or f"c{i}")  # type: ignore[arg-type]  # fmt: skip


def test_halves_split_test_items_by_cluster_and_keep_the_rest(tmp_path: Path) -> None:
    items = [_it(i) for i in range(400)]
    items += [
        Item(id=f"gandalf:{i}~spaced", text="x y", label=1, source="gandalf",
             family="obf:spaced", split="test", cluster=f"c{i}")
        for i in range(400)
    ]  # fmt: skip
    items += [_it(i, split="dev", source="oasst") for i in range(50)]
    items += [_it(i, source="dev_check") for i in range(8)]
    write_jsonl(tmp_path / "s" / "items.jsonl", items)
    m = split_suite(tmp_path / "s", tmp_path / "out")
    screen = {it.id: it for it in read_jsonl(tmp_path / "out" / "screen" / "items.jsonl")}
    final = {it.id: it for it in read_jsonl(tmp_path / "out" / "final" / "items.jsonl")}

    def tests(p: dict[str, Item]) -> set[str]:
        return {i for i, it in p.items() if it.split == "test" and it.source != "dev_check"}

    assert not tests(screen) & tests(final)
    assert len(tests(screen)) + len(tests(final)) == 800
    assert 300 < len(tests(screen)) < 500
    for i in range(400):  # a disguised copy sits with its original
        assert (f"gandalf:{i}" in screen) == (f"gandalf:{i}~spaced" in screen)
    for part in (screen, final):
        assert sum(it.split == "dev" for it in part.values()) == 50
        assert sum(it.source == "dev_check" for it in part.values()) == 8
    assert m["final"]["test_ids_sha256"] != m["screen"]["test_ids_sha256"]
