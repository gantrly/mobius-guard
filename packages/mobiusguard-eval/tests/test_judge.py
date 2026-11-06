"""The label-cleaning rule (decision 0012, 2026-11-05), without calling any model."""

from __future__ import annotations

from collections.abc import Mapping

import pytest
from mobiusguard_eval import judge
from mobiusguard_eval.items import ATTACK, BENIGN, Item, make_item

RULE = judge.Rule(
    keep_attack_flips=frozenset({"keep_src"}),
    revert_attack_flips=frozenset({"revert_src"}),
    keep_harmful_flips=frozenset({"harm_src"}),
    judges=("j1", "j2"),
)


def _item(text: str, label: int, source: str, harmful: str) -> Item:
    return make_item(text, ATTACK if label else BENIGN, source, meta={"harmful": harmful})


def _labels(
    *pairs: tuple[Item, Mapping[str, object], Mapping[str, object]],
) -> dict[str, dict[str, Mapping[str, object]]]:
    out: dict[str, dict[str, Mapping[str, object]]] = {"j1": {}, "j2": {}}
    for it, a, b in pairs:
        out["j1"][it.id] = a
        out["j2"][it.id] = b
    return out


def test_parse_reply_takes_the_array_inside_extra_words() -> None:
    rows = judge.parse_reply('Here you go:\n[{"n": 0, "attack": 1, "harmful": "unsure"}]\nDone.')
    assert rows == [{"n": 0, "attack": 1, "harmful": "unsure"}]
    with pytest.raises(ValueError, match="no JSON array"):
        judge.parse_reply("I cannot help with that.")


def test_harmful_values() -> None:
    assert [judge.harmful_value(v) for v in (1, 0, "1", "0", "unsure", None)] == [
        "1",
        "0",
        "1",
        "0",
        "",
        "",
    ]


def test_the_rule() -> None:
    agree = _item("judges agree with the source", 1, "plain", "0")
    split = _item("judges disagree on attack", 1, "plain", "0")
    kept_flip = _item("a flip in a keep source", 0, "keep_src", "0")
    reverted = _item("a flip in a revert source", 1, "revert_src", "0")
    dropped = _item("a flip anywhere else", 1, "plain", "0")
    harm_kept = _item("a harmful flip in a keep source", 0, "harm_src", "0")
    harm_lost = _item("a harmful flip elsewhere", 0, "plain", "1")
    harm_fill = _item("source had no harmful label", 1, "plain", "")
    yes, no = {"attack": 1, "harmful": 0}, {"attack": 0, "harmful": 0}
    labels = _labels(
        (agree, yes, yes),
        (split, yes, no),
        (kept_flip, yes, yes),
        (reverted, no, no),
        (dropped, no, no),
        (harm_kept, {"attack": 0, "harmful": 1}, {"attack": 0, "harmful": "1"}),
        (harm_lost, no, no),
        (harm_fill, {"attack": 1, "harmful": 1}, {"attack": 1, "harmful": 1}),
    )
    items = [agree, split, kept_flip, reverted, dropped, harm_kept, harm_lost, harm_fill]
    kept, stats = judge.apply(items, labels, RULE)
    out = {it.id: it for it in kept}
    assert set(out) == {
        agree.id,
        kept_flip.id,
        reverted.id,
        harm_kept.id,
        harm_lost.id,
        harm_fill.id,
    }
    assert out[kept_flip.id].label == 1
    assert out[reverted.id].label == 1  # the source's label, not the judges'
    assert out[harm_kept.id].meta["harmful"] == "1"
    assert out[harm_lost.id].meta["harmful"] == ""  # a flip outside the keep list: unknown
    assert out[harm_fill.id].meta["harmful"] == "1"  # the judges fill a missing label
    assert out[agree.id].meta["source_attack"] == "1"
    assert stats["plain"]["dropped_disagree"] == 1
    assert stats["plain"]["dropped_attack_flip"] == 1
    assert stats["revert_src"]["attack_reverted"] == 1


def test_trusted_sources_keep_their_labels() -> None:
    rule = judge.Rule(
        trust_attack=frozenset({"pairs"}),
        trust_harmful=frozenset({"pairs", "human"}),
        judges=("j1", "j2"),
    )
    injected = _item("an injected window the judges miss", 1, "pairs", "")
    twin = _item("its clean twin the judges disagree on", 0, "pairs", "0")
    human = _item("a human-labelled safe prompt", 0, "human", "0")
    yes, no = {"attack": 1, "harmful": 1}, {"attack": 0, "harmful": 1}
    labels = _labels((injected, no, no), (twin, yes, no), (human, no, no))
    kept, stats = judge.apply([injected, twin, human], labels, rule)
    out = {it.id: it for it in kept}
    assert out[injected.id].label == 1  # kept: constructed and checked
    assert out[twin.id].label == 0  # the judges split; the source's label stands
    assert out[human.id].meta["harmful"] == "0"  # the human label, not the judges' 1
    assert stats["pairs"]["judges_dispute_attack"] == 2
    assert stats["human"]["judges_dispute_harmful"] == 1


def test_the_new_rule_treats_the_old_sources_like_the_old_rule() -> None:
    old, new = judge.RULE_2026_11_05, judge.RULE_2026_11_06
    for name in ("keep_attack_flips", "revert_attack_flips", "keep_harmful_flips"):
        assert getattr(old, name) <= getattr(new, name)
    olds = {"hackaprompt", "mosscap", "satml", "wild_jb", "wildjailbreak", "salad", "salad_base",
            "wildchat", "ultrachat", "wild_regular", "gandalf_sum", "jbb_harmful", "jbb_benign",
            "wildjailbreak_benign", "wildjailbreak_harmful"}  # fmt: skip
    added = (new.keep_attack_flips - old.keep_attack_flips) | new.trust_attack | new.trust_harmful
    assert not added & olds
