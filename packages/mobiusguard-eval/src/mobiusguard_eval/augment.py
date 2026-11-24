"""Disguised training copies that carry no label, and the harmless test sets that check it.

Fortress v1 caught 99.5% of the suite's spaced-out attacks, but only 53% of the same
attacks in plain text, and it blocks 94% of harmless messages once they are spaced out: it
had learned "spaced letters = attack", because the only spaced texts it trained on were 36
attacks. v2 added 99 harmless spaced messages (wildchat_dev) and learned the opposite. A
disguise must tell the model nothing, so here the same share of attack and harmless items
gets a disguised copy, and the model can only score a disguised text by what it says.

Rules:

- Each item gets at most one copy, chosen by a hash of its ID; each disguise takes
  ``RATE`` of the eligible items, whatever their label.
- Only texts of at most ``MAX_CHARS`` characters are copied: a disguise multiplies the
  token count, and a cut copy could lose the part that made it an attack.
- A copy keeps its original's label, split and cluster, so no copy sits in ``val`` while
  its original is in ``train``.
- The disguises are training variants, not the suite's (``obfuscate.py``): other
  separators, partial spacing, a larger leetspeak map, other invisible characters. Look-
  alike letters are not used at all, so the suite's ``obf:homoglyph`` stays a disguise the
  model never saw: the honest check that it reads through disguises in general.

Group weight: the harmless developer and tool-call sources added for v2 (``DEV_GROUP``)
hold 33k items and pulled everything they share with attacks towards harmless. Their loss
weight makes the group count as one source at the build's per-source cap (``CAP``).

``extend_suite`` adds harmless test items to a copy of the suite: the calibration source's
test messages disguised with the suite's own transforms, and the developer check's eight
messages. The calibration half is unchanged, so thresholds are too.
"""

from __future__ import annotations

import hashlib
import json
import random
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

from .items import Item, read_jsonl, write_jsonl
from .obfuscate import TRANSFORMS as SUITE_TRANSFORMS
from .obfuscate import item_rng as suite_rng
from .train_data import CAP

RATE = 0.04  # per disguise, of the eligible items
MAX_CHARS = 450
DEV_GROUP = frozenset({
    "toucan", "glaive_fc", "wildchat_dev", "dev_secrets", "when2call", "toolace", "hermes_fc",
    "magicoder", "self_oss", "opencodeinstruct", "codefeedback",
})  # fmt: skip
HELD_OUT = "homoglyph"  # never used in training: the suite's check of an unseen disguise

_LEET = {"a": "4@", "e": "3", "i": "1!", "o": "0", "s": "5$", "t": "7", "g": "9", "b": "8",
         "l": "1", "z": "2"}  # fmt: skip
_INVISIBLE = ("​", "‌", "‍", "⁠", "﻿")


def seeded(key: str) -> random.Random:
    seed = int.from_bytes(hashlib.sha256(f"augment:{key}".encode()).digest()[:8], "big")
    return random.Random(seed)  # noqa: S311 - reproducible training data, not security


def _unit(key: str) -> float:
    return (
        int.from_bytes(hashlib.sha256(f"augment-pick:{key}".encode()).digest()[:8], "big") / 2**64
    )


def spaced(text: str, rng: random.Random) -> str:
    """Letters apart, three styles: all words, hyphen or dot joined, or about half the words."""
    style = rng.randrange(3)
    words = text.split(" ")
    if style == 0:
        return rng.choice(("  ", "   ")).join(" ".join(w) for w in words)
    if style == 1:
        sep = rng.choice("-.")
        return " ".join(sep.join(w) for w in words)
    return " ".join(" ".join(w) if rng.random() < 0.5 else w for w in words)


def leetspeak(text: str, rng: random.Random) -> str:
    """Swap some of the swappable letters (a share drawn per text) for digits or symbols."""
    p = rng.uniform(0.5, 1.0)
    out: list[str] = []
    for c in text:
        subs = _LEET.get(c.lower())
        out.append(rng.choice(subs) if subs and rng.random() < p else c)
    return "".join(out)


def zero_width(text: str, rng: random.Random) -> str:
    """Invisible characters after a share of the letters (drawn per text), some after spaces."""
    p = rng.uniform(0.1, 0.5)
    out: list[str] = []
    for c in text:
        out.append(c)
        if (c.isalpha() and rng.random() < p) or (c == " " and rng.random() < p / 2):
            out.append(rng.choice(_INVISIBLE))
    return "".join(out)


TRAIN_TRANSFORMS: dict[str, Callable[[str, random.Random], str]] = {
    "spaced": spaced,
    "leetspeak": leetspeak,
    "zero_width": zero_width,
}
assert HELD_OUT not in TRAIN_TRANSFORMS  # noqa: S101 - a design rule, checked at import


def pick(it: Item) -> str | None:
    """The disguise this item's copy gets, or None for no copy."""
    if len(it.text) > MAX_CHARS or it.meta.get("augmented"):
        return None
    u = _unit(it.id)
    names = list(TRAIN_TRANSFORMS)
    k = int(u / RATE)
    return names[k] if k < len(names) else None


def disguise(it: Item, name: str) -> Item:
    text = TRAIN_TRANSFORMS[name](it.text, seeded(f"{it.id}|{name}"))
    return replace(it, id=f"{it.id}~aug:{name}", text=text,
                   meta={**it.meta, "augmented": name, "original": it.id})  # fmt: skip


def group_weight(items: Sequence[Item]) -> float:
    n = sum(it.source in DEV_GROUP for it in items)
    return min(1.0, CAP / n) if n else 1.0


def weigh(it: Item, w: float) -> Item:
    if it.source not in DEV_GROUP or w >= 1.0:
        return it
    return replace(it, meta={**it.meta, "weight": f"{w:.4f}"})


def augment(data: Path, out: Path) -> dict[str, Any]:
    """Write ``out/{train,val}.jsonl`` and ``summary.json``: the items of ``data`` with
    their group weights, plus one disguised copy for the picked items."""
    parts = {p: list(read_jsonl(data / f"{p}.jsonl")) for p in ("train", "val")}
    w = group_weight([it for items in parts.values() for it in items])
    out.mkdir(parents=True, exist_ok=True)
    counts: Counter[str] = Counter()
    ids: list[str] = []
    for part, items in parts.items():
        result: list[Item] = []
        for it in items:
            it = weigh(it, w)
            result.append(it)
            if name := pick(it):
                result.append(disguise(it, name))
                counts[f"{name}/{'attack' if it.label else 'benign'}/{part}"] += 1
        write_jsonl(out / f"{part}.jsonl", result)
        ids += [f"{it.id}\t{it.meta.get('weight', '1')}" for it in result]
        counts[f"items/{part}"] = len(result)
    base = json.loads((data / "summary.json").read_text())
    summary: dict[str, Any] = {
        **{k: base[k] for k in ("from_build", "suite_ids_sha256", "judges", "rule") if k in base},
        "from_data": str(data),
        "from_ids_sha256": base.get("ids_sha256"),
        "augment": {
            "rate": RATE,
            "max_chars": MAX_CHARS,
            "transforms": sorted(TRAIN_TRANSFORMS),
            "held_out": HELD_OUT,
            "dev_group": sorted(DEV_GROUP),
            "dev_group_weight": round(w, 4),
        },
        "counts": dict(sorted(counts.items())),
        # IDs and weights: two sets with the same items but other weights are other data.
        "ids_sha256": hashlib.sha256("\n".join(sorted(ids)).encode()).hexdigest(),
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


EXTRA_PER_DISGUISE = 1_000
BENIGN_DISGUISES = ("spaced", "leetspeak", "homoglyph", "zero_width")  # base64 adds an order


def extend_suite(suite: Path, out: Path, calibration_source: str = "oasst") -> dict[str, Any]:
    """A copy of the suite plus harmless test items: disguised calibration-source test
    messages (``obf-benign:<name>``, the suite's own transforms) and the developer check's
    eight messages (``dev_check``). Thresholds come from the unchanged calibration half."""
    from .dev_texts import TEXTS

    items = list(read_jsonl(suite / "items.jsonl"))
    pool = [it for it in items if it.source == calibration_source and it.split == "test"
            and it.label == 0 and len(it.text) >= 40]  # fmt: skip
    pool.sort(key=lambda it: hashlib.sha256(f"benign-obf:{it.id}".encode()).hexdigest())
    chosen = pool[:EXTRA_PER_DISGUISE]
    extra: list[Item] = []
    for name in BENIGN_DISGUISES:
        for it in chosen:
            fam = f"obf-benign:{name}"
            extra.append(replace(it, id=f"{it.id}~benign:{name}", source=fam, family=fam,
                                 text=SUITE_TRANSFORMS[name](it.text, suite_rng(it.id, name)),
                                 meta={**it.meta, "original": it.id}))  # fmt: skip
    for i, (name, text) in enumerate(TEXTS):
        extra.append(Item(id=f"dev_check:{i}", text=text, label=0, source="dev_check",
                          family="dev_check", lang="en", split="test", cluster=f"dev_check:{i}",
                          meta={"name": name}))  # fmt: skip
    out.mkdir(parents=True, exist_ok=True)
    write_jsonl(out / "items.jsonl", sorted(items + extra, key=lambda it: it.id))
    manifest = {
        "from_suite": str(suite),
        "from_ids_sha256": hashlib.sha256("\n".join(it.id for it in items).encode()).hexdigest(),
        "added": dict(Counter(it.source for it in extra)),
        "items": len(items) + len(extra),
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest
