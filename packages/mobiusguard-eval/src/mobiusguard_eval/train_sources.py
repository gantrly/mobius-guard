"""Training sources for the v0.2 classifier (decision 0012, docs/training-data.md).

The model has two outputs, so each item has two labels: ``label`` (1 = an injection or a
jailbreak) and ``meta["harmful"]`` ("1" = a harmful request, "0" = not, "" = unknown, which
the harmful output's loss skips). None of these is an evaluation source: the suite stays
held out. Licences, revisions and
columns were checked against each source on 2026-11-04. Two sets are gated on Hugging Face
(``gated=True`` in the notes): download them where a logged-in account has accepted their
terms, and copy the cached files to the training machine, never the token.
"""

from __future__ import annotations

import csv
import importlib
import json
import random
import re
from collections import defaultdict
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, cast

from .items import ATTACK, BENIGN, Item, make_item
from .ledger import TRAINING, Remote, Source, register


def _rows_parquet(path: Path, columns: list[str] | None = None) -> Iterator[dict[str, Any]]:
    pq: Any = importlib.import_module("pyarrow.parquet")
    yield from cast("list[dict[str, Any]]", pq.read_table(path, columns=columns).to_pylist())


def _hf(repo: str, revision: str, *paths: str) -> tuple[Remote, ...]:
    return tuple(Remote("hf_dataset", repo, p, revision) for p in paths)


def junk(text: str) -> bool:
    """Too short, or one character repeated ("aaaa…"): not a usable example either way."""
    s = text.strip()
    return len(s) < 8 or len(set(s)) < 5


def _keep(text: object) -> str | None:
    s = text if isinstance(text, str) else ""
    return None if junk(s) else s


def _json_rows(path: Path) -> Iterator[dict[str, Any]]:
    """A JSON array, or JSON Lines (one object per line), read either way."""
    with path.open(encoding="utf-8") as f:
        head = f.read(1)
        while head.isspace():
            head = f.read(1)
        f.seek(0)
        if head == "[":
            yield from cast("list[dict[str, Any]]", json.load(f))
            return
        for line in f:
            if line.strip():
                yield cast("dict[str, Any]", json.loads(line))


def _add(source: Source) -> None:
    register(source, ledger=TRAINING)


def _m(harmful: str, **extra: str) -> dict[str, str]:
    return {"harmful": harmful, **extra}


HARMFUL_KEY = "harmful"


# ------------------------------------------------------------------------------ attacks


def _hackaprompt(paths: list[Path]) -> Iterator[Item]:
    cols = ["user_input", "correct", "level", "model", "dataset"]
    for r in _rows_parquet(paths[0], cols):
        if r["correct"] and (text := _keep(r["user_input"])):
            meta = _m("0", level=str(r["level"]), model=str(r["model"]), set=str(r["dataset"]))
            yield make_item(text, ATTACK, "hackaprompt", lang="en", meta=meta)


_add(
    Source(
        id="hackaprompt",
        title="HackAPrompt (successful submissions)",
        homepage="https://huggingface.co/datasets/hackaprompt/hackaprompt-dataset",
        licence="MIT",
        role="attack",
        files=_hf(
            "hackaprompt/hackaprompt-dataset",
            "25b87fbedfb86840abaf8cd09af7a029208a971a",
            "hackaprompt.parquet",
        ),
        parse=_hackaprompt,
        notes="Gated. 601,757 competition submissions (2023); only the user inputs that made "
        "the model say the target phrase (correct=True) are used.",
    )
)

# Mosscap logs every prompt the game received, attacks or not. Keep the ones aimed at the
# secret or at the model's instructions; a hand check of 200 decides whether this is enough.
_MOSSCAP_CUES = re.compile(
    r"password|passw|secret|pass ?word|instruction|ignore|reveal|spell|letters?\b|hint|encod"
    r"|revers|translat|riddle|acrostic|system prompt|forget|pretend|role ?play|developer"
    r"|admin|bypass|rules|disregard|previous|above|override|jailbreak|\bdan\b",
    re.IGNORECASE,
)


def _mosscap(paths: list[Path]) -> Iterator[Item]:
    for path in paths:
        for r in _rows_parquet(path, ["prompt", "level"]):
            text = _keep(r["prompt"])
            if text and _MOSSCAP_CUES.search(text):
                yield make_item(text, ATTACK, "mosscap", meta=_m("0", level=str(r["level"])))


_add(
    Source(
        id="mosscap",
        title="Lakera Mosscap prompt injections (filtered)",
        homepage="https://huggingface.co/datasets/Lakera/mosscap_prompt_injection",
        licence="MIT",
        role="attack",
        files=_hf(
            "Lakera/mosscap_prompt_injection",
            "b7e495ff63373ff7f7dabc1e9390cf62b5838570",
            "data/train-00000-of-00001-07ae0ed17fa07cc1.parquet",
            "data/validation-00000-of-00001-e136a45438d15f16.parquet",
            "data/test-00000-of-00001-06acab2d6a2bcf9f.parquet",
        ),
        parse=_mosscap,
        notes="Every prompt sent to the DEF CON 31 game; kept only when it mentions the secret "
        "or the model's instructions (_MOSSCAP_CUES), checked by hand on a sample.",
    )
)


def _satml(paths: list[Path]) -> Iterator[Item]:
    for chat in _json_rows(paths[0]):
        if not chat.get("is_attack") or chat.get("is_evaluation"):
            continue
        for msg in cast("list[dict[str, Any]]", chat.get("history") or []):
            if msg.get("role") == "user" and (text := _keep(msg.get("content"))):
                yield make_item(text, ATTACK, "satml", meta=_m("0", model=str(chat.get("model"))))


_add(
    Source(
        id="satml",
        title="SaTML 2024 LLM CTF attack chats (attacker messages)",
        homepage="https://huggingface.co/datasets/ethz-spylab/ctf-satml24",
        licence="MIT",
        role="attack",
        files=_hf(
            "ethz-spylab/ctf-satml24", "11426babe61ee16b0efe7b55e0430359e0fc4235", "chat.json"
        ),
        parse=_satml,
        notes="137k chats in which attackers tried to extract a secret past a defended system "
        "prompt; the user turns of chats marked is_attack, without junk.",
    )
)

_WILD = ("TrustAIRLab/in-the-wild-jailbreak-prompts", "a10aab8eff1c73165a442d4464dce192bd28b9c5")


def _wild(paths: list[Path]) -> Iterator[Item]:
    attack = "jailbreak_" in str(paths[0])
    source = "wild_jb" if attack else "wild_regular"
    for r in _rows_parquet(paths[0], ["prompt", "platform"]):
        if text := _keep(r["prompt"]):
            # A jailbreak template's request is often a placeholder: harmful unknown.
            meta = _m("" if attack else "0", platform=str(r["platform"]))
            yield make_item(text, ATTACK if attack else BENIGN, source, meta=meta)


_add(
    Source(
        id="wild_jb",
        title="In-the-wild jailbreak prompts (2023-12-25)",
        homepage="https://huggingface.co/datasets/TrustAIRLab/in-the-wild-jailbreak-prompts",
        licence="MIT",
        role="attack",
        files=_hf(*_WILD, "jailbreak_2023_12_25/train-00000-of-00001.parquet"),
        parse=_wild,
        notes="Jailbreak prompts collected from Discord, Reddit and prompt sites (Shen et al., "
        "CCS 2024). The suite's jackhhao set came from similar sites: near duplicates of it "
        "are dropped by the builder.",
    )
)

_WJB = ("allenai/wildjailbreak", "5ddc12a7894f842b0619b8e1c7ee496b198af009", "train/train.tsv")


def _wildjailbreak_rows(path: Path) -> Iterator[dict[str, str]]:
    csv.field_size_limit(1 << 24)
    with path.open(encoding="utf-8", newline="") as f:
        yield from csv.DictReader(f, delimiter="\t")


def _wildjailbreak(paths: list[Path]) -> Iterator[Item]:
    for r in _wildjailbreak_rows(paths[0]):
        if r["data_type"] == "adversarial_harmful" and (text := _keep(r["adversarial"])):
            yield make_item(text, ATTACK, "wildjailbreak", lang="en", meta=_m("1"))


def _wildjailbreak_benign(paths: list[Path]) -> Iterator[Item]:
    for r in _wildjailbreak_rows(paths[0]):
        kind = r["data_type"]
        column = {"adversarial_benign": "adversarial", "vanilla_benign": "vanilla"}.get(kind)
        if column and (text := _keep(r[column])):
            yield make_item(
                text, BENIGN, "wildjailbreak_benign", lang="en", meta=_m("0", type=kind)
            )


def _wildjailbreak_harmful(paths: list[Path]) -> Iterator[Item]:
    for r in _wildjailbreak_rows(paths[0]):
        if r["data_type"] == "vanilla_harmful" and (text := _keep(r["vanilla"])):
            yield make_item(text, BENIGN, "wildjailbreak_harmful", lang="en", meta=_m("1"))


_add(
    Source(
        id="wildjailbreak",
        title="WildJailbreak (adversarial harmful)",
        homepage="https://huggingface.co/datasets/allenai/wildjailbreak",
        licence="ODC-BY-1.0",
        role="attack",
        files=_hf(*_WJB),
        parse=_wildjailbreak,
        notes="Gated (AI2 terms). Synthetic jailbreaks wrapping harmful requests: attack and "
        "harmful.",
    )
)
_add(
    Source(
        id="wildjailbreak_harmful",
        title="WildJailbreak (vanilla harmful)",
        homepage="https://huggingface.co/datasets/allenai/wildjailbreak",
        licence="ODC-BY-1.0",
        role="benign",
        files=_hf(*_WJB),
        parse=_wildjailbreak_harmful,
        notes="Gated. Plain harmful requests: harmful, but not an injection or a jailbreak "
        "(attack label 0), so the attack output learns the difference.",
    )
)
_add(
    Source(
        id="wildjailbreak_benign",
        title="WildJailbreak (adversarial and vanilla benign)",
        homepage="https://huggingface.co/datasets/allenai/wildjailbreak",
        licence="ODC-BY-1.0",
        role="benign",
        files=_hf(*_WJB),
        parse=_wildjailbreak_benign,
        notes="Gated. Harmless requests, plain and in jailbreak-style wording: a hard contrast.",
    )
)


def _salad(paths: list[Path]) -> Iterator[Item]:
    for r in _json_rows(paths[0]):
        if text := _keep(r.get("augq")):
            yield make_item(text, ATTACK, "salad", lang="en",
                            meta=_m("1", method=str(r.get("method"))))  # fmt: skip


def _salad_base(paths: list[Path]) -> Iterator[Item]:
    for r in _json_rows(paths[0]):
        if text := _keep(r.get("question")):
            yield make_item(text, BENIGN, "salad_base", lang="en", meta=_m("1"))


_add(
    Source(
        id="salad",
        title="Salad-Data attack-enhanced set",
        homepage="https://huggingface.co/datasets/OpenSafetyLab/Salad-Data",
        licence="Apache-2.0",
        role="attack",
        files=_hf(
            "OpenSafetyLab/Salad-Data",
            "d21a325e276a99bd69b1fbb8aa51a9f249486b72",
            "attack_enhanced_set.json",
        ),
        parse=_salad,
        notes="Harmful questions wrapped by jailbreak methods (GPTFuzz, AutoDAN, ...): attack "
        "and harmful. ProtectAI v2 trained on Salad-Data.",
    )
)
_add(
    Source(
        id="salad_base",
        title="Salad-Data base set (plain harmful questions)",
        homepage="https://huggingface.co/datasets/OpenSafetyLab/Salad-Data",
        licence="Apache-2.0",
        role="benign",
        files=_hf(
            "OpenSafetyLab/Salad-Data", "d21a325e276a99bd69b1fbb8aa51a9f249486b72", "base_set.json"
        ),
        parse=_salad_base,
        notes="Plain harmful questions: harmful, attack label 0. ProtectAI v2 trained on "
        "Salad-Data.",
    )
)

_JBB = ("JailbreakBench/JBB-Behaviors", "886acc352a31533ffbcf4ef22c744658688086fc")


def _jbb(paths: list[Path]) -> Iterator[Item]:
    harmful = "harmful-" in paths[0].name
    source = "jbb_harmful" if harmful else "jbb_benign"
    csv.field_size_limit(1 << 24)
    with paths[0].open(encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            if text := _keep(r.get("Goal")):
                meta = _m("1" if harmful else "0", category=r.get("Category", ""))
                yield make_item(text, BENIGN, source, lang="en", meta=meta)


_add(
    Source(
        id="jbb_harmful",
        title="JailbreakBench behaviors (harmful)",
        homepage="https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors",
        licence="MIT",
        role="benign",
        files=_hf(*_JBB, "data/harmful-behaviors.csv"),
        parse=_jbb,
        notes="100 harmful requests across ten categories: harmful, attack label 0. Some come "
        "from AdvBench and HarmBench.",
    )
)
_add(
    Source(
        id="jbb_benign",
        title="JailbreakBench behaviors (benign twins)",
        homepage="https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors",
        licence="MIT",
        role="benign",
        files=_hf(*_JBB, "data/benign-behaviors.csv"),
        parse=_jbb,
        notes="100 harmless requests on the same topics as the harmful ones: a hard contrast "
        "for the harmful output.",
    )
)


def _gandalf_sum(paths: list[Path]) -> Iterator[Item]:
    for path in paths:
        for r in _rows_parquet(path, ["text"]):
            if text := _keep(r["text"]):
                yield make_item(text, ATTACK, "gandalf_sum", lang="en", meta=_m("0"))


_add(
    Source(
        id="gandalf_sum",
        title="Lakera Gandalf summarization (indirect)",
        homepage="https://huggingface.co/datasets/Lakera/gandalf_summarization",
        licence="MIT",
        role="attack",
        files=_hf(
            "Lakera/gandalf_summarization",
            "8e213cc8dd65f099c61dc32dbcfdb2ff6b1c92d8",
            "data/train-00000-of-00001-44378fdb62cbf9b7.parquet",
            "data/validation-00000-of-00001-c7b174a69fca3472.parquet",
            "data/test-00000-of-00001-1696577a5023b698.parquet",
        ),
        parse=_gandalf_sum,
        notes="Texts given to a summarising Gandalf level that hide an instruction to reveal "
        "the password: indirect injection.",
    )
)

# ------------------------------------------------------------------------------ benign

_LANGS = {
    "English": "en", "Chinese": "zh", "Russian": "ru", "French": "fr", "Spanish": "es",
    "Portuguese": "pt", "German": "de", "Arabic": "ar", "Italian": "it", "Turkish": "tr",
    "Japanese": "ja", "Korean": "ko", "Polish": "pl", "Vietnamese": "vi", "Indonesian": "id",
    "Persian": "fa", "Dutch": "nl", "Ukrainian": "uk", "Hindi": "hi",
}  # fmt: skip


def _wildchat(paths: list[Path]) -> Iterator[Item]:
    cols = ["conversation", "language", "toxic", "openai_moderation"]
    for r in _rows_parquet(paths[0], cols):
        if r["toxic"]:
            continue
        turns = cast("list[dict[str, Any]]", r["conversation"] or [])
        i, first = next(((i, t) for i, t in enumerate(turns) if t.get("role") == "user"),
                        (0, None))  # fmt: skip
        if first and (text := _keep(first.get("content"))):
            lang = _LANGS.get(str(r["language"]), "other")
            mod = cast("list[dict[str, Any]]", r["openai_moderation"] or [])
            # Real users do ask for harmful things: a message the moderation API flagged is
            # not known to be harmless, so its harmful label is left unknown.
            flagged = bool(mod[i].get("flagged")) if i < len(mod) else True
            yield make_item(text, BENIGN, "wildchat", lang=lang, meta=_m("" if flagged else "0"))


_add(
    Source(
        id="wildchat",
        title="WildChat-1M (first user turns, one shard)",
        homepage="https://huggingface.co/datasets/allenai/WildChat-1M",
        licence="ODC-BY-1.0",
        role="benign",
        files=_hf(
            "allenai/WildChat-1M",
            "7d6490e462285cf85d91eabea0f9a954fbddcd1f",
            "data/train-00000-of-00014.parquet",
        ),
        parse=_wildchat,
        languages=("multilingual",),
        notes="Real users' first messages to ChatGPT (2023-24), toxic-flagged ones left out. "
        "Real users also try jailbreaks: the builder drops items near a known attack.",
    )
)


def _ultrachat(paths: list[Path]) -> Iterator[Item]:
    for r in _rows_parquet(paths[0], ["prompt"]):
        if text := _keep(r["prompt"]):
            yield make_item(text, BENIGN, "ultrachat", lang="en", meta=_m("0"))


_add(
    Source(
        id="ultrachat",
        title="UltraChat 200k (first user turns, one shard)",
        homepage="https://huggingface.co/datasets/HuggingFaceH4/ultrachat_200k",
        licence="MIT",
        role="benign",
        files=_hf(
            "HuggingFaceH4/ultrachat_200k",
            "8049631c405ae6576f93f445c6b8166f76f5505a",
            "data/train_sft-00000-of-00003-a3ecf92756993583.parquet",
        ),
        parse=_ultrachat,
        notes="Synthetic multi-turn dialogues; the opening user prompt only.",
    )
)

_add(
    Source(
        id="wild_regular",
        title="In-the-wild regular prompts (2023-12-25)",
        homepage="https://huggingface.co/datasets/TrustAIRLab/in-the-wild-jailbreak-prompts",
        licence="MIT",
        role="benign",
        files=_hf(*_WILD, "regular_2023_12_25/train-00000-of-00001.parquet"),
        parse=_wild,
        notes="Ordinary prompts from the same communities as the jailbreaks: a hard contrast.",
    )
)


# ------------------------------------------------------------------- added 2026-11-06
# Indirect injection (decision 0012, "Order of training") and hard benign text for the
# harmful output: docs/research/2026-11-05-indirect-injection-datasets.md and
# 2026-11-06-over-refusal-datasets.md. Twins (an injected document and its clean version)
# share meta["pair"], so the build caps and splits them together.

# BrowseSafe++: web pages, each injected page paired with a clean control. Only the train
# split (CC BY 4.0); the test split's licence forbids training, so its files are never
# listed. Pages run to tens of thousands of characters and the injection sits anywhere,
# so each page becomes one window of about 512 tokens: on an injected page, a window
# that contains an injection fragment, at a random offset; on its control, a window of
# the same length from a random place. The Markdown view keeps an injection in only
# about a third of the pages (most hide in HTML), so Markdown windows come only from
# those pages; HTML windows can come from any page.
_BSP = ("perplexity-ai/browsesafe-plus-plus", "7674843074bf3b36c0a0209dfd06e03cf47743dd")
_BSP_COLUMNS = ("entry_id", "arm", "label", "split", "language_page", "page_type",
                "attack_type", "content_markdown", "content_html",
                "injection_text_fragments_json")  # fmt: skip
_BSP_FILES = tuple(
    Remote(
        "hf_dataset", _BSP[0], f"data/members-train-{i:04d}.parquet", _BSP[1], columns=_BSP_COLUMNS
    )
    for i in range(21)
)
_BSP_CANARY = "a3f0c1de-7b52-4e8e-9d61-2f84c5b9e017"
# About 900 characters fits 512 tokens for both bases (measured on a 300-page sample:
# 1,600 Markdown characters ran past 512 tokens on 44-48% of windows).
WINDOW_CHARS = {"content_markdown": 900, "content_html": 900}


def _snap(text: str, start: int, view: str) -> int:
    """Move a window's start to the next word (Markdown) or tag (HTML), if one is close."""
    stop = "<" if view == "content_html" else " \n"
    for i in range(start, min(start + 40, len(text))):
        if text[i] in stop:
            return i + (0 if view == "content_html" else 1)
    return start


def attack_window(text: str, fragments: list[str], width: int, rng: random.Random,
                  view: str) -> str | None:  # fmt: skip
    """A window of ``width`` characters that holds the most fragments whole (at least
    one), placed at a random offset around them; None when no fragment is in the text."""
    found = attack_window_at(text, fragments, width, rng, view)
    return found[1] if found else None


def attack_window_at(text: str, fragments: list[str], width: int, rng: random.Random,
                     view: str) -> tuple[float, str] | None:  # fmt: skip
    """``attack_window``, with where it starts as a fraction of the room the text has."""
    found = [(text.find(f), f) for f in fragments if f and f in text]
    if not found:
        return None
    best: tuple[int, int] = (0, -1)
    for off, frag in found:
        lo = max(0, off + len(frag) - width)
        start = rng.randint(lo, max(lo, off))
        held = sum(o >= start and o + len(f) <= start + width for o, f in found)
        if held > best[1]:
            best = (start, held)
    start = best[0]
    where = start / max(1, len(text) - width)
    snapped = _snap(text, start, view)
    window = text[snapped : snapped + width]
    if any(f in window for _, f in found):
        return where, window
    return where, text[start : start + width]


def control_window(text: str, width: int, rng: random.Random, view: str,
                   where: float | None = None) -> str:  # fmt: skip
    """A window of ``width`` characters: at ``where`` (a fraction of the room the text
    has, to match its injected twin's position), else at a random place."""
    room = max(0, len(text) - width)
    start = round(min(1.0, max(0.0, where)) * room) if where is not None else rng.randint(0, room)
    start = _snap(text, start, view)
    return text[start : start + width]


def _browsesafe(view: str, source: str) -> Callable[[list[Path]], Iterator[Item]]:
    width = WINDOW_CHARS[view]

    cols = ["entry_id", "arm", "label", "split", "language_page", "page_type", "attack_type",
            view, "injection_text_fragments_json"]  # fmt: skip

    def parse(paths: list[Path]) -> Iterator[Item]:
        # File by file, one view only: all pages with both views at once is several GB.
        # A pair's two pages are in the same file.
        for path in paths:
            pages: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
            for r in _rows_parquet(path, cols):
                if r["split"] == "train":
                    pages[r["entry_id"].rsplit("_", 1)[0]][r["arm"]] = r
            yield from _browsesafe_pairs(pages, view, source, width)

    return parse


def _browsesafe_pairs(pages: dict[str, dict[str, dict[str, Any]]], view: str, source: str,
                      width: int) -> Iterator[Item]:  # fmt: skip
    for pair, p in sorted(pages.items()):
        a, c = p.get("attack"), p.get("control")
        if not a or not c or a["label"] != "yes" or c["label"] != "no":
            continue
        rng = random.Random(f"{source}:{pair}")  # noqa: S311 - a sample, not a secret
        frags = [f for f in json.loads(a["injection_text_fragments_json"] or "[]")
                 if isinstance(f, str)]  # fmt: skip
        # The control's window sits at the same relative place as the attack's, so the
        # model can't tell them apart by which part of a page a window comes from.
        hit = attack_window_at(a[view] or "", frags, width, rng, view)
        if not hit:
            continue
        where, bad = hit
        good = control_window(c[view] or "", width, rng, view, where)
        if junk(good) or _BSP_CANARY in bad + good:
            continue
        if any(f and f in good for f in frags):
            continue  # the control must not hold the injection
        langs = [str(x) for x in cast("list[Any]", a["language_page"] or [])]
        lang = langs[0] if len(langs) == 1 else "und"
        common = {"pair": f"bsp:{pair}", "page_type": a["page_type"] or "", "view": view}
        yield make_item(bad, ATTACK, source, lang=lang,
                        meta=_m("", attack_type=a["attack_type"] or "", **common))  # fmt: skip
        yield make_item(good, BENIGN, source, lang=lang, meta=_m("0", **common))


for _view, _id, _cap in (
    ("content_markdown", "browsesafe_md", 0),
    ("content_html", "browsesafe_html", 10_000),
):
    _add(
        Source(
            id=_id,
            title=f"BrowseSafe++ train split, {'Markdown' if 'mark' in _view else 'HTML'} windows",
            homepage="https://huggingface.co/datasets/perplexity-ai/browsesafe-plus-plus",
            licence="CC-BY-4.0",
            role="mixed",
            files=_BSP_FILES,
            parse=_browsesafe(_view, _id),
            languages=("en", "es", "pt", "ru", "fr", "und"),
            cap=_cap,
            notes="gated=True. Injected web pages and their clean controls (pairs), train split "
            "only. The card's canary line asks that benchmark data stay out of training "
            "corpora; the train split is CC BY 4.0 and is used as training data for a "
            "detector, decided 2026-11-06. Columns fetched without the screenshots.",
        )
    )


# Nemotron agentic indirect injection: simulated tool-returned records (patient notes,
# orders, resumes...) with an injection written into one field. The record holding it is
# the attack; the same record with the injection removed is its twin.
def _holder(node: Any, needle: str) -> tuple[dict[str, Any], str] | None:
    """The innermost dict with a string field containing ``needle``, and that field."""
    if isinstance(node, dict):
        node_d = cast("dict[str, Any]", node)
        for v in node_d.values():
            if (inner := _holder(v, needle)) is not None:
                return inner
        for k, v in node_d.items():
            if isinstance(v, str) and needle in v:
                return node_d, k
    elif isinstance(node, list):
        for v in cast("list[Any]", node):
            if (inner := _holder(v, needle)) is not None:
                return inner
    return None


def _nemotron_ipi(paths: list[Path]) -> Iterator[Item]:
    for r in _json_rows(paths[0]):
        injection = cast("dict[str, Any]", r.get("injection") or {})
        inj = str(injection.get("injection_text") or "")
        if not inj or not (hit := _holder(r.get("environment"), inj)):
            continue
        record, key = hit
        clean = dict(record)
        clean[key] = re.sub(r"\s{2,}", " ", record[key].replace(inj, " ")).strip()
        bad = json.dumps(record, ensure_ascii=False)
        good = json.dumps(clean, ensure_ascii=False)
        pair = f"nemotron:{r['id']}"
        meta = {"pair": pair, "domain": str(r.get("domain", "")),
                "category": str(r.get("attack_category", ""))}  # fmt: skip
        yield make_item(bad, ATTACK, "nemotron_ipi", lang="en", meta=_m("", **meta))
        yield make_item(good, BENIGN, "nemotron_ipi", lang="en", meta=_m("0", **meta))


_add(
    Source(
        id="nemotron_ipi",
        title="Nemotron RL agentic indirect prompt injection v1",
        homepage="https://huggingface.co/datasets/nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1",
        licence="CC-BY-4.0",
        role="mixed",
        files=_hf(
            "nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1",
            "d738d4f361cc38bb4d7a42b9066776dade5332f5",
            "train.jsonl",
        ),
        parse=_nemotron_ipi,
        notes="Synthetic enterprise records with an injection in one field, rewritten until it "
        "fooled a model; the record with the injection removed is its clean twin.",
    )
)


# Tool responses with one injection inserted into a field, paired by response_id. The
# injections come from neuralchemy/Prompt-injection-dataset; only those from its parts
# with a permissive licence are kept (its WildGuard part is "Research").
_NEURALCHEMY = ("neuralchemy/Prompt-injection-dataset", "7d70432dfcf47a821612cbf9d34e9d9e3ad20e75")
_NEURALCHEMY_OK = frozenset({"neuralchemy_v1", "original", "hackaprompt", "harmbench"})


def _rgeada(paths: list[Path]) -> Iterator[Item]:
    sources: dict[str, set[str]] = defaultdict(set)
    for p in paths[1:]:
        for r in _rows_parquet(p, ["text", "label", "source"]):
            if r["label"] == 1:
                sources[str(r["text"]).strip()].add(str(r["source"]))
    csv.field_size_limit(1 << 24)
    rows: dict[str, dict[str, dict[str, str]]] = defaultdict(dict)
    with paths[0].open(encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            rows[r["response_id"]][r["label"]] = r
    width = WINDOW_CHARS["content_markdown"]
    for rid, p in sorted(rows.items()):
        bad, good = p.get("injection"), p.get("safe")
        if not bad or not good:
            continue
        origin = sources.get(bad["injection"].strip(), set())
        if not origin or not origin <= _NEURALCHEMY_OK:
            continue
        meta = {"pair": f"rgeada:{rid}", "injection_source": "+".join(sorted(origin))}
        t, u, inj = bad["text"], good["text"], bad["injection"]
        if inj and inj not in t:
            inj = json.dumps(inj, ensure_ascii=False)[1:-1]  # inside a JSON string: escaped
        if len(t) > width and inj and (o := t.find(inj)) >= 0:
            # A long response: a window around the injection. The clean response is the
            # same text without it, so its twin is the same span when the two agree before
            # the injection, else a window from a random place.
            rng = random.Random(f"rgeada:{rid}")  # noqa: S311 - a sample, not a secret
            start = max(0, min(o - rng.randint(0, max(0, width - len(inj))), len(t) - width))
            aligned = u[:o] == t[:o]
            t = t[start : start + width]
            if aligned:
                u = u[start : start + width - len(inj)]
            else:
                u = control_window(u, width, rng, "content_markdown")
        elif len(t) > width:
            continue  # long, and the injection can't be found: truncation might cut it off
        if (t := _keep(t)) and (u := _keep(u)):
            yield make_item(t, ATTACK, "rgeada_tool", lang="en", meta=_m("", **meta))
            yield make_item(u, BENIGN, "rgeada_tool", lang="en", meta=_m("0", **meta))


_add(
    Source(
        id="rgeada_tool",
        title="Tool-response injections (rgeada), permissive injections only",
        homepage="https://huggingface.co/datasets/rgeada/tool-response-injections",
        licence="Apache-2.0",
        role="mixed",
        files=(
            Remote(
                "hf_dataset",
                "rgeada/tool-response-injections",
                "tool_response_injections_train.csv",
                "39050de797f2694f0d72e1086003154de1919379",
            ),
            *_hf(
                *_NEURALCHEMY,
                "full/train-00000-of-00001.parquet",
                "full/validation-00000-of-00001.parquet",
                "full/test-00000-of-00001.parquet",
            ),
        ),
        parse=_rgeada,
        notes="Tool responses (Apache-2.0, interstellarninja/tool-calls-single-reasoning) with "
        "an injection from neuralchemy/Prompt-injection-dataset (Apache-2.0). Injections from "
        "its WildGuard part (licence 'Research'), or not traced to a part, are left out.",
    )
)


# ------------------------------------------------------ hard benign for the harmful output
_AEGIS = ("nvidia/Aegis-AI-Content-Safety-Dataset-2.0", "d86bb8bedff51d25ac834ab7838f1cc61acb7a2c")


def _aegis(paths: list[Path]) -> Iterator[Item]:
    seen: set[str] = set()
    for path in paths:
        for r in _json_rows(path):
            if (
                r.get("reconstruction_id_if_redacted") is not None
                or r.get("prompt_label_source") != "human"
            ):
                continue
            text = _keep(r.get("prompt"))
            if not text or text == "REDACTED" or text in seen:
                continue
            seen.add(text)
            harmful = {"safe": "0", "unsafe": "1"}.get(str(r.get("prompt_label")), "")
            if harmful:
                cats = str(r.get("violated_categories") or "")
                yield make_item(
                    text, BENIGN, "aegis2", lang="en", meta=_m(harmful, categories=cats)
                )


_add(
    Source(
        id="aegis2",
        title="Aegis 2.0 content safety (NVIDIA), prompts",
        homepage="https://huggingface.co/datasets/nvidia/Aegis-AI-Content-Safety-Dataset-2.0",
        licence="CC-BY-4.0",
        role="mixed",
        files=_hf(*_AEGIS, "train.json", "validation.json"),
        parse=_aegis,
        notes="Prompts from red-team attempts with human safe/unsafe labels: the safe ones sound "
        "risky, on the same topics as the unsafe. Redacted rows dropped. Its jailbreak "
        "prompts arrive with attack label 0; the judges set their attack label.",
    )
)


def _phtest(paths: list[Path]) -> Iterator[Item]:
    csv.field_size_limit(1 << 24)
    with paths[0].open(encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            if r.get("Harmfulness") == "harmless" and (text := _keep(r.get("Request"))):
                yield make_item(text, BENIGN, "phtest", lang="en", meta=_m("0"))


_add(
    Source(
        id="phtest",
        title="PHTest pseudo-harmful prompts (harmless only)",
        homepage="https://huggingface.co/datasets/furonghuang-lab/PHTest",
        licence="MIT",
        role="benign",
        files=_hf(
            "furonghuang-lab/PHTest", "edb80210812ecc7dab2219aa2e70921710c01888", "PHTest.csv"
        ),
        parse=_phtest,
        notes="Harmless prompts made to trigger refusals in real models, human-labelled. The "
        "'controversial' ones are left out. The repository has no licence file; the card says MIT.",
    )
)

_CSE = "https://raw.githubusercontent.com/meta-llama/PurpleLlama/f64eebd53003a87d9c2d2a3a712133534c214c8d/CybersecurityBenchmarks/datasets"


def _cse(paths: list[Path]) -> Iterator[Item]:
    frr = paths[0].name == "mitre_frr.json"
    source = "cse_frr" if frr else "cse_mitre"
    for r in json.loads(paths[0].read_text(encoding="utf-8")):
        text = _keep(r.get("mutated_prompt") if frr else r.get("base_prompt"))
        if text:
            meta = _m("0" if frr else "1", category=str(r.get("mitre_category", "")))
            yield make_item(text, BENIGN, source, lang="en", meta=meta)


_add(
    Source(
        id="cse_frr",
        title="CyberSecEval MITRE false-refusal prompts (Meta)",
        homepage="https://github.com/meta-llama/PurpleLlama/tree/main/CybersecurityBenchmarks",
        licence="MIT",
        role="benign",
        files=(
            Remote(
                "url",
                f"{_CSE}/mitre_frr/mitre_frr.json",
                sha256="7a9b400bdf5ddbb36d5e7c3e8f6b5adb5d13125b8d03be66fd252a0f20b79d15",
            ),
        ),
        parse=_cse,
        notes="Borderline security-research requests that are fine to answer. Written by "
        "Llama-2-70b-chat; Llama 2's licence limits using outputs to improve other large "
        "language models, and this classifier is not one.",
    )
)
_add(
    Source(
        id="cse_mitre",
        title="CyberSecEval MITRE attack-help prompts (Meta), base prompts",
        homepage="https://github.com/meta-llama/PurpleLlama/tree/main/CybersecurityBenchmarks",
        licence="MIT",
        role="benign",
        files=(
            Remote(
                "url",
                f"{_CSE}/mitre/mitre_benchmark_100_per_category_with_augmentation.json",
                sha256="0dc5ef0e4dc0f6937c1090473d85ee0d2800c83c5e9ccca568a3da7176b97d6a",
            ),
        ),
        parse=_cse,
        notes="Requests for help with cyber attacks in ten ATT&CK categories: harmful, attack "
        "label 0. Only the short base prompts; the augmented versions are left out.",
    )
)

_COCONOT = ("allenai/coconot", "2cbe16aabf9069f17e48c8daad8aeabc29469eb7")
_COCONOT_SAFETY = frozenset({"dangerous or sensitive topics", "privacy violations",
                             "triggers for offensive language"})  # fmt: skip


def _coconot(paths: list[Path]) -> Iterator[Item]:
    for path in paths:
        contrast = "/contrast/" in path.as_posix() or "pref" in path.as_posix()
        for r in _rows_parquet(path, ["prompt", "category", "subcategory"]):
            if r["subcategory"] in _COCONOT_SAFETY and (text := _keep(r["prompt"])):
                meta = _m("0" if contrast else "1", subcategory=str(r["subcategory"]),
                          set="contrast" if contrast else "original")  # fmt: skip
                yield make_item(text, BENIGN, "coconot", lang="en", meta=meta)


_add(
    Source(
        id="coconot",
        title="CoCoNot (AI2): requests with safety concerns and their contrast set",
        homepage="https://huggingface.co/datasets/allenai/coconot",
        licence="ODC-BY-1.0",
        role="mixed",
        files=_hf(
            *_COCONOT,
            "contrast/test-00000-of-00001.parquet",
            "pref/train-00000-of-00001.parquet",
            "original/train-00000-of-00001.parquet",
        ),
        parse=_coconot,
        notes="Safety subcategories only (dangerous or sensitive topics, privacy, offensive "
        "triggers): the original requests are harmful, the contrast set's look like them but "
        "are fine. Its WildChat items are left out (already a source). LICENSE.md is ODC-By.",
    )
)


def training_sources(ids: list[str] | None = None) -> list[Source]:
    return [TRAINING[i] for i in ids] if ids else list(TRAINING.values())
