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
import re
from collections.abc import Iterator
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


def training_sources(ids: list[str] | None = None) -> list[Source]:
    return [TRAINING[i] for i in ids] if ids else list(TRAINING.values())
