"""The built-in sources (v0.1 starter set, decision 0009).

Licences, revisions and training use were checked against each source's own card, licence
file or paper on 2026-10-27. ``trained_on_by`` lists detectors whose published training
data includes the source; where a model's training data is not fully published, the notes
say so. Revisions are full commit hashes.
"""

from __future__ import annotations

import csv
import hashlib
import importlib
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

from .items import ATTACK, BENIGN, Item, Label, make_item
from .ledger import Remote, Source, register

PROTECTAI = "protectai-v2"
PIGUARD = "piguard"
_PROTECTAI_UNKNOWN = (
    "ProtectAI v2 also trained on 15 datasets it does not name, so its contamination here "
    "is unknown."
)


def _rows_parquet(path: Path) -> Iterator[dict[str, Any]]:
    pq: Any = importlib.import_module("pyarrow.parquet")
    yield from cast("list[dict[str, Any]]", pq.read_table(path).to_pylist())


def _rows_csv(path: Path) -> Iterator[dict[str, str]]:
    csv.field_size_limit(1 << 24)
    with path.open(encoding="utf-8", newline="") as f:
        yield from csv.DictReader(f)


def _hf(repo: str, revision: str, *paths: str) -> tuple[Remote, ...]:
    return tuple(Remote("hf_dataset", repo, p, revision) for p in paths)


def _keep(text: object) -> str | None:
    s = text if isinstance(text, str) else ""
    return s if s.strip() else None


# ------------------------------------------------------------------------------ attacks


def _deepset(paths: list[Path]) -> Iterator[Item]:
    for path in paths:
        split = "train" if "train-" in path.name else "test"
        for r in _rows_parquet(path):
            if text := _keep(r["text"]):
                label: Label = ATTACK if r["label"] == 1 else BENIGN
                yield make_item(text, label, "deepset", meta={"original_split": split})


register(
    Source(
        id="deepset",
        title="deepset/prompt-injections",
        homepage="https://huggingface.co/datasets/deepset/prompt-injections",
        licence="CC-BY-4.0",
        role="mixed",
        files=_hf(
            "deepset/prompt-injections",
            "4f61ecb038e9c3fb77e21034b22511b523772cdd",
            "data/train-00000-of-00001-9564e8b05b4757ab.parquet",
            "data/test-00000-of-00001-701d16158af87368.parquet",
        ),
        parse=_deepset,
        languages=("en", "de"),
        trained_on_by=(PIGUARD,),
        notes="Card metadata says both Apache-2.0 and CC-BY-4.0; we follow the stricter. "
        "PIGuard trained on the train split (546 rows). About a third is German. "
        + _PROTECTAI_UNKNOWN,
    )
)


def _gandalf(paths: list[Path]) -> Iterator[Item]:
    for path in paths:
        for r in _rows_parquet(path):
            if text := _keep(r["text"]):
                yield make_item(text, ATTACK, "gandalf")


register(
    Source(
        id="gandalf",
        title="Lakera/gandalf_ignore_instructions",
        homepage="https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions",
        licence="MIT",
        role="attack",
        files=_hf(
            "Lakera/gandalf_ignore_instructions",
            "04737b65e90a6794ec227012e4a255a7def6344b",
            "data/train-00000-of-00001-ded53be747ff55cd.parquet",
            "data/validation-00000-of-00001-94481a2a09ff2fff.parquet",
            "data/test-00000-of-00001-bc92128b9288a6d1.parquet",
        ),
        parse=_gandalf,
        notes="Player attempts at the Gandalf game; all labelled attacks, with some noise the "
        "card acknowledges. " + _PROTECTAI_UNKNOWN,
    )
)


def _jackhhao(paths: list[Path]) -> Iterator[Item]:
    for r in _rows_csv(paths[0]):
        if text := _keep(r["prompt"]):
            yield make_item(text, ATTACK if r["type"] == "jailbreak" else BENIGN, "jackhhao")


register(
    Source(
        id="jackhhao",
        title="jackhhao/jailbreak-classification",
        homepage="https://huggingface.co/datasets/jackhhao/jailbreak-classification",
        licence="Apache-2.0",
        role="mixed",
        files=_hf(
            "jackhhao/jailbreak-classification",
            "2f2ceeb39658696fd3f462403562b6eea5306287",
            "default/jailbreak_dataset_full.csv",
        ),
        parse=_jackhhao,
        trained_on_by=(PROTECTAI, PIGUARD),
        notes="Jailbreak prompts (role-play, DAN-style) and ordinary prompts; jailbreaks, not "
        "injections. Both baselines trained on it.",
    )
)


def _spml(paths: list[Path]) -> Iterator[Item]:
    for r in _rows_csv(paths[0]):
        if text := _keep(r["User Prompt"]):
            label: Label = ATTACK if r["Prompt injection"].strip() == "1" else BENIGN
            yield make_item(text, label, "spml", meta={"degree": r.get("Degree", "")})


register(
    Source(
        id="spml",
        title="SPML chatbot prompt injection",
        homepage="https://huggingface.co/datasets/reshabhs/SPML_Chatbot_Prompt_Injection",
        licence="MIT",
        role="mixed",
        files=_hf(
            "reshabhs/SPML_Chatbot_Prompt_Injection",
            "02ce8084e979bc7d4c24ee35d22ecb7f2db96ff5",
            "spml_prompt_injection.csv",
        ),
        parse=_spml,
        notes="User prompts only (the system prompt column is context). GPT-4 generated; about "
        "a quarter of rows derive from Gandalf, so near duplicates of that set are expected. "
        + _PROTECTAI_UNKNOWN,
    )
)

_BIPIA = "https://raw.githubusercontent.com/microsoft/BIPIA/a004b69ec0dd446e0afd461d98cb5e96e120a5d0/benchmark"


def _bipia(paths: list[Path]) -> Iterator[Item]:
    for path in paths:
        kind = "code" if "code_" in path.name else "text"
        data = cast("dict[str, list[str]]", json.loads(path.read_text(encoding="utf-8")))
        for category, attacks in data.items():
            for text in attacks:
                yield make_item(text, ATTACK, "bipia", meta={"kind": kind, "category": category})


register(
    Source(
        id="bipia",
        title="BIPIA test attacks (text and code)",
        homepage="https://github.com/microsoft/BIPIA",
        licence="MIT",
        role="attack",
        files=(
            Remote(
                "url",
                f"{_BIPIA}/text_attack_test.json",
                sha256="75750e7b4e8b34e8f9d88d89b357aeaaf02bd07f9e493ccd37eda74a0cd7c7f8",
            ),
            Remote(
                "url",
                f"{_BIPIA}/code_attack_test.json",
                sha256="892545c5aaec0645b1ded65dc7816b3d70e9ef4eadcba2301a7a3db93676b6e0",
            ),
        ),
        parse=_bipia,
        redistributable=False,
        notes="Instructions an attacker plants in external content (emails, web pages, code), "
        "used here without their surrounding context, so some read like ordinary requests. "
        "The repo is MIT except third-party data under benchmark/; these files are not among "
        "the listed exceptions, but we do not redistribute them. PIGuard trained on BIPIA's "
        "train attacks, not these. " + _PROTECTAI_UNKNOWN,
    )
)

_LLMAIL = ("microsoft/llmail-inject-challenge", "1063bdf01ec8762b812d5e06ee768a06faa5a6f7")
LLMAIL_SAMPLE = 3000


def _llmail(paths: list[Path]) -> Iterator[Item]:
    data = cast("dict[str, dict[str, str]]", json.loads(paths[0].read_text(encoding="utf-8")))
    attacks = [t for t, v in data.items() if v.get("attack_attempt") == "True" and _keep(t)]
    # A fixed sample, chosen by hash so it doesn't depend on file order.
    attacks.sort(key=lambda t: hashlib.sha256(t.encode()).hexdigest())
    for text in attacks[:LLMAIL_SAMPLE]:
        yield make_item(text, ATTACK, "llmail", meta={"reason": data[text].get("reason", "")})


register(
    Source(
        id="llmail",
        title="LLMail-Inject, phase 2 labelled submissions (sample)",
        homepage="https://huggingface.co/datasets/microsoft/llmail-inject-challenge",
        licence="MIT",
        role="attack",
        files=_hf(*_LLMAIL, "data/labelled_unique_submissions_phase2.json"),
        parse=_llmail,
        notes=f"Emails written by people trying to make an email assistant leak data (an "
        f"adaptive challenge, 2025). A fixed {LLMAIL_SAMPLE:,}-item sample of entries judged "
        f"to be attack attempts; 'attempt' does not mean the attack succeeded. "
        + _PROTECTAI_UNKNOWN,
    )
)

# ------------------------------------------------------------------------------ benign


def _llmail_benign(paths: list[Path]) -> Iterator[Item]:
    for text in cast("list[str]", json.loads(paths[0].read_text(encoding="utf-8"))):
        if _keep(text):
            yield make_item(text, BENIGN, "llmail_benign")


register(
    Source(
        id="llmail_benign",
        title="LLMail-Inject false-positive emails",
        homepage="https://huggingface.co/datasets/microsoft/llmail-inject-challenge",
        licence="MIT",
        role="benign",
        files=_hf(*_LLMAIL, "data/emails_for_fp_tests.json"),
        parse=_llmail_benign,
        notes="Ordinary business emails in the same format as the LLMail attacks.",
    )
)


def _notinject(paths: list[Path]) -> Iterator[Item]:
    for path in paths:
        subset = path.name.split("_")[1].split("-")[0]  # one, two, three trigger words
        for r in _rows_parquet(path):
            if text := _keep(r["prompt"]):
                meta = {"trigger_words": subset, "category": str(r.get("category", ""))}
                yield make_item(text, BENIGN, "notinject", meta=meta)


register(
    Source(
        id="notinject",
        title="NotInject",
        homepage="https://huggingface.co/datasets/leolee99/NotInject",
        licence="MIT",
        role="benign",
        files=_hf(
            "leolee99/NotInject",
            "847ae76cf8fea5ed325429e569ae8cfef022d2e0",
            "data/NotInject_one-00000-of-00001.parquet",
            "data/NotInject_two-00000-of-00001.parquet",
            "data/NotInject_three-00000-of-00001.parquet",
        ),
        parse=_notinject,
        languages=("en", "zh", "other"),
        notes="Benign prompts containing one to three words common in attacks ('ignore', "
        "'bypass', ...). Made by the PIGuard authors as an evaluation set.",
    )
)


def _xstest(paths: list[Path]) -> Iterator[Item]:
    for r in _rows_csv(paths[0]):
        if r["label"] == "safe" and (text := _keep(r["prompt"])):
            yield make_item(
                text, BENIGN, "xstest", meta={"type": r.get("type", ""), "harmful": "0"}
            )


def _xstest_unsafe(paths: list[Path]) -> Iterator[Item]:
    for r in _rows_csv(paths[0]):
        if r["label"] == "unsafe" and (text := _keep(r["prompt"])):
            meta = {"type": r.get("type", ""), "harmful": "1"}
            yield make_item(text, BENIGN, "xstest_unsafe", meta=meta)


register(
    Source(
        id="xstest",
        title="XSTest (safe prompts)",
        homepage="https://huggingface.co/datasets/Paul/XSTest",
        licence="CC-BY-4.0",
        role="benign",
        files=_hf("Paul/XSTest", "f600c994b256f12867dfa5b3eb3d545a3e62f8b5", "xstest_prompts.csv"),
        parse=_xstest,
        trained_on_by=(PROTECTAI, PIGUARD),
        notes="Safe prompts that sound unsafe ('How do I kill a Python process?'). The 200 "
        "unsafe prompts are the xstest_unsafe family. Both baselines trained on a copy of "
        "these prompts (natolambert/xstest-v2-copy).",
    )
)

register(
    Source(
        id="xstest_unsafe",
        title="XSTest (unsafe prompts)",
        homepage="https://huggingface.co/datasets/Paul/XSTest",
        licence="CC-BY-4.0",
        role="benign",
        files=_hf("Paul/XSTest", "f600c994b256f12867dfa5b3eb3d545a3e62f8b5", "xstest_prompts.csv"),
        parse=_xstest_unsafe,
        trained_on_by=(PROTECTAI, PIGUARD),
        notes="Added 2026-11-04 (decision 0012): the 200 unsafe prompts, the safe prompts' "
        "contrasts. Harmful requests, not injections: harmful 1, attack 0. They measure the "
        "v0.2 classifier's harmful output; for the attack output they are hard benign.",
    )
)


def _orbench(paths: list[Path]) -> Iterator[Item]:
    toxic = "toxic" in paths[0].name
    source = "orbench_toxic" if toxic else "orbench"
    for r in _rows_csv(paths[0]):
        if text := _keep(r["prompt"]):
            meta = {"category": r.get("category", ""), "harmful": "1" if toxic else "0"}
            yield make_item(text, BENIGN, source, meta=meta)


register(
    Source(
        id="orbench",
        title="OR-Bench hard-1k",
        homepage="https://huggingface.co/datasets/bench-llm/or-bench",
        licence="CC-BY-4.0",
        role="benign",
        files=_hf(
            "bench-llm/or-bench", "e36d8b80e81837c8a8f264bbb2a49f1b32c7e272", "or-bench-hard-1k.csv"
        ),
        parse=_orbench,
        notes="Prompts that seem harmful but are not; built to measure over-refusal.",
    )
)

register(
    Source(
        id="orbench_toxic",
        title="OR-Bench toxic",
        homepage="https://huggingface.co/datasets/bench-llm/or-bench",
        licence="CC-BY-4.0",
        role="benign",
        files=_hf(
            "bench-llm/or-bench", "e36d8b80e81837c8a8f264bbb2a49f1b32c7e272", "or-bench-toxic.csv"
        ),
        parse=_orbench,
        notes="Added 2026-11-04 (decision 0012): 655 harmful prompts on the same topics as "
        "OR-Bench hard-1k. Harmful 1, attack 0: they measure the v0.2 classifier's harmful "
        "output; for the attack output they are hard benign.",
    )
)


def _oasst(paths: list[Path]) -> Iterator[Item]:
    for path in paths:
        for r in _rows_parquet(path):
            if r["role"] != "prompter" or r.get("deleted"):
                continue
            if text := _keep(r["text"]):
                yield make_item(text, BENIGN, "oasst", lang=str(r.get("lang") or "und"))


register(
    Source(
        id="oasst",
        title="OpenAssistant oasst1 (user messages)",
        homepage="https://huggingface.co/datasets/OpenAssistant/oasst1",
        licence="Apache-2.0",
        role="calibration",
        files=_hf(
            "OpenAssistant/oasst1",
            "fdf72ae0827c1cda404aff25b6603abec9e3399b",
            "data/train-00000-of-00001-b42a775f407cee45.parquet",
            "data/validation-00000-of-00001-134b8fd0c89408b6.parquet",
        ),
        parse=_oasst,
        languages=("multilingual (35)",),
        notes="Human-written user messages in 35 languages. Half (by cluster) sets the "
        "thresholds; the other half is reported as ordinary-traffic false positives. Also the "
        "carrier text and benign corpus for the redactor evaluation.",
    )
)
