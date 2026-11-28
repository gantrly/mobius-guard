"""Red-team seeds and where they come from (decision 0014).

A seed is one attack from an attack tool, as that tool would send it: a list of messages
and the index of the one that carries the attack. Seeds are read at run time from the
installed tool (garak: :mod:`.garak_export`) and never committed. Each tool is registered
in :data:`REDTEAM` with its licence, the datasets it reads and the known detectors trained
on them, the way the evaluation suite's sources are (decision 0006, rule 1). The red-team
registry is kept apart from the suite (``LEDGER``) and the training sources (``TRAINING``):
a test checks that no ID is in two of them.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Dataset:
    id: str  # Hugging Face dataset ID
    licence: str
    origin: str = ""  # the dataset it was copied from, if any


@dataclass(frozen=True, slots=True)
class RedTeamSource:
    id: str
    title: str
    homepage: str
    licence: str  # of the tool and the data it ships
    package: str  # the pinned package that provides the seeds
    modules: tuple[str, ...]  # the tool's attack modules we use
    datasets: tuple[Dataset, ...] = ()  # data the modules download at export time
    trained_on_by: tuple[str, ...] = ()  # detectors known to have trained on it
    notes: str = ""


REDTEAM: dict[str, RedTeamSource] = {}


def register(src: RedTeamSource) -> RedTeamSource:
    if src.id in REDTEAM:
        raise ValueError(f"duplicate red-team source {src.id}")
    REDTEAM[src.id] = src
    return src


GARAK = register(
    RedTeamSource(
        id="garak",
        title="garak, the LLM vulnerability scanner (NVIDIA): static prompt-injection probes",
        homepage="https://github.com/NVIDIA/garak",
        licence="Apache-2.0",
        package="garak==0.17.1",
        modules=("latentinjection", "promptinject", "encoding", "sysprompt_extraction"),
        datasets=(
            Dataset(
                "garak-llm/drh-System-Prompt-processed",
                "Apache-2.0",
                "danielrosehill/System-Prompt-Library-030825 (MIT)",
            ),
            Dataset("garak-llm/tm-system_prompt", "CC-BY-4.0", "teilomillet/system_prompt"),
        ),
        notes=(
            "latentinjection and encoding are garak's own templates and payloads. promptinject "
            "is garak's copy of PromptInject (Perez & Ribeiro 2022, MIT). sysprompt_extraction "
            "pairs garak's attacks with system prompts from the two datasets above, which "
            "garak reads without a pinned revision: the export records their commits. No "
            "detector we compare is known to have trained on these probes."
        ),
    )
)


@dataclass(frozen=True, slots=True)
class Seed:
    id: str  # "<source>:<hash of the messages>"
    source: str
    family: str  # the tool's module, e.g. latentinjection
    probe: str  # the class that produced it, e.g. latentinjection.LatentInjectionResume
    messages: tuple[dict[str, str], ...]
    payload: int  # index of the message that carries the attack
    lang: str = ""
    meta: dict[str, str] = field(default_factory=dict[str, str])

    @property
    def text(self) -> str:
        return self.messages[self.payload]["content"]


def read_seeds(path: Path) -> Iterator[Seed]:
    """Seeds from a ``seeds.jsonl`` written by an exporter. Checks each row's shape."""
    with path.open(encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            d = json.loads(line)
            msgs = tuple({"role": str(m["role"]), "content": str(m["content"])}
                         for m in d["messages"])  # fmt: skip
            payload = int(d["payload"])
            if not 0 <= payload < len(msgs) or msgs[payload]["role"] != "user":
                raise ValueError(f"{path}:{n}: payload must point at a user message")
            if d["source"] not in REDTEAM:
                raise ValueError(f"{path}:{n}: unregistered source {d['source']!r}")
            if d["family"] not in REDTEAM[d["source"]].modules:
                raise ValueError(f"{path}:{n}: {d['family']!r} is not a registered module")
            yield Seed(
                id=str(d["id"]),
                source=str(d["source"]),
                family=str(d["family"]),
                probe=str(d.get("probe", "")),
                messages=msgs,
                payload=payload,
                lang=str(d.get("lang", "")),
            )
