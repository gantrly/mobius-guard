"""Export garak's probe prompts as red-team seeds (decision 0014). Standard library + garak only.

garak pins transformers below the version our training extras need, so it lives in its own
environment and this file runs with *that* Python, by path:

    venv-garak/bin/python packages/mobiusguard-eval/src/mobiusguard_eval/redteam/garak_export.py \\
        --out runs/redteam/seeds-garak latentinjection promptinject encoding sysprompt_extraction

It writes ``seeds.jsonl`` (one seed per line: id, source, family, probe, messages, the index
of the message that carries the attack, language) and ``manifest.json`` (garak's version,
the settings, counts per probe, and the commit of every Hugging Face dataset a probe read).

- Every probe class of each named module is loaded, active or not, with garak's prompt cap
  turned off and its random seed fixed, so an export is complete and repeatable.
- garak's "Full" variants contain the others' prompts; a prompt that two probes share is
  kept once, under the first probe (sorted by name) that produced it.
- Prompt text is written to the seeds file only; the script prints counts.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import inspect
import json
import pkgutil
import platform
import random
import sys
import time
from pathlib import Path
from typing import Any, cast

SEED = 0


def seed_id(messages: list[dict[str, str]]) -> str:
    """``garak:<hash of the messages>``, stable across exports."""
    blob = json.dumps(messages, ensure_ascii=False, sort_keys=True).encode()
    return "garak:" + hashlib.sha256(blob).hexdigest()[:16]


def to_messages(prompt: Any) -> tuple[list[dict[str, str]], int, str]:
    """(messages, index of the attack message, language) from a garak prompt.

    A prompt is a string or a ``garak.attempt.Conversation`` whose turns have a role and a
    ``Message`` with ``text``. The attack is in the last user turn.
    """
    if isinstance(prompt, str):
        return [{"role": "user", "content": prompt}], 0, ""
    turns = getattr(prompt, "turns", None)
    if not turns:
        raise TypeError(f"unsupported prompt type {type(prompt).__name__}")
    messages: list[dict[str, str]] = []
    lang = ""
    for t in turns:
        role = str(getattr(t, "role", "user"))
        content = getattr(t, "content", None)
        text = getattr(content, "text", None) if content is not None else None
        if not isinstance(text, str):
            raise TypeError("a turn without text")
        messages.append({"role": role, "content": text})
        lang = lang or str(getattr(content, "lang", "") or "")
    users = [i for i, m in enumerate(messages) if m["role"] == "user"]
    if not users:
        raise TypeError("a conversation without a user turn")
    return messages, users[-1], lang


def dataset_names(cls: type) -> list[str]:
    """Hugging Face dataset IDs in a probe's default parameters ("owner/name")."""
    out: list[str] = []
    params = cast("dict[str, object]", getattr(cls, "DEFAULT_PARAMS", {}))
    for v in params.values():
        values = list(cast("list[object]", v)) if isinstance(v, list | tuple) else [v]
        for x in values:
            if isinstance(x, str) and x.count("/") == 1 and " " not in x and "." not in x:
                out.append(x)
    return out


def probe_classes(garak_probes: Any, module: str) -> list[tuple[str, type]]:
    mod = importlib.import_module(f"garak.probes.{module}")
    base = garak_probes.Probe
    return sorted(
        (f"{module}.{name}", cls)
        for name, cls in inspect.getmembers(mod, inspect.isclass)
        if cls.__module__ == mod.__name__ and issubclass(cls, base) and not name.startswith("_")
    )


def export(modules: list[str], out: Path) -> dict[str, Any]:
    garak = importlib.import_module("garak")
    garak_probes = importlib.import_module("garak.probes")
    config = importlib.import_module("garak._config")
    config.load_base_config()
    config.run.seed = SEED
    config.run.soft_probe_prompt_cap = None  # every prompt, not a random 256
    known = {m.name for m in pkgutil.iter_modules(garak_probes.__path__)}
    missing = [m for m in modules if m not in known]
    if missing:
        raise SystemExit(f"no such garak probe module: {missing}")
    out.mkdir(parents=True, exist_ok=True)
    seen: set[str] = set()
    probes: dict[str, Any] = {}
    datasets: dict[str, str] = {}
    t0 = time.time()
    with (out / "seeds.jsonl").open("w", encoding="utf-8") as f:
        for module in modules:
            for name, cls in probe_classes(garak_probes, module):
                random.seed(SEED)  # some probes sample their templates at init
                try:
                    probe = cls()
                except Exception as e:  # a probe that cannot load is recorded, not fatal
                    probes[name] = {"error": f"{type(e).__name__}: {e}"[:200]}
                    continue
                prompts = list(getattr(probe, "prompts", []))
                new = 0
                for p in prompts:
                    messages, payload, lang = to_messages(p)
                    sid = seed_id(messages)
                    if sid in seen:
                        continue
                    seen.add(sid)
                    new += 1
                    row = {"id": sid, "source": "garak", "family": module, "probe": name,
                           "messages": messages, "payload": payload,
                           "lang": lang or str(getattr(probe, "lang", "") or "")}  # fmt: skip
                    f.write(json.dumps(row, ensure_ascii=False) + "\n")
                probes[name] = {"prompts": len(prompts), "new": new,
                                "active": bool(getattr(cls, "active", False))}  # fmt: skip
                for ds in dataset_names(cls):
                    datasets.setdefault(ds, "")
    if datasets:
        hub = importlib.import_module("huggingface_hub")
        for ds in datasets:
            try:
                datasets[ds] = str(hub.HfApi().dataset_info(ds).sha)
            except Exception as e:
                datasets[ds] = f"unknown ({type(e).__name__})"
    manifest = {
        "garak": garak.__version__,
        "python": platform.python_version(),
        "modules": modules,
        "seed": SEED,
        "prompt_cap": None,
        "seeds": len(seen),
        "probes": probes,
        "hf_datasets": datasets,
        "seconds": round(time.time() - t0, 1),
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    ap.add_argument("modules", nargs="+", help="garak probe modules, e.g. latentinjection")
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args(argv)
    m = export(a.modules, a.out)
    for name, p in m["probes"].items():
        print(f"{name}: {p}")
    print(f"garak {m['garak']}: {m['seeds']} seeds in {m['seconds']}s -> {a.out}")
    print(f"datasets: {m['hf_datasets']}")


if __name__ == "__main__":
    sys.exit(main())
