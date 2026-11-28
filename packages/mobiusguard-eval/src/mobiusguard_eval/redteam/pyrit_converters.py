"""PyRIT's prompt converters as mutation steps (decision 0014). Needs ``mobiusguard-eval[pyrit]``.

    steps = {"pyrit:ROT13Converter": converter_step("ROT13Converter")}
    attempts_for(seed, chains=[("pyrit:ROT13Converter",)], extra=steps)

Only text-to-text converters that call nothing are allowed. A converter that takes a
``converter_target`` would call an LLM for every attempt, and one configured with a key,
endpoint or region calls a cloud service (Azure Speech, for one): both cost money and are
not reproducible, so :func:`converter_step` refuses them, and image, audio and file
converters, which do not return text. PyRIT's converters are async; each call
here runs one to completion. They take no random seed, so a converter that samples (some
do) is not repeatable run to run; :func:`converter_step` records nothing about that, so use
deterministic ones for runs you compare.
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
import random
from typing import Any

from .mutate import Step

PREFIX = "pyrit:"


def _module() -> Any:
    """PyRIT's converter module: ``pyrit.converter`` from 1.0, ``pyrit.prompt_converter`` before."""
    for name in ("pyrit.converter", "pyrit.prompt_converter"):
        try:
            return importlib.import_module(name)
        except ImportError:
            continue
    raise ImportError("PyRIT converters need: pip install 'mobiusguard-eval[pyrit]'")


def _base(mod: Any) -> type:
    base = getattr(mod, "Converter", None) or getattr(mod, "PromptConverter", None)
    if not isinstance(base, type):
        raise ImportError("PyRIT's converter base class was not found")
    return base


# Constructor parameters that mean a converter calls a model or a service.
CALLS_OUT = ("converter_target", "key", "endpoint", "region", "url", "token", "credential",
             "api")  # fmt: skip


def needs_model(cls: type) -> bool:
    """Whether a converter calls a model or a service (it takes a target, key, endpoint...)."""
    try:
        params = inspect.signature(cls.__init__).parameters
    except (TypeError, ValueError):
        return True
    return any(word in p.lower() for p in params for word in CALLS_OUT)


def text_to_text(cls: type) -> bool:
    """Whether a converter takes and returns text (not images, audio or files)."""
    ins = getattr(cls, "SUPPORTED_INPUT_TYPES", ("text",))
    outs = getattr(cls, "SUPPORTED_OUTPUT_TYPES", ("text",))
    return "text" in ins and tuple(outs) == ("text",)


def allowed(cls: type) -> bool:
    return text_to_text(cls) and not needs_model(cls)


def available() -> list[str]:
    """Names of PyRIT's text-to-text converters that call nothing."""
    mod = _module()
    base = _base(mod)
    return sorted(
        name
        for name, cls in inspect.getmembers(mod, inspect.isclass)
        if issubclass(cls, base) and cls is not base and allowed(cls)
    )


def converter_step(name: str, **kwargs: Any) -> Step:
    """A mutation step that runs PyRIT's ``name`` converter on the text."""
    mod = _module()
    cls = getattr(mod, name, None)
    if not (isinstance(cls, type) and issubclass(cls, _base(mod))):
        raise KeyError(f"PyRIT has no converter {name!r}")
    if needs_model(cls):
        raise ValueError(f"{name} calls a model or a service; only converters that call nothing")
    if not text_to_text(cls):
        raise ValueError(f"{name} does not turn text into text")
    conv = cls(**kwargs)

    def step(text: str, rng: random.Random) -> str:
        del rng
        result = asyncio.run(conv.convert_async(prompt=text, input_type="text"))
        out = getattr(result, "output_text", None)
        if not isinstance(out, str):
            raise TypeError(f"{name} returned no text")
        return out

    return step
