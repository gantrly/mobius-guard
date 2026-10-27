"""Download pinned dataset files into a local cache.

The cache is ``$MOBIUSGUARD_CACHE``, else ``~/.cache/mobiusguard``. Nothing is written
into the repository.
"""

from __future__ import annotations

import hashlib
import importlib
import os
import urllib.request
from pathlib import Path
from typing import Any

from .ledger import Remote, Source


def cache_dir() -> Path:
    root = os.environ.get("MOBIUSGUARD_CACHE") or Path.home() / ".cache" / "mobiusguard"
    return Path(root)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def fetch_file(remote: Remote) -> Path:
    if remote.kind == "hf_dataset":
        hub: Any = importlib.import_module("huggingface_hub")
        return Path(
            hub.hf_hub_download(
                repo_id=remote.location,
                filename=remote.path,
                repo_type="dataset",
                revision=remote.revision,
                cache_dir=cache_dir() / "hf",
            )
        )
    dest = cache_dir() / "url" / remote.sha256 / Path(remote.location).name
    if dest.exists() and _sha256(dest) == remote.sha256:
        return dest
    if not remote.location.startswith("https://"):
        raise ValueError(f"only https URLs: {remote.location}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    with urllib.request.urlopen(remote.location, timeout=60) as resp:  # noqa: S310 - https only
        tmp.write_bytes(resp.read())
    got = _sha256(tmp)
    if got != remote.sha256:
        tmp.unlink()
        raise ValueError(f"sha256 mismatch for {remote.location}: {got}")
    tmp.replace(dest)
    return dest


def fetch(source: Source) -> list[Path]:
    """Local paths of all of a source's files, downloading what is missing."""
    return [fetch_file(f) for f in source.files]
