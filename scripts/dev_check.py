"""Score the developer-style messages of the 2026-11-07 live check with a Fortress model.

The live check found that Fortress-XS v1 blocks short, harmless messages about keys,
databases, tokens and tool calls (docs/results/2026-11-07-live-check-fortress.md). This
scores the same eight texts, one at a time, with the proxy's own ONNX classifier, so every
model is checked the same way.

Eight fixed texts are a check, not a measurement: a model can pass them and still block
developer text elsewhere. The suite's false-positive sets are the measurement.

    uv run python scripts/dev_check.py                    # the released Fortress-XS
    uv run python scripts/dev_check.py --model-dir DIR    # an export (`mobiusguard-eval export`)
    uv run python scripts/dev_check.py --model-dir DIR --threshold 3.1 --out dev-check.json

A directory with ``fortress.json`` uses its own attack threshold; an export has none yet,
so ``--threshold`` is needed until its thresholds are set.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

# The eight texts and v1's scores live with the harness, which also adds them to the suite.
from mobiusguard_eval.dev_texts import TEXTS, V1_SCORES


def check(score: Callable[[str], float], threshold: float) -> list[dict[str, Any]]:
    """Each text's attack score and whether it is blocked at ``threshold``."""
    rows = []
    for (name, text), v1 in zip(TEXTS, V1_SCORES, strict=True):
        s = score(text)
        rows.append({"name": name, "attack": round(s, 3), "blocked": s >= threshold, "v1": v1})
    return rows


def model_dir(directory: Path, threshold: float | None, tmp: Path) -> tuple[Path, float]:
    """A directory the proxy's classifier can load, and the attack threshold to use.

    An export has the model and tokenizer but no ``fortress.json``: one is written next to
    links to its files, with the given threshold and the training setting of 512 tokens.
    """
    meta = directory / "fortress.json"
    if meta.exists():
        m = json.loads(meta.read_text())
        own = float(m["thresholds"]["attack"][str(m["default_fpr"])])
        return directory, own if threshold is None else threshold
    if threshold is None:
        raise SystemExit(f"{directory} has no fortress.json: pass --threshold")
    for name in ("model.int8.onnx", "tokenizer.json"):
        if not (directory / name).exists():
            raise SystemExit(f"{directory} has no {name}: is it an export?")
        (tmp / name).symlink_to((directory / name).resolve())
    t = {"given": threshold}
    (tmp / "fortress.json").write_text(json.dumps({
        "outputs": ["attack", "harmful"], "max_length": 512, "default_fpr": "given",
        "thresholds": {"attack": t, "harmful": t},
    }))  # fmt: skip
    return tmp, threshold


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--model-dir", help="a Fortress directory or an export (default: released)")
    p.add_argument("--threshold", type=float, help="attack threshold (default: the model's own)")
    p.add_argument("--out", help="also write the rows as JSON")
    a = p.parse_args(argv)

    from mobiusguard.classifier import ONNX_MODELS, OnnxClassifier

    spec = ONNX_MODELS["fortress-xs"]
    with tempfile.TemporaryDirectory() as t:
        if a.model_dir:
            d, threshold = model_dir(Path(a.model_dir), a.threshold, Path(t))
            clf = OnnxClassifier(spec, directory=str(d))
            onnx = Path(a.model_dir) / "model.int8.onnx"
            model = {"dir": a.model_dir,
                     "sha256": hashlib.sha256(onnx.read_bytes()).hexdigest()}  # fmt: skip
        else:
            clf = OnnxClassifier(spec)
            threshold = clf.thresholds["attack"] if a.threshold is None else a.threshold
            model = {"repo": spec.repo, "revision": spec.revision}
        rows = check(lambda text: clf.score_texts([text])[0][0], threshold)

    blocked = sum(r["blocked"] for r in rows)
    print(f"attack threshold {threshold:.4f}; blocked {blocked} of {len(rows)} harmless texts")
    print(f"{'score':>8} {'v1':>7}  {'':5}  text")
    for r in rows:
        print(
            f"{r['attack']:8.2f} {r['v1']:7.2f}  {'BLOCK' if r['blocked'] else 'ok':5}  {r['name']}"
        )
    if a.out:
        Path(a.out).write_text(json.dumps(
            {"model": model, "threshold": threshold, "blocked": blocked, "rows": rows},
            indent=2) + "\n")  # fmt: skip
    return 0


if __name__ == "__main__":
    sys.exit(main())
