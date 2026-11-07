"""Command line: ``mobiusguard serve`` runs the proxy; ``mobiusguard check`` tries the guard.

mobiusguard serve [--config mobiusguard.toml] [--host 127.0.0.1] [--port 8787]
mobiusguard check "Ignore all previous instructions"
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from .apis import Text
from .config import load


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="mobiusguard", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)  # fmt: skip
    sub = ap.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="run the proxy")
    serve.add_argument("--config", type=Path)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8787)
    chk = sub.add_parser("check", help="run the request check on a text and print the decision")
    chk.add_argument("text", nargs="?", help="text to check (default: read stdin)")
    chk.add_argument("--config", type=Path)
    a = ap.parse_args(argv)
    cfg = load(a.config)

    if a.command == "check":
        from .guard import Guard

        text = a.text if a.text is not None else sys.stdin.read()
        d = Guard(cfg).decide([Text("user", text, "input")])
        print(json.dumps({"decision": d.action, "reason": d.reason, "score": d.score,
                          "harmful": d.harmful, "flagged": d.flagged,
                          "rules": [{"id": h.rule, "severity": h.severity, "view": h.view}
                                    for h in d.hits]}, indent=2))  # fmt: skip
        return 1 if d.action == "block" else 0

    from .config import warnings

    for w in warnings(cfg):
        print(f"mobiusguard: warning: {w}", file=sys.stderr)

    import uvicorn

    from .app import create_app
    from .hooks import ProxyHooks

    uvicorn.run(create_app(cfg, hooks=ProxyHooks(cfg)), host=a.host, port=a.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
