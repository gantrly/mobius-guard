"""``mobiusguard-eval redteam run | summary | findings`` (decision 0014)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .findings import findings_for_run, write
from .mutate import CHAINS, DELIVERIES, parse_chain
from .run import Plan, parse_shard, run, summary
from .seeds import read_seeds
from .targets import API_NAMES, GuardTarget, HttpTarget, Target


def add_parser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:  # pyright: ignore[reportPrivateUsage]
    p = sub.add_parser("redteam", help="attack a Mobius Guard configuration (decision 0014)")
    rsub = p.add_subparsers(dest="redteam_command", required=True)

    r = rsub.add_parser("run", help="send every attempt; resumes what was sent")
    r.add_argument("--seeds", required=True, help="seeds.jsonl from an exporter")
    r.add_argument("--out", required=True)
    who = r.add_mutually_exclusive_group(required=True)
    who.add_argument("--config", help="a proxy config: run its guard in this process")
    who.add_argument(
        "--http", help="a running proxy's URL (each allowed request reaches its model)"
    )
    r.add_argument("--api", default="chat", choices=API_NAMES)
    r.add_argument("--model", default="redteam", help="model name sent with --http")
    r.add_argument(
        "--chains", default="all", help="'all' or a comma list, e.g. plain,spaced+base64"
    )
    r.add_argument("--deliveries", default=",".join(DELIVERIES))
    r.add_argument("--sample", type=int, default=0, help="a fixed random N seeds (the small run)")
    r.add_argument("--sample-seed", type=int, default=0)
    r.add_argument("--shard", default="0/1", help="i/n: this process's share of the seeds")
    r.add_argument("--stop-after-minutes", type=float, default=0.0)

    s = rsub.add_parser("summary", help="counts across shards")
    s.add_argument("--out", required=True)

    f = rsub.add_parser("findings", help="what got through, by group and chain (no text)")
    f.add_argument("--out", required=True, help="the run's directory")
    f.add_argument("--seeds", required=True, help="the run's seeds.jsonl")
    f.add_argument("--report", required=True, help="where findings.json and .md go")
    f.add_argument("--holdout", help="holdout.json: leave its sealed groups out")


def main(a: argparse.Namespace) -> int:
    if a.redteam_command == "summary":
        print(json.dumps(summary(Path(a.out)), indent=2))
        return 0
    if a.redteam_command == "findings":
        held: list[str] = []
        if a.holdout:
            held = list(json.loads(Path(a.holdout).read_text())["groups"])
        seeds = list(read_seeds(Path(a.seeds)))
        f = findings_for_run(Path(a.out), seeds, exclude=held)
        write(f, Path(a.report))
        t = f["total"]
        print(
            f"{t['attempts']} attempts, {t['through']} got through ({100 * t['rate']:.1f}%), "
            f"{len(f['findings'])} findings in {f['groups']} groups -> {a.report}"
        )
        return 0
    chains = CHAINS if a.chains == "all" else tuple(parse_chain(c) for c in a.chains.split(","))
    unknown = [c for c in chains if c not in CHAINS]
    if unknown:
        raise SystemExit(f"unknown chains: {unknown}")
    target: Target
    if a.config:
        target = GuardTarget.from_config(a.config, api=a.api)
    else:
        target = HttpTarget(a.http, api=a.api, model=a.model)
    plan = Plan(seeds=Path(a.seeds), out=Path(a.out), chains=chains,
                deliveries=tuple(a.deliveries.split(",")), sample=a.sample,
                sample_seed=a.sample_seed, shard=parse_shard(a.shard))  # fmt: skip
    counts = run(plan, target, stop_after_seconds=a.stop_after_minutes * 60)
    if isinstance(target, HttpTarget):
        counts["http_requests"] = target.requests
        counts["reached_the_model"] = target.allowed
    print(json.dumps(counts))
    return 0
