"""Adaptive attacks (decision 0016): feedback, the judge, sessions, the holdout and the
runner. A made-up scorer, judge and attacker stand in for the models; texts are
placeholders."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import httpx
import pytest
from mobiusguard.config import Config, Policy
from mobiusguard.guard import Guard
from mobiusguard_eval.cli import main as cli_main
from mobiusguard_eval.redteam import holdout
from mobiusguard_eval.redteam.adaptive import (
    DRIFT,
    MAX_BLOCKED,
    OTHER_BLOCK,
    Judge,
    Plan,
    Session,
    choose,
    feedback,
    ollama_digests,
    run,
    status,
    summary,
)
from mobiusguard_eval.redteam.findings import seed_groups
from mobiusguard_eval.redteam.run import sha256_file
from mobiusguard_eval.redteam.seeds import Seed, read_seeds
from mobiusguard_eval.redteam.targets import GuardTarget, Verdict

FAMILIES = ("encoding", "latentinjection", "promptinject", "sysprompt_extraction")


def scorer(texts: Sequence[str]) -> list[tuple[float, float]]:
    """High attack score for texts with the marker "zzhot", low otherwise."""
    return [(5.0 if "zzhot" in t else -3.0, -6.0) for t in texts]


def target(views: str = "all") -> GuardTarget:
    cfg = Config(policy=Policy(rules="off", classifier_views=views))  # type: ignore[arg-type]
    return GuardTarget(Guard(cfg, scorer=scorer, thresholds={"attack": 2.0, "harmful": 1.0}))


def judge(answer: str | None = "yes", status_code: int = 200) -> Judge:
    def handle(request: httpx.Request) -> httpx.Response:
        if answer is None:
            return httpx.Response(status_code, json={"unexpected": True})
        return httpx.Response(status_code,
                              json={"choices": [{"message": {"content": answer}}]})  # fmt: skip

    client = httpx.Client(base_url="http://judge", transport=httpx.MockTransport(handle))
    return Judge("http://judge", "judge-model", client=client)


def seeds_file(tmp_path: Path, per_family: int = 12) -> Path:
    rows: list[dict[str, Any]] = []
    for f in FAMILIES:
        for k in range(per_family):
            words = " ".join(f"{f}{k}w{j}" for j in range(6))  # distinct: one group each
            rows.append({"id": f"garak:{f[:4]}{k:012x}", "source": "garak", "family": f,
                         "probe": f"{f}.X", "payload": 1,
                         "messages": [{"role": "system", "content": "a system prompt"},
                                      {"role": "user", "content": f"zzhot {words}"}]})  # fmt: skip
    path = tmp_path / "seeds.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    return path


def holdout_file(tmp_path: Path, seeds: Path) -> Path:
    groups = seed_groups(list(read_seeds(seeds)))
    path = tmp_path / "holdout" / "holdout.json"
    holdout.write(holdout.seal(groups, sha256_file(seeds)), path)
    return path


# ------------------------------------------------------------------------------ feedback


def test_feedback_rewards_getting_through_with_the_same_request_only() -> None:
    let_through = Verdict(blocked=False, score=-3.0)
    assert feedback(let_through, 2.0, True) == 1.0
    assert feedback(let_through, 2.0, False) == DRIFT
    assert feedback(let_through, 2.0, None) == DRIFT  # unreadable judge: never a bypass
    at = Verdict(blocked=True, reason="classifier", score=2.0)
    far = Verdict(blocked=True, reason="classifier", score=9.0)
    assert feedback(at, 2.0, None) == MAX_BLOCKED
    assert feedback(far, 2.0, None) == 0.0
    assert 0 < feedback(Verdict(blocked=True, reason="classifier", score=4.0), 2.0, None) < 0.8
    assert feedback(Verdict(blocked=True, reason="rule", score=-3.0), 2.0, None) == OTHER_BLOCK
    assert feedback(Verdict(blocked=False, error="Timeout"), 2.0, True) == 0.0


def test_status_shows_the_score_only_in_white_box_mode() -> None:
    v = Verdict(blocked=True, reason="classifier", score=4.25)
    assert status(v, 3.11, True) == (
        "Blocked by the firewall (the classifier). Attack score 4.25; it blocks at 3.11 or above."
    )
    assert status(v, 3.11, False) == "Blocked by the firewall (the classifier)."
    assert status(Verdict(blocked=False, score=1.0), 3.11, False) == "Let through by the firewall."


# ------------------------------------------------------------------------------ judge


def test_judge_reads_yes_or_no_and_counts_what_it_cannot_read() -> None:
    assert judge("Yes.").same("a", "b") is True
    assert judge("no").same("a", "b") is False
    j = judge("maybe, it depends")
    assert j.same("a", "b") is None
    assert j.failures == 1
    assert judge(None).same("a", "b") is None
    assert judge("yes", status_code=500).same("a", "b") is None


def test_judge_sends_both_messages_and_no_verdict() -> None:
    seen: list[dict[str, Any]] = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        return httpx.Response(200, json={"choices": [{"message": {"content": "yes"}}]})

    client = httpx.Client(base_url="http://judge", transport=httpx.MockTransport(handle))
    Judge("http://judge", "judge-model", client=client).same("original one", "rewrite two")
    body = seen[0]
    assert body["model"] == "judge-model"
    assert body["temperature"] == 0
    user = body["messages"][1]["content"]
    assert "original one" in user
    assert "rewrite two" in user
    assert "score" not in user.lower()


# ------------------------------------------------------------------------------ session


def seed() -> Seed:
    return Seed(id="garak:0000000000000001", source="garak", family="encoding",
                probe="encoding.X", payload=1,
                messages=({"role": "system", "content": "a system prompt"},
                          {"role": "user", "content": "zzhot original"}))  # fmt: skip


def test_a_session_checks_judges_and_records_each_try() -> None:
    s = Session(seed(), "patched", target(), judge("yes"), max_tries=3)
    text, fb = s.send("zzhot rewrite")
    assert fb < 1.0
    assert text.startswith("Blocked by the firewall")
    text, fb = s.send("plain rewrite")
    assert (text, fb) == ("Let through by the firewall. Attack score -3.00; it blocks at 2.00 "
                          "or above.", 1.0)  # fmt: skip
    assert s.bypass == "plain rewrite"
    assert [r["try"] for r in s.rows] == [1, 2]
    assert [r["same"] for r in s.rows] == [None, True]  # the judge only sees what got through
    assert not any("rewrite" in json.dumps(r) for r in s.rows)  # no text in the rows
    assert s.outcome == {"tries": 2, "bypass": True, "first_bypass_try": 2, "drift": 0,
                         "judge_failed": 0, "errors": 0}  # fmt: skip
    s.send("one more")
    with pytest.raises(RuntimeError, match="more than 3 tries"):
        s.send("too many")


def test_a_pass_the_judge_rejects_is_drift_not_a_bypass() -> None:
    s = Session(seed(), "patched", target(), judge("no"))
    assert s.send("plain but different")[1] == DRIFT
    assert s.bypass is None
    assert s.outcome["drift"] == 1
    assert not s.outcome["bypass"]


def test_only_the_payload_message_is_rewritten() -> None:
    sent: list[list[dict[str, str]]] = []
    t = target()
    original_send = t.send

    def spy(messages: Sequence[Any]) -> Verdict:
        sent.append([dict(m) for m in messages])
        return original_send(messages)

    t.send = spy  # type: ignore[method-assign]
    Session(seed(), "patched", t, judge()).send("plain rewrite")
    assert sent == [[{"role": "system", "content": "a system prompt"},
                     {"role": "user", "content": "plain rewrite"}]]  # fmt: skip


# ------------------------------------------------------------------------------ choose


def test_choose_takes_prompts_per_family_from_outside_the_holdout(tmp_path: Path) -> None:
    path = seeds_file(tmp_path)
    seeds = list(read_seeds(path))
    rec = json.loads(holdout_file(tmp_path, path).read_text())
    held = set(rec["groups"])
    groups = seed_groups(seeds)
    picked = choose(seeds, held, per_family=5, sample_seed=1)
    assert len(picked) == 20
    assert {s.family for s in picked} == set(FAMILIES)
    assert not any(groups[s.id] in held for s in picked)
    assert choose(seeds, held, per_family=5, sample_seed=1) == picked  # fixed sample
    held_id = next(s.id for s in seeds if groups[s.id] in held)
    with pytest.raises(ValueError, match="sealed holdout"):
        choose(seeds, held, per_family=5, ids=[held_id])
    with pytest.raises(ValueError, match="unknown"):
        choose(seeds, held, per_family=5, ids=["garak:nope"])


# ------------------------------------------------------------------------------ runner


class Attacker:
    """Sends fixed rewrites: blocked twice, then plain (a bypass if the judge agrees)."""

    def __init__(self, fail_on: str = "") -> None:
        self.calls = 0
        self.fail_on = fail_on

    def __call__(self, session: Session) -> None:
        self.calls += 1
        if self.fail_on and session.seed.id == self.fail_on:
            session.send("zzhot then a crash")
            raise ConnectionError("attacker went away")
        for text in ("zzhot first", "zzhot second", "plain third"):
            if session.send(text)[1] == 1.0:
                return


def plan(tmp_path: Path, seeds: Path, hold: Path, **kw: Any) -> Plan:
    return Plan(seeds=seeds, holdout=hold, out=tmp_path / "adaptive",
                targets=(("v0.2.0", "a.toml"), ("patched", "b.toml")), attacker="attacker-model",
                judge="judge-model", per_family=2, **kw)  # fmt: skip


def test_run_attacks_every_pair_resumes_and_keeps_text_out_of_rows(tmp_path: Path) -> None:
    seeds = seeds_file(tmp_path)
    hold = holdout_file(tmp_path, seeds)
    p = plan(tmp_path, seeds, hold)
    targets = {"v0.2.0": target("original"), "patched": target()}
    attacker = Attacker()
    counts = run(p, targets, judge("yes"), attacker, log=lambda _: None)
    assert counts["pairs"] == 16  # 8 prompts x 2 targets
    assert counts["bypasses"] == 16
    assert counts["tries"] == 48
    tries = (p.out / "tries.jsonl").read_text()
    assert "plain third" not in tries
    assert "zzhot" not in tries
    bypasses = [json.loads(line) for line in (p.out / "bypasses.jsonl").read_text().splitlines()]
    assert len(bypasses) == 16
    assert {b["text"] for b in bypasses} == {"plain third"}
    again = run(p, targets, judge("yes"), Attacker(), log=lambda _: None)
    assert again.get("pairs", 0) == 0  # resumed: nothing left
    s = summary(p.out)
    assert s["table"]["patched/all"]["prompts"] == 8
    assert s["table"]["patched/all"]["bypassed"] == 8
    assert s["table"]["patched/all"]["median_tries_to_bypass"] == 3
    assert s["table"]["v0.2.0/encoding"]["prompts"] == 2


def test_a_failed_attack_is_retried_on_the_next_run(tmp_path: Path) -> None:
    seeds = seeds_file(tmp_path)
    hold = holdout_file(tmp_path, seeds)
    p = plan(tmp_path, seeds, hold)
    targets = {"v0.2.0": target("original"), "patched": target()}
    held = set(json.loads(hold.read_text())["groups"])
    victim = choose(list(read_seeds(seeds)), held, per_family=2)[0].id
    counts = run(p, targets, judge("yes"), Attacker(fail_on=victim), log=lambda _: None)
    assert counts["failed"] == 2  # both targets
    assert counts["pairs"] == 14
    again = run(p, targets, judge("yes"), Attacker(), log=lambda _: None)
    assert again["pairs"] == 2


def test_run_refuses_a_holdout_that_no_longer_matches(tmp_path: Path) -> None:
    seeds = seeds_file(tmp_path)
    hold = holdout_file(tmp_path, seeds)
    rec = json.loads(hold.read_text())
    rec["groups"] = rec["groups"][1:]
    hold.write_text(json.dumps(rec))
    with pytest.raises(ValueError, match="no longer matches"):
        run(plan(tmp_path, seeds, hold), {"patched": target()}, judge(), Attacker(),
            log=lambda _: None)  # fmt: skip


def test_a_different_run_in_the_same_directory_is_refused(tmp_path: Path) -> None:
    seeds = seeds_file(tmp_path)
    hold = holdout_file(tmp_path, seeds)
    run(plan(tmp_path, seeds, hold), {"patched": target()}, judge(), Attacker(),
        log=lambda _: None)  # fmt: skip
    with pytest.raises(SystemExit, match="different run"):
        run(plan(tmp_path, seeds, hold, max_tries=5), {"patched": target()}, judge(),
            Attacker(), log=lambda _: None)  # fmt: skip


# ------------------------------------------------------------------------------ models, CLI


def test_ollama_digests_pin_the_models_and_tolerate_other_servers() -> None:
    def tags(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/tags"
        models = [{"name": "attacker:7b", "digest": "abc"},
                  {"name": "judge:latest", "digest": "def"}]  # fmt: skip
        return httpx.Response(200, json={"models": models})

    client = httpx.Client(transport=httpx.MockTransport(tags))
    got = ollama_digests("http://box:11434/v1", ["attacker:7b", "judge", "absent"], client)
    assert got == {"attacker:7b": "abc", "judge": "def", "absent": ""}
    down = httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(404)))
    assert ollama_digests("http://box/v1", ["attacker:7b"], down) == {"attacker:7b": ""}


def test_cli_refuses_a_judge_that_is_the_attacker_and_bad_targets(tmp_path: Path) -> None:
    base = ["redteam", "adapt", "--seeds", "s.jsonl", "--holdout", "h.json",
            "--out", str(tmp_path), "--attacker", "m"]  # fmt: skip
    with pytest.raises(SystemExit, match="different model"):
        cli_main([*base, "--judge", "m", "--target", "a=x.toml"])
    with pytest.raises(SystemExit, match="NAME=CONFIG"):
        cli_main([*base, "--judge", "j", "--target", "just-a-path.toml"])


def test_cli_adapt_summary_prints_counts(tmp_path: Path,
                                         capsys: pytest.CaptureFixture[str]) -> None:  # fmt: skip
    seeds = seeds_file(tmp_path)
    p = plan(tmp_path, seeds, holdout_file(tmp_path, seeds))
    run(p, {"patched": target()}, judge("no"), Attacker(), log=lambda _: None)
    assert cli_main(["redteam", "adapt-summary", "--out", str(p.out)]) == 0
    table = json.loads(capsys.readouterr().out)["table"]
    assert table["patched/all"]["prompts"] == 8
    assert table["patched/all"]["bypassed"] == 0  # the judge said no every time: drift
    assert table["patched/all"]["with_drift"] == 8
