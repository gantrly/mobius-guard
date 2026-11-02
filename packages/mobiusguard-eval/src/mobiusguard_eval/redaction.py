"""Evaluate the streaming redactor (decision 0009).

Two measurements:

1. **Firing on real text.** Run every pattern over the suite's texts (public prompts and
   messages) and count, per pattern, how many items it fires on. These texts were not
   chosen to contain secrets, so a secret rule that fires often is a false-positive
   suspect; each finding is written out with its context for a person to review. PII rules
   firing here may be correct (people do paste emails), which is why this is reported as a
   firing rate, not a false-positive rate.
2. **Recall on synthetic secrets in real text.** For every curated pattern, generate valid
   values, place them in ordinary messages with a typical surrounding phrase, stream the
   result in random chunk sizes, and check that no part of the value comes out, that the
   streamed output equals the one-shot output, and which label replaced it. Near misses
   (bad check digit, too short) check that the validators hold. Synthetic values measure
   matching in context, not how often real secrets look like this.
3. **Recall on garbled values.** Models do not repeat a secret exactly (live check,
   2026-10-30): they wrap it in backticks or quotes, add or drop a few characters, or change
   what surrounds it. Each garbling is its own family, so a gap shows where it is.

The keyword prefilter is checked on the way: every public text is redacted with and
without it, and any difference is reported.
"""

from __future__ import annotations

import base64
import json
import random
import string
from collections import Counter, defaultdict
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mobiusguard_redact import Pattern, StreamRedactor, default_patterns, redact
from mobiusguard_redact import __version__ as redact_version
from mobiusguard_redact.validators import _V_D, _V_P  # pyright: ignore[reportPrivateUsage]

from .checkpoint import Checkpoint, fingerprint, write_atomic
from .items import Item

ALNUM = string.ascii_letters + string.digits
TOK = ALNUM + "_-"
B32 = string.ascii_uppercase + "234567"


def _s(rng: random.Random, alphabet: str, n: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def _luhn_digit(body: str) -> str:
    total = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return str((10 - total % 10) % 10)


def _verhoeff_digit(body: str) -> str:
    c = 0
    for i, ch in enumerate(reversed(body + "0")):
        c = _V_D[c][_V_P[i % 8][int(ch)]]
    return str((0, 4, 3, 2, 1, 5, 6, 7, 8, 9)[c])


def _iban(rng: random.Random, country: str, bban: str) -> str:
    numeric = "".join(str(int(c, 36)) for c in bban + country + "00")
    check = 98 - int(numeric) % 97
    return f"{country}{check:02d}{bban}"


def _group(s: str, rng: random.Random, size: int = 4) -> str:
    sep = rng.choice([" ", "-", ""]) if s.isdigit() else rng.choice([" ", ""])
    return sep.join(s[i : i + size] for i in range(0, len(s), size))


def _b64url(obj: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


# For each curated pattern: (value generator, phrases it appears in). ``{}`` is the value.
Gen = Callable[[random.Random], str]


def _card(r: random.Random) -> str:
    body = "4" + _s(r, string.digits, 14)
    return _group(body + _luhn_digit(body), r)


def _aadhaar(r: random.Random) -> str:
    body = r.choice("23456789") + _s(r, string.digits, 10)
    return _group(body + _verhoeff_digit(body), r)


def _iban_any(r: random.Random) -> str:
    if r.random() < 0.5:
        value = _iban(r, "DE", _s(r, string.digits, 18))
    else:
        value = _iban(r, "GB", _s(r, string.ascii_uppercase, 4) + _s(r, string.digits, 14))
    return _group(value, r) if r.random() < 0.5 else value


def _phone(r: random.Random) -> str:
    cc = r.choice(["1", "44", "91", "49", "33", "61"])
    rest = _s(r, string.digits, 10 - (len(cc) - 1))
    return f"+{cc} {rest[:3]} {rest[3:6]} {rest[6:]}"


def _pem(r: random.Random) -> str:
    lines = "\n".join(_s(r, ALNUM + "+/", 64) for _ in range(6))
    return f"-----BEGIN RSA PRIVATE KEY-----\n{lines}\n-----END RSA PRIVATE KEY-----"


GENERATORS: dict[str, tuple[Gen, tuple[str, ...]]] = {
    "aws_access_key_id": (
        lambda r: "AKIA" + _s(r, B32, 16),
        ("my access key is {} if you need it", "AWS_ACCESS_KEY_ID={}", '"AccessKeyId": "{}"'),
    ),
    "aws_secret_access_key": (
        lambda r: _s(r, ALNUM + "/+", 40),
        ('aws_secret_access_key = "{}"', "AWS secret key: {}", "export AWS_SECRET_ACCESS_KEY={}"),
    ),
    "github_token": (lambda r: "ghp_" + _s(r, ALNUM, 36), ("use the token {} for the API",)),
    "github_fine_grained_token": (
        lambda r: "github_pat_" + _s(r, ALNUM + "_", 82),
        ("GITHUB_TOKEN={}", "here is my PAT: {}"),
    ),
    "gitlab_token": (lambda r: "glpat-" + _s(r, TOK, 20), ("token = {}",)),
    "openai_api_key": (
        lambda r: "sk-proj-" + _s(r, TOK, 48),
        ("OPENAI_API_KEY={}", 'client = OpenAI(api_key="{}")'),
    ),
    "anthropic_api_key": (
        lambda r: "sk-ant-api03-" + _s(r, TOK, 93),
        ("ANTHROPIC_API_KEY={}", "my key is {}"),
    ),
    "google_api_key": (lambda r: "AIza" + _s(r, TOK, 35), ("?key={}&q=coffee", "key: {}")),
    "huggingface_token": (lambda r: "hf_" + _s(r, ALNUM, 34), ("HF_TOKEN={}",)),
    "slack_token": (
        lambda r: f"xoxb-{_s(r, string.digits, 12)}-{_s(r, string.digits, 13)}-{_s(r, ALNUM, 24)}",
        ("SLACK_BOT_TOKEN={}",),
    ),
    "slack_webhook_url": (
        lambda r: (
            "https://hooks.slack.com/services/T"
            + _s(r, string.ascii_uppercase + string.digits, 8)
            + "/B"
            + _s(r, string.ascii_uppercase + string.digits, 10)
            + "/"
            + _s(r, ALNUM, 24)
        ),
        ("post it to {} please", "webhook: {}"),
    ),
    "stripe_secret_key": (lambda r: "sk_live_" + _s(r, ALNUM, 24), ("stripe.api_key = '{}'",)),
    "npm_token": (lambda r: "npm_" + _s(r, ALNUM, 36), ("//registry.npmjs.org/:_authToken={}",)),
    "json_web_token": (
        lambda r: (
            _b64url({"alg": "HS256", "typ": "JWT"})
            + "."
            + _b64url({"sub": _s(r, string.digits, 10), "name": _s(r, string.ascii_letters, 8)})
            + "."
            + _s(r, TOK, 43)
        ),
        ("Authorization: {}", "the session cookie was {}"),
    ),
    "private_key": (_pem, ("here is the key:\n{}\n", "{}")),
    "connection_string_password": (
        lambda r: _s(r, ALNUM + "!#%^*", 14),
        (
            "DATABASE_URL=postgres://app:{}@db.internal:5432/prod",
            "mongodb+srv://admin:{}@c0.x.net/",
        ),
    ),
    "bearer_token": (
        lambda r: _s(r, ALNUM + "._-", 40),
        ("curl -H 'Authorization: Bearer {}' https://api.example.com",),
    ),
    "email": (
        lambda r: (
            f"{_s(r, string.ascii_lowercase, 6)}.{_s(r, string.ascii_lowercase, 7)}"
            f"@{r.choice(['gmail.com', 'example.org', 'company.co.uk', 'mail.de'])}"
        ),
        ("you can reach me at {}", "email: {}", "send it to <{}>"),
    ),
    "payment_card": (_card, ("my card number is {}", "card: {} exp 04/29")),
    "iban": (_iban_any, ("IBAN: {}", "please transfer to {} by Friday")),
    "us_ssn": (
        lambda r: f"{r.randint(1, 665):03d}-{r.randint(1, 99):02d}-{r.randint(1, 9999):04d}",
        ("SSN {}", "my social security number is {}"),
    ),
    "in_aadhaar": (_aadhaar, ("Aadhaar: {}", "my aadhaar number is {}")),
    "in_pan": (
        lambda r: (
            _s(r, string.ascii_uppercase, 3)
            + r.choice("ABCFGHJLPT")
            + _s(r, string.ascii_uppercase, 1)
            + _s(r, string.digits, 4)
            + _s(r, string.ascii_uppercase, 1)
        ),
        ("PAN {}", "my PAN card number is {}"),
    ),
    "phone_international": (_phone, ("call me on {}", "phone: {}")),
}

# Values that look right but must not be redacted by the named pattern.
NEAR_MISSES: dict[str, Gen] = {
    "payment_card": lambda r: (lambda c: c[:-1] + str((int(c[-1]) + 1) % 10))(_card(r)),
    "iban": lambda r: (lambda v: v[:2] + f"{(int(v[2:4]) + 1) % 100:02d}" + v[4:])(
        _iban(r, "DE", _s(r, string.digits, 18))
    ),
    "in_aadhaar": lambda r: (lambda c: c[:-1] + str((int(c[-1]) + 1) % 10))(_aadhaar(r)),
    "phone_international": lambda r: f"+1 {_s(r, string.digits, 3)} {_s(r, string.digits, 3)}",
    # Too short to be a key, even one with a few characters dropped.
    "aws_access_key_id": lambda r: "AKIA" + _s(r, B32, 8),
}


# Patterns whose values are tokens with a fixed prefix: a model may add or drop characters.
TOKENS = (
    "aws_access_key_id", "github_token", "github_fine_grained_token", "gitlab_token",
    "openai_api_key", "anthropic_api_key", "google_api_key", "huggingface_token",
    "slack_token", "stripe_secret_key", "npm_token", "json_web_token",
)  # fmt: skip
WRAPS = ("`{}`", '"{}"', "'{}'", "({})", "{}.", "{},", "**{}**", "<{}>", "{}:", "[{}]")
# Other surroundings a model writes for patterns that depend on context.
CONTEXTS: dict[str, tuple[str, ...]] = {
    "connection_string_password": (
        "postgres://app:{}/db/prod",  # the host dropped, as in the live check
        "postgresql://app:{}@localhost/prod",
        "redis://:{}@cache:6379/0",
        "mysql://root:{}@10.0.0.5/app",
    ),
    "aws_secret_access_key": ("secret key {}", "AWS secret: {}", "SecretAccessKey: {}"),
    "bearer_token": ("Bearer {}", "authorization: bearer {}", '"Authorization": "Bearer {}"'),
}


# Values that sit inside a URL: the model wraps the whole URL, not the password.
WRAP_PHRASE = frozenset({"connection_string_password"})


def _wrapped(gen: Gen) -> Gen:
    return lambda r: r.choice(WRAPS).format(gen(r))


def _wrapped_phrases(phrases: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(w.replace("{}", p) for p in phrases for w in WRAPS)


def _longer(gen: Gen) -> Gen:
    def g(r: random.Random) -> str:
        v = gen(r)
        return v + "".join(r.choice(v[-10:]) for _ in range(r.randint(1, 4)))

    return g


def _shorter(gen: Gen) -> Gen:
    return lambda r: gen(r)[: -r.randint(1, 3)]


def garbled_jobs() -> list[tuple[str, str, Gen, tuple[str, ...]]]:
    jobs = [
        (pid, "garbled:wrapped", g, _wrapped_phrases(ph))
        if pid in WRAP_PHRASE
        else (pid, "garbled:wrapped", _wrapped(g), ph)
        for pid, (g, ph) in GENERATORS.items()
    ]
    for pid in TOKENS:
        g, ph = GENERATORS[pid]
        jobs += [(pid, "garbled:longer", _longer(g), ph), (pid, "garbled:shorter", _shorter(g), ph)]
    jobs += [(pid, "garbled:context", GENERATORS[pid][0], ph) for pid, ph in CONTEXTS.items()]
    return jobs


def leaked(value: str, output: str, window: int = 8, *, context: str = "") -> bool:
    """Whether any ``window``-character piece of ``value`` reached ``output``.

    Pieces that also occur in ``context`` (the message the value was put into) are not
    counted: "services" in a webhook URL is not a leak when the message says "services".
    """
    if len(value) <= window:
        return value in output
    pieces = {value[i : i + window] for i in range(len(value) - window + 1)}
    return any(p in output and p not in context for p in pieces)


LEAK_CHECK = 2  # bump when ``leaked`` changes, so saved results are recomputed


def _stream(text: str, rng: random.Random, patterns: Sequence[Pattern]) -> str:
    r = StreamRedactor(patterns)
    out: list[str] = []
    i = 0
    while i < len(text):
        n = rng.randint(1, 12)
        out.append(r.feed(text[i : i + n]))
        i += n
    out.append(r.flush())
    return "".join(out)


def _insert(carrier: str, phrase: str, rng: random.Random) -> str:
    cuts = [i + 1 for i, c in enumerate(carrier) if c in ".!?\n"] or [len(carrier)]
    at = rng.choice(cuts)
    return f"{carrier[:at]} {phrase} {carrier[at:]}"


@dataclass(frozen=True, slots=True)
class SyntheticResult:
    pattern_id: str
    kind: str  # "positive", "near_miss" or "garbled:<how>"
    leaked: bool
    labels: tuple[str, ...]  # labels in the output that were not in the carrier's output
    stream_equal: bool


def synthetic_jobs() -> list[tuple[str, str, Gen, tuple[str, ...]]]:
    """(pattern, kind, value generator, phrases): one unit of synthetic work each."""
    jobs: list[tuple[str, str, Gen, tuple[str, ...]]] = [
        (pid, "positive", gen, phrases) for pid, (gen, phrases) in GENERATORS.items()
    ]
    jobs += [(pid, "near_miss", gen, GENERATORS[pid][1]) for pid, gen in NEAR_MISSES.items()]
    return jobs + garbled_jobs()


def synthetic_job(
    pid: str,
    kind: str,
    gen: Gen,
    phrases: tuple[str, ...],
    carriers: Sequence[str],
    *,
    per_pattern: int,
    seed: int,
    patterns: Sequence[Pattern],
) -> list[SyntheticResult]:
    """One pattern's cases. Seeded by pattern and kind, so a job gives the same cases
    whether it runs alone, after others, or after a restart."""
    rng = random.Random(f"{seed}:{pid}:{kind}")  # noqa: S311 - reproducible test data
    base_labels: dict[str, Counter[str]] = {}

    def labels_in(text: str) -> Counter[str]:
        out = redact(text, patterns)
        return Counter(part.split("]", 1)[0] for part in out.split("[REDACTED:")[1:] if "]" in part)

    results: list[SyntheticResult] = []
    for _ in range(per_pattern):
        carrier = rng.choice(carriers)
        value = gen(rng)
        text = _insert(carrier, rng.choice(phrases).format(value), rng)
        one_shot = redact(text, patterns)
        streamed = _stream(text, rng, patterns)
        if carrier not in base_labels:
            base_labels[carrier] = labels_in(carrier)
        new = labels_in(text) - base_labels[carrier]
        results.append(
            SyntheticResult(
                pattern_id=pid,
                kind=kind,
                leaked=leaked(value, one_shot, context=carrier),
                labels=tuple(sorted(new)),
                stream_equal=one_shot == streamed,
            )
        )
    return results


def synthetic(
    carriers: Sequence[str], *, per_pattern: int = 200, seed: int = 0, patterns: Sequence[Pattern]
) -> list[SyntheticResult]:
    """Every pattern's cases, without checkpoints."""
    return [
        r
        for pid, kind, gen, phrases in synthetic_jobs()
        for r in synthetic_job(
            pid, kind, gen, phrases, carriers, per_pattern=per_pattern, seed=seed, patterns=patterns
        )
    ]


def firing(
    items: Sequence[Item], patterns: Sequence[Pattern]
) -> tuple[Counter[str], list[dict[str, str]], list[str]]:
    """Per pattern, the number of items it fired on; every finding with its context; and
    the items whose output changes without the keyword prefilter (should be none)."""
    per_pattern: Counter[str] = Counter()
    findings: list[dict[str, str]] = []
    differs: list[str] = []
    for it in items:
        r = StreamRedactor(patterns)
        out = r.feed(it.text) + r.flush()
        if out != redact(it.text, patterns, prefilter=False):
            differs.append(it.id)
        for pid in {f.pattern_id for f in r.findings}:
            per_pattern[pid] += 1
        for f in r.findings:
            findings.append(
                {
                    "item": it.id,
                    "source": it.source,
                    "pattern": f.pattern_id,
                    "category": f.category or "",
                    "context": it.text[max(0, f.start - 40) : f.end + 40],
                }
            )
    return per_pattern, findings, differs


FIRING_CHUNK = 2000


def patterns_key(patterns: Sequence[Pattern]) -> str:
    """Identifies a pattern set: everything that decides what gets redacted."""
    return fingerprint(
        [
            [
                p.id,
                p.regex,
                str(p.group),
                p.min_entropy,
                p.not_after,
                list(p.keywords),
                p.priority,
                getattr(p.validator, "__name__", ""),
                [[a.target, a.regexes, a.stopwords, a.require_all] for a in p.allowlists],
            ]
            for p in patterns
        ]
        + [redact_version]
    )


def evaluate(
    items: Sequence[Item],
    out: Path,
    *,
    per_pattern: int = 200,
    seed: int = 0,
    force: bool = False,
    log: Callable[[str], None] = lambda _: None,
) -> dict[str, Any]:
    """Run both measurements on a suite's original texts; write files into ``out``.

    Resumable: firing is saved per 2,000 texts and the synthetic cases per pattern in
    ``redaction.partial.jsonl``; a restart only does what is missing.
    """
    patterns = default_patterns()
    by_id = {p.id: p for p in patterns}
    texts = [it for it in items if not it.family.startswith("obf:")]
    carriers = [it.text for it in texts if it.source == "oasst" and it.split == "test"]
    carriers = [c for c in carriers if len(c) < 2000] or [it.text for it in texts[:1000]]
    key = {
        "patterns": patterns_key(patterns),
        "texts": fingerprint([it.id for it in texts]),
        "per_pattern": per_pattern,
        "seed": seed,
        "leak_check": LEAK_CHECK,
        "jobs": [[pid, kind] for pid, kind, *_ in synthetic_jobs()],
    }
    out.mkdir(parents=True, exist_ok=True)
    partial = out / "redaction.partial.jsonl"
    if force and partial.exists():
        partial.unlink()
    ckpt = Checkpoint(partial, key)

    for start in range(0, len(texts), FIRING_CHUNK):
        unit = f"firing-{start // FIRING_CHUNK:05d}"
        if unit in ckpt:
            continue
        fired, found, differs = firing(texts[start : start + FIRING_CHUNK], patterns)
        ckpt.add(unit, {"fired": dict(fired), "findings": found, "prefilter_differs": differs})
        log(f"redaction: {unit} done")
    for pid, kind, gen, phrases in synthetic_jobs():
        unit = f"synthetic-{pid}/{kind}"
        if unit in ckpt:
            continue
        res = synthetic_job(pid, kind, gen, phrases, carriers, per_pattern=per_pattern,
                            seed=seed, patterns=patterns)  # fmt: skip
        ckpt.add(unit, [[r.leaked, list(r.labels), r.stream_equal] for r in res])
        log(f"redaction: {unit} done")

    fired_all: Counter[str] = Counter()
    findings: list[dict[str, str]] = []
    differs_all: list[str] = []
    groups: dict[tuple[str, str], list[SyntheticResult]] = defaultdict(list)
    for unit, data in sorted(ckpt.units.items()):
        if unit.startswith("firing-"):
            fired_all.update(data["fired"])
            findings.extend(data["findings"])
            differs_all.extend(data["prefilter_differs"])
        else:
            pid, kind = unit.removeprefix("synthetic-").split("/")
            for leak, labels, equal in data:
                groups[(pid, kind)].append(SyntheticResult(pid, kind, leak, tuple(labels), equal))

    write_atomic(
        out / "redaction_findings.jsonl",
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in findings),
    )
    write_atomic(
        out / "redaction_synthetic.jsonl",
        "".join(
            json.dumps(
                {
                    "pattern": r.pattern_id,
                    "kind": r.kind,
                    "leaked": r.leaked,
                    "labels": r.labels,
                    "stream_equal": r.stream_equal,
                }
            )
            + "\n"
            for g in groups.values()
            for r in g
        ),
    )
    summary: dict[str, Any] = {
        "texts": len(texts),
        "patterns": len(patterns),
        "patterns_with_keywords": sum(bool(p.keywords) for p in patterns),
        "prefilter_differs": differs_all,
        "firing": {
            pid: {
                "items": n,
                "per_10k": round(1e4 * n / len(texts), 2),
                # holdback_overflow is the redactor's own marker, not a pattern
                "category": by_id[pid].category if pid in by_id else "overflow",
                "source": by_id[pid].source if pid in by_id else "redactor",
            }
            for pid, n in fired_all.most_common()
        },
        "synthetic": {
            f"{pid}/{kind}": {
                "n": len(g),
                "leaked": sum(r.leaked for r in g),
                "expected_label": sum(pid in r.labels for r in g),
                "stream_equal": sum(r.stream_equal for r in g),
                "other_labels": dict(Counter(lab for r in g for lab in r.labels if lab != pid)),
            }
            for (pid, kind), g in sorted(groups.items())
        },
    }
    write_atomic(out / "redaction_summary.json", json.dumps(summary, indent=2) + "\n")
    write_atomic(out / "redaction_report.md", render_redaction(summary))
    return summary


def render_redaction(summary: dict[str, Any]) -> str:
    lines = [
        "# Redactor evaluation",
        "",
        f"{summary['patterns']} patterns over {summary['texts']:,} public prompts and messages.",
        "",
        "## Synthetic values placed in real messages, streamed in random chunks",
        "",
        "Positives: *redacted* = no 8-character piece of the value reached the output. "
        "Near misses (bad check digit, too short): *redacted* should be 0 for the named "
        "pattern's label.",
        "",
    ]
    head = [
        "| Pattern | Kind | n | Redacted % | Expected label % | Stream = one-shot % "
        "| Other labels |",
        "|---|---|---:|---:|---:|---:|---|",
    ]

    def rows(garbled: bool) -> list[str]:
        out: list[str] = []
        for key, s in summary["synthetic"].items():
            pid, kind = key.split("/")
            if kind.startswith("garbled:") != garbled:
                continue
            n = s["n"]
            redacted = s["expected_label"] if kind == "near_miss" else n - s["leaked"]
            others = ", ".join(f"{k} {v}" for k, v in sorted(s["other_labels"].items())) or "-"
            out.append(
                f"| {pid} | {kind.removeprefix('garbled:')} | {n} | {100 * redacted / n:.1f} | "
                f"{100 * s['expected_label'] / n:.1f} | {100 * s['stream_equal'] / n:.1f} "
                f"| {others} |"
            )
        return out

    lines += [*head, *rows(False)]
    lines += [
        "",
        "## Values garbled the way models repeat them",
        "",
        "*wrapped*: in backticks, quotes, brackets or bold, or followed by punctuation. "
        "*longer* / *shorter*: a token with 1-4 characters added or 1-3 dropped. "
        "*context*: other surroundings (a connection string without its host, a bare "
        "`Bearer`). *Redacted* = no 8-character piece of the value as written came out.",
        "",
        *head,
        *rows(True),
    ]
    differs = summary.get("prefilter_differs", [])
    lines += [
        "",
        "## Keyword prefilter",
        "",
        f"{summary.get('patterns_with_keywords', 0)} patterns run only where one of their "
        f"keywords is present. Texts whose output changes without the prefilter: "
        f"**{len(differs)}**" + (f" ({', '.join(differs[:10])})" if differs else "") + ".",
    ]
    lines += [
        "",
        "## How often each pattern fires on public text",
        "",
        "Items fired on, per 10,000 texts. Secret patterns firing here are false-positive "
        "suspects; review `redaction_findings.jsonl`. PII may be real.",
        "",
        "| Pattern | Category | Source | Items | Per 10k |",
        "|---|---|---|---:|---:|",
    ]
    for pid, f in summary["firing"].items():
        lines.append(
            f"| {pid} | {f['category']} | {f['source']} | {f['items']:,} | {f['per_10k']} |"
        )
    return "\n".join(lines) + "\n"
