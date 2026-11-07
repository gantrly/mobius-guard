"""Charts for the README and the Fortress model card, from a report's metrics.json.

    uv run python scripts/release_charts.py runs/report-v0.3-attack/metrics.json docs/assets

Static SVG. ``fortress-*.svg`` follows the viewer's colour scheme (for Hugging Face);
``-light`` and ``-dark`` are fixed, for GitHub's ``<picture>``, which follows GitHub's own
theme. Every chart has a table of the same numbers next to it in the docs. Latency
is not in metrics.json: it is copied from the results notes (CPU, batch 1, 512 tokens).
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path
from typing import Any

DETECTORS = [  # (key in metrics.json, label, colour slot)
    ("retrain-deberta", "Fortress-XS (ours)", 1),
    ("piguard", "PIGuard", 2),
    ("protectai-v2", "ProtectAI v2", 3),
    ("keyword", "Keyword rules", 4),
]
LATENCY_MS_512 = {  # docs/results/2026-11-07-… and 2026-10-27-baselines.md
    "retrain-deberta": 183.0,
    "piguard": 1151.0,
    "protectai-v2": 1151.0,
    "keyword": 0.21,
}
FAMILIES = [  # the families no compared detector trained on
    ("gandalf", "Gandalf"),
    ("llmail", "LLMail-Inject (indirect)"),
    ("bipia", "BIPIA (indirect)"),
    ("spml", "SPML"),
    ("obf:base64", "base64"),
    ("obf:spaced", "Spaced letters"),
    ("obf:leetspeak", "Leetspeak"),
    ("obf:homoglyph", "Look-alike letters"),
    ("obf:zero_width", "Invisible characters"),
]
BENIGN = [
    ("oasst", "Ordinary messages (oasst1)"),
    ("notinject", "NotInject (trigger words)"),
    ("orbench", "OR-Bench hard"),
    ("llmail_benign", "LLMail benign emails"),
]

LIGHT = """.bg{fill:#fcfcfb} .t1{fill:#0b0b0b} .t2{fill:#52514e} .grid{stroke:#e4e3df}
  .axis{stroke:#b9b8b2} .s1{fill:#2a78d6} .s2{fill:#eb6834} .s3{fill:#1baf7a}
  .s4{fill:#eda100} .muted{fill:#8f8e88} .ring{stroke:#fcfcfb}"""
DARK = """.bg{fill:#1a1a19} .t1{fill:#f0efec} .t2{fill:#c3c2b7} .grid{stroke:#383835}
  .axis{stroke:#5a5955} .s1{fill:#3987e5} .s2{fill:#d95926} .s3{fill:#199e70}
  .s4{fill:#c98500} .muted{fill:#8f8e88} .ring{stroke:#1a1a19}"""
FONT = 'text{font-family:-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}'
THEMES = {
    "": f"<style>{LIGHT} {FONT} @media (prefers-color-scheme: dark){{{DARK}}}</style>",
    "-light": f"<style>{LIGHT} {FONT}</style>",
    "-dark": f"<style>{DARK} {FONT}</style>",
}
STYLE = "@STYLE@"


def _at(entry: dict[str, Any], fpr: float = 0.01) -> float:
    return 100 * next(a["rate"] for a in entry["at"] if abs(a["target_fpr"] - fpr) < 1e-9)


def _svg(w: int, h: int, title: str, body: list[str]) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" '
        f'viewBox="0 0 {w} {h}" role="img" aria-label="{title}">{STYLE}'
        f'<title>{title}</title><rect class="bg" width="{w}" height="{h}" rx="8"/>'
        + "".join(body)
        + "</svg>\n"
    )


def _legend(x: int, y: int) -> list[str]:
    out: list[str] = []
    for _, label, slot in DETECTORS:
        out.append(f'<rect class="s{slot}" x="{x}" y="{y - 9}" width="10" height="10" rx="2"/>')
        out.append(f'<text class="t2" x="{x + 15}" y="{y}" font-size="12">{label}</text>')
        x += 30 + 7 * len(label)
    return out


def _bars(
    m: dict[str, Any],
    rows: list[tuple[str, str]],
    kind: str,
    xmax: float,
    title: str,
    unit: str,
    ticks: int = 5,
) -> str:
    w, left, right, top = 760, 190, 30, 64
    bar, gap, group_gap = 7, 2, 14
    group = len(DETECTORS) * (bar + gap) - gap
    h = top + len(rows) * (group + group_gap) + 34
    plot = w - left - right
    body = [f'<text class="t1" x="16" y="26" font-size="15" font-weight="600">{title}</text>']
    body += _legend(16, 48)
    for i in range(ticks + 1):
        v = xmax * i / ticks
        x = left + plot * i / ticks
        body.append(f'<line class="grid" x1="{x:.1f}" y1="{top - 6}" x2="{x:.1f}" '
                    f'y2="{h - 30}" stroke-width="1"/>')  # fmt: skip
        body.append(f'<text class="t2" x="{x:.1f}" y="{h - 14}" font-size="11" '
                    f'text-anchor="middle">{v:g}{unit}</text>')  # fmt: skip
    y = top
    for key, label in rows:
        body.append(f'<text class="t1" x="{left - 10}" y="{y + group / 2 + 4:.1f}" '
                    f'font-size="12" text-anchor="end">{label}</text>')  # fmt: skip
        for det, name, slot in DETECTORS:
            v = _at(m[det][kind][key])
            bw = max(plot * min(v, xmax) / xmax, 1.5)
            tip = f"<title>{name}, {label}: {v:.1f}%</title>"
            body.append(f'<rect class="s{slot}" x="{left}" y="{y}" width="{bw:.1f}" '
                        f'height="{bar}" rx="2">{tip}</rect>')  # fmt: skip
            y += bar + gap
        y += group_gap - gap
    body.append(f'<line class="axis" x1="{left}" y1="{top - 6}" x2="{left}" y2="{h - 30}"/>')
    return _svg(w, h, title, body)


def recall_chart(m: dict[str, Any]) -> str:
    return _bars(m, FAMILIES, "recall", 100, "Attacks caught at 1% false positives (%)", "%")


def fpr_chart(m: dict[str, Any]) -> str:
    return _bars(
        m, BENIGN, "fpr", 12, "False positives on benign text (%), lower is better", "%", 6
    )


def speed_chart(m: dict[str, Any]) -> str:
    w, h, left, right, top, bottom = 760, 380, 70, 40, 56, 52
    pw, ph = w - left - right, h - top - bottom
    lo, hi = math.log10(0.1), math.log10(3000)

    def px(ms: float) -> float:
        return left + pw * (math.log10(ms) - lo) / (hi - lo)

    def py(v: float) -> float:
        return top + ph * (1 - v / 80)

    title = "Accuracy vs CPU speed"
    sub = ("Average recall over 9 attack families none of them trained on, at 1% false "
           "positives; CPU, batch 1, 512 tokens")  # fmt: skip
    body = [f'<text class="t1" x="16" y="26" font-size="15" font-weight="600">{title}</text>',
            f'<text class="t2" x="16" y="44" font-size="12">{sub}</text>']  # fmt: skip
    for v in range(0, 81, 20):
        body.append(f'<line class="grid" x1="{left}" y1="{py(v):.1f}" x2="{w - right}" '
                    f'y2="{py(v):.1f}"/>')  # fmt: skip
        body.append(f'<text class="t2" x="{left - 8}" y="{py(v) + 4:.1f}" font-size="11" '
                    f'text-anchor="end">{v}%</text>')  # fmt: skip
    for ms in (0.1, 1, 10, 100, 1000):
        body.append(f'<text class="t2" x="{px(ms):.1f}" y="{h - bottom + 18}" font-size="11" '
                    f'text-anchor="middle">{ms:g} ms</text>')  # fmt: skip
    body.append(
        f'<text class="t2" x="{left + pw / 2}" y="{h - 10}" font-size="11" '
        'text-anchor="middle">Latency per request (log scale; left is faster)</text>'
    )
    body.append(f'<line class="axis" x1="{left}" y1="{h - bottom}" x2="{w - right}" '
                f'y2="{h - bottom}"/>')  # fmt: skip
    keys = [f for f, _ in FAMILIES]
    offsets = {"piguard": -14, "protectai-v2": 22}
    for det, name, slot in DETECTORS:
        v = sum(_at(m[det]["recall"][k]) for k in keys) / len(keys)
        x, y = px(LATENCY_MS_512[det]), py(v)
        cls = f"s{slot}" if slot == 1 else "muted"
        r = 8 if slot == 1 else 6
        body.append(f'<circle class="{cls} ring" cx="{x:.1f}" cy="{y:.1f}" r="{r}" '
                    f'stroke-width="2"><title>{name}: {v:.1f}%, '
                    f'{LATENCY_MS_512[det]:g} ms</title></circle>')  # fmt: skip
        anchor, dx = ("end", -14) if x > left + pw * 0.6 else ("start", 14)
        weight = ' font-weight="600"' if slot == 1 else ""
        body.append(f'<text class="t1" x="{x + dx:.1f}" y="{y + 4 + offsets.get(det, 0):.1f}" '
                    f'font-size="12" text-anchor="{anchor}"{weight}>{name}: {v:.1f}%, '
                    f'{LATENCY_MS_512[det]:g} ms</text>')  # fmt: skip
    return _svg(w, h, title, body)


def main() -> None:
    metrics = json.loads(Path(sys.argv[1]).read_text())["detectors"]
    out = Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    for name, fn in (("recall", recall_chart), ("false-positives", fpr_chart),
                     ("speed", speed_chart)):  # fmt: skip
        svg = fn(metrics)
        for suffix, style in THEMES.items():
            path = out / f"fortress-{name}{suffix}.svg"
            path.write_text(svg.replace(STYLE, style))
            print(path)


if __name__ == "__main__":
    main()
