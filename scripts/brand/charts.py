"""Draw the README's result charts as SVG, light and dark.

Usage:  uv run python scripts/brand/charts.py

Every number is copied from a dated results page (the source is next to it below); change
them only together with that page. Writes .github/assets/stats(-dark).svg and
obfuscation(-dark).svg in Gantrly's Hi-vis palette, the same as hero.py.
"""

from __future__ import annotations

from html import escape
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent.parent / ".github" / "assets"

THEMES = {
    "": {
        "bg": "#F7F8F9", "panel": "#FFFFFF", "line": "#DDE1E6", "text": "#1B1E23",
        "muted": "#6B7480", "track": "#EEF0F2", "base": "#9AA3AE", "amber": "#F5B301",
    },
    "-dark": {
        "bg": "#121418", "panel": "#1B1E23", "line": "#2C3239", "text": "#E8EBEE",
        "muted": "#9AA3AE", "track": "#242930", "base": "#6B7480", "amber": "#F5B301",
    },
}  # fmt: skip

SANS = "-apple-system,'Segoe UI',Helvetica,Arial,sans-serif"

# docs/results/2026-11-02-redactor.md, 2026-10-29-proxy.md, decision 0007 (AWS g6.xlarge CPU)
STATS = [
    ("0 / 15,000", "secrets leaked", "exact and garbled"),
    ("0 / 23,221", "benign texts blocked", "by the request rules"),
    ("0.15 ms", "per streamed token", "245 patterns, one CPU core"),
    ("≈ 1 word", "of delay", "3 characters at the median"),
]

# docs/results/2026-10-29-proxy.md: recall at 1% false positives on ordinary messages (%)
OBFUSCATION = [
    ("Spaced letters", {"PIGuard": (0.8, 61.0), "ProtectAI v2": (0.0, 38.2)}),
    ("Look-alike letters", {"PIGuard": (4.1, 60.7), "ProtectAI v2": (16.6, 40.7)}),
    ("Invisible characters", {"PIGuard": (0.2, 60.5), "ProtectAI v2": (11.2, 41.4)}),
]


def _svg(width: int, height: int, body: list[str], t: dict[str, str], title: str) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-label="{escape(title)}">'
        f"<title>{escape(title)}</title>"
        f"<style>text{{font-family:{SANS}}}</style>"
        f'<rect width="{width}" height="{height}" rx="14" fill="{t["bg"]}"/>'
        + "".join(body)
        + "</svg>\n"
    )


def stats(t: dict[str, str]) -> str:
    width, height, pad, gap = 880, 132, 16, 12
    w = (width - 2 * pad - 3 * gap) / 4
    body: list[str] = []
    for i, (big, label, note) in enumerate(STATS):
        x = pad + i * (w + gap)
        body += [
            f'<rect x="{x:.1f}" y="{pad}" width="{w:.1f}" height="{height - 2 * pad}" rx="10" '
            f'fill="{t["panel"]}" stroke="{t["line"]}"/>',
            f'<rect x="{x:.1f}" y="{pad}" width="4" height="{height - 2 * pad}" rx="2" '
            f'fill="{t["amber"]}"/>',
            f'<text x="{x + 20:.1f}" y="{pad + 42}" font-size="28" font-weight="700" '
            f'fill="{t["text"]}">{escape(big)}</text>',
            f'<text x="{x + 20:.1f}" y="{pad + 66}" font-size="14" font-weight="600" '
            f'fill="{t["text"]}">{escape(label)}</text>',
            f'<text x="{x + 20:.1f}" y="{pad + 86}" font-size="12" '
            f'fill="{t["muted"]}">{escape(note)}</text>',
        ]
    return _svg(width, height, body, t, "Mobius Guard in four numbers")


def obfuscation(t: dict[str, str]) -> str:
    width, left, right = 880, 200, 70
    bar_w = width - left - right
    row_h, bar_h = 30, 11
    y = 112
    body = [
        f'<text x="24" y="36" font-size="16" font-weight="700" fill="{t["text"]}">'
        "Normalisation lets existing classifiers see through obfuscation</text>",
        f'<text x="24" y="58" font-size="12.5" fill="{t["muted"]}">Recall (%) at 1% false '
        "positives on ordinary messages, 1,000 obfuscated attacks per trick</text>",
    ]
    # legend, under the subtitle
    body += [
        f'<rect x="24" y="72" width="14" height="10" rx="2" fill="{t["base"]}"/>',
        f'<text x="44" y="81" font-size="12" fill="{t["muted"]}">model alone</text>',
        f'<rect x="134" y="72" width="14" height="10" rx="2" fill="{t["amber"]}"/>',
        f'<text x="154" y="81" font-size="12" fill="{t["muted"]}">'
        "with Mobius Guard's normalisation in front</text>",
    ]
    for trick, models in OBFUSCATION:
        body.append(
            f'<text x="24" y="{y + 4}" font-size="13.5" font-weight="700" '
            f'fill="{t["text"]}">{escape(trick)}</text>'
        )
        y += 14
        for model, (before, after) in models.items():
            body.append(
                f'<text x="40" y="{y + 15}" font-size="12.5" fill="{t["muted"]}">'
                f"{escape(model)}</text>"
            )
            for k, (value, colour) in enumerate(((before, t["base"]), (after, t["amber"]))):
                by = y + 2 + k * (bar_h + 3)
                vw = max(2.0, bar_w * value / 100)
                body += [
                    f'<rect x="{left}" y="{by}" width="{bar_w}" height="{bar_h}" rx="3" '
                    f'fill="{t["track"]}"/>',
                    f'<rect x="{left}" y="{by}" width="{vw:.1f}" height="{bar_h}" rx="3" '
                    f'fill="{colour}"/>',
                    f'<text x="{left + vw + 6:.1f}" y="{by + 10}" font-size="11.5" '
                    f'font-weight="{700 if k else 400}" fill="{t["text"]}">{value:g}</text>',
                ]
            y += row_h
        y += 14
    height = y + 4
    return _svg(width, height, body, t, "Recall on obfuscated attacks, before and after")


def main() -> None:
    for suffix, theme in THEMES.items():
        (OUT / f"stats{suffix}.svg").write_text(stats(theme))
        (OUT / f"obfuscation{suffix}.svg").write_text(obfuscation(theme))
    print(f"wrote stats and obfuscation charts to {OUT}")


if __name__ == "__main__":
    main()
