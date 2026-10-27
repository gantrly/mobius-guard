"""Draw the README's hero: a reply streamed through the redactor, as an animated SVG.

Usage:  uv run python scripts/brand/hero.py

Nothing in the picture is made up. The sample reply is cut into token-sized chunks and fed
to ``StreamRedactor`` one chunk at a time; the bottom panel shows exactly what the redactor
had emitted after each chunk, holdback included. Writes .github/assets/hero.svg and
hero-dark.svg (colours from Gantrly's Hi-vis palette).
"""

from __future__ import annotations

import random
from html import escape
from pathlib import Path

from mobiusguard_redact import StreamRedactor

OUT = Path(__file__).resolve().parent.parent.parent / ".github" / "assets"

REPLY = (
    "Sure! Add these to your .env file:\n"
    "\n"
    "OPENAI_API_KEY=sk-proj-Q7wE9rT2yLm4Nx8Pq3Vd6Zs1Kb5Hc0Jf7Gt2Wa9Rb\n"
    "DATABASE_URL=postgres://app:Sup3rS3cret!@db:5432/prod\n"
    "\n"
    "Then restart the server."
)

THEMES = {
    "hero.svg": {
        "bg": "#F7F8F9", "panel": "#FFFFFF", "line": "#DDE1E6", "text": "#1B1E23",
        "muted": "#6B7480", "chip_a": "#EEF0F2", "chip_b": "#E2E6EA", "amber": "#F5B301",
        "on_amber": "#1B1E23",
    },
    "hero-dark.svg": {
        "bg": "#121418", "panel": "#1B1E23", "line": "#2C3239", "text": "#E8EBEE",
        "muted": "#9AA3AE", "chip_a": "#242930", "chip_b": "#2C3239", "amber": "#F5B301",
        "on_amber": "#1B1E23",
    },
}  # fmt: skip

CHAR_W = 8.4  # monospace advance at 14 px
LINE_H = 22
STEP = 0.11  # seconds per chunk
HOLD = 3.5  # seconds the finished picture stays before the loop restarts
X0 = 36
WIDTH = 880


def chunks(text: str, seed: int = 7) -> list[str]:
    """Token-sized pieces (1 to 7 characters), the way a model streams."""
    rng = random.Random(seed)  # noqa: S311 - a fixed picture, not security
    out: list[str] = []
    i = 0
    while i < len(text):
        n = rng.randint(1, 7)
        out.append(text[i : i + n])
        i += n
    return out


def emitted_by_step(pieces: list[str]) -> list[str]:
    """What the redactor had emitted after each chunk (the last entry includes flush)."""
    r = StreamRedactor()
    outs: list[str] = []
    for i, p in enumerate(pieces):
        o = r.feed(p)
        if i == len(pieces) - 1:
            o += r.flush()
        outs.append(o)
    return outs


def layout(runs: list[tuple[str, int, bool]]) -> list[tuple[float, float, str, int, bool]]:
    """Place text runs (text, step, is_label) left to right, breaking at newlines."""
    placed: list[tuple[float, float, str, int, bool]] = []
    col = 0
    row = 0
    for text, step, label in runs:
        parts = text.split("\n")
        for k, part in enumerate(parts):
            if k:
                row += 1
                col = 0
            if part:
                placed.append((X0 + col * CHAR_W, row * LINE_H, part, step, label))
                col += len(part)
    return placed


def keyframes(name: str, t: float, total: float) -> str:
    p = 100 * t / total
    return (
        f"@keyframes {name}{{0%,{max(p - 0.01, 0):.2f}%{{opacity:0}}"
        f"{p:.2f}%,97%{{opacity:1}}100%{{opacity:0}}}}"
    )


def svg(theme: dict[str, str]) -> str:
    pieces = chunks(REPLY)
    outs = emitted_by_step(pieces)
    total = len(pieces) * STEP + HOLD

    top = layout([(p, i, False) for i, p in enumerate(pieces)])
    bottom_runs: list[tuple[str, int, bool]] = []
    for i, o in enumerate(outs):
        rest = o
        while "[REDACTED:" in rest:  # labels get their own run, drawn on amber
            a = rest.index("[REDACTED:")
            b = rest.index("]", a) + 1
            if a:
                bottom_runs.append((rest[:a], i, False))
            bottom_runs.append((rest[a:b], i, True))
            rest = rest[b:]
        if rest:
            bottom_runs.append((rest, i, False))
    bottom = layout(bottom_runs)

    rows_top = max(y for _, y, *_ in top) // LINE_H + 1
    rows_bottom = max(y for _, y, *_ in bottom) // LINE_H + 1
    top_y = 64
    panel_top_h = rows_top * LINE_H + 28
    mid_y = top_y + panel_top_h + 56
    panel_bottom_h = rows_bottom * LINE_H + 28
    height = mid_y + panel_bottom_h + 28

    css: list[str] = [
        "text{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:14px;"
        f"fill:{theme['text']};white-space:pre}}",
        f".h{{font-family:-apple-system,'Segoe UI',Helvetica,Arial,sans-serif;font-size:13px;"
        f"font-weight:600;fill:{theme['muted']};letter-spacing:.02em}}",
        f".lab{{fill:{theme['on_amber']};font-weight:600}}",
        "@media (prefers-reduced-motion:reduce){.a{animation:none!important;opacity:1!important}}",
    ]
    body: list[str] = []
    steps_used = sorted({s for *_, s, _ in top} | {s for *_, s, _ in bottom})
    for s in steps_used:
        css.append(keyframes(f"k{s}", s * STEP, total))

    def anim(step: int) -> str:
        return f'class="a" style="opacity:0;animation:k{step} {total:.2f}s linear infinite"'

    body.append(f'<rect width="{WIDTH}" height="{height}" rx="14" fill="{theme["bg"]}"/>')
    body.append(
        f'<text class="h" x="{X0 - 8}" y="{top_y - 16}">FROM THE MODEL, AS IT STREAMS</text>'
    )
    body.append(
        f'<rect x="{X0 - 16}" y="{top_y}" width="{WIDTH - 2 * (X0 - 16)}" height="{panel_top_h}" '
        f'rx="10" fill="{theme["panel"]}" stroke="{theme["line"]}"/>'
    )
    for n, (x, y, text, step, _) in enumerate(top):
        fill = theme["chip_a"] if n % 2 == 0 else theme["chip_b"]
        yy = top_y + 18 + y
        body.append(
            f'<g {anim(step)}><rect x="{x:.1f}" y="{yy - 1}" width="{len(text) * CHAR_W:.1f}" '
            f'height="19" rx="3" fill="{fill}"/><text x="{x:.1f}" y="{yy + 14}">'
            f"{escape(text)}</text></g>"
        )
    body.append(
        f'<text class="h" x="{X0 - 8}" y="{mid_y - 16}">'
        "WHAT YOUR USER SEES (mobiusguard-redact)</text>"
    )
    body.append(
        f'<rect x="{X0 - 16}" y="{mid_y}" width="{WIDTH - 2 * (X0 - 16)}" '
        f'height="{panel_bottom_h}" rx="10" fill="{theme["panel"]}" stroke="{theme["line"]}"/>'
    )
    for x, y, text, step, label in bottom:
        yy = mid_y + 18 + y
        if label:
            body.append(
                f'<g {anim(step)}><rect x="{x - 2:.1f}" y="{yy - 1}" '
                f'width="{len(text) * CHAR_W + 4:.1f}" height="19" rx="4" fill="{theme["amber"]}"/>'
                f'<text class="lab" x="{x:.1f}" y="{yy + 14}">{escape(text)}</text></g>'
            )
        else:
            body.append(f'<text {anim(step)} x="{x:.1f}" y="{yy + 14}">{escape(text)}</text>')
    title = "A reply streamed through Mobius Guard: secrets split across chunks are replaced"
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {WIDTH} {height}" '
        f'width="{WIDTH}" height="{height}" role="img"><title>{title}</title>'
        f"<style>{''.join(css)}</style>{''.join(body)}</svg>\n"
    )


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, theme in THEMES.items():
        (OUT / name).write_text(svg(theme))
        print("wrote", OUT / name)


if __name__ == "__main__":
    main()
