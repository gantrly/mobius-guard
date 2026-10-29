"""Server-sent events: parse an upstream byte stream into events and write them back out.

All three APIs stream SSE: ``event:`` (optional) and ``data:`` lines, an empty line ends
an event. Chat Completions ends with ``data: [DONE]``. The parser keeps unknown fields and
comments so that what we don't rewrite is passed through as it came.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass


@dataclass(slots=True)
class Event:
    data: str = ""
    event: str = ""
    extra: tuple[str, ...] = ()  # other lines (id:, retry:, comments), kept in order

    def encode(self) -> bytes:
        lines = list(self.extra)
        if self.event:
            lines.append(f"event: {self.event}")
        lines.extend(f"data: {line}" for line in self.data.split("\n"))
        return ("\n".join(lines) + "\n\n").encode()


async def parse(chunks: AsyncIterator[bytes]) -> AsyncIterator[Event]:
    """Events from a stream of byte chunks, however the bytes are split."""
    buf = b""
    async for chunk in chunks:
        buf += chunk
        while True:
            # an event ends at a blank line (\n\n, or \r\n\r\n)
            cut = min((i for i in (buf.find(b"\n\n"), buf.find(b"\r\n\r\n")) if i >= 0),
                      default=-1)  # fmt: skip
            if cut < 0:
                break
            sep = 4 if buf[cut : cut + 4] == b"\r\n\r\n" else 2
            block, buf = buf[:cut], buf[cut + sep :]
            ev = _event(block.decode("utf-8", errors="replace"))
            if ev is not None:
                yield ev
    if buf.strip():
        ev = _event(buf.decode("utf-8", errors="replace"))
        if ev is not None:
            yield ev


def _event(block: str) -> Event | None:
    data: list[str] = []
    event = ""
    extra: list[str] = []
    for line in block.replace("\r\n", "\n").split("\n"):
        if line.startswith("data:"):
            data.append(line[5:].removeprefix(" "))
        elif line.startswith("event:"):
            event = line[6:].strip()
        elif line:
            extra.append(line)
    if not data and not event and not extra:
        return None
    return Event("\n".join(data), event, tuple(extra))
