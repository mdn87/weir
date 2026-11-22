"""Read labelled counts or states from an observation, with a bounded pixel fallback."""

from __future__ import annotations

import io
import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Iterable

if TYPE_CHECKING:
    from PIL.Image import Image


def _normal(text: str) -> str:
    return " ".join(text.split()).casefold()


@dataclass(frozen=True)
class ValueQuery:
    label: str
    choices: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if len(self.choices) > 16:
            raise ValueError("at most 16 possible states are supported")
        for term in (self.label, *self.choices):
            if (
                not isinstance(term, str)
                or not 1 <= len(term) <= 100
                or not term.isprintable()
                or not term.strip()
            ):
                raise ValueError("labels and states must contain 1 to 100 printable characters")
        if len(set(map(_normal, self.choices))) != len(self.choices):
            raise ValueError("possible states must be distinct")

    def parse(self, text: str) -> int | str | None:
        if self.choices:
            return next((choice for choice in self.choices if _normal(choice) == text), None)
        if re.fullmatch(r"(?:0|[1-9][0-9]{0,11}|[1-9][0-9]{0,2}(?:,[0-9]{3}){1,3})", text):
            return int(text.replace(",", ""))
        return None


@dataclass(frozen=True)
class Answer:
    status: str
    value: str | int | None = None


def _matches(query: ValueQuery, names: Iterable[str]) -> Counter:
    label = re.escape(_normal(query.label))
    pattern = re.compile(rf"^{label}(?:(\s*:\s*)|(\s+)|$)(.*)$")
    matches = Counter()
    for name in names:
        match = pattern.fullmatch(_normal(name))
        if match:
            remainder = match[3]
            value = query.parse(remainder)
            if (
                match[2]
                and value is None
                and not re.search(rf"(?<!\w){label}(?:\s*:|\s+|$)", remainder)
            ):
                continue
            matches[value] += 1
            if value is None and re.search(rf"(?<!\w){label}(?:\s*:|\s+|$)", remainder):
                matches[None] += 1
    return matches


def _answer(matches: Counter) -> Answer:
    if not matches:
        return Answer("missing")
    if matches.total() != 1:
        return Answer("ambiguous")
    value = next(iter(matches))
    return Answer("unreadable") if value is None else Answer("answered", value)


def _aria_names(snapshot: object) -> Iterable[str]:
    if not isinstance(snapshot, str):
        return
    # Playwright ARIA snapshots use role "name" [attributes] or role: text.
    for line in snapshot.splitlines():
        line = line.strip()
        if line.startswith("- '") and line.endswith("'"):
            line = "- " + line[3:-1].replace("''", "'")
        elif line.startswith('- "') and line.endswith('"'):
            try:
                line = "- " + json.loads(line[2:])
            except ValueError:
                continue
        match = re.fullmatch(r'- [\w-]+ "((?:[^"\\]|\\.)*)"(?: \[[^\]]*\])*(?::)?', line)
        if match:
            yield match[1].replace(r"\"", '"')
            continue
        match = re.fullmatch(r"- [\w-]+: (.*)", line)
        if match:
            yield match[1].strip('"')


def structured_value(query: ValueQuery, names: Iterable[str], snapshot: object) -> Answer:
    # Element summaries overlap the ARIA tree. Preserve duplicates within each source.
    return _answer(_matches(query, names) | _matches(query, _aria_names(snapshot)))


def candidate(query: ValueQuery, text: str) -> Answer:
    return _answer(_matches(query, [text]))


def agreement(answers: list[Answer]) -> Answer:
    if len(answers) != 2:
        return Answer("reader_unavailable")
    if answers[0].status == answers[1].status == "answered":
        return answers[0] if answers[0] == answers[1] else Answer("ambiguous")
    return Answer(
        "ambiguous"
        if any(answer.status in {"answered", "ambiguous"} for answer in answers)
        else "unreadable"
    )


def visual_value(query: ValueQuery, texts: list[str]) -> Answer:
    return agreement([candidate(query, text) for text in texts])


@dataclass(frozen=True)
class Region:
    x: int
    y: int
    width: int
    height: int

    def __post_init__(self) -> None:
        if any(type(n) is not int or n < 0 for n in (self.x, self.y, self.width, self.height)):
            raise ValueError("region coordinates must be nonnegative integers")
        if not (
            0 < self.width <= 2048
            and 0 < self.height <= 2048
            and self.width * self.height <= 1_048_576
        ):
            raise ValueError("region must have positive dimensions and at most one megapixel")


def crop_image(png: bytes, region: Region) -> Image:
    from PIL import Image

    if len(png) > 10 * 1024 * 1024:
        raise ValueError("screenshot exceeds the encoded size limit")
    with Image.open(io.BytesIO(png), formats=["PNG"]) as source:
        if source.width * source.height > 16_777_216 or source.n_frames != 1:
            raise ValueError("expected one bounded PNG frame")
        right, bottom = region.x + region.width, region.y + region.height
        if right > source.width or bottom > source.height:
            raise ValueError("region lies outside the retained screenshot")
        crop = source.crop((region.x, region.y, right, bottom))
        if "A" in crop.getbands() or "transparency" in source.info:
            if crop.convert("RGBA").getchannel("A").getextrema() != (255, 255):
                raise ValueError("screenshot region must be opaque to verify its visible pixels")
        return crop.convert("RGB")


def png_bytes(image: Image) -> bytes:
    stream = io.BytesIO()
    image.save(stream, format="PNG")
    return stream.getvalue()


def read_region(png: bytes) -> list[dict]:
    """Keep WinRT and ONNX in separate processes; give each only the selected pixels."""
    import sys

    engines = ["windows", "rapidocr"] if sys.platform == "win32" else ["rapidocr"]
    results = [pair for backend in engines if (pair := _read_backend(backend, png))]
    if len(results) == 2:
        return [pair[0] for pair in results]
    return results[0] if results else []


def _read_backend(backend: str, png: bytes) -> list[dict]:
    import subprocess
    import sys

    try:
        process = subprocess.run(
            [sys.executable, "-I", "-m", "weir.visual_ocr", backend],
            cwd=Path(__file__).resolve().parent,
            input=png,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=True,
        )
        reads = json.loads(process.stdout)
        if (
            isinstance(reads, list)
            and len(reads) == 2
            and all(
                isinstance(r, dict)
                and set(r) == {"reader", "text"}
                and isinstance(r.get("text"), str)
                and len(r["text"]) <= 4096
                and r.get("reader") == "aire." + backend + suffix
                for r, suffix in zip(reads, ("", ".contrast"))
            )
        ):
            return reads
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    return []
