"""Private process entry point for Aire's local region readers."""

from __future__ import annotations

import io
import json
import os
import socket
import sys


def _offline(event: str, args: tuple) -> None:
    if event in {"socket.connect", "socket.getaddrinfo", "socket.sendto", "socket.sendmsg"} or (
        event == "socket.__new__" and args[1] in {socket.AF_INET, socket.AF_INET6}
    ):
        raise PermissionError("model downloads are disabled during a visual read")


def recognize(backend: str, pixels: bytes) -> list[dict]:
    from aire.observer.signals import RapidOcrRegionTextSource, WindowsOcrRegionTextSource
    from PIL import Image, ImageOps

    with Image.open(io.BytesIO(pixels), formats=["PNG"]) as source:
        if source.width * source.height > 1_048_576 or source.n_frames != 1:
            raise ValueError("expected a dashboard crop")
        image = source.convert("RGB")
    # A black-and-white dashboard can already span the full contrast range.
    # A second scale still gives the recognizer a different sampling of each glyph.
    size = (image.width + max(1, image.width // 4), image.height + max(1, image.height // 4))
    contrast = (
        ImageOps.autocontrast(ImageOps.grayscale(image))
        .resize(size, Image.Resampling.LANCZOS)
        .convert("RGB")
    )
    if backend == "windows":
        engine = WindowsOcrRegionTextSource()
    elif backend == "rapidocr":
        engine = RapidOcrRegionTextSource(upscale=1)
    else:
        raise ValueError("unknown local region reader")
    return [
        {"reader": "aire." + backend, "text": engine.read("dashboard", image)},
        {"reader": "aire." + backend + ".contrast", "text": engine.read("dashboard", contrast)},
    ]


def main() -> None:
    (backend,) = sys.argv[1:]
    if backend == "rapidocr":
        # RapidOCR may fetch missing weights. This dedicated process uses only local models.
        sys.addaudithook(_offline)
    pixels = sys.stdin.buffer.read(4_194_305)
    if len(pixels) > 4_194_304:
        raise ValueError("encoded crop exceeds the size limit")
    # Native libraries also write to fd 1. Reserve a separate handle for the JSON receipt.
    with os.fdopen(os.dup(sys.stdout.fileno()), "w", encoding="utf-8") as response:
        os.dup2(sys.stderr.fileno(), sys.stdout.fileno())
        reads = recognize(backend, pixels)
        print(json.dumps(reads), file=response)


if __name__ == "__main__":
    main()
