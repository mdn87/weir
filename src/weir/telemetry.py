from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Protocol

from weir.models import WebRequest


@dataclass(frozen=True, slots=True)
class TraceSpan:
    name: str
    occurred_at: str
    run_id: str
    request_id: str
    attributes: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class TraceSink(Protocol):
    def emit(self, name: str, request: WebRequest, **attributes: Any) -> None: ...


class NullTraceSink:
    def emit(self, name: str, request: WebRequest, **attributes: Any) -> None:
        return None


class RecordingTraceSink:
    """In-memory sink useful to embedders and deterministic tests."""

    def __init__(self) -> None:
        self.spans: list[TraceSpan] = []

    def emit(self, name: str, request: WebRequest, **attributes: Any) -> None:
        self.spans.append(_span(name, request, attributes))


class JsonlTraceSink:
    """Append metadata-only WEIR spans for ingestion by AITU or another collector."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = Lock()

    def emit(self, name: str, request: WebRequest, **attributes: Any) -> None:
        line = json.dumps(
            _span(name, request, attributes).to_dict(), sort_keys=True, ensure_ascii=False
        )
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8", newline="\n") as stream:
                stream.write(line + "\n")


def _span(name: str, request: WebRequest, attributes: dict[str, Any]) -> TraceSpan:
    return TraceSpan(
        name=name,
        occurred_at=datetime.now(timezone.utc).isoformat(),
        run_id=request.run_id,
        request_id=request.request_id,
        attributes=attributes,
    )
