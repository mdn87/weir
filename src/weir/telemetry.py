from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Protocol

from weir.models import WebRequest

TRACE_ATTRIBUTE_KEYS = frozenset(
    {
        "age_seconds",
        "cache_key",
        "capture_id",
        "capture_policy",
        "content_bytes",
        "content_hash",
        "content_truncated",
        "duration_ms",
        "engine_id",
        "engine_ids",
        "envelope_hash",
        "evidence_ref_id",
        "failure_class",
        "from_engine_id",
        "mode",
        "outcome",
        "profile_id",
        "reason_code",
        "reference_hash",
        "route_class",
        "stored",
        "to_engine_id",
        "ttl_seconds",
        "work_context_hash",
    }
)


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
    if not isinstance(name, str) or not name or len(name) > 128:
        raise ValueError("trace name must be a non-empty string of at most 128 characters")
    for field_name, value in (("run_id", request.run_id), ("request_id", request.request_id)):
        if not isinstance(value, str) or not value or len(value) > 128:
            raise ValueError(
                f"trace {field_name} must be a non-empty string of at most 128 characters"
            )
    return TraceSpan(
        name=name,
        occurred_at=datetime.now(timezone.utc).isoformat(),
        run_id=request.run_id,
        request_id=request.request_id,
        attributes=_metadata_only(attributes),
    )


def _metadata_only(attributes: dict[str, Any]) -> dict[str, Any]:
    """Reject arbitrary request, page, credential, and error content at the sink."""

    unknown = set(attributes) - TRACE_ATTRIBUTE_KEYS
    if unknown:
        raise ValueError(
            "unsupported trace attributes: " + ", ".join(sorted(unknown))
        )
    sanitized: dict[str, Any] = {}
    for key, value in attributes.items():
        if value is None or type(value) in {bool, int}:
            sanitized[key] = value
        elif isinstance(value, float) and math.isfinite(value):
            sanitized[key] = value
        elif isinstance(value, str) and len(value) <= 256:
            sanitized[key] = value
        elif key == "engine_ids" and isinstance(value, (list, tuple)) and (
            len(value) <= 16
            and all(isinstance(item, str) and len(item) <= 128 for item in value)
        ):
            sanitized[key] = list(value)
        else:
            raise TypeError(f"trace attribute {key!r} is not bounded metadata")
    return sanitized
