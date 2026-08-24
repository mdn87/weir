from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from weir.engines.base import EngineCannotRead, EngineFailure, EngineUnavailable, ReaderEngine
from weir.models import DataClass, RequestMode, WebCapture, WebRequest


@dataclass(slots=True)
class BenchTask:
    task_id: str
    url: str
    description: str = ""
    task_class: str = "public_acquisition"

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> BenchTask:
        return cls(
            task_id=value["task_id"],
            url=value["url"],
            description=value.get("description", ""),
            task_class=value.get("task_class", "public_acquisition"),
        )


@dataclass(slots=True)
class BenchRecord:
    run_id: str
    task_id: str
    task_class: str
    url: str
    engine: str
    engine_version: str | None
    started_at: str
    latency_seconds: float
    verdict: str
    failure_class: str | None = None
    failure_detail: str | None = None
    capture_id: str | None = None
    content_hash: str | None = None
    content_chars: int | None = None
    title: str | None = None
    final_url: str | None = None
    diagnostics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _failure_class(exc: Exception) -> str:
    if isinstance(exc, EngineUnavailable):
        return "engine_unavailable"
    if isinstance(exc, EngineCannotRead):
        return "cannot_read"
    if isinstance(exc, EngineFailure):
        return "engine_failure"
    return "unknown"


def load_corpus(path: Path) -> list[BenchTask]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    tasks = payload["tasks"] if isinstance(payload, dict) else payload
    return [BenchTask.from_dict(task) for task in tasks]


def run_task(engine: ReaderEngine, task: BenchTask, run_id: str) -> BenchRecord:
    probe = engine.probe()
    request = WebRequest(
        request_id=f"webreq-{uuid.uuid4().hex}",
        run_id=run_id,
        mode=RequestMode.READ,
        data_class=DataClass.PUBLIC,
        auth_context="none",
        url=task.url,
        preferred_engine=engine.id,
        evidence_required=True,
        side_effects_allowed=False,
    )
    started_at = datetime.now(timezone.utc).isoformat()
    started = time.perf_counter()

    if not probe.available:
        return BenchRecord(
            run_id=run_id,
            task_id=task.task_id,
            task_class=task.task_class,
            url=task.url,
            engine=engine.id,
            engine_version=probe.version,
            started_at=started_at,
            latency_seconds=0.0,
            verdict="skipped",
            failure_class="engine_unavailable",
            failure_detail=probe.detail,
        )

    try:
        result = engine.read(request)
    except Exception as exc:  # noqa: BLE001 - every failure must land in a normalized class
        return BenchRecord(
            run_id=run_id,
            task_id=task.task_id,
            task_class=task.task_class,
            url=task.url,
            engine=engine.id,
            engine_version=probe.version,
            started_at=started_at,
            latency_seconds=round(time.perf_counter() - started, 3),
            verdict="failure",
            failure_class=_failure_class(exc),
            failure_detail=str(exc),
        )

    latency = round(time.perf_counter() - started, 3)
    capture = WebCapture.from_reader_result(result, request)
    content_chars = len(json.dumps(capture.content, ensure_ascii=False)) if capture.content is not None else 0
    return BenchRecord(
        run_id=run_id,
        task_id=task.task_id,
        task_class=task.task_class,
        url=task.url,
        engine=engine.id,
        engine_version=probe.version or result.engine_version,
        started_at=started_at,
        latency_seconds=latency,
        verdict="success",
        capture_id=capture.capture_id,
        content_hash=capture.content_hash,
        content_chars=content_chars,
        title=capture.title,
        final_url=capture.final_url,
        diagnostics=result.diagnostics,
    )


def run_benchmark(
    engines: list[ReaderEngine],
    tasks: list[BenchTask],
    out_dir: Path,
    run_id: str | None = None,
) -> tuple[Path, list[BenchRecord]]:
    run_id = run_id or f"bench-{uuid.uuid4().hex}"
    records: list[BenchRecord] = []
    for task in tasks:
        for engine in engines:
            records.append(run_task(engine, task, run_id))

    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{run_id}.jsonl"
    with out_path.open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record.to_dict(), ensure_ascii=False) + "\n")
    return out_path, records


def summarize(records: list[BenchRecord]) -> dict[str, Any]:
    by_engine: dict[str, dict[str, Any]] = {}
    for record in records:
        stats = by_engine.setdefault(
            record.engine,
            {"tasks": 0, "success": 0, "failure": 0, "skipped": 0, "total_latency": 0.0, "failure_classes": {}},
        )
        stats["tasks"] += 1
        stats[record.verdict] += 1
        stats["total_latency"] += record.latency_seconds
        if record.failure_class:
            classes = stats["failure_classes"]
            classes[record.failure_class] = classes.get(record.failure_class, 0) + 1

    for stats in by_engine.values():
        attempted = stats["success"] + stats["failure"]
        stats["mean_latency_seconds"] = round(stats["total_latency"] / attempted, 3) if attempted else None
        del stats["total_latency"]
    return by_engine
