from __future__ import annotations

import json
import time
import urllib.parse
from dataclasses import dataclass, replace
from typing import Any, Callable

from weir.engines.base import (
    EngineCannotRead,
    EnginePolicyBlocked,
    FailureClass,
    ReaderEngine,
    SearchEngine,
    WeirEngineError,
)
from weir.engines.http_connector import check_target_policy
from weir.models import ReaderResult, RequestMode, WebCapture, WebRequest
from weir.persistence import (
    CachePolicy,
    CaptureStore,
    FileCaptureCache,
    PersistenceInfo,
    apply_capture_policy,
)
from weir.profiles import SiteProfile, SiteProfileRegistry
from weir.router import EngineRegistry, RouteDecision, classify
from weir.telemetry import NullTraceSink, TraceSink

MAX_NORMALIZED_CONTENT_BYTES = 5 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class EngineAttempt:
    engine: str
    outcome: str
    duration_ms: float
    failure_class: str | None = None
    error: str | None = None

    def failure_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "engine": self.engine,
            "class": self.failure_class,
            "error": self.error,
            "duration_ms": self.duration_ms,
        }
        return value


@dataclass(frozen=True, slots=True)
class CacheInfo:
    status: str
    reason: str
    source_capture_id: str | None = None
    age_seconds: float | None = None

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {"status": self.status, "reason": self.reason}
        if self.source_capture_id is not None:
            value["source_capture_id"] = self.source_capture_id
        if self.age_seconds is not None:
            value["age_seconds"] = round(self.age_seconds, 3)
        return value


@dataclass(frozen=True, slots=True)
class AcquisitionResult:
    request: WebRequest
    capture: WebCapture
    attempts: tuple[EngineAttempt, ...]
    route: RouteDecision | None = None
    profile: SiteProfile | None = None
    cache: CacheInfo | None = None
    persistence: PersistenceInfo | None = None
    warnings: tuple[str, ...] = ()

    def to_envelope(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "ok": True,
            "request": self.request.to_dict(),
            "capture": self.capture.to_dict(),
        }
        if self.route is not None:
            value["route"] = self.route.to_dict()
        failures = [
            attempt.failure_dict() for attempt in self.attempts if attempt.outcome == "failure"
        ]
        if failures:
            value["fallbacks"] = failures
        if self.profile is not None:
            value["site_profile"] = self.profile.id
        if self.cache is not None:
            value["cache"] = self.cache.to_dict()
        if self.persistence is not None:
            value["persistence"] = self.persistence.to_dict()
        if self.warnings:
            value["warnings"] = list(self.warnings)
        return value


class AcquisitionFailed(RuntimeError):
    def __init__(
        self,
        message: str,
        attempts: list[EngineAttempt] | None = None,
        route: RouteDecision | None = None,
        failure_class: FailureClass = FailureClass.CANNOT_READ,
    ) -> None:
        super().__init__(message)
        self.attempts = tuple(attempts or [])
        self.route = route
        self.failure_class = failure_class

    def to_envelope(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "ok": False,
            "class": self.failure_class.value,
            "error": str(self),
        }
        if self.route is not None:
            value["route"] = self.route.to_dict()
        failures = [
            attempt.failure_dict() for attempt in self.attempts if attempt.outcome == "failure"
        ]
        if failures:
            value["attempts"] = failures
        return value


class AcquisitionBroker:
    """Reusable public-acquisition path shared by the CLI and Lugos callers."""

    def __init__(
        self,
        registry: EngineRegistry | None = None,
        profiles: SiteProfileRegistry | None = None,
        store: CaptureStore | None = None,
        cache: FileCaptureCache | None = None,
        cache_policy: CachePolicy | None = None,
        trace_sink: TraceSink | None = None,
        allow_test_engine: bool = False,
        timer: Callable[[], float] = time.perf_counter,
        max_capture_bytes: int = MAX_NORMALIZED_CONTENT_BYTES,
    ) -> None:
        if max_capture_bytes < 256:
            raise ValueError("max_capture_bytes must be at least 256")
        self.registry = registry if registry is not None else EngineRegistry()
        self.profiles = profiles if profiles is not None else SiteProfileRegistry()
        self.store = store
        self.cache = cache
        self.cache_policy = cache_policy if cache_policy is not None else CachePolicy()
        self.trace_sink = trace_sink if trace_sink is not None else NullTraceSink()
        self.allow_test_engine = allow_test_engine
        self._timer = timer
        self.max_capture_bytes = max_capture_bytes

    def read(self, request: WebRequest, engine_id: str = "auto") -> AcquisitionResult:
        request.validate()
        if request.mode is not RequestMode.READ:
            raise ValueError("AcquisitionBroker.read requires mode=read")
        if engine_id == "auto":
            route = classify(request)
            candidates = list(route.engine_candidates)
        else:
            route = None
            candidates = [engine_id]
        candidates, profile = self._prepare(request, candidates)
        return self._acquire(request, candidates, "read", route, profile)

    def search(self, request: WebRequest) -> AcquisitionResult:
        request.validate()
        if request.mode is not RequestMode.SEARCH:
            raise ValueError("AcquisitionBroker.search requires mode=search")
        route = classify(request)
        candidates, profile = self._prepare(request, list(route.engine_candidates))
        return self._acquire(request, candidates, "search", route, profile)

    def enrich(self, request: WebRequest) -> AcquisitionResult:
        request.validate()
        if request.mode is not RequestMode.READ:
            raise ValueError("AcquisitionBroker.enrich requires mode=read")
        route = RouteDecision(
            route_class="compact_reader",
            engine_candidates=["oc", "agent-browser-read"],
            reasons=["listing enrichment uses the bounded rung-2 compact-reader chain"],
        )
        candidates, profile = self._prepare(request, list(route.engine_candidates))
        return self._acquire(request, candidates, "read", route, profile)

    def _prepare(
        self, request: WebRequest, candidates: list[str]
    ) -> tuple[list[str], SiteProfile | None]:
        if not candidates:
            route = classify(request)
            raise AcquisitionFailed(
                route.reasons[0]
                if route.reasons
                else f"no engine route for mode={request.mode.value}",
                route=route,
            )
        candidates, profile = self.profiles.apply(request, candidates)
        if request.preferred_engine in candidates and candidates[0] != request.preferred_engine:
            candidates = [request.preferred_engine] + [
                engine for engine in candidates if engine != request.preferred_engine
            ]
        if not candidates:
            raise AcquisitionFailed("site profile left no eligible engine candidates")
        return candidates, profile

    def _check_public_target(self, request: WebRequest, candidates: list[str]) -> None:
        if not request.url:
            return
        if candidates == ["fake"] and self.allow_test_engine:
            return
        check_target_policy(request.url, request.allowed_domains)

    def _acquire(
        self,
        request: WebRequest,
        candidates: list[str],
        operation: str,
        route: RouteDecision | None,
        profile: SiteProfile | None,
    ) -> AcquisitionResult:
        warnings: list[str] = []
        route_class = route.route_class if route is not None else "explicit"
        self._trace(
            warnings,
            "web.route",
            request,
            mode=request.mode.value,
            route_class=route_class,
            engine_candidates=candidates,
            site_profile=profile.id if profile else None,
            target_host=_target_host(request.url),
        )
        try:
            self._check_public_target(request, candidates)
        except WeirEngineError as exc:
            self._trace(
                warnings,
                "web.policy.check",
                request,
                outcome="failure",
                failure_class=exc.failure_class.value,
                target_host=_target_host(request.url),
            )
            raise

        cache_decision = self.cache_policy.decide(request)
        cache_key: str | None = None
        cache_info: CacheInfo | None
        if self.cache is None:
            cache_info = CacheInfo("disabled", "no capture cache is configured")
        elif not cache_decision.enabled:
            cache_info = CacheInfo("bypass", cache_decision.reason)
            self._trace(warnings, "web.cache.bypass", request, reason=cache_decision.reason)
        else:
            cache_key = self.cache.key_for(request, candidates, self.max_capture_bytes)
            cached = self.cache.get(cache_key, cache_decision.ttl_seconds)
            if cached is not None:
                cache_info = CacheInfo(
                    "hit", cache_decision.reason, cached.capture.capture_id, cached.age_seconds
                )
                self._trace(
                    warnings,
                    "web.cache.hit",
                    request,
                    capture_id=cached.capture.capture_id,
                    age_seconds=round(cached.age_seconds, 3),
                )
                return AcquisitionResult(
                    request=request,
                    capture=cached.capture,
                    attempts=(),
                    route=route,
                    profile=profile,
                    cache=cache_info,
                    warnings=tuple(warnings),
                )
            cache_info = CacheInfo("miss", cache_decision.reason)
            self._trace(warnings, "web.cache.miss", request, ttl_seconds=cache_decision.ttl_seconds)

        attempts: list[EngineAttempt] = []
        capture: WebCapture | None = None
        for index, engine_id in enumerate(candidates):
            started = self._timer()
            try:
                engine = self.registry.get(engine_id)
                if operation == "read":
                    if not isinstance(engine, ReaderEngine):
                        raise TypeError(f"engine {engine_id!r} has no read capability")
                    result = engine.read(request)
                else:
                    if not isinstance(engine, SearchEngine):
                        raise TypeError(f"engine {engine_id!r} has no search capability")
                    result = engine.search(request)
                if request.url and not (engine_id == "fake" and self.allow_test_engine):
                    # External readers may follow redirects internally. Revalidate
                    # the returned target before retaining or exposing evidence.
                    check_target_policy(result.final_url, request.allowed_domains)
                result, content_bytes, content_truncated = _bound_reader_result(
                    result, request.mode, self.max_capture_bytes
                )
                capture = WebCapture.from_reader_result(result, request)
            except Exception as exc:  # engine adapters are normalized at this boundary
                failure_class = _failure_class(exc)
                attempt = EngineAttempt(
                    engine=engine_id,
                    outcome="failure",
                    duration_ms=round((self._timer() - started) * 1000, 3),
                    failure_class=failure_class.value,
                    error=str(exc),
                )
                attempts.append(attempt)
                self._trace(
                    warnings,
                    "web.reader.fetch" if operation == "read" else "web.connector.search",
                    request,
                    engine=engine_id,
                    outcome="failure",
                    failure_class=failure_class.value,
                    duration_ms=attempt.duration_ms,
                )
                if isinstance(exc, EnginePolicyBlocked):
                    raise AcquisitionFailed(
                        str(exc), attempts, route, FailureClass.POLICY_BLOCKED
                    ) from exc
                if index + 1 < len(candidates):
                    self._trace(
                        warnings,
                        "web.engine.fallback",
                        request,
                        from_engine=engine_id,
                        to_engine=candidates[index + 1],
                        failure_class=failure_class.value,
                    )
                continue

            attempt = EngineAttempt(
                engine=engine_id,
                outcome="success",
                duration_ms=round((self._timer() - started) * 1000, 3),
            )
            attempts.append(attempt)
            self._trace(
                warnings,
                "web.reader.fetch" if operation == "read" else "web.connector.search",
                request,
                engine=engine_id,
                outcome="success",
                duration_ms=attempt.duration_ms,
                content_bytes=content_bytes,
                content_truncated=content_truncated,
            )
            break

        if capture is None:
            last_class = (
                FailureClass(attempts[-1].failure_class) if attempts else FailureClass.CANNOT_READ
            )
            raise AcquisitionFailed("all candidate engines failed", attempts, route, last_class)

        persistence: PersistenceInfo | None = None
        if self.store is not None:
            try:
                capture, persistence = self.store.persist(capture, request)
            except OSError as exc:
                warnings.append(f"capture persistence failed: {exc}")
                persistence = PersistenceInfo(False, None, None, str(exc))
            self._trace(
                warnings,
                "web.capture.persist",
                request,
                capture_id=capture.capture_id,
                content_hash=capture.content_hash,
                stored=persistence.stored,
            )
        capture = apply_capture_policy(capture, request)

        if self.cache is not None and cache_decision.enabled and cache_key is not None:
            try:
                self.cache.put(cache_key, capture)
            except OSError as exc:
                warnings.append(f"capture cache write failed: {exc}")

        return AcquisitionResult(
            request=request,
            capture=capture,
            attempts=tuple(attempts),
            route=route,
            profile=profile,
            cache=cache_info,
            persistence=persistence,
            warnings=tuple(warnings),
        )

    def _trace(
        self,
        warnings: list[str],
        name: str,
        request: WebRequest,
        **attributes: Any,
    ) -> None:
        try:
            self.trace_sink.emit(name, request, **attributes)
        except (OSError, TypeError, ValueError) as exc:
            warning = f"trace emission failed: {exc}"
            if warning not in warnings:
                warnings.append(warning)


def _failure_class(exc: Exception) -> FailureClass:
    if isinstance(exc, WeirEngineError):
        return exc.failure_class
    if isinstance(exc, KeyError):
        return FailureClass.ENGINE_UNAVAILABLE
    return FailureClass.UNKNOWN


def _target_host(url: str | None) -> str | None:
    if not url:
        return None
    try:
        return urllib.parse.urlsplit(url).hostname
    except ValueError:
        return None


def _bound_reader_result(
    result: ReaderResult, mode: RequestMode, max_bytes: int
) -> tuple[ReaderResult, int, bool]:
    encoded = json.dumps(
        result.content,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    content_bytes = len(encoded)
    if content_bytes <= max_bytes:
        return result, content_bytes, False
    if mode is RequestMode.SEARCH:
        raise EngineCannotRead(
            f"structured search result exceeds the {max_bytes}-byte normalized-content limit"
        )

    marker: dict[str, Any] = {
        "weir_truncated": True,
        "original_content_bytes": content_bytes,
        "preview": "",
    }
    overhead = len(json.dumps(marker, separators=(",", ":")).encode("utf-8"))
    preview = encoded[: max(max_bytes - overhead, 0)].decode("utf-8", errors="ignore")
    lower = 0
    upper = len(preview)
    while lower < upper:
        midpoint = (lower + upper + 1) // 2
        marker["preview"] = preview[:midpoint]
        size = len(json.dumps(marker, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
        if size <= max_bytes:
            lower = midpoint
        else:
            upper = midpoint - 1
    marker["preview"] = preview[:lower]
    diagnostics = dict(result.diagnostics)
    diagnostics.update({"content_bytes": content_bytes, "content_truncated": True})
    return replace(result, content=marker, diagnostics=diagnostics), content_bytes, True
