from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import OrderedDict
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Protocol

from weir.browser.models import ObservedElement
from weir.engines.base import EngineProbe, FailureClass, WeirEngineError
from weir.models import DataClass

BROWSER_PROTOCOL_VERSION = "0.2"


class WorkerCapability(StrEnum):
    OPEN = "open"
    ATTACH = "attach"
    NAVIGATE = "navigate"
    OBSERVE = "observe"
    SCREENSHOT = "screenshot"
    FENCE = "fence"
    CLOSE = "close"


class WorkerResultStatus(StrEnum):
    COMPLETED = "completed"
    FAILED = "failed"


class WorkerProtocolError(WeirEngineError):
    """Worker-protocol failure with a stable class for durable broker journals."""


class CommandExpired(WorkerProtocolError):
    default_failure_class = FailureClass.COMMAND_EXPIRED


class StaleWorkerCommand(WorkerProtocolError):
    default_failure_class = FailureClass.STALE_REFERENCE


class WorkerIdempotencyConflict(WorkerProtocolError):
    default_failure_class = FailureClass.IDEMPOTENCY_CONFLICT


def canonical_digest(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True, slots=True)
class WorkerDescriptor:
    worker_id: str
    engine: str
    capabilities: frozenset[WorkerCapability]
    version: str | None = None
    instance_id: str | None = None

    def supports(self, capability: WorkerCapability) -> bool:
        return capability in self.capabilities


@dataclass(frozen=True, slots=True)
class WorkerResultEnvelope:
    command_id: str
    session_id: str
    status: WorkerResultStatus
    completed_at: str
    result_digest: str
    metadata: dict[str, Any]
    failure_class: FailureClass | None = None
    detail: str | None = None
    protocol_version: str = BROWSER_PROTOCOL_VERSION

    @classmethod
    def create(
        cls,
        *,
        command: WorkerCommand,
        status: WorkerResultStatus,
        completed_at: datetime,
        metadata: dict[str, Any] | None = None,
        failure_class: FailureClass | None = None,
        detail: str | None = None,
    ) -> WorkerResultEnvelope:
        if completed_at.tzinfo is None:
            raise WorkerProtocolError("worker-result timestamp must include a timezone")
        safe_metadata = dict(metadata or {})
        result = cls(
            command_id=command.command_id,
            session_id=command.session_id,
            status=status,
            completed_at=completed_at.astimezone(timezone.utc).isoformat(),
            result_digest=canonical_digest(safe_metadata),
            metadata=safe_metadata,
            failure_class=failure_class,
            detail=detail,
        )
        result.validate()
        return result

    def validate(self) -> None:
        if self.protocol_version != BROWSER_PROTOCOL_VERSION:
            raise WorkerProtocolError("unsupported worker-result protocol version")
        if any(
            not isinstance(value, str) or not value
            for value in (self.command_id, self.session_id)
        ):
            raise WorkerProtocolError("worker-result identifiers cannot be empty")
        if not isinstance(self.status, WorkerResultStatus):
            raise WorkerProtocolError("worker-result status is invalid")
        if not isinstance(self.completed_at, str):
            raise WorkerProtocolError("worker-result timestamp must be a string")
        try:
            completed = datetime.fromisoformat(self.completed_at)
        except ValueError as exc:
            raise WorkerProtocolError("worker-result timestamp is invalid") from exc
        if completed.tzinfo is None:
            raise WorkerProtocolError("worker-result timestamp must include a timezone")
        if not _is_sha256_digest(self.result_digest):
            raise WorkerProtocolError("worker-result digest is invalid")
        if not isinstance(self.metadata, dict) or any(
            not isinstance(key, str) for key in self.metadata
        ):
            raise WorkerProtocolError("worker-result metadata must be an object")
        try:
            metadata_digest = canonical_digest(self.metadata)
        except (TypeError, ValueError) as exc:
            raise WorkerProtocolError(
                "worker-result metadata must be JSON-compatible"
            ) from exc
        if metadata_digest != self.result_digest:
            raise WorkerProtocolError("worker-result digest does not match its metadata")
        if self.failure_class is not None and not isinstance(
            self.failure_class, FailureClass
        ):
            raise WorkerProtocolError("worker-result failure class is invalid")
        if self.detail is not None and not isinstance(self.detail, str):
            raise WorkerProtocolError("worker-result detail must be a string or null")
        if self.status is WorkerResultStatus.COMPLETED and self.failure_class is not None:
            raise WorkerProtocolError("completed worker results cannot carry a failure class")
        if self.status is WorkerResultStatus.FAILED and self.failure_class is None:
            raise WorkerProtocolError("failed worker results require a failure class")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "protocol_version": self.protocol_version,
            "command_id": self.command_id,
            "session_id": self.session_id,
            "status": self.status.value,
            "completed_at": self.completed_at,
            "result_digest": self.result_digest,
            "metadata": self.metadata,
            "failure_class": (
                None if self.failure_class is None else self.failure_class.value
            ),
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class WorkerCommand:
    """Versioned command metadata shared by every browser-worker operation."""

    command_id: str
    operation: str
    session_id: str
    worker_session_id: str
    owner_run_id: str
    expected_revision: int
    session_epoch: int
    lease_fence: int
    deadline_at: str
    request_digest: str
    protocol_version: str = BROWSER_PROTOCOL_VERSION

    @classmethod
    def build(
        cls,
        *,
        command_id: str,
        operation: str,
        session_id: str,
        worker_session_id: str,
        owner_run_id: str,
        expected_revision: int,
        session_epoch: int,
        lease_fence: int,
        deadline_at: datetime,
        payload: Any,
    ) -> WorkerCommand:
        if deadline_at.tzinfo is None:
            raise WorkerProtocolError("browser worker deadline must include a timezone")
        return cls(
            command_id=command_id,
            operation=operation,
            session_id=session_id,
            worker_session_id=worker_session_id,
            owner_run_id=owner_run_id,
            expected_revision=expected_revision,
            session_epoch=session_epoch,
            lease_fence=lease_fence,
            deadline_at=deadline_at.astimezone(timezone.utc).isoformat(),
            request_digest=canonical_digest(payload),
        )

    def validate(self, now: datetime | None = None) -> None:
        if self.protocol_version != BROWSER_PROTOCOL_VERSION:
            raise WorkerProtocolError(
                f"unsupported browser protocol version {self.protocol_version!r}"
            )
        identifiers = (
            self.command_id,
            self.operation,
            self.session_id,
            self.worker_session_id,
            self.owner_run_id,
        )
        if any(not isinstance(value, str) or not value for value in identifiers):
            raise WorkerProtocolError("browser worker command identifiers cannot be empty")
        if self.operation not in {capability.value for capability in WorkerCapability}:
            raise WorkerProtocolError(f"unknown browser worker operation {self.operation!r}")
        counters = (
            (self.expected_revision, 0),
            (self.session_epoch, 1),
            (self.lease_fence, 1),
        )
        if any(type(value) is not int or value < minimum for value, minimum in counters):
            raise WorkerProtocolError("browser worker revision, epoch, and lease fence are invalid")
        if not _is_sha256_digest(self.request_digest):
            raise WorkerProtocolError("browser worker request_digest is invalid")
        if not isinstance(self.deadline_at, str):
            raise WorkerProtocolError("browser worker deadline must be a string")
        try:
            deadline = datetime.fromisoformat(self.deadline_at)
        except ValueError as exc:
            raise WorkerProtocolError("browser worker deadline is invalid") from exc
        if deadline.tzinfo is None:
            raise WorkerProtocolError("browser worker deadline must include a timezone")
        current = now or datetime.now(timezone.utc)
        if not isinstance(current, datetime) or current.tzinfo is None:
            raise WorkerProtocolError("browser worker clock must include a timezone")
        if current >= deadline:
            raise CommandExpired(f"browser worker command {self.command_id!r} expired")

    def validate_for(
        self,
        operation: str,
        payload: Any,
        *,
        now: datetime | None = None,
    ) -> None:
        self.validate(now)
        if self.operation != operation:
            raise WorkerProtocolError(
                f"worker command operation {self.operation!r} does not match {operation!r}"
            )
        if self.request_digest != canonical_digest(payload):
            raise WorkerIdempotencyConflict(
                f"worker command {self.command_id!r} digest does not match its payload"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol_version": self.protocol_version,
            "command_id": self.command_id,
            "operation": self.operation,
            "session_id": self.session_id,
            "worker_session_id": self.worker_session_id,
            "owner_run_id": self.owner_run_id,
            "expected_revision": self.expected_revision,
            "session_epoch": self.session_epoch,
            "lease_fence": self.lease_fence,
            "deadline_at": self.deadline_at,
            "request_digest": self.request_digest,
        }

    @property
    def binding_digest(self) -> str:
        """Bind a command ID to its target, revision, fence, and typed payload."""

        return canonical_digest(
            {
                "protocol_version": self.protocol_version,
                "operation": self.operation,
                "session_id": self.session_id,
                "worker_session_id": self.worker_session_id,
                "owner_run_id": self.owner_run_id,
                "expected_revision": self.expected_revision,
                "session_epoch": self.session_epoch,
                "lease_fence": self.lease_fence,
                "deadline_at": self.deadline_at,
                "request_digest": self.request_digest,
            }
        )


def _is_sha256_digest(value: Any) -> bool:
    return bool(
        isinstance(value, str)
        and len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    )


@dataclass(frozen=True, slots=True)
class SessionSpec:
    session_id: str
    worker_session_id: str
    owner_run_id: str
    profile_id: str
    credential_binding_id: str
    site_profile_id: str
    credential_scope: str
    data_class: DataClass
    allowed_domains: tuple[str, ...]
    initial_url: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "worker_session_id": self.worker_session_id,
            "owner_run_id": self.owner_run_id,
            "profile_id": self.profile_id,
            "credential_binding_id": self.credential_binding_id,
            "site_profile_id": self.site_profile_id,
            "credential_scope": self.credential_scope,
            "data_class": self.data_class.value,
            "allowed_domains": list(self.allowed_domains),
            "initial_url": self.initial_url,
        }


@dataclass(frozen=True, slots=True)
class WorkerObservation:
    url: str
    title: str | None
    elements: tuple[ObservedElement, ...]
    accessibility_snapshot: str | None = None
    notes: tuple[str, ...] = ()
    screenshot: bytes | None = None


class BrowserWorker(Protocol):
    @property
    def descriptor(self) -> WorkerDescriptor: ...

    def probe(self) -> EngineProbe: ...

    def open_session(self, spec: SessionSpec, command: WorkerCommand) -> str: ...

    def attach_session(self, spec: SessionSpec, command: WorkerCommand) -> bool: ...

    def navigate(self, session_id: str, url: str, command: WorkerCommand) -> str: ...

    def observe(
        self,
        session_id: str,
        command: WorkerCommand,
        *,
        include_screenshot: bool = False,
    ) -> WorkerObservation: ...

    def screenshot(self, session_id: str, command: WorkerCommand) -> bytes: ...

    def fence_session(self, session_id: str, command: WorkerCommand) -> None: ...

    def close_session(self, session_id: str, command: WorkerCommand) -> None: ...


class IdempotentWorkerGuard:
    """In-process command replay and fencing guard for worker implementations."""

    def __init__(
        self,
        *,
        max_cached_results: int = 256,
        max_cached_result_bytes: int = 1024 * 1024,
        max_seen_commands: int = 65_536,
    ) -> None:
        if (
            max_cached_results < 1
            or max_cached_result_bytes < 1
            or max_seen_commands < max_cached_results
        ):
            raise ValueError("worker replay-cache limits must be positive")
        self._weir_fences: dict[str, tuple[int, int]] = {}
        self._weir_results: OrderedDict[
            str, tuple[str, Any, int, str]
        ] = OrderedDict()
        self._weir_cached_result_bytes = 0
        self._weir_tombstones: dict[str, tuple[str, str]] = {}
        self._weir_inflight: dict[str, tuple[str, str]] = {}
        self._weir_max_cached_results = max_cached_results
        self._weir_max_cached_result_bytes = max_cached_result_bytes
        self._weir_max_seen_commands = max_seen_commands
        self._weir_lock_index = threading.RLock()
        self._weir_session_locks: dict[str, threading.RLock] = {}

    @contextmanager
    def serialize_worker_session(self, session_id: str) -> Iterator[None]:
        """Serialize worker effects and make fence commands true drain barriers."""

        with self._weir_lock_index:
            lock = self._weir_session_locks.setdefault(session_id, threading.RLock())
        with lock:
            yield

    def begin_worker_command(self, command: WorkerCommand) -> tuple[bool, Any]:
        command.validate()
        binding = command.binding_digest
        with self._weir_lock_index:
            cached = self._weir_results.get(command.command_id)
            if cached is not None:
                digest, result, _, _ = cached
                if digest != binding:
                    raise WorkerIdempotencyConflict(
                        f"command id {command.command_id!r} was reused with different content"
                    )
                self._weir_results.move_to_end(command.command_id)
                if result is _NON_REPLAYABLE:
                    raise WorkerProtocolError(
                        f"command {command.command_id!r} completed but its large result "
                        "is no longer replayable in worker memory"
                    )
                return True, result

            tombstone = self._weir_tombstones.get(command.command_id)
            if tombstone is not None:
                digest, _ = tombstone
                if digest != binding:
                    raise WorkerIdempotencyConflict(
                        f"command id {command.command_id!r} was reused with different content"
                    )
                raise WorkerProtocolError(
                    f"command {command.command_id!r} history is retired; "
                    "the effect will not be replayed"
                )
            inflight = self._weir_inflight.get(command.command_id)
            if inflight is not None:
                digest, _ = inflight
                if digest != binding:
                    raise WorkerIdempotencyConflict(
                        f"command id {command.command_id!r} was reused with different content"
                    )
                raise WorkerProtocolError(
                    f"command {command.command_id!r} is already in flight or ended uncertainly"
                )
            if (
                len(self._weir_results)
                + len(self._weir_tombstones)
                + len(self._weir_inflight)
                >= self._weir_max_seen_commands
            ):
                raise WorkerProtocolError(
                    "worker idempotency history is full; restart only after broker fencing"
                )

            current = self._weir_fences.get(command.session_id)
            incoming = (command.session_epoch, command.lease_fence)
            if current is not None and incoming < current:
                raise StaleWorkerCommand(
                    f"worker command fence {incoming} is older than active fence {current}"
                )
            self._weir_fences[command.session_id] = incoming
            self._weir_inflight[command.command_id] = (
                binding,
                command.session_id,
            )
            return False, None

    def remember_worker_result(self, command: WorkerCommand, result: Any) -> Any:
        size = _cached_result_size(result)
        cached_result = result
        if size > self._weir_max_cached_result_bytes:
            cached_result = _NON_REPLAYABLE
            size = 0
        with self._weir_lock_index:
            inflight = self._weir_inflight.pop(command.command_id, None)
            if inflight is not None and inflight[0] != command.binding_digest:
                raise WorkerIdempotencyConflict(
                    f"command id {command.command_id!r} completed with different content"
                )
            previous = self._weir_results.pop(command.command_id, None)
            if previous is not None:
                self._weir_cached_result_bytes -= previous[2]
            self._weir_results[command.command_id] = (
                command.binding_digest,
                cached_result,
                size,
                command.session_id,
            )
            self._weir_cached_result_bytes += size
            while (
                len(self._weir_results) > self._weir_max_cached_results
                or self._weir_cached_result_bytes > self._weir_max_cached_result_bytes
            ):
                evicted_id, (
                    evicted_digest,
                    _,
                    evicted_size,
                    evicted_session,
                ) = self._weir_results.popitem(last=False)
                self._weir_cached_result_bytes -= evicted_size
                self._weir_tombstones[evicted_id] = (
                    evicted_digest,
                    evicted_session,
                )
        return result

    def forget_worker_session(
        self, session_id: str, *, exclude_command_id: str | None = None
    ) -> None:
        # Retain the highest fence for the process lifetime. Removing it on close
        # would let a delayed command from the closed generation pass the guard.
        with self._weir_lock_index:
            command_ids = [
                command_id
                for command_id, (_, _, _, cached_session_id) in self._weir_results.items()
                if cached_session_id == session_id
            ]
            for command_id in command_ids:
                digest, _, size, cached_session_id = self._weir_results.pop(command_id)
                self._weir_cached_result_bytes -= size
                self._weir_tombstones[command_id] = (digest, cached_session_id)
            uncertain_ids = [
                command_id
                for command_id, (_, inflight_session_id) in self._weir_inflight.items()
                if inflight_session_id == session_id and command_id != exclude_command_id
            ]
            for command_id in uncertain_ids:
                digest, inflight_session_id = self._weir_inflight.pop(command_id)
                self._weir_tombstones[command_id] = (digest, inflight_session_id)


_NON_REPLAYABLE = object()


def _cached_result_size(result: Any) -> int:
    if result is None:
        return 0
    if isinstance(result, bytes):
        return len(result)
    if isinstance(result, str):
        return len(result.encode("utf-8"))
    return len(repr(result).encode("utf-8"))


def monotonic_deadline(seconds: float = 10.0) -> datetime:
    """Compatibility helper for callers that only have a relative timeout."""
    if seconds <= 0:
        raise ValueError("browser command timeout must be positive")
    # `time.time` keeps this serializable across processes; monotonic clocks
    # cannot be compared by a remote worker.
    return datetime.fromtimestamp(time.time() + seconds, timezone.utc)
