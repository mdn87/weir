from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import StrEnum

from weir.models import ReaderResult, WebRequest


class FailureClass(StrEnum):
    ENGINE_UNAVAILABLE = "engine_unavailable"
    ENGINE_FAILURE = "engine_failure"
    NETWORK_FAILURE = "network_failure"
    BLOCKED_TARGET = "blocked_target"
    CANNOT_READ = "cannot_read"
    JAVASCRIPT_REQUIRED = "javascript_required"
    AUTH_REQUIRED = "auth_required"
    CHALLENGE = "challenge"
    POLICY_BLOCKED = "policy_blocked"
    APPROVAL_REQUIRED = "approval_required"
    STALE_REFERENCE = "stale_reference"
    SESSION_LOST = "session_lost"
    CONTROLLER_CONFLICT = "controller_conflict"
    PROFILE_IN_USE = "profile_in_use"
    AMBIGUOUS_TARGET = "ambiguous_target"
    IDEMPOTENCY_CONFLICT = "idempotency_conflict"
    COMMAND_EXPIRED = "command_expired"
    VERIFICATION_FAILED = "verification_failed"
    UNKNOWN = "unknown"


class WeirEngineError(RuntimeError):
    """Base class for failures carrying a stable WEIR failure class."""

    default_failure_class = FailureClass.UNKNOWN

    def __init__(self, message: str, failure_class: FailureClass | None = None) -> None:
        super().__init__(message)
        self.failure_class = failure_class or self.default_failure_class


class EngineUnavailable(WeirEngineError):
    default_failure_class = FailureClass.ENGINE_UNAVAILABLE


class EngineCannotRead(WeirEngineError):
    default_failure_class = FailureClass.CANNOT_READ


class EngineFailure(WeirEngineError):
    default_failure_class = FailureClass.ENGINE_FAILURE


class EnginePolicyBlocked(WeirEngineError):
    """Target rejected by policy (scheme, private address, domain constraint)."""

    default_failure_class = FailureClass.POLICY_BLOCKED


class ControllerConflict(WeirEngineError):
    default_failure_class = FailureClass.CONTROLLER_CONFLICT


class ProfileInUse(WeirEngineError):
    default_failure_class = FailureClass.PROFILE_IN_USE


class IdempotencyConflict(WeirEngineError):
    default_failure_class = FailureClass.IDEMPOTENCY_CONFLICT


class CommandExpiredError(WeirEngineError):
    default_failure_class = FailureClass.COMMAND_EXPIRED


@dataclass(frozen=True, slots=True)
class EngineProbe:
    engine: str
    available: bool
    version: str | None = None
    detail: str | None = None


class Engine(ABC):
    id: str

    @abstractmethod
    def probe(self) -> EngineProbe:
        raise NotImplementedError


class ReaderEngine(Engine):
    @abstractmethod
    def read(self, request: WebRequest) -> ReaderResult:
        raise NotImplementedError


class SearchEngine(Engine):
    """Capability interface for connectors that return structured result sets."""

    @abstractmethod
    def search(self, request: WebRequest) -> ReaderResult:
        raise NotImplementedError
