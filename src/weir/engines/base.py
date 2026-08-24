from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from weir.models import ReaderResult, WebRequest


class WeirEngineError(RuntimeError):
    """Base class for normalized engine failures."""


class EngineUnavailable(WeirEngineError):
    pass


class EngineCannotRead(WeirEngineError):
    pass


class EngineFailure(WeirEngineError):
    pass


@dataclass(frozen=True, slots=True)
class EngineProbe:
    engine: str
    available: bool
    version: str | None = None
    detail: str | None = None


class ReaderEngine(ABC):
    id: str

    @abstractmethod
    def probe(self) -> EngineProbe:
        raise NotImplementedError

    @abstractmethod
    def read(self, request: WebRequest) -> ReaderResult:
        raise NotImplementedError
