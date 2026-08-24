from __future__ import annotations

from weir.engines import AgentBrowserReader, FakeReader, OcReader
from weir.engines.base import ReaderEngine


class EngineRegistry:
    """Small seed registry.

    This is intentionally not the final policy router. Explicit engine choice
    keeps P0 benchmark runs reproducible while the route evidence is gathered.
    """

    def __init__(self) -> None:
        self._engines: dict[str, ReaderEngine] = {
            "oc": OcReader(),
            "agent-browser-read": AgentBrowserReader(),
            "fake": FakeReader(),
        }

    def get(self, engine_id: str) -> ReaderEngine:
        try:
            return self._engines[engine_id]
        except KeyError as exc:
            known = ", ".join(sorted(self._engines))
            raise KeyError(f"unknown engine {engine_id!r}; known: {known}") from exc

    def all(self) -> list[ReaderEngine]:
        return list(self._engines.values())
