from __future__ import annotations

import urllib.parse
from dataclasses import asdict, dataclass, field
from typing import Any

from weir.engines import AgentBrowserReader, EbayConnector, FakeReader, HttpConnector, OcReader
from weir.engines.base import Engine
from weir.engines.ebay_connector import is_ebay_item_url
from weir.models import RequestMode, WebRequest


class EngineRegistry:
    """Small seed registry.

    This is intentionally not the final policy router. Explicit engine choice
    keeps benchmark runs reproducible while the route evidence is gathered.
    """

    def __init__(self, engines: list[Engine] | None = None) -> None:
        if engines is None:
            engines = [
                HttpConnector(),
                EbayConnector(),
                OcReader(),
                AgentBrowserReader(),
                FakeReader(),
            ]
        self._engines: dict[str, Engine] = {}
        for engine in engines:
            self.register(engine)

    def register(self, engine: Engine) -> None:
        if engine.id in self._engines:
            raise ValueError(f"duplicate engine id {engine.id!r}")
        self._engines[engine.id] = engine

    def get(self, engine_id: str) -> Engine:
        try:
            return self._engines[engine_id]
        except KeyError as exc:
            known = ", ".join(sorted(self._engines))
            raise KeyError(f"unknown engine {engine_id!r}; known: {known}") from exc

    def all(self) -> list[Engine]:
        return list(self._engines.values())


@dataclass(frozen=True, slots=True)
class RouteDecision:
    route_class: str
    engine_candidates: list[str]
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


MARKETPLACE_SOURCES = {"ebay": "ebay"}

API_HOST_PREFIXES = ("api.",)
API_HOSTS = {"raw.githubusercontent.com", "hnrss.org"}
API_PATH_SUFFIXES = (".json", ".xml", ".rss", ".atom", ".txt", ".md", ".rst", ".csv")
FEED_PATH_MARKERS = ("/feed", "/rss", "/atom", "/llms.txt")


def _looks_api_shaped(url: str) -> list[str]:
    """Deterministic API/feed-shape heuristics.

    Evidence: first route comparison showed renderer engines truncate JSON
    APIs (oc returned 464 chars of a ~7KB response), so API-shaped targets
    route to the direct connector first. Extend this list only with
    benchmark evidence.
    """
    parsed = urllib.parse.urlsplit(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    reasons = []
    if host.startswith(API_HOST_PREFIXES):
        reasons.append(f"host prefix marks an API host: {host}")
    if host in API_HOSTS:
        reasons.append(f"host serves raw/feed content natively: {host}")
    if path.endswith(API_PATH_SUFFIXES):
        reasons.append(f"path suffix marks structured content: {path}")
    if any(marker in path for marker in FEED_PATH_MARKERS):
        reasons.append(f"path marks a feed endpoint: {path}")
    return reasons


def classify(request: WebRequest) -> RouteDecision:
    """Map a read request to a route class and ordered engine candidates.

    Seed classifier for the public lane: connector/API outranks compact
    readers per the capability ladder; a caller's preferred_engine is
    advisory and moves that engine to the front without removing fallbacks.
    """
    request.validate()
    if request.mode is RequestMode.SEARCH:
        if request.source in MARKETPLACE_SOURCES:
            return RouteDecision(
                route_class="connector",
                engine_candidates=[MARKETPLACE_SOURCES[request.source]],
                reasons=[
                    f"structured marketplace search routes to the {request.source} "
                    "connector (rung 1)"
                ],
            )
        return RouteDecision(
            route_class="unsupported",
            engine_candidates=[],
            reasons=[f"no connector seeded for search source {request.source!r}"],
        )
    if request.mode is not RequestMode.READ:
        return RouteDecision(
            route_class="unsupported",
            engine_candidates=[],
            reasons=[
                f"mode {request.mode} has no seeded route; only read and search are classified"
            ],
        )
    if not request.url:
        return RouteDecision(
            route_class="discover",
            engine_candidates=[],
            reasons=["query-only requests need the discovery route, which is not seeded yet"],
        )

    if is_ebay_item_url(request.url):
        candidates = ["ebay", "oc", "agent-browser-read"]
        reasons = [
            "eBay item URL has a first-party Browse API connector; compact readers remain fallbacks"
        ]
        if request.preferred_engine in candidates and request.preferred_engine != candidates[0]:
            candidates = [request.preferred_engine] + [
                item for item in candidates if item != request.preferred_engine
            ]
            reasons.append(f"caller preference {request.preferred_engine!r} honored (advisory)")
        return RouteDecision(
            route_class="connector",
            engine_candidates=candidates,
            reasons=reasons,
        )

    api_reasons = _looks_api_shaped(request.url)
    if api_reasons:
        route_class = "connector"
        candidates = ["http", "oc", "agent-browser-read"]
        reasons = api_reasons + ["connector/API outranks renderers on the capability ladder"]
    else:
        route_class = "compact_reader"
        candidates = ["oc", "agent-browser-read"]
        reasons = ["no API/feed shape detected; compact reader first, rendered reader fallback"]

    preferred = request.preferred_engine
    if preferred and preferred in candidates and candidates[0] != preferred:
        candidates = [preferred] + [c for c in candidates if c != preferred]
        reasons.append(f"caller preference {preferred!r} honored (advisory)")

    return RouteDecision(route_class=route_class, engine_candidates=candidates, reasons=reasons)
