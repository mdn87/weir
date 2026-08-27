from __future__ import annotations

from urllib.parse import urlparse

from weir.engines.base import (
    EngineCannotRead,
    EngineFailure,
    EngineProbe,
    EngineUnavailable,
    ReaderEngine,
)
from weir.models import ReaderResult, RequestMode, WebRequest


class FakeReader(ReaderEngine):
    """Deterministic in-process engine for harness and benchmark tests.

    Failure modes are selected by the URL host so a task corpus can exercise
    the normalized failure classes without any network or external binary:

        fake://ok/...            deterministic content
        fake://cannot-read/...   EngineCannotRead
        fake://unavailable/...   EngineUnavailable
        fake://failure/...       EngineFailure
    """

    id = "fake"

    def probe(self) -> EngineProbe:
        return EngineProbe(self.id, True, version="0", detail="in-process")

    def read(self, request: WebRequest) -> ReaderResult:
        request.validate()
        if request.mode is not RequestMode.READ:
            raise EngineFailure("FakeReader supports mode=read only")
        if not request.url:
            raise EngineFailure("FakeReader requires a URL")

        host = urlparse(request.url).netloc
        if host == "cannot-read":
            raise EngineCannotRead("fake: no readable content")
        if host == "unavailable":
            raise EngineUnavailable("fake: engine unavailable")
        if host == "failure":
            raise EngineFailure("fake: engine failure")

        return ReaderResult(
            engine=self.id,
            requested_url=request.url,
            final_url=request.url,
            title=f"Fake page for {request.url}",
            http_status=200,
            engine_version="0",
            auth_scope="none",
            content={"url": request.url, "text": f"deterministic content for {request.url}"},
        )
