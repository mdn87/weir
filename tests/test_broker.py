import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from weir.broker import AcquisitionBroker, AcquisitionFailed
from weir.engines.base import (
    Engine,
    EnginePolicyBlocked,
    EngineProbe,
    EngineUnavailable,
    FailureClass,
    ReaderEngine,
    SearchEngine,
)
from weir.models import DataClass, ReaderResult, RequestMode, WebRequest
from weir.persistence import CaptureStore, FileCaptureCache
from weir.telemetry import RecordingTraceSink


class StubReader(ReaderEngine):
    def __init__(
        self,
        engine_id: str,
        failure: Exception | None = None,
        content=None,
        final_url: str | None = None,
    ) -> None:
        self.id = engine_id
        self.failure = failure
        self.content = content if content is not None else {"text": "evidence"}
        self.final_url = final_url
        self.calls = 0

    def probe(self) -> EngineProbe:
        return EngineProbe(self.id, True, version="test")

    def read(self, request: WebRequest) -> ReaderResult:
        self.calls += 1
        if self.failure is not None:
            raise self.failure
        return ReaderResult(
            engine=self.id,
            engine_version="test",
            requested_url=request.url or "https://example.com",
            final_url=self.final_url or request.url or "https://example.com",
            content=self.content,
        )


class StubRegistry:
    def __init__(self, *engines: Engine) -> None:
        self.engines = {engine.id: engine for engine in engines}

    def get(self, engine_id: str) -> Engine:
        if engine_id not in self.engines:
            raise KeyError(engine_id)
        return self.engines[engine_id]


class StubSearch(SearchEngine):
    id = "ebay"

    def probe(self) -> EngineProbe:
        return EngineProbe(self.id, True, version="test")

    def search(self, request: WebRequest) -> ReaderResult:
        return ReaderResult(
            engine=self.id,
            engine_version="test",
            requested_url="https://api.ebay.com/search",
            final_url="https://api.ebay.com/search",
            content={"listings": ["x" * 2_000]},
        )


def _request(request_id: str = "r1", capture_policy: str = "content") -> WebRequest:
    return WebRequest(
        request_id=request_id,
        run_id="run1",
        mode=RequestMode.READ,
        data_class=DataClass.PUBLIC,
        auth_context="none",
        url="https://example.com/page",
        capture_policy=capture_policy,
    )


class AcquisitionBrokerTests(unittest.TestCase):
    @mock.patch("weir.broker.check_target_policy")
    def test_fallback_is_reusable_outside_the_cli_and_traced(self, policy_check):
        oc = StubReader("oc", EngineUnavailable("oc missing"))
        agent = StubReader("agent-browser-read")
        traces = RecordingTraceSink()
        broker = AcquisitionBroker(registry=StubRegistry(oc, agent), trace_sink=traces)

        result = broker.read(_request())

        self.assertEqual(policy_check.call_count, 2)
        self.assertEqual(result.capture.engine, "agent-browser-read")
        self.assertEqual(result.attempts[0].failure_class, "engine_unavailable")
        self.assertEqual(result.to_envelope()["fallbacks"][0]["class"], "engine_unavailable")
        names = [span.name for span in traces.spans]
        self.assertIn("web.route", names)
        self.assertIn("web.engine.fallback", names)
        self.assertEqual(names.count("web.reader.fetch"), 2)

    @mock.patch("weir.broker.check_target_policy")
    def test_engine_policy_block_is_not_laundered_through_fallback(self, policy_check):
        first = StubReader("oc", EnginePolicyBlocked("redirect left allowlist"))
        second = StubReader("agent-browser-read")
        broker = AcquisitionBroker(registry=StubRegistry(first, second))

        with self.assertRaises(AcquisitionFailed) as raised:
            broker.read(_request())

        self.assertEqual(raised.exception.failure_class, FailureClass.POLICY_BLOCKED)
        self.assertEqual(second.calls, 0)

    def test_disallowed_reader_final_url_is_rejected_as_a_policy_failure(self):
        first = StubReader("oc", final_url="http://127.0.0.1/private")
        second = StubReader("agent-browser-read")
        broker = AcquisitionBroker(registry=StubRegistry(first, second))

        def policy(url, allowed_domains):
            if url == "https://example.com/page":
                return None
            raise EnginePolicyBlocked("reader returned a disallowed final URL")

        with mock.patch("weir.broker.check_target_policy", side_effect=policy):
            with self.assertRaises(AcquisitionFailed) as raised:
                broker.read(_request())
        self.assertEqual(raised.exception.failure_class, FailureClass.POLICY_BLOCKED)
        self.assertEqual(second.calls, 0)

    def test_boundary_policy_runs_before_an_engine(self):
        reader = StubReader("oc")
        traces = RecordingTraceSink()
        broker = AcquisitionBroker(registry=StubRegistry(reader), trace_sink=traces)
        with mock.patch(
            "weir.broker.check_target_policy", side_effect=EnginePolicyBlocked("private target")
        ):
            with self.assertRaises(EnginePolicyBlocked):
                broker.read(_request(), "oc")
        self.assertEqual(reader.calls, 0)
        self.assertEqual([span.name for span in traces.spans], ["web.route", "web.policy.check"])

    @mock.patch("weir.broker.check_target_policy")
    def test_public_unauthenticated_capture_cache_reuses_original_evidence(self, policy_check):
        reader = StubReader("reader")
        with tempfile.TemporaryDirectory() as temp:
            cache = FileCaptureCache(Path(temp) / "cache")
            broker = AcquisitionBroker(registry=StubRegistry(reader), cache=cache)
            first = broker.read(_request("first"), "reader")
            second = broker.read(_request("second"), "reader")

        self.assertEqual(reader.calls, 1)
        self.assertEqual(first.cache.status, "miss")
        self.assertEqual(second.cache.status, "hit")
        self.assertEqual(second.capture.capture_id, first.capture.capture_id)
        self.assertEqual(second.capture.request_id, "first")
        self.assertEqual(second.cache.source_capture_id, first.capture.capture_id)

    @mock.patch("weir.broker.check_target_policy")
    def test_cache_key_includes_the_brokers_content_limit(self, policy_check):
        reader = StubReader("reader", content={"text": "x" * 2_000})
        with tempfile.TemporaryDirectory() as temp:
            cache = FileCaptureCache(Path(temp) / "cache")
            large = AcquisitionBroker(
                registry=StubRegistry(reader), cache=cache, max_capture_bytes=4_096
            )
            small = AcquisitionBroker(
                registry=StubRegistry(reader), cache=cache, max_capture_bytes=256
            )
            first = large.read(_request("first"), "reader")
            second = small.read(_request("second"), "reader")

        self.assertEqual(reader.calls, 2)
        self.assertEqual(first.cache.status, "miss")
        self.assertEqual(second.cache.status, "miss")
        self.assertTrue(second.capture.content["weir_truncated"])

    @mock.patch("weir.broker.check_target_policy")
    def test_metadata_policy_hashes_content_but_does_not_retain_it(self, policy_check):
        reader = StubReader("reader")
        with tempfile.TemporaryDirectory() as temp:
            store = CaptureStore(Path(temp))
            broker = AcquisitionBroker(registry=StubRegistry(reader), store=store)
            result = broker.read(_request(capture_policy="metadata"), "reader")
            loaded = store.load_capture(result.capture.capture_id)

        self.assertIsNone(result.capture.content)
        self.assertIsNone(result.capture.raw_artifact_ref)
        self.assertIsNone(loaded.content)
        self.assertTrue(result.capture.content_hash.startswith("sha256:"))
        self.assertTrue(result.persistence.stored)

    @mock.patch("weir.broker.check_target_policy")
    def test_oversized_reader_output_is_bounded_and_explicit(self, policy_check):
        reader = StubReader("reader", content={"text": "x" * 2_000})
        broker = AcquisitionBroker(
            registry=StubRegistry(reader),
            max_capture_bytes=256,
        )
        result = broker.read(_request(), "reader")

        self.assertTrue(result.capture.content["weir_truncated"])
        self.assertEqual(result.capture.content["original_content_bytes"], 2_011)
        encoded = json.dumps(result.capture.content, separators=(",", ":")).encode("utf-8")
        self.assertLessEqual(len(encoded), 256)

    def test_oversized_structured_result_fails_instead_of_changing_shape(self):
        request = WebRequest(
            request_id="r1",
            run_id="run1",
            mode=RequestMode.SEARCH,
            data_class=DataClass.PUBLIC,
            auth_context="none",
            query="keyboard",
            source="ebay",
        )
        broker = AcquisitionBroker(registry=StubRegistry(StubSearch()), max_capture_bytes=256)
        with self.assertRaises(AcquisitionFailed) as raised:
            broker.search(request)
        self.assertEqual(raised.exception.failure_class, FailureClass.CANNOT_READ)


if __name__ == "__main__":
    unittest.main()
