import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from weir.broker import AcquisitionBroker, AcquisitionFailed
from weir.contract import ContractViolation, canonical_digest
from weir.engines.base import (
    Engine,
    EnginePolicyBlocked,
    EngineProbe,
    EngineUnavailable,
    FailureClass,
    ReaderEngine,
    SearchEngine,
)
from weir.evidence import ACQUISITION_ENVELOPE_VERSION, AcquisitionEnvelope
from weir.models import DataClass, ReaderResult, RequestMode, WebRequest
from weir.persistence import CacheIntegrityError, CaptureStore, FileCaptureCache
from weir.telemetry import RecordingTraceSink
from weir.work_context import WorkContext, WorkContextSource


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

    def __init__(self) -> None:
        self.calls = 0

    def probe(self) -> EngineProbe:
        return EngineProbe(self.id, True, version="test")

    def search(self, request: WebRequest) -> ReaderResult:
        self.calls += 1
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


def _search_request(request_id: str = "search-1") -> WebRequest:
    return WebRequest(
        request_id=request_id,
        run_id="run1",
        mode=RequestMode.SEARCH,
        data_class=DataClass.PUBLIC,
        auth_context="none",
        query="private marketplace phrase",
        source="ebay",
        capture_policy="content",
    )


def _context(request: WebRequest, *, run_id: str | None = None) -> WorkContext:
    return WorkContext.create(
        context_id=f"context-{request.request_id}-{run_id or request.run_id}",
        run_id=run_id or request.run_id,
        correlation_id=request.request_id,
        source=WorkContextSource.CALLER,
        created_at="2026-08-27T12:00:00+00:00",
    )


def _acquisition(request: WebRequest) -> AcquisitionEnvelope:
    return AcquisitionEnvelope.create(work_context=_context(request), request=request)


def _unchecked_acquisition(
    request: WebRequest, context: WorkContext
) -> AcquisitionEnvelope:
    basis = {
        "contract_version": ACQUISITION_ENVELOPE_VERSION,
        "work_context": context.to_dict(),
        "request": request.to_dict(),
    }
    return AcquisitionEnvelope(
        work_context=context,
        request=request,
        envelope_hash=canonical_digest(basis),
    )


class AcquisitionBrokerTests(unittest.TestCase):
    @mock.patch("weir.broker.check_target_policy")
    def test_legacy_cli_fallback_is_traced(self, policy_check):
        oc = StubReader("oc", EngineUnavailable("oc missing"))
        agent = StubReader("agent-browser-read")
        traces = RecordingTraceSink()
        broker = AcquisitionBroker(registry=StubRegistry(oc, agent), trace_sink=traces)

        result = broker._legacy_read_for_cli(_request())

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
            broker._legacy_read_for_cli(_request())

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
                broker._legacy_read_for_cli(_request())
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
                broker._legacy_read_for_cli(_request(), "oc")
        self.assertEqual(reader.calls, 0)
        self.assertEqual([span.name for span in traces.spans], ["web.route", "web.policy.check"])

    @mock.patch("weir.broker.check_target_policy")
    def test_public_unauthenticated_capture_cache_reuses_original_evidence(self, policy_check):
        reader = StubReader("reader")
        with tempfile.TemporaryDirectory() as temp:
            cache = FileCaptureCache(Path(temp) / "cache")
            broker = AcquisitionBroker(registry=StubRegistry(reader), cache=cache)
            first = broker._legacy_read_for_cli(_request("first"), "reader")
            second = broker._legacy_read_for_cli(_request("second"), "reader")

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
            first = large._legacy_read_for_cli(_request("first"), "reader")
            second = small._legacy_read_for_cli(_request("second"), "reader")

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
            result = broker._legacy_read_for_cli(
                _request(capture_policy="metadata"), "reader"
            )
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
        result = broker._legacy_read_for_cli(_request(), "reader")

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
            broker._legacy_search_for_cli(request)
        self.assertEqual(raised.exception.failure_class, FailureClass.CANNOT_READ)


class ContextBoundAcquisitionTests(unittest.TestCase):
    def test_public_methods_reject_bare_requests_before_engine_access(self):
        reader = StubReader("oc")
        search = StubSearch()
        with tempfile.TemporaryDirectory() as temp:
            broker = AcquisitionBroker(
                registry=StubRegistry(reader, search),
                store=CaptureStore(Path(temp)),
            )
            with self.assertRaisesRegex(TypeError, "AcquisitionEnvelope"):
                broker.read(_request())  # type: ignore[arg-type]
            with self.assertRaisesRegex(TypeError, "AcquisitionEnvelope"):
                broker.search(_search_request())  # type: ignore[arg-type]
            with self.assertRaisesRegex(TypeError, "AcquisitionEnvelope"):
                broker.enrich(_request())  # type: ignore[arg-type]

        self.assertEqual(reader.calls, 0)
        self.assertEqual(search.calls, 0)

    def test_public_acquisition_requires_a_store_before_engine_access(self):
        reader = StubReader("reader")
        broker = AcquisitionBroker(registry=StubRegistry(reader))
        with self.assertRaisesRegex(RuntimeError, "durable CaptureStore"):
            broker.read(_acquisition(_request()), "reader")
        self.assertEqual(reader.calls, 0)

    @mock.patch("weir.broker.check_target_policy")
    def test_public_result_is_detached_from_the_callers_mutable_request(
        self, policy_check
    ):
        request = _request()
        acquisition = _acquisition(request)
        with tempfile.TemporaryDirectory() as temp:
            broker = AcquisitionBroker(
                registry=StubRegistry(StubReader("reader")),
                store=CaptureStore(Path(temp)),
            )
            result = broker.read(acquisition, "reader")
            request.intent = "caller mutation after return"

        self.assertEqual(result.request.intent, "")
        result.acquisition.validate()

    @mock.patch("weir.broker.check_target_policy")
    def test_run_mismatch_fails_before_policy_or_network(self, policy_check):
        request = _request()
        reader = StubReader("reader")
        mismatched = _unchecked_acquisition(
            request, _context(request, run_id="different-run")
        )
        with tempfile.TemporaryDirectory() as temp:
            broker = AcquisitionBroker(
                registry=StubRegistry(reader),
                store=CaptureStore(Path(temp)),
            )
            with self.assertRaises(ContractViolation) as raised:
                broker.read(mismatched, "reader")

        self.assertEqual(raised.exception.reason_code, "acquisition_run_mismatch")
        self.assertEqual(reader.calls, 0)
        policy_check.assert_not_called()

    @mock.patch("weir.broker.check_target_policy")
    def test_read_returns_a_persisted_context_binding(self, policy_check):
        request = _request()
        reader = StubReader("reader")
        with tempfile.TemporaryDirectory() as temp:
            store = CaptureStore(Path(temp))
            broker = AcquisitionBroker(
                registry=StubRegistry(reader),
                store=store,
                evidence_id_factory=lambda: "evidence-read-1",
            )
            result = broker.read(_acquisition(request), "reader")
            wire = result.to_envelope()

            self.assertEqual(
                store.load_evidence_reference(result.evidence_reference_ref),
                result.evidence_reference,
            )
            self.assertEqual(
                store.materialize_evidence(result.evidence_reference),
                {"text": "evidence"},
            )

        self.assertEqual(result.evidence_reference.request_id, request.request_id)
        self.assertEqual(
            result.evidence_reference.work_context_hash,
            result.acquisition.work_context.context_hash,
        )
        self.assertEqual(wire["evidence_reference_ref"], "weir-evidence:evidence-read-1")
        self.assertNotEqual(wire["capture"], wire["evidence_reference"])

    @mock.patch("weir.broker.check_target_policy")
    def test_cache_hit_rebinds_without_duplicating_the_capture(self, policy_check):
        reader = StubReader("reader")
        evidence_ids = iter(("evidence-cache-first", "evidence-cache-second"))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            store = CaptureStore(root)
            cache = FileCaptureCache(root / "cache")
            broker = AcquisitionBroker(
                registry=StubRegistry(reader),
                store=store,
                cache=cache,
                evidence_id_factory=lambda: next(evidence_ids),
            )
            first = broker.read(_acquisition(_request("first")), "reader")
            second = broker.read(_acquisition(_request("second")), "reader")

            first_content = store.materialize_evidence(first.evidence_reference)
            second_content = store.materialize_evidence(second.evidence_reference)
            capture_files = list((root / "captures").glob("*.json"))
            artifact_files = list((root / "artifacts").rglob("*.json"))
            reference_files = list((root / "evidence-references").glob("*.json"))

        self.assertEqual(reader.calls, 1)
        self.assertEqual(first.cache.status, "miss")
        self.assertEqual(second.cache.status, "hit")
        self.assertEqual(second.capture.capture_id, first.capture.capture_id)
        self.assertEqual(second.capture.request_id, "first")
        self.assertEqual(second.evidence_reference.request_id, "second")
        self.assertNotEqual(
            first.evidence_reference.reference_hash,
            second.evidence_reference.reference_hash,
        )
        self.assertEqual(first_content, second_content)
        self.assertEqual(len(capture_files), 1)
        self.assertEqual(len(artifact_files), 1)
        self.assertEqual(len(reference_files), 2)

    @mock.patch("weir.broker.check_target_policy")
    def test_corrupt_cache_fails_before_network_retry(self, policy_check):
        reader = StubReader("reader")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cache = FileCaptureCache(root / "cache")
            broker = AcquisitionBroker(
                registry=StubRegistry(reader),
                store=CaptureStore(root),
                cache=cache,
            )
            broker.read(_acquisition(_request("first")), "reader")
            key = cache.key_for(_request("second"), ["reader"], broker.max_capture_bytes)
            path = root / "cache" / f"{key}.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["capture"]["content"] = {"text": "tampered"}
            path.write_text(json.dumps(value), encoding="utf-8")

            with self.assertRaises(CacheIntegrityError):
                broker.read(_acquisition(_request("second")), "reader")

        self.assertEqual(reader.calls, 1)

    @mock.patch("weir.broker.check_target_policy")
    def test_tampered_artifact_fails_during_cache_rebinding(self, policy_check):
        reader = StubReader("reader")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            broker = AcquisitionBroker(
                registry=StubRegistry(reader),
                store=CaptureStore(root),
                cache=FileCaptureCache(root / "cache"),
            )
            first = broker.read(_acquisition(_request("first")), "reader")
            digest = (first.capture.raw_artifact_ref or "").removeprefix(
                "weir-artifact:sha256:"
            )
            artifact_path = root / "artifacts" / "sha256" / digest[:2] / f"{digest}.json"
            artifact_path.write_bytes(b'{"text":"tampered"}')

            with self.assertRaises(ContractViolation) as raised:
                broker.read(_acquisition(_request("second")), "reader")

        self.assertEqual(raised.exception.reason_code, "artifact_hash_mismatch")
        self.assertEqual(reader.calls, 1)

    def test_search_and_enrich_are_context_bound_and_emit_metadata_only(self):
        search = StubSearch()
        reader = StubReader("oc")
        traces = RecordingTraceSink()
        with tempfile.TemporaryDirectory() as temp:
            broker = AcquisitionBroker(
                registry=StubRegistry(search, reader),
                store=CaptureStore(Path(temp)),
                trace_sink=traces,
            )
            search_result = broker.search(_acquisition(_search_request()))
            with mock.patch("weir.broker.check_target_policy"):
                enrich_result = broker.enrich(_acquisition(_request("enrich-1")))

        serialized_spans = json.dumps([span.to_dict() for span in traces.spans])
        self.assertNotIn("private marketplace phrase", serialized_spans)
        self.assertEqual(search.calls, 1)
        self.assertEqual(reader.calls, 1)
        self.assertEqual(search_result.evidence_reference.request_id, "search-1")
        self.assertEqual(enrich_result.evidence_reference.request_id, "enrich-1")
        self.assertEqual(search_result.warnings, ())
        self.assertEqual(enrich_result.warnings, ())
        binding_spans = [span for span in traces.spans if span.name == "web.evidence.bind"]
        self.assertEqual(len(binding_spans), 2)
        self.assertTrue(all("work_context_hash" in span.attributes for span in binding_spans))


if __name__ == "__main__":
    unittest.main()
