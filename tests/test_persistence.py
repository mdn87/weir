import json
import tempfile
import threading
import unittest
from pathlib import Path

from weir.contract import ContractViolation
from weir.evidence import EvidenceReference
from weir.models import DataClass, ReaderResult, RequestMode, WebCapture, WebRequest
from weir.persistence import CacheIntegrityError, CachePolicy, CaptureStore, FileCaptureCache
from weir.work_context import WorkContext, WorkContextSource


def _request(
    data_class: DataClass = DataClass.PUBLIC,
    auth_context: str = "none",
    profile_id: str | None = None,
    capture_policy: str = "content",
) -> WebRequest:
    return WebRequest(
        request_id="r1",
        run_id="run1",
        mode=RequestMode.READ,
        data_class=data_class,
        auth_context=auth_context,
        profile_id=profile_id,
        url="https://example.com/data.json",
        capture_policy=capture_policy,
    )


def _capture(request: WebRequest) -> WebCapture:
    result = ReaderResult(
        engine="http",
        requested_url=request.url or "",
        final_url=request.url or "",
        content={"json": {"answer": 42}},
    )
    return WebCapture.from_reader_result(result, request)


def _context(request: WebRequest) -> WorkContext:
    return WorkContext.create(
        context_id="context-persistence",
        run_id=request.run_id,
        correlation_id=request.request_id,
        source=WorkContextSource.CALLER,
        created_at="2026-08-27T12:00:00+00:00",
    )


class CaptureStoreTests(unittest.TestCase):
    def test_content_is_addressed_by_hash_and_manifest_is_loadable(self):
        request = _request()
        capture = _capture(request)
        with tempfile.TemporaryDirectory() as temp:
            store = CaptureStore(Path(temp))
            stored, info = store.persist(capture, request)
            loaded_capture = store.load_capture(capture.capture_id)
            manifest_capture = store.load_capture(capture.capture_id, hydrate=False)
            loaded_content = store.load_artifact(stored.raw_artifact_ref or "")

        self.assertTrue(info.stored)
        self.assertEqual(stored.raw_artifact_ref, info.artifact_ref)
        self.assertEqual(loaded_capture.to_dict(), stored.to_dict())
        self.assertIsNone(manifest_capture.content)
        self.assertEqual(loaded_content, capture.content)

    def test_restricted_capture_is_not_written(self):
        request = _request(DataClass.RESTRICTED, capture_policy="full_evidence")
        capture = _capture(request)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            stored, info = CaptureStore(root).persist(capture, request)
            files = list(root.rglob("*"))

        self.assertFalse(info.stored)
        self.assertEqual(stored, capture)
        self.assertEqual(files, [])

    def test_non_public_content_requires_explicit_full_evidence_policy(self):
        ordinary = _request(DataClass.PERSONAL, auth_context="browser", capture_policy="content")
        explicit = _request(
            DataClass.PERSONAL, auth_context="browser", capture_policy="full_evidence"
        )
        with tempfile.TemporaryDirectory() as temp:
            store = CaptureStore(Path(temp))
            _, ordinary_info = store.persist(_capture(ordinary), ordinary)
            _, explicit_info = store.persist(_capture(explicit), explicit)

        self.assertFalse(ordinary_info.stored)
        self.assertTrue(explicit_info.stored)

    def test_content_hash_mismatch_fails_before_any_store_write(self):
        request = _request(capture_policy="metadata")
        capture = _capture(request)
        capture.content = {"json": {"answer": "mutated"}}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaises(ContractViolation) as raised:
                CaptureStore(root).persist(capture, request)
            self.assertEqual(list(root.rglob("*")), [])
        self.assertEqual(raised.exception.reason_code, "artifact_hash_mismatch")

    def test_capture_lookup_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as temp:
            store = CaptureStore(Path(temp))
            with self.assertRaisesRegex(ValueError, "invalid capture id"):
                store.load_capture("../../outside")

    def test_binary_evidence_is_content_addressed_and_policy_gated(self):
        with tempfile.TemporaryDirectory() as temp:
            store = CaptureStore(Path(temp))
            public = _request(capture_policy="full_evidence")
            first = store.persist_blob(b"png-bytes", public)
            second = store.persist_blob(b"png-bytes", public)
            self.assertEqual(first, second)
            self.assertEqual(store.load_blob(first or ""), b"png-bytes")

            metadata_only = _request(capture_policy="metadata")
            self.assertIsNone(store.persist_blob(b"not-retained", metadata_only))

    def test_concurrent_immutable_writers_publish_one_complete_blob(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            store = CaptureStore(root)
            request = _request(capture_policy="full_evidence")
            payload = b"same-evidence" * 100_000
            refs = []
            failures = []

            def persist():
                try:
                    refs.append(store.persist_blob(payload, request))
                except Exception as exc:  # pragma: no cover - asserted below
                    failures.append(exc)

            writers = [threading.Thread(target=persist) for _ in range(8)]
            for writer in writers:
                writer.start()
            for writer in writers:
                writer.join(timeout=5)

            self.assertTrue(all(not writer.is_alive() for writer in writers))
            self.assertEqual(failures, [])
            self.assertEqual(len(set(refs)), 1)
            self.assertEqual(store.load_blob(refs[0] or ""), payload)
            self.assertEqual(list(root.rglob("*.tmp")), [])

    def test_evidence_reference_is_durable_and_materializes_exact_content(self):
        request = _request(capture_policy="content")
        with tempfile.TemporaryDirectory() as temp:
            store = CaptureStore(Path(temp))
            capture, _ = store.persist(_capture(request), request)
            reference = EvidenceReference.create(
                evidence_ref_id="evidence-persistence",
                work_context=_context(request),
                request=request,
                capture=capture,
            )
            reference_ref = store.persist_evidence_reference(reference)

            self.assertEqual(reference_ref, "weir-evidence:evidence-persistence")
            self.assertEqual(store.load_evidence_reference(reference_ref), reference)
            self.assertEqual(store.materialize_evidence(reference), capture.content)

    def test_tampered_reference_and_artifact_fail_closed(self):
        request = _request(capture_policy="content")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            store = CaptureStore(root)
            capture, _ = store.persist(_capture(request), request)
            reference = EvidenceReference.create(
                evidence_ref_id="evidence-tamper",
                work_context=_context(request),
                request=request,
                capture=capture,
            )
            store.persist_evidence_reference(reference)
            reference_path = root / "evidence-references" / "evidence-tamper.json"
            original_reference = reference_path.read_bytes()
            value = json.loads(original_reference)
            value["capture_id"] = "webcap-substituted"
            reference_path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ContractViolation) as raised:
                store.load_evidence_reference(reference.evidence_ref_id)
            self.assertEqual(raised.exception.reason_code, "reference_hash_mismatch")

            reference_path.write_bytes(original_reference)
            digest = (capture.raw_artifact_ref or "").removeprefix(
                "weir-artifact:sha256:"
            )
            artifact_path = root / "artifacts" / "sha256" / digest[:2] / f"{digest}.json"
            artifact_path.write_bytes(b'{"tampered":true}')
            with self.assertRaises(ContractViolation) as raised:
                store.materialize_evidence(reference)
            self.assertEqual(raised.exception.reason_code, "artifact_hash_mismatch")


class CachePolicyTests(unittest.TestCase):
    def test_only_public_unauthenticated_evidence_is_shared_cache_eligible(self):
        policy = CachePolicy()
        self.assertTrue(policy.decide(_request()).enabled)
        self.assertFalse(
            policy.decide(_request(DataClass.PERSONAL, auth_context="browser")).enabled
        )
        self.assertFalse(policy.decide(_request(DataClass.BWA_INTERNAL)).enabled)
        self.assertFalse(policy.decide(_request(DataClass.RESTRICTED)).enabled)
        self.assertFalse(
            policy.decide(_request(auth_context="app", profile_id="service-app")).enabled
        )

    def test_expired_entry_is_a_miss_without_destroying_evidence(self):
        now = [100.0]
        request = _request()
        capture = _capture(request)
        with tempfile.TemporaryDirectory() as temp:
            cache = FileCaptureCache(Path(temp), clock=lambda: now[0])
            key = cache.key_for(request, ["http"])
            cache.put(key, capture)
            self.assertIsNotNone(cache.get(key, 10))
            now[0] = 111.0
            self.assertIsNone(cache.get(key, 10))
            self.assertEqual(len(list(Path(temp).glob("*.json"))), 1)

    def test_cache_lookup_rejects_non_digest_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            cache = FileCaptureCache(Path(temp))
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                cache.get("../outside", 10)

    def test_tampered_cache_capture_fails_closed(self):
        request = _request()
        capture = _capture(request)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cache = FileCaptureCache(root)
            key = cache.key_for(request, ["http"])
            cache.put(key, capture)
            path = root / f"{key}.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["capture"]["content"] = {"json": {"answer": "tampered"}}
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(CacheIntegrityError):
                cache.get(key, 10)

    def test_expired_tampered_cache_still_fails_closed(self):
        now = [100.0]
        request = _request()
        capture = _capture(request)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cache = FileCaptureCache(root, clock=lambda: now[0])
            key = cache.key_for(request, ["http"])
            cache.put(key, capture)
            path = root / f"{key}.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["capture"]["content"] = {"json": {"answer": "tampered"}}
            path.write_text(json.dumps(value), encoding="utf-8")
            now[0] = 1_000.0
            with self.assertRaises(CacheIntegrityError):
                cache.get(key, 10)


if __name__ == "__main__":
    unittest.main()
