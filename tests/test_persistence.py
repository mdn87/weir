import json
import tempfile
import unittest
from pathlib import Path

from weir.models import DataClass, ReaderResult, RequestMode, WebCapture, WebRequest
from weir.persistence import CachePolicy, CaptureStore, FileCaptureCache


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

    def test_capture_lookup_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as temp:
            store = CaptureStore(Path(temp))
            with self.assertRaisesRegex(ValueError, "invalid capture id"):
                store.load_capture("../../outside")


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

    def test_tampered_cache_capture_is_a_miss(self):
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
            self.assertIsNone(cache.get(key, 10))


if __name__ == "__main__":
    unittest.main()
