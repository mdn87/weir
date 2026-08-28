import json
import tempfile
import unittest
from pathlib import Path

from weir.models import DataClass, RequestMode, WebRequest
from weir.telemetry import JsonlTraceSink


class JsonlTraceSinkTests(unittest.TestCase):
    def test_span_contains_ids_and_metadata_without_request_content(self):
        request = WebRequest(
            request_id="r1",
            run_id="run1",
            mode=RequestMode.SEARCH,
            data_class=DataClass.PUBLIC,
            auth_context="app",
            profile_id="ebay-app",
            query="private search phrase",
            source="ebay",
        )
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "spans.jsonl"
            JsonlTraceSink(path).emit(
                "web.route", request, route_class="connector", engine_ids=["ebay"]
            )
            payload = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(payload["name"], "web.route")
        self.assertEqual(payload["run_id"], "run1")
        self.assertEqual(payload["request_id"], "r1")
        self.assertNotIn("private search phrase", json.dumps(payload))

    def test_sink_rejects_arbitrary_content_attributes(self):
        request = WebRequest(
            request_id="r1",
            run_id="run1",
            mode=RequestMode.READ,
            data_class=DataClass.PUBLIC,
            url="https://example.com/private",
        )
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "spans.jsonl"
            sink = JsonlTraceSink(path)
            with self.assertRaisesRegex(ValueError, "unsupported trace attributes"):
                sink.emit("web.reader.fetch", request, page_content="secret body")
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
