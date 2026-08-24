import json
import unittest
from pathlib import Path

from jsonschema import FormatChecker, ValidationError
from jsonschema.validators import Draft202012Validator

from weir.models import DataClass, ReaderResult, RequestMode, WebCapture, WebRequest

CONTRACTS = Path(__file__).resolve().parents[1] / "contracts"


def _validator(schema_name: str) -> Draft202012Validator:
    schema = json.loads((CONTRACTS / schema_name).read_text(encoding="utf-8"))
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _request() -> WebRequest:
    return WebRequest(
        request_id="webreq-test",
        run_id="run-test",
        mode=RequestMode.READ,
        data_class=DataClass.PUBLIC,
        auth_context="none",
        url="https://example.com/docs",
    )


def _reader_result() -> ReaderResult:
    return ReaderResult(
        engine="oc",
        requested_url="https://example.com/docs",
        final_url="https://example.com/docs/index",
        title="Example Docs",
        content={"text": "hello", "links": ["https://example.com/a"]},
        diagnostics={"isolated_session": True},
    )


class WebRequestContractTests(unittest.TestCase):
    def test_request_dict_matches_schema(self):
        _validator("web-request.schema.json").validate(_request().to_dict())


class WebCaptureContractTests(unittest.TestCase):
    def test_capture_from_reader_result_matches_schema(self):
        capture = WebCapture.from_reader_result(_reader_result(), _request())
        _validator("web-capture.schema.json").validate(capture.to_dict())

    def test_capture_carries_provenance(self):
        capture = WebCapture.from_reader_result(_reader_result(), _request())
        self.assertEqual(capture.request_id, "webreq-test")
        self.assertEqual(capture.trust, "untrusted_external_content")
        self.assertTrue(capture.content_hash.startswith("sha256:"))

    def test_content_hash_is_deterministic(self):
        first = WebCapture.from_reader_result(_reader_result(), _request())
        second = WebCapture.from_reader_result(_reader_result(), _request())
        self.assertEqual(first.content_hash, second.content_hash)

    def test_invalid_trust_fails_schema(self):
        capture = WebCapture.from_reader_result(_reader_result(), _request()).to_dict()
        capture["trust"] = "totally_trusted"
        with self.assertRaises(ValidationError):
            _validator("web-capture.schema.json").validate(capture)

    def test_diagnostics_stay_off_the_contract(self):
        capture = WebCapture.from_reader_result(_reader_result(), _request()).to_dict()
        self.assertNotIn("diagnostics", capture)


if __name__ == "__main__":
    unittest.main()
