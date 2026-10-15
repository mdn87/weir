"""Offline contract for the CLI surface Lode's WeirCollector consumes.

Lode shells out to `weir search QUERY --source ebay --pages N` and
`weir enrich URL`, reads stdout on exit 0 and stderr on failure. These tests
pin that surface using the same transcripts Lode vendors as fixtures.
"""

import http.client
import importlib.util
import json
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

from jsonschema import FormatChecker
from jsonschema.validators import Draft202012Validator
from referencing import Registry, Resource
from weir.engines.agent_browser_reader import AgentBrowserReader
from weir.engines.base import EngineCannotRead, EngineFailure, FailureClass
from weir.engines.ebay_connector import listing_hash
from weir.models import DataClass, RequestMode, WebRequest, _content_hash

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts"


def _load_transcripts():
    path = ROOT / "scripts" / "export_lode_cli_transcripts.py"
    spec = importlib.util.spec_from_file_location("weir_lode_cli_transcripts", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


transcripts = _load_transcripts()


def _search_result_validator() -> Draft202012Validator:
    resources = []
    for name in ("marketplace-listing", "marketplace-search-result"):
        schema = json.loads((CONTRACTS / f"{name}.schema.json").read_text(encoding="utf-8"))
        resources.append((schema["$id"], Resource.from_contents(schema)))
    registry = Registry().with_resources(resources)
    schema = registry.contents("https://lugos.local/weir/marketplace-search-result.schema.json")
    return Draft202012Validator(schema, registry=registry, format_checker=FormatChecker())


class SearchTranscriptTests(unittest.TestCase):
    def test_success_envelope_carries_everything_lode_maps(self):
        result = transcripts.run_scenario("search-ok")
        self.assertEqual(result["returncode"], 0)
        self.assertEqual(result["stderr"], "")
        envelope = json.loads(result["stdout"])
        self.assertIs(envelope["ok"], True)

        capture = envelope["capture"]
        content = capture["content"]
        self.assertTrue(capture["capture_id"].startswith("webcap-"))
        self.assertEqual(capture["content_hash"], _content_hash(content))
        self.assertEqual(capture["request_id"], envelope["request"]["request_id"])
        self.assertEqual(envelope["request"]["run_id"], transcripts.RUN_ID)
        self.assertEqual(capture["engine"], "ebay")
        self.assertEqual(capture["engine_version"], "browse-v1")
        self.assertEqual(capture["auth_scope"], "app:ebay-app")
        self.assertEqual(list(_search_result_validator().iter_errors(content)), [])
        self.assertEqual(
            content["pagination"], {"pages_fetched": 2, "total_reported": 4, "truncated": False}
        )

        listings = {listing["source_item_id"]: listing for listing in content["listings"]}
        self.assertEqual(
            sorted(listings),
            ["v1|316000000001|0", "v1|316000000002|0", "v1|316000000003|0", "v1|316000000004|0"],
        )
        fixed = listings["v1|316000000001|0"]
        # Canonical evidence URL drops tracking; the raw provider record keeps it.
        self.assertEqual(fixed["canonical_url"], "https://www.ebay.com/itm/316000000001")
        self.assertIn("hash=item", fixed["raw"]["itemWebUrl"])
        self.assertEqual(fixed["price"], {"amount": "689.99", "currency": "USD"})
        self.assertEqual(fixed["shipping"], {"amount": "0.00", "currency": "USD"})
        self.assertEqual(fixed["condition"], {"raw": "Used", "condition_id": "3000"})
        self.assertEqual(fixed["enrichment"], "none")
        self.assertEqual(fixed["content_hash"], listing_hash(fixed))

        # Unknowns stay explicit; WEIR never drops or guesses them for Lode.
        self.assertEqual(listings["v1|316000000002|0"]["shipping"], "unknown")
        self.assertEqual(listings["v1|316000000003|0"]["price"], "unknown")
        self.assertEqual(listings["v1|316000000003|0"]["condition"], "unknown")

        captured_at = datetime.fromisoformat(capture["captured_at"])
        for listing in listings.values():
            observed_at = datetime.fromisoformat(listing["observed_at"])
            self.assertEqual(observed_at.utcoffset(), timedelta(0))
            self.assertLessEqual(observed_at, captured_at)

    def test_only_a_reported_zero_total_is_an_empty_success(self):
        result = transcripts.run_scenario("search-no-matches")
        self.assertEqual(result["returncode"], 0)
        content = json.loads(result["stdout"])["capture"]["content"]
        self.assertEqual(content["listings"], [])
        self.assertEqual(content["pagination"]["total_reported"], 0)

    def test_failed_acquisitions_exit_nonzero_with_classified_json(self):
        expected = {
            "search-missing-credentials": FailureClass.ENGINE_UNAVAILABLE,
            "search-access-denied": FailureClass.AUTH_REQUIRED,
            "search-throttled": FailureClass.NETWORK_FAILURE,
            "search-timeout": FailureClass.NETWORK_FAILURE,
            "search-malformed-body": FailureClass.ENGINE_FAILURE,
            "search-unusable-listings": FailureClass.ENGINE_FAILURE,
        }
        for name, failure_class in expected.items():
            with self.subTest(name):
                result = transcripts.run_scenario(name)
                self.assertEqual(result["returncode"], 2)
                self.assertEqual(result["stdout"], "")
                error = json.loads(result["stderr"])
                self.assertIs(error["ok"], False)
                self.assertEqual(error["class"], failure_class.value)
                self.assertEqual(error["attempts"][-1]["engine"], "ebay")

    def test_missing_credentials_keep_the_phrase_lode_classifies_on(self):
        result = transcripts.run_scenario("search-missing-credentials")
        # Lode maps this phrase to a configuration error rather than an engine failure.
        self.assertIn("credentials not configured", result["stderr"])
        self.assertIn("EBAY_CLIENT_ID", result["stderr"])
        self.assertNotIn("contract-secret", result["stderr"])


class EnrichTranscriptTests(unittest.TestCase):
    def test_page_enrichment_is_a_page_capture_only(self):
        result = transcripts.run_scenario("enrich-page")
        self.assertEqual(result["returncode"], 0)
        envelope = json.loads(result["stdout"])
        self.assertEqual(envelope["enrichment"], "page")
        capture = envelope["capture"]
        self.assertEqual(capture["engine"], "oc")
        self.assertEqual(capture["auth_scope"], "none")
        self.assertEqual(capture["content_hash"], _content_hash(capture["content"]))
        self.assertIn("Tested, no artifacts", json.dumps(capture["content"]))
        # Page text carries no normalized price or availability state.
        self.assertNotIn("listing", capture["content"])

    def test_runner_without_reader_clis_fails_instead_of_returning_nothing(self):
        result = transcripts.run_scenario("enrich-no-readers")
        self.assertEqual(result["returncode"], 2)
        self.assertEqual(result["stdout"], "")
        error = json.loads(result["stderr"])
        self.assertEqual(error["class"], FailureClass.ENGINE_UNAVAILABLE.value)
        self.assertEqual(
            [attempt["engine"] for attempt in error["attempts"]], ["oc", "agent-browser-read"]
        )

    def test_blank_agent_browser_read_is_cannot_read(self):
        reader = AgentBrowserReader()
        request = WebRequest(
            request_id="r1",
            run_id="run1",
            mode=RequestMode.READ,
            data_class=DataClass.PUBLIC,
            url="https://www.ebay.com/itm/316000000001",
        )
        module = "weir.engines.agent_browser_reader"
        with mock.patch(f"{module}.shutil.which", return_value="/usr/bin/agent-browser"):
            for stdout in ("", "  \n", '{"success": true, "data": {"content": "   "}}'):
                with self.subTest(stdout=stdout):
                    with mock.patch(f"{module}._run_detached_safe", return_value=(0, stdout, "")):
                        with self.assertRaises(EngineCannotRead):
                            reader.read(request)
            page = '{"success": true, "data": {"content": "# RTX 3090"}}'
            with mock.patch(f"{module}._run_detached_safe", return_value=(0, page, "")):
                self.assertEqual(reader.read(request).content["data"]["content"], "# RTX 3090")


class TransportFailureTests(unittest.TestCase):
    def test_dropped_connection_is_a_retried_network_failure(self):
        from weir.engines.ebay_connector import EbayConnector

        engine = EbayConnector(
            environ=transcripts.CREDENTIALS, sleeper=lambda _seconds: None
        )
        dropped = http.client.RemoteDisconnected("Remote end closed connection")
        with mock.patch("urllib.request.urlopen", side_effect=dropped) as urlopen:
            with self.assertRaises(EngineFailure) as raised:
                engine._access_token("ebay-app")
        self.assertEqual(raised.exception.failure_class, FailureClass.NETWORK_FAILURE)
        self.assertEqual(urlopen.call_count, 3)


if __name__ == "__main__":
    unittest.main()
