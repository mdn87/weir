import unittest

from weir.engines.base import EngineProbe, SearchEngine
from weir.models import DataClass, ReaderResult, RequestMode, WebRequest
from weir.router import EngineRegistry, classify


class SearchOnlyEngine(SearchEngine):
    id = "search-only"

    def probe(self) -> EngineProbe:
        return EngineProbe(self.id, True)

    def search(self, request: WebRequest) -> ReaderResult:
        return ReaderResult(self.id, "https://example.com", "https://example.com", {})


def _request(
    url: str, preferred_engine: str | None = None, mode: RequestMode = RequestMode.READ
) -> WebRequest:
    return WebRequest(
        request_id="r1",
        run_id="run1",
        mode=mode,
        data_class=DataClass.PUBLIC,
        auth_context="none",
        url=url,
        preferred_engine=preferred_engine,
    )


class ClassifyTests(unittest.TestCase):
    def test_registry_accepts_an_independent_search_capability(self):
        registry = EngineRegistry([SearchOnlyEngine()])
        self.assertIsInstance(registry.get("search-only"), SearchEngine)

    def test_api_host_routes_to_connector_first(self):
        decision = classify(_request("https://api.github.com/repos/python/cpython"))
        self.assertEqual(decision.route_class, "connector")
        self.assertEqual(decision.engine_candidates[0], "http")

    def test_feed_path_routes_to_connector(self):
        decision = classify(_request("https://hnrss.org/frontpage"))
        self.assertEqual(decision.route_class, "connector")

    def test_json_suffix_routes_to_connector(self):
        decision = classify(_request("https://example.com/data/report.json"))
        self.assertEqual(decision.route_class, "connector")

    def test_html_page_routes_to_compact_reader(self):
        decision = classify(_request("https://en.wikipedia.org/wiki/Weir"))
        self.assertEqual(decision.route_class, "compact_reader")
        self.assertEqual(decision.engine_candidates, ["oc", "agent-browser-read"])

    def test_preferred_engine_is_advisory_front_of_line(self):
        decision = classify(
            _request("https://en.wikipedia.org/wiki/Weir", preferred_engine="agent-browser-read")
        )
        self.assertEqual(decision.engine_candidates[0], "agent-browser-read")
        self.assertIn("oc", decision.engine_candidates)

    def test_preferred_engine_outside_route_is_ignored(self):
        decision = classify(_request("https://en.wikipedia.org/wiki/Weir", preferred_engine="fake"))
        self.assertEqual(decision.engine_candidates[0], "oc")

    def test_every_decision_has_reasons(self):
        for url in ["https://api.github.com/x", "https://example.com/page"]:
            self.assertTrue(classify(_request(url)).reasons)

    def test_non_read_mode_is_unsupported(self):
        decision = classify(_request("https://example.com", mode=RequestMode.OBSERVE))
        self.assertEqual(decision.route_class, "unsupported")
        self.assertEqual(decision.engine_candidates, [])

    def test_ebay_caller_preference_remains_advisory(self):
        request = _request(
            "https://www.ebay.com/itm/110001",
            preferred_engine="agent-browser-read",
        )
        decision = classify(request)
        self.assertEqual(decision.engine_candidates[0], "agent-browser-read")
        self.assertIn("ebay", decision.engine_candidates)


if __name__ == "__main__":
    unittest.main()
