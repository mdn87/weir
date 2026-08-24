import json
import unittest
from pathlib import Path

from jsonschema import FormatChecker, ValidationError
from jsonschema.validators import Draft202012Validator

from weir.engines.base import EngineCannotRead, EngineUnavailable
from weir.engines.ebay_connector import EbayConnector, listing_hash, normalize_summary
from weir.models import DataClass, RequestMode, WebCapture, WebRequest
from weir.router import classify

CONTRACTS = Path(__file__).resolve().parents[1] / "contracts"

TOKEN_RESPONSE = json.dumps({"access_token": "tok-1", "expires_in": 7200}).encode()

ITEM_FULL = {
    "itemId": "v1|110001|0",
    "title": "Keychron C2 Pro QMK/VIA Wired Mechanical Keyboard",
    "itemWebUrl": "https://www.ebay.com/itm/110001",
    "price": {"value": "39.99", "currency": "USD"},
    "shippingOptions": [{"shippingCost": {"value": "0.00", "currency": "USD"}}],
    "condition": "New",
    "conditionId": "1000",
}
ITEM_THIN = {
    "itemId": "v1|110002|0",
    "title": "Keychron C2 Pro (no shipping info)",
    "itemWebUrl": "https://www.ebay.com/itm/110002",
    "price": {"value": "35.00", "currency": "USD"},
}

SEARCH_PAGE_1 = {
    "total": 3,
    "itemSummaries": [ITEM_FULL, ITEM_THIN],
    "next": "https://api.ebay.com/buy/browse/v1/item_summary/search?q=x&offset=50",
}
SEARCH_PAGE_2 = {"total": 3, "itemSummaries": [dict(ITEM_FULL, itemId="v1|110003|0", itemWebUrl="https://www.ebay.com/itm/110003")]}

ENV = {"WEIR_EBAY_CLIENT_ID": "cid", "WEIR_EBAY_CLIENT_SECRET": "cs", "WEIR_EBAY_ENV": "production"}


def fake_transport(req):
    url = req.full_url
    if "/oauth2/token" in url:
        return 200, TOKEN_RESPONSE
    if "offset=50" in url:
        return 200, json.dumps(SEARCH_PAGE_2).encode()
    if "item_summary/search" in url:
        return 200, json.dumps(SEARCH_PAGE_1).encode()
    if "get_item_by_legacy_id" in url:
        return 200, json.dumps(ITEM_FULL).encode()
    return 404, b"{}"


def _search_request(pages: int = 1) -> WebRequest:
    return WebRequest(
        request_id="r1",
        run_id="run1",
        mode=RequestMode.SEARCH,
        data_class=DataClass.PUBLIC,
        auth_context="app",
        query="Keychron C2 Pro",
        source="ebay",
        profile_id="ebay-app",
        maximum_depth=pages - 1,
    )


class EbaySearchTests(unittest.TestCase):
    def setUp(self):
        self.engine = EbayConnector(transport=fake_transport, environ=ENV)

    def test_missing_credentials_is_engine_unavailable(self):
        engine = EbayConnector(transport=fake_transport, environ={})
        with self.assertRaises(EngineUnavailable):
            engine.search(_search_request())
        self.assertFalse(engine.probe().available)

    def test_search_normalizes_listings(self):
        result = self.engine.search(_search_request())
        listings = result.content["listings"]
        self.assertEqual(len(listings), 2)
        full, thin = listings
        self.assertEqual(full["price"], {"amount": "39.99", "currency": "USD"})
        self.assertEqual(full["shipping"], {"amount": "0.00", "currency": "USD"})
        self.assertEqual(full["condition"], {"raw": "New", "condition_id": "1000"})
        self.assertEqual(thin["shipping"], "unknown")
        self.assertEqual(thin["condition"], "unknown")

    def test_pagination_is_bounded_and_reported(self):
        one_page = self.engine.search(_search_request(pages=1))
        self.assertEqual(one_page.content["pagination"], {"pages_fetched": 1, "total_reported": 3, "truncated": True})
        two_pages = self.engine.search(_search_request(pages=2))
        self.assertEqual(len(two_pages.content["listings"]), 3)
        self.assertFalse(two_pages.content["pagination"]["truncated"])

    def test_listings_validate_against_contract(self):
        schema = json.loads((CONTRACTS / "marketplace-listing.schema.json").read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        for listing in self.engine.search(_search_request(pages=2)).content["listings"]:
            validator.validate(listing)
        with self.assertRaises(ValidationError):
            validator.validate({"source": "ebay"})

    def test_listing_hash_is_stable_across_observations(self):
        first = normalize_summary(ITEM_FULL, "2026-08-24T00:00:00+00:00")
        later = normalize_summary(ITEM_FULL, "2026-08-25T09:00:00+00:00")
        self.assertEqual(first["content_hash"], later["content_hash"])
        changed = normalize_summary(dict(ITEM_FULL, price={"value": "29.99", "currency": "USD"}), "2026-08-25T09:00:00+00:00")
        self.assertNotEqual(first["content_hash"], changed["content_hash"])

    def test_search_result_wraps_into_valid_webcapture(self):
        schema = json.loads((CONTRACTS / "web-capture.schema.json").read_text(encoding="utf-8"))
        request = _search_request()
        capture = WebCapture.from_reader_result(self.engine.search(request), request)
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(capture.to_dict())


class EbayReadTests(unittest.TestCase):
    def setUp(self):
        self.engine = EbayConnector(transport=fake_transport, environ=ENV)

    def _read_request(self, url: str) -> WebRequest:
        return WebRequest(
            request_id="r1",
            run_id="run1",
            mode=RequestMode.READ,
            data_class=DataClass.PUBLIC,
            auth_context="app",
            url=url,
            profile_id="ebay-app",
        )

    def test_item_url_resolves_via_api(self):
        result = self.engine.read(self._read_request("https://www.ebay.com/itm/110001"))
        self.assertEqual(result.content["listing"]["source_item_id"], "v1|110001|0")

    def test_non_item_url_is_cannot_read(self):
        with self.assertRaises(EngineCannotRead):
            self.engine.read(self._read_request("https://www.ebay.com/sch/i.html?_nkw=keyboard"))


class SearchRoutingTests(unittest.TestCase):
    def test_ebay_search_routes_to_connector(self):
        decision = classify(_search_request())
        self.assertEqual(decision.route_class, "connector")
        self.assertEqual(decision.engine_candidates, ["ebay"])

    def test_unknown_source_is_unsupported(self):
        request = _search_request()
        request.source = "newegg"
        decision = classify(request)
        self.assertEqual(decision.route_class, "unsupported")
        self.assertEqual(decision.engine_candidates, [])

    def test_search_requires_query_and_source(self):
        request = _search_request()
        request.query = None
        request.url = "https://www.ebay.com"
        with self.assertRaises(ValueError):
            request.validate()


if __name__ == "__main__":
    unittest.main()
