from __future__ import annotations

import http.client
import io
import json
import unittest
import urllib.error
import urllib.parse
from unittest import mock

from tests.test_ebay_connector import ENV, ITEM_FULL, _search_request
from weir.engines.agent_browser_reader import AgentBrowserReader
from weir.engines.base import EngineCannotRead, EngineFailure, EngineUnavailable, FailureClass
from weir.engines.ebay_connector import EbayConnector, is_ebay_item_url
from weir.models import DataClass, RequestMode, WebRequest


class HostedReviewRegressions(unittest.TestCase):
    def test_missing_and_non_string_reader_content_fail(self):
        request = WebRequest(
            request_id="r",
            run_id="test",
            mode=RequestMode.READ,
            data_class=DataClass.PUBLIC,
            url="https://www.ebay.com/itm/110001",
        )
        module = "weir.engines.agent_browser_reader"
        for data in ({}, {"content": None}, {"content": []}, {"content": 42}):
            with (
                self.subTest(data=data),
                mock.patch(f"{module}.shutil.which", return_value="reader"),
            ):
                with mock.patch(
                    f"{module}._run_detached_safe",
                    return_value=(0, json.dumps({"success": True, "data": data}), ""),
                ):
                    with self.assertRaises(EngineCannotRead):
                        AgentBrowserReader().read(request)

    def test_falsey_non_list_summaries_are_not_zero_deals(self):
        for summaries in ({}, "", None, 0, False):
            with self.subTest(summaries=summaries):

                def transport(req):
                    payload = (
                        {"access_token": "token", "expires_in": 7200}
                        if "/oauth2/token" in req.full_url
                        else {"total": 0, "itemSummaries": summaries}
                    )
                    return 200, json.dumps(payload).encode()

                with self.assertRaises(EngineFailure):
                    EbayConnector(transport=transport, environ=ENV).search(_search_request())

    def test_localized_marketplace_item_hosts_are_accepted(self):
        for marketplace, domain in (
            ("EBAY_GB", "ebay.co.uk"),
            ("EBAY_DE", "ebay.de"),
            ("EBAY_AU", "ebay.com.au"),
        ):
            with self.subTest(marketplace=marketplace):
                item = dict(ITEM_FULL, itemWebUrl=f"https://www.{domain}/itm/110001")

                def transport(req):
                    payload = (
                        {"access_token": "token", "expires_in": 7200}
                        if "/oauth2/token" in req.full_url
                        else {"total": 1, "itemSummaries": [item]}
                    )
                    return 200, json.dumps(payload).encode()

                result = EbayConnector(
                    transport=transport, environ=dict(ENV, EBAY_MARKETPLACE_ID=marketplace)
                ).search(_search_request())
                self.assertEqual(result.content["listings"][0]["canonical_url"], item["itemWebUrl"])
                self.assertTrue(is_ebay_item_url(item["itemWebUrl"]))
                self.assertFalse(is_ebay_item_url(f"https://{domain}.example.invalid/itm/110001"))

    def test_unknown_marketplace_is_rejected(self):
        engine = EbayConnector(environ=dict(ENV, EBAY_MARKETPLACE_ID="EBAY_NOTREAL"))
        with self.assertRaises(EngineUnavailable):
            engine._marketplace_id("ebay-app")

    def test_truncated_http_error_bodies_are_retried(self):
        for error in (
            http.client.IncompleteRead(b"partial"),
            http.client.RemoteDisconnected("closed"),
            TimeoutError(),
        ):
            with self.subTest(error=type(error).__name__):

                class BrokenBody(io.BytesIO):
                    def read(self, *args):
                        raise error

                def fail_request(*args, **kwargs):
                    raise urllib.error.HTTPError(
                        "https://api.ebay.com", 503, "unavailable", {}, BrokenBody()
                    )

                engine = EbayConnector(environ=ENV, sleeper=lambda _: None)
                with mock.patch("urllib.request.urlopen", side_effect=fail_request) as send:
                    with self.assertRaises(EngineFailure) as raised:
                        engine._access_token("ebay-app")
                    self.assertEqual(raised.exception.failure_class, FailureClass.NETWORK_FAILURE)
                    self.assertEqual(send.call_count, 3)


class SearchOrderTests(unittest.TestCase):
    def test_newly_listed_constraint_reaches_browse_api(self):
        urls = []
        def transport(req):
            urls.append(req.full_url)
            payload = {"access_token":"token","expires_in":7200} if "/oauth2/token" in req.full_url else {"total":0}
            return 200, json.dumps(payload).encode()
        request = _search_request()
        request.constraints = {"sort":"newlyListed"}
        EbayConnector(transport=transport,environ=ENV).search(request)
        self.assertEqual(urllib.parse.parse_qs(urllib.parse.urlsplit(urls[-1]).query)["sort"], ["newlyListed"])

    def test_unsupported_sort_fails_before_requesting_credentials(self):
        request = _search_request()
        request.constraints = {"sort":"unexpected"}
        with self.assertRaisesRegex(EngineFailure,"sort"):
            EbayConnector(environ={}).search(request)
