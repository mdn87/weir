from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from weir.engines.base import (
    EngineCannotRead,
    EngineFailure,
    EngineProbe,
    EngineUnavailable,
    ReaderEngine,
)
from weir.models import ReaderResult, RequestMode, WebRequest

API_HOSTS = {
    "production": "https://api.ebay.com",
    "sandbox": "https://api.sandbox.ebay.com",
}
OAUTH_SCOPE = "https://api.ebay.com/oauth/api_scope"
PAGE_LIMIT = 50
MAX_PAGES_HARD_CAP = 10
ITEM_URL_PATTERN = re.compile(r"ebay\.[a-z.]+/itm/(?:[^/]+/)?(\d+)")

# Profile indirection: credentials are resolved from the environment by
# profile id and never travel inside a WebRequest (authority-boundaries.md).
PROFILES = {
    "ebay-app": {
        "client_id": "WEIR_EBAY_CLIENT_ID",
        "client_secret": "WEIR_EBAY_CLIENT_SECRET",
        "environment": "WEIR_EBAY_ENV",
    },
}

Transport = Callable[[urllib.request.Request], tuple[int, bytes]]


def _default_transport(req: urllib.request.Request) -> tuple[int, bytes]:
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except urllib.error.URLError as exc:
        raise EngineFailure(f"network_failure: {exc.reason}") from exc
    except TimeoutError as exc:
        raise EngineFailure("network_failure: timeout") from exc


def listing_hash(listing: dict[str, Any]) -> str:
    """Stable hash over the state-bearing fields for change detection.

    observed_at, enrichment, and raw payload are excluded so a listing whose
    substance is unchanged hashes identically across observations.
    """
    basis = {k: listing[k] for k in ("source", "source_item_id", "canonical_url", "title", "price", "shipping", "condition")}
    canonical = json.dumps(basis, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _money(value: Any) -> dict[str, str] | str:
    if isinstance(value, dict) and value.get("value") is not None and value.get("currency"):
        return {"amount": str(value["value"]), "currency": str(value["currency"])}
    return "unknown"


def normalize_summary(item: dict[str, Any], observed_at: str) -> dict[str, Any]:
    """Normalize one Browse API item summary; unknown stays unknown."""
    shipping: dict[str, str] | str = "unknown"
    for option in item.get("shippingOptions") or []:
        cost = _money(option.get("shippingCost"))
        if cost != "unknown":
            shipping = cost
            break

    condition: dict[str, Any] | str = "unknown"
    if item.get("condition"):
        condition = {"raw": str(item["condition"]), "condition_id": item.get("conditionId")}

    listing = {
        "source": "ebay",
        "source_item_id": str(item.get("itemId") or ""),
        "canonical_url": item.get("itemWebUrl") or "",
        "title": item.get("title") or "",
        "price": _money(item.get("price")),
        "shipping": shipping,
        "condition": condition,
        "observed_at": observed_at,
        "enrichment": "none",
        "raw": item,
    }
    listing["content_hash"] = listing_hash(listing)
    return listing


class EbayConnector(ReaderEngine):
    """Browse API connector: rung 1 of the capability ladder for eBay.

    search() returns a normalized listing set; read() resolves one item page
    URL to its API detail record — it never scrapes the page itself. WEIR
    owns pagination and bounded retry here so consumers do not reimplement
    acquisition mechanics (marketplace-slice.md).
    """

    id = "ebay"

    def __init__(self, transport: Transport | None = None, environ: dict[str, str] | None = None) -> None:
        self._transport = transport or _default_transport
        self._environ = environ if environ is not None else os.environ  # type: ignore[assignment]
        self._token: str | None = None
        self._token_expires: float = 0.0

    def _credentials(self, profile_id: str | None) -> tuple[str, str, str]:
        profile = PROFILES.get(profile_id or "ebay-app")
        if profile is None:
            raise EngineUnavailable(f"unknown ebay profile {profile_id!r}; known: {sorted(PROFILES)}")
        client_id = self._environ.get(profile["client_id"], "")
        client_secret = self._environ.get(profile["client_secret"], "")
        environment = self._environ.get(profile["environment"], "") or "production"
        if environment not in API_HOSTS:
            raise EngineUnavailable(f"unsupported ebay environment {environment!r}")
        if not client_id or not client_secret:
            raise EngineUnavailable(
                f"ebay credentials not configured: set {profile['client_id']} and {profile['client_secret']}"
            )
        return client_id, client_secret, environment

    def probe(self) -> EngineProbe:
        try:
            _, _, environment = self._credentials(None)
        except EngineUnavailable as exc:
            return EngineProbe(self.id, False, detail=str(exc))
        return EngineProbe(self.id, True, version="browse-v1", detail=f"credentials configured ({environment})")

    def _access_token(self, profile_id: str | None) -> tuple[str, str]:
        client_id, client_secret, environment = self._credentials(profile_id)
        host = API_HOSTS[environment]
        if self._token and time.monotonic() < self._token_expires:
            return self._token, host

        basic = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        body = urllib.parse.urlencode({"grant_type": "client_credentials", "scope": OAUTH_SCOPE}).encode()
        req = urllib.request.Request(
            f"{host}/identity/v1/oauth2/token",
            data=body,
            headers={"Authorization": f"Basic {basic}", "Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        status, payload = self._transport(req)
        if status != 200:
            raise EngineCannotRead(f"auth_required: ebay token endpoint returned HTTP {status}")
        token_data = json.loads(payload)
        self._token = token_data["access_token"]
        self._token_expires = time.monotonic() + max(int(token_data.get("expires_in", 300)) - 60, 60)
        return self._token, host

    def _api_get(self, url: str, token: str) -> dict[str, Any]:
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
        status, payload = self._transport(req)
        if status == 429:
            raise EngineFailure("rate_limited: ebay Browse API returned HTTP 429")
        if status in {401, 403}:
            raise EngineCannotRead(f"auth_required: HTTP {status}")
        if status == 404:
            raise EngineCannotRead("HTTP 404: item not found")
        if status != 200:
            raise EngineFailure(f"ebay Browse API returned HTTP {status}")
        return json.loads(payload)

    def search(self, request: WebRequest) -> ReaderResult:
        request.validate()
        if request.mode is not RequestMode.SEARCH:
            raise EngineFailure("EbayConnector.search requires mode=search")
        if request.source != "ebay":
            raise EngineFailure(f"EbayConnector cannot search source {request.source!r}")

        token, host = self._access_token(request.profile_id)
        observed_at = datetime.now(timezone.utc).isoformat()
        max_pages = min(request.maximum_depth + 1, MAX_PAGES_HARD_CAP)

        params = urllib.parse.urlencode({"q": request.query, "limit": PAGE_LIMIT})
        url: str | None = f"{host}/buy/browse/v1/item_summary/search?{params}"
        first_url = url
        listings: list[dict[str, Any]] = []
        pages = 0
        total: int | None = None
        while url and pages < max_pages:
            page = self._api_get(url, token)
            total = page.get("total", total)
            listings.extend(normalize_summary(item, observed_at) for item in page.get("itemSummaries") or [])
            url = page.get("next")
            pages += 1

        return ReaderResult(
            engine=self.id,
            requested_url=first_url,
            final_url=first_url,
            title=f"ebay search: {request.query}",
            http_status=200,
            engine_version="browse-v1",
            content={
                "query": request.query,
                "source": "ebay",
                "listings": listings,
                "pagination": {"pages_fetched": pages, "total_reported": total, "truncated": bool(url)},
            },
            diagnostics={"page_limit": PAGE_LIMIT, "max_pages": max_pages},
        )

    def read(self, request: WebRequest) -> ReaderResult:
        """Resolve an eBay item page URL to its Browse API detail record."""
        request.validate()
        if request.mode is not RequestMode.READ:
            raise EngineFailure("EbayConnector.read requires mode=read")
        if not request.url:
            raise EngineFailure("EbayConnector.read requires a URL")
        match = ITEM_URL_PATTERN.search(request.url)
        if not match:
            raise EngineCannotRead(f"not an ebay item URL: {request.url}")

        token, host = self._access_token(request.profile_id)
        legacy_id = match.group(1)
        detail = self._api_get(
            f"{host}/buy/browse/v1/item/get_item_by_legacy_id?legacy_item_id={legacy_id}", token
        )
        observed_at = datetime.now(timezone.utc).isoformat()
        listing = normalize_summary(detail, observed_at)
        return ReaderResult(
            engine=self.id,
            requested_url=request.url,
            final_url=detail.get("itemWebUrl") or request.url,
            title=detail.get("title"),
            http_status=200,
            engine_version="browse-v1",
            content={"listing": listing},
        )
