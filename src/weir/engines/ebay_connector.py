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
    EnginePolicyBlocked,
    EngineProbe,
    EngineUnavailable,
    FailureClass,
    ReaderEngine,
    SearchEngine,
    WeirEngineError,
)
from weir.models import ReaderResult, RequestMode, WebRequest

API_HOSTS = {
    "production": "https://api.ebay.com",
    "sandbox": "https://api.sandbox.ebay.com",
}
OAUTH_SCOPE = "https://api.ebay.com/oauth/api_scope"
PAGE_LIMIT = 50
MAX_PAGES_HARD_CAP = 10
MAX_API_ATTEMPTS = 3
RETRY_BASE_SECONDS = 0.25
ITEM_PATH_PATTERN = re.compile(r"/itm/(?:[^/]+/)?(\d+)(?:/|$)")
MONEY_PATTERN = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?")
CURRENCY_PATTERN = re.compile(r"[A-Z]{3}")

# Profile indirection: credentials are resolved from the environment by
# profile id and never travel inside a WebRequest (authority-boundaries.md).
# Each entry lists env var names in priority order; the Lode names come
# second so one keyset can serve both projects without duplication.
PROFILES = {
    "ebay-app": {
        "client_id": ("WEIR_EBAY_CLIENT_ID", "EBAY_CLIENT_ID"),
        "client_secret": ("WEIR_EBAY_CLIENT_SECRET", "EBAY_CLIENT_SECRET"),
        "environment": ("WEIR_EBAY_ENV",),
    },
}

Transport = Callable[[urllib.request.Request], tuple[int, bytes]]
Sleeper = Callable[[float], None]


def _default_transport(req: urllib.request.Request) -> tuple[int, bytes]:
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except urllib.error.URLError as exc:
        raise EngineFailure(str(exc.reason), FailureClass.NETWORK_FAILURE) from exc
    except TimeoutError as exc:
        raise EngineFailure("timeout", FailureClass.NETWORK_FAILURE) from exc


def listing_hash(listing: dict[str, Any]) -> str:
    """Stable hash over the state-bearing fields for change detection.

    observed_at, enrichment, and raw payload are excluded so a listing whose
    substance is unchanged hashes identically across observations.
    """
    basis = {
        k: listing[k]
        for k in (
            "source",
            "source_item_id",
            "canonical_url",
            "title",
            "price",
            "shipping",
            "condition",
        )
    }
    canonical = json.dumps(basis, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _money(value: Any) -> dict[str, str] | str:
    if isinstance(value, dict) and value.get("value") is not None and value.get("currency"):
        amount = str(value["value"])
        currency = str(value["currency"]).upper()
        if MONEY_PATTERN.fullmatch(amount) and CURRENCY_PATTERN.fullmatch(currency):
            return {"amount": amount, "currency": currency}
    return "unknown"


def _canonical_url(raw_url: str) -> str:
    """Strip tracking query/fragment from an item URL.

    Browse API itemWebUrl values carry '&hash=item...' tracking parameters;
    the canonical evidence URL is the bare scheme+host+path.
    """
    if not raw_url:
        return ""
    parts = urllib.parse.urlsplit(raw_url)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def ebay_legacy_item_id(raw_url: str) -> str | None:
    """Return a legacy item id only for a genuine HTTPS eBay item URL."""
    parts = urllib.parse.urlsplit(raw_url)
    host = (parts.hostname or "").lower()
    try:
        port = parts.port
    except ValueError:
        return None
    if (
        parts.scheme != "https"
        or parts.username
        or parts.password
        or port not in {None, 443}
        or (host != "ebay.com" and not host.endswith(".ebay.com"))
    ):
        return None
    match = ITEM_PATH_PATTERN.search(parts.path)
    return match.group(1) if match else None


def is_ebay_item_url(raw_url: str) -> bool:
    return ebay_legacy_item_id(raw_url) is not None


def normalize_summary(item: dict[str, Any], observed_at: str) -> dict[str, Any]:
    """Normalize one Browse API item summary; unknown stays unknown."""
    raw_item_id = item.get("itemId")
    if isinstance(raw_item_id, bool) or not isinstance(raw_item_id, (str, int)):
        raise ValueError("ebay listing has an invalid itemId")
    source_item_id = str(raw_item_id)
    canonical_url = _canonical_url(str(item.get("itemWebUrl") or ""))
    if not source_item_id:
        raise ValueError("ebay listing has no itemId")
    if not is_ebay_item_url(canonical_url):
        raise ValueError("ebay listing has no valid eBay item URL")
    shipping: dict[str, str] | str = "unknown"
    shipping_options = item.get("shippingOptions") or []
    if not isinstance(shipping_options, list):
        raise ValueError("ebay listing has invalid shippingOptions")
    for option in shipping_options:
        if not isinstance(option, dict):
            continue
        cost = _money(option.get("shippingCost"))
        if cost != "unknown":
            shipping = cost
            break

    condition: dict[str, Any] | str = "unknown"
    if item.get("condition"):
        condition = {"raw": str(item["condition"]), "condition_id": item.get("conditionId")}

    listing = {
        "source": "ebay",
        "source_item_id": source_item_id,
        "canonical_url": canonical_url,
        "title": str(item.get("title") or ""),
        "price": _money(item.get("price")),
        "shipping": shipping,
        "condition": condition,
        "observed_at": observed_at,
        "enrichment": "none",
        "raw": item,
    }
    listing["content_hash"] = listing_hash(listing)
    return listing


class EbayConnector(ReaderEngine, SearchEngine):
    """Browse API connector: rung 1 of the capability ladder for eBay.

    search() returns a normalized listing set; read() resolves one item page
    URL to its API detail record — it never scrapes the page itself. WEIR
    owns pagination and bounded retry here so consumers do not reimplement
    acquisition mechanics (marketplace-slice.md).
    """

    id = "ebay"

    def __init__(
        self,
        transport: Transport | None = None,
        environ: dict[str, str] | None = None,
        sleeper: Sleeper = time.sleep,
        max_attempts: int = MAX_API_ATTEMPTS,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        self._transport = transport or _default_transport
        self._environ = environ if environ is not None else os.environ  # type: ignore[assignment]
        self._sleeper = sleeper
        self._max_attempts = max_attempts
        self._tokens: dict[tuple[str, str, str], tuple[str, float]] = {}

    def _credentials(self, profile_id: str) -> tuple[str, str, str]:
        profile = PROFILES.get(profile_id)
        if profile is None:
            raise EngineUnavailable(
                f"unknown ebay profile {profile_id!r}; known: {sorted(PROFILES)}"
            )

        def resolve(names: tuple[str, ...]) -> str:
            for name in names:
                value = self._environ.get(name, "")
                if value:
                    return value
            return ""

        client_id = resolve(profile["client_id"])
        client_secret = resolve(profile["client_secret"])
        environment = resolve(profile["environment"]) or "production"
        if environment not in API_HOSTS:
            raise EngineUnavailable(f"unsupported ebay environment {environment!r}")
        if not client_id or not client_secret:
            wanted = (
                " or ".join(profile["client_id"]) + " / " + " or ".join(profile["client_secret"])
            )
            raise EngineUnavailable(f"ebay credentials not configured: set {wanted}")
        return client_id, client_secret, environment

    def probe(self) -> EngineProbe:
        try:
            _, _, environment = self._credentials("ebay-app")
        except EngineUnavailable as exc:
            return EngineProbe(self.id, False, detail=str(exc))
        return EngineProbe(
            self.id, True, version="browse-v1", detail=f"credentials configured ({environment})"
        )

    def _access_token(self, profile_id: str | None) -> tuple[str, str]:
        if not profile_id:
            raise EngineUnavailable(
                "ebay connector requires an explicit profile_id (normally 'ebay-app')"
            )
        client_id, client_secret, environment = self._credentials(profile_id)
        host = API_HOSTS[environment]
        token_key = (profile_id, environment, client_id)
        cached = self._tokens.get(token_key)
        if cached and time.monotonic() < cached[1]:
            return cached[0], host

        basic = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        body = urllib.parse.urlencode(
            {"grant_type": "client_credentials", "scope": OAUTH_SCOPE}
        ).encode()
        req = urllib.request.Request(
            f"{host}/identity/v1/oauth2/token",
            data=body,
            headers={
                "Authorization": f"Basic {basic}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            method="POST",
        )
        status, payload = self._send_with_retry(req, "ebay token endpoint")
        if status != 200:
            raise EngineCannotRead(
                f"ebay token endpoint returned HTTP {status}", FailureClass.AUTH_REQUIRED
            )
        try:
            token_data = json.loads(payload)
            raw_token = token_data["access_token"]
            if not isinstance(raw_token, str) or not raw_token:
                raise ValueError("missing access token")
            token = raw_token
            expires_in = token_data.get("expires_in", 300)
            if isinstance(expires_in, bool):
                raise ValueError("invalid token expiry")
            expires_at = time.monotonic() + max(int(expires_in) - 60, 60)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise EngineFailure("ebay token endpoint returned an invalid response") from exc
        self._tokens[token_key] = (token, expires_at)
        return token, host

    def _send_with_retry(self, req: urllib.request.Request, operation: str) -> tuple[int, bytes]:
        """Retry transient transport, throttling, and server failures within a small bound."""
        for attempt in range(1, self._max_attempts + 1):
            try:
                status, payload = self._transport(req)
            except WeirEngineError as exc:
                if (
                    exc.failure_class is not FailureClass.NETWORK_FAILURE
                    or attempt == self._max_attempts
                ):
                    raise
            else:
                if status != 429 and not 500 <= status < 600:
                    return status, payload
                if attempt == self._max_attempts:
                    raise EngineFailure(
                        f"{operation} returned transient HTTP {status} after {attempt} attempts",
                        FailureClass.NETWORK_FAILURE,
                    )
            self._sleeper(RETRY_BASE_SECONDS * (2 ** (attempt - 1)))
        raise AssertionError("retry loop exhausted without returning or raising")

    @staticmethod
    def _validated_api_url(url: str, host: str) -> str:
        candidate = urllib.parse.urljoin(host + "/", url)
        actual = urllib.parse.urlsplit(candidate)
        expected = urllib.parse.urlsplit(host)
        try:
            actual_port = actual.port
            expected_port = expected.port
        except ValueError as exc:
            raise EnginePolicyBlocked(
                "ebay API supplied a pagination URL with an invalid port"
            ) from exc
        if (
            actual.scheme != "https"
            or actual.hostname != expected.hostname
            or actual_port != expected_port
            or actual.username
            or actual.password
            or not actual.path.startswith("/buy/browse/v1/")
        ):
            raise EnginePolicyBlocked(
                "ebay API supplied a pagination URL outside the configured Browse API origin"
            )
        return candidate

    def _api_get(self, url: str, token: str, host: str) -> dict[str, Any]:
        url = self._validated_api_url(url, host)
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
        status, payload = self._send_with_retry(req, "ebay Browse API")
        if status in {401, 403}:
            raise EngineCannotRead(
                f"ebay Browse API returned HTTP {status}", FailureClass.AUTH_REQUIRED
            )
        if status == 404:
            raise EngineCannotRead("HTTP 404: item not found")
        if status != 200:
            raise EngineFailure(f"ebay Browse API returned HTTP {status}")
        try:
            value = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise EngineFailure("ebay Browse API returned invalid JSON") from exc
        if not isinstance(value, dict):
            raise EngineFailure("ebay Browse API returned a non-object JSON payload")
        return value

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
        invalid_listings = 0
        pages = 0
        total: int | None = None
        while url and pages < max_pages:
            page = self._api_get(url, token, host)
            reported_total = page.get("total")
            if type(reported_total) is int and reported_total >= 0:
                total = reported_total
            summaries = page.get("itemSummaries") or []
            if not isinstance(summaries, list):
                raise EngineFailure("ebay Browse API returned non-list itemSummaries")
            for item in summaries:
                if not isinstance(item, dict):
                    invalid_listings += 1
                    continue
                try:
                    listings.append(normalize_summary(item, observed_at))
                except ValueError:
                    invalid_listings += 1
            next_url = page.get("next")
            if next_url is not None and not isinstance(next_url, str):
                raise EngineFailure("ebay Browse API returned a non-string pagination URL")
            url = next_url
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
                "constraints": request.constraints,
                "listings": listings,
                "pagination": {
                    "pages_fetched": pages,
                    "total_reported": total,
                    "truncated": bool(url),
                },
            },
            auth_scope=f"app:{request.profile_id}",
            diagnostics={
                "page_limit": PAGE_LIMIT,
                "max_pages": max_pages,
                "invalid_listings": invalid_listings,
                "unapplied_constraints": sorted(request.constraints),
            },
        )

    def read(self, request: WebRequest) -> ReaderResult:
        """Resolve an eBay item page URL to its Browse API detail record."""
        request.validate()
        if request.mode is not RequestMode.READ:
            raise EngineFailure("EbayConnector.read requires mode=read")
        if not request.url:
            raise EngineFailure("EbayConnector.read requires a URL")
        legacy_id = ebay_legacy_item_id(request.url)
        if not legacy_id:
            raise EngineCannotRead(f"not an ebay item URL: {request.url}")

        token, host = self._access_token(request.profile_id)
        detail = self._api_get(
            f"{host}/buy/browse/v1/item/get_item_by_legacy_id?legacy_item_id={legacy_id}",
            token,
            host,
        )
        observed_at = datetime.now(timezone.utc).isoformat()
        try:
            listing = normalize_summary(detail, observed_at)
        except ValueError as exc:
            raise EngineCannotRead(f"ebay item detail was malformed: {exc}") from exc
        return ReaderResult(
            engine=self.id,
            requested_url=request.url,
            final_url=_canonical_url(detail.get("itemWebUrl") or request.url),
            title=detail.get("title"),
            http_status=200,
            engine_version="browse-v1",
            auth_scope=f"app:{request.profile_id}",
            content={"listing": listing},
        )
