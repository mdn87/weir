from __future__ import annotations

import ipaddress
import json
import socket
import urllib.error
import urllib.parse
import urllib.request

from weir.engines.base import (
    EngineCannotRead,
    EngineFailure,
    EnginePolicyBlocked,
    EngineProbe,
    FailureClass,
    ReaderEngine,
)
from weir.models import ReaderResult, RequestMode, WebRequest

MAX_RESPONSE_BYTES = 5 * 1024 * 1024
USER_AGENT = "weir-http-connector/0.1 (+https://github.com/mdn87/weir)"


def check_target_policy(url: str, allowed_domains: list[str]) -> None:
    """Reject non-http(s) schemes, credentials in URLs, private/internal
    addresses, and hosts outside the request's allowed domains.

    Applied to the initial URL and to every redirect hop, per the security
    note that redirects remain subject to policy.
    """
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"}:
        raise EnginePolicyBlocked(f"scheme {parsed.scheme!r} is not allowed")
    if parsed.username or parsed.password:
        raise EnginePolicyBlocked("credentials in URLs are not allowed")
    host = parsed.hostname
    if not host:
        raise EnginePolicyBlocked("URL has no host")

    if allowed_domains and not any(host == d or host.endswith("." + d) for d in allowed_domains):
        raise EnginePolicyBlocked(f"host {host!r} is outside allowed_domains")

    try:
        infos = socket.getaddrinfo(host, None)
    except OSError as exc:
        raise EngineFailure(
            f"cannot resolve {host!r}: {exc}", FailureClass.NETWORK_FAILURE
        ) from exc
    for info in infos:
        address = ipaddress.ip_address(info[4][0])
        if not address.is_global:
            raise EnginePolicyBlocked(f"host {host!r} resolves to non-public address {address}")


class _GuardedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_domains: list[str]) -> None:
        self.allowed_domains = allowed_domains
        self.hops: list[str] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        check_target_policy(newurl, self.allowed_domains)
        self.hops.append(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class HttpConnector(ReaderEngine):
    """Direct HTTP engine for API-shaped public resources.

    First benchmark evidence showed renderer engines truncate or bloat JSON
    APIs and feeds; this engine fetches them verbatim with stdlib urllib.
    It never executes JavaScript and never renders.
    """

    id = "http"

    def probe(self) -> EngineProbe:
        return EngineProbe(self.id, True, version="stdlib", detail="urllib.request")

    def read(self, request: WebRequest) -> ReaderResult:
        request.validate()
        if request.mode is not RequestMode.READ:
            raise EngineFailure("HttpConnector supports mode=read only")
        if not request.url:
            raise EngineFailure("HttpConnector requires a URL")

        check_target_policy(request.url, request.allowed_domains)
        redirect_handler = _GuardedRedirectHandler(request.allowed_domains)
        opener = urllib.request.build_opener(redirect_handler)
        req = urllib.request.Request(
            request.url,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/json, application/feed+json, */*",
            },
        )
        try:
            with opener.open(req, timeout=60) as response:
                body = response.read(MAX_RESPONSE_BYTES + 1)
                status = response.status
                final_url = response.url
                content_type = response.headers.get_content_type()
                charset = response.headers.get_content_charset() or "utf-8"
        except urllib.error.HTTPError as exc:
            if exc.code in {401, 403}:
                raise EngineCannotRead(f"HTTP {exc.code}", FailureClass.AUTH_REQUIRED) from exc
            if 400 <= exc.code < 500:
                raise EngineCannotRead(f"HTTP {exc.code}") from exc
            raise EngineFailure(f"HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise EngineFailure(str(exc.reason), FailureClass.NETWORK_FAILURE) from exc
        except TimeoutError as exc:
            raise EngineFailure("timeout", FailureClass.NETWORK_FAILURE) from exc

        if len(body) > MAX_RESPONSE_BYTES:
            raise EngineCannotRead(f"response exceeds {MAX_RESPONSE_BYTES} byte cap")

        text = body.decode(charset, errors="replace")
        content: dict[str, object] = {"content_type": content_type}
        if content_type.endswith("json"):
            try:
                content["json"] = json.loads(text)
            except json.JSONDecodeError:
                content["text"] = text
        else:
            content["text"] = text

        return ReaderResult(
            engine=self.id,
            requested_url=request.url,
            final_url=final_url,
            title=None,
            http_status=status,
            engine_version="stdlib",
            auth_scope="none",
            content=content,
            diagnostics={"redirect_hops": redirect_handler.hops, "bytes": len(body)},
        )
