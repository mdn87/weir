from __future__ import annotations

import ipaddress
import socket
import urllib.parse
from collections.abc import Iterable

from weir.engines.base import EngineFailure, EnginePolicyBlocked, FailureClass
from weir.models import DOMAIN_NAME_PATTERN, DataClass


def normalize_allowed_domains(domains: Iterable[str]) -> tuple[str, ...]:
    normalized = tuple(domains)
    if not normalized:
        raise EnginePolicyBlocked("browser sessions require an explicit domain allowlist")
    if any(
        not isinstance(domain, str)
        or not domain
        or len(domain) > 253
        or domain != domain.strip().lower().rstrip(".")
        or not DOMAIN_NAME_PATTERN.fullmatch(domain)
        for domain in normalized
    ):
        raise EnginePolicyBlocked(
            "browser allowed_domains must be normalized lowercase domain names"
        )
    if len(set(normalized)) != len(normalized):
        raise EnginePolicyBlocked("browser allowed_domains cannot contain duplicates")
    return normalized


def host_is_allowed(host: str, allowed_domains: Iterable[str]) -> bool:
    host = host.lower().rstrip(".")
    return any(host == domain or host.endswith("." + domain) for domain in allowed_domains)


def check_browser_target_policy(
    url: str,
    allowed_domains: Iterable[str],
    data_class: DataClass,
    *,
    resolve: bool = True,
) -> str:
    """Validate a top-level browser target and return its normalized host.

    Public sessions retain the acquisition broker's public-address requirement.
    Non-public sessions may reach an internal address only when its hostname or IP
    literal is present in the explicit session allowlist.
    """

    domains = normalize_allowed_domains(allowed_domains)
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"}:
        raise EnginePolicyBlocked(f"scheme {parsed.scheme!r} is not allowed")
    if parsed.username is not None or parsed.password is not None:
        raise EnginePolicyBlocked("credentials in URLs are not allowed")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        raise EnginePolicyBlocked("URL has no host")
    if not host_is_allowed(host, domains):
        raise EnginePolicyBlocked(f"host {host!r} is outside allowed_domains")

    if not resolve:
        return host
    resolve_browser_host(host, data_class)
    return host


def resolve_browser_host(host: str, data_class: DataClass) -> str:
    """Resolve, validate, and deterministically select one address for pinning."""

    try:
        infos = socket.getaddrinfo(host, None)
    except OSError as exc:
        raise EngineFailure(
            f"cannot resolve {host!r}: {exc}", FailureClass.NETWORK_FAILURE
        ) from exc
    if not infos:
        raise EngineFailure(
            f"cannot resolve {host!r}: no addresses returned",
            FailureClass.NETWORK_FAILURE,
        )
    addresses = {
        ipaddress.ip_address(str(info[4][0]).split("%", 1)[0]) for info in infos
    }
    if data_class is DataClass.PUBLIC:
        for address in addresses:
            if not address.is_global:
                raise EnginePolicyBlocked(
                    f"public browser host {host!r} resolves to non-public address {address}"
                )
    selected = min(addresses, key=lambda address: (address.version, int(address)))
    return selected.compressed


def check_browser_resource_policy(
    url: str,
    allowed_domains: Iterable[str],
    data_class: DataClass,
    *,
    resolve: bool = True,
) -> None:
    """Apply navigation policy to network resources and renderer-local URLs."""

    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme in {"about", "blob", "data"}:
        return
    check_browser_target_policy(url, allowed_domains, data_class, resolve=resolve)


__all__ = [
    "check_browser_resource_policy",
    "check_browser_target_policy",
    "host_is_allowed",
    "normalize_allowed_domains",
    "resolve_browser_host",
]
