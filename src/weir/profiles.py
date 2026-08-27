from __future__ import annotations

import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from weir.actions import Risk
from weir.engines.base import EnginePolicyBlocked
from weir.models import (
    CONTRACT_VERSION,
    DOMAIN_NAME_PATTERN,
    SOURCE_NAME_PATTERN,
    RequestMode,
    WebRequest,
)

PROFILE_FIELDS = {
    "contract_version",
    "id",
    "domains",
    "sources",
    "preferred_engines",
    "auth_mode",
    "allowed_modes",
    "approval_risks",
    "known_failures",
    "retention",
    "browser_observation",
    "notes",
}
RETENTION_POLICIES: dict[str, frozenset[str]] = {
    "public_content": frozenset({"content_hash_and_capture", "metadata_only", "prohibited"}),
    "screenshots": frozenset({"full_evidence", "prohibited"}),
    "har": frozenset({"full_evidence", "metadata_only", "prohibited"}),
}


@dataclass(frozen=True, slots=True)
class SiteProfile:
    """Validated routing and policy hints for one evidence-backed site class."""

    id: str
    domains: tuple[str, ...]
    sources: tuple[str, ...]
    preferred_engines: tuple[str, ...]
    auth_mode: str
    allowed_modes: frozenset[RequestMode]
    approval_risks: frozenset[Risk]
    known_failures: dict[str, str]
    retention: dict[str, Any]
    browser_observation: dict[str, str]
    notes: tuple[str, ...]
    contract_version: str = CONTRACT_VERSION

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> SiteProfile:
        unexpected = sorted(set(value) - PROFILE_FIELDS)
        if unexpected:
            raise ValueError(f"site profile has unexpected fields: {unexpected}")
        if value.get("contract_version") != CONTRACT_VERSION:
            raise ValueError(
                f"unsupported site-profile contract_version {value.get('contract_version')!r}"
            )
        profile_id = value.get("id")
        domains = value.get("domains")
        sources = value.get("sources", [])
        preferred = value.get("preferred_engines")
        allowed = value.get("allowed_modes")
        auth_mode = value.get("auth_mode")
        approval_risks = value.get("approval_risks", [])
        known_failures = value.get("known_failures", {})
        retention = value.get("retention", {})
        browser_observation = value.get("browser_observation", {})
        notes = value.get("notes", [])
        if not isinstance(profile_id, str) or not profile_id:
            raise ValueError("site profile requires a non-empty id")
        if (
            not isinstance(domains, list)
            or not domains
            or not all(isinstance(item, str) for item in domains)
        ):
            raise ValueError(f"site profile {profile_id!r} requires domains")
        normalized_domains = tuple(domain.strip().lower().rstrip(".") for domain in domains)
        if any(
            not domain or domain != original
            for domain, original in zip(normalized_domains, domains, strict=True)
        ):
            raise ValueError(
                f"site profile {profile_id!r} domains must be normalized lowercase names"
            )
        if len(set(normalized_domains)) != len(normalized_domains) or any(
            len(domain) > 253 or not DOMAIN_NAME_PATTERN.fullmatch(domain)
            for domain in normalized_domains
        ):
            raise ValueError(f"site profile {profile_id!r} has invalid or duplicate domains")
        if not isinstance(sources, list) or not all(
            isinstance(item, str) and item for item in sources
        ):
            raise ValueError(f"site profile {profile_id!r} sources must be a list of names")
        normalized_sources = tuple(source.strip().lower() for source in sources)
        if any(
            source != original for source, original in zip(normalized_sources, sources, strict=True)
        ):
            raise ValueError(
                f"site profile {profile_id!r} sources must be normalized lowercase names"
            )
        if len(set(normalized_sources)) != len(normalized_sources) or any(
            not SOURCE_NAME_PATTERN.fullmatch(source) for source in normalized_sources
        ):
            raise ValueError(f"site profile {profile_id!r} has invalid or duplicate sources")
        if (
            not isinstance(preferred, list)
            or not preferred
            or not all(isinstance(item, str) and item for item in preferred)
            or len(set(preferred)) != len(preferred)
        ):
            raise ValueError(f"site profile {profile_id!r} requires preferred_engines")
        if (
            not isinstance(allowed, list)
            or not allowed
            or not all(isinstance(item, str) for item in allowed)
        ):
            raise ValueError(f"site profile {profile_id!r} requires allowed_modes")
        if len(set(allowed)) != len(allowed):
            raise ValueError(f"site profile {profile_id!r} has duplicate allowed modes")
        try:
            allowed_modes = frozenset(RequestMode(item) for item in allowed)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"site profile {profile_id!r} has an invalid allowed mode") from exc
        if auth_mode not in {"none", "optional", "dedicated_profile"}:
            raise ValueError(f"site profile {profile_id!r} has invalid auth_mode {auth_mode!r}")
        if not isinstance(approval_risks, list) or len(set(approval_risks)) != len(
            approval_risks
        ):
            raise ValueError(f"site profile {profile_id!r} has invalid approval_risks")
        try:
            parsed_risks = frozenset(Risk(item) for item in approval_risks)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"site profile {profile_id!r} has an invalid approval risk"
            ) from exc
        if not isinstance(known_failures, dict) or any(
            not isinstance(key, str)
            or not key
            or not isinstance(remedy, str)
            or not remedy
            for key, remedy in known_failures.items()
        ):
            raise ValueError(
                f"site profile {profile_id!r} known_failures must map names to remedies"
            )
        if not isinstance(retention, dict):
            raise ValueError(f"site profile {profile_id!r} retention must be an object")
        unknown_retention = sorted(set(retention) - set(RETENTION_POLICIES))
        if unknown_retention:
            raise ValueError(
                f"site profile {profile_id!r} has unknown retention policies: "
                f"{unknown_retention}"
            )
        for artifact, policy in retention.items():
            if not isinstance(policy, str) or policy not in RETENTION_POLICIES[artifact]:
                raise ValueError(
                    f"site profile {profile_id!r} has invalid {artifact!r} "
                    f"retention policy {policy!r}"
                )
        expected_observation_policy = {
            "javascript": "disabled",
            "network_methods": "get_head_only",
            "credential_scope": "read_only",
        }
        if not isinstance(browser_observation, dict) or (
            browser_observation and browser_observation != expected_observation_policy
        ):
            raise ValueError(
                f"site profile {profile_id!r} browser_observation must be empty or "
                f"exactly {expected_observation_policy!r}"
            )
        if not isinstance(notes, list) or any(
            not isinstance(note, str) or not note for note in notes
        ):
            raise ValueError(f"site profile {profile_id!r} notes must be non-empty strings")
        return cls(
            id=profile_id,
            domains=normalized_domains,
            sources=normalized_sources,
            preferred_engines=tuple(preferred),
            auth_mode=auth_mode,
            allowed_modes=allowed_modes,
            approval_risks=parsed_risks,
            known_failures=dict(known_failures),
            retention=dict(retention),
            browser_observation=dict(browser_observation),
            notes=tuple(notes),
        )

    def matches_host(self, host: str) -> bool:
        return self.match_specificity(host) >= 0

    def match_specificity(self, host: str) -> int:
        host = host.lower().rstrip(".")
        return max(
            (
                len(domain)
                for domain in self.domains
                if host == domain or host.endswith("." + domain)
            ),
            default=-1,
        )

    def order_candidates(self, candidates: list[str]) -> list[str]:
        rank = {engine: index for index, engine in enumerate(self.preferred_engines)}
        indexed = list(enumerate(candidates))
        indexed.sort(key=lambda item: (rank.get(item[1], len(rank)), item[0]))
        return [engine for _, engine in indexed]


class SiteProfileRegistry:
    def __init__(self, profiles: list[SiteProfile] | None = None) -> None:
        profiles = profiles or []
        self._profiles: dict[str, SiteProfile] = {}
        self._sources: dict[str, SiteProfile] = {}
        self._domains: dict[str, SiteProfile] = {}
        for profile in profiles:
            if profile.id in self._profiles:
                raise ValueError(f"duplicate site profile id {profile.id!r}")
            self._profiles[profile.id] = profile
            for domain in profile.domains:
                if domain in self._domains:
                    owner = self._domains[domain]
                    raise ValueError(
                        f"site profile domain {domain!r} is owned by both "
                        f"{owner.id!r} and {profile.id!r}"
                    )
                self._domains[domain] = profile
            for source in profile.sources:
                if source in self._sources:
                    raise ValueError(f"duplicate site profile source {source!r}")
                self._sources[source] = profile

    @classmethod
    def from_directory(cls, directory: Path) -> SiteProfileRegistry:
        profiles: list[SiteProfile] = []
        paths = sorted((*directory.glob("*.yaml"), *directory.glob("*.yml")))
        for path in paths:
            try:
                value = yaml.safe_load(path.read_text(encoding="utf-8"))
            except (OSError, yaml.YAMLError) as exc:
                raise ValueError(f"cannot load site profile {path}: {exc}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"site profile {path} must contain a YAML object")
            profiles.append(SiteProfile.from_dict(value))
        return cls(profiles)

    @classmethod
    def from_resource_directory(cls, directory: Any) -> SiteProfileRegistry:
        """Load profiles from an importlib.resources Traversable directory."""

        profiles: list[SiteProfile] = []
        if not directory.is_dir():
            raise ValueError("packaged WEIR profile directory is missing")
        paths = sorted(
            (
                path
                for path in directory.iterdir()
                if path.is_file() and Path(path.name).suffix.lower() in {".yaml", ".yml"}
            ),
            key=lambda path: path.name,
        )
        for path in paths:
            try:
                value = yaml.safe_load(path.read_text(encoding="utf-8"))
            except (OSError, yaml.YAMLError) as exc:
                raise ValueError(f"cannot load packaged site profile {path.name}: {exc}") from exc
            if not isinstance(value, dict):
                raise ValueError(
                    f"packaged site profile {path.name} must contain a YAML object"
                )
            profiles.append(SiteProfile.from_dict(value))
        return cls(profiles)

    def resolve(self, request: WebRequest) -> SiteProfile | None:
        if request.source and request.source in self._sources:
            return self._sources[request.source]
        if not request.url:
            return None
        host = urllib.parse.urlsplit(request.url).hostname or ""
        matches = [
            (profile.match_specificity(host), profile)
            for profile in self._profiles.values()
            if profile.matches_host(host)
        ]
        if not matches:
            return None
        return max(matches, key=lambda match: match[0])[1]

    def apply(
        self, request: WebRequest, candidates: list[str]
    ) -> tuple[list[str], SiteProfile | None]:
        profile = self.resolve(request)
        if profile is None:
            return candidates, None
        if request.mode not in profile.allowed_modes:
            raise EnginePolicyBlocked(
                f"site profile {profile.id!r} does not allow mode={request.mode.value}"
            )
        if profile.auth_mode == "none" and request.auth_context != "none":
            raise EnginePolicyBlocked(
                f"site profile {profile.id!r} does not allow authenticated access"
            )
        if profile.auth_mode == "dedicated_profile" and (
            request.auth_context == "none" or request.profile_id is None
        ):
            raise EnginePolicyBlocked(f"site profile {profile.id!r} requires a dedicated profile")
        return profile.order_candidates(candidates), profile

    def all(self) -> list[SiteProfile]:
        return list(self._profiles.values())

    def get(self, profile_id: str) -> SiteProfile | None:
        return self._profiles.get(profile_id)
