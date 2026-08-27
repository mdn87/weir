from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any
from urllib.parse import urlsplit

from weir.models import DOMAIN_NAME_PATTERN, DataClass

BROWSER_CONTRACT_VERSION = "0.2"
_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}")
_ROLE_PATTERN = re.compile(r"[a-z][a-z0-9_-]{0,63}")
_STATE_PATTERN = re.compile(r"[a-z][a-z0-9_-]{0,63}")
_HASH_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")


class SessionState(StrEnum):
    OPENING = "opening"
    ACTIVE = "active"
    PAUSED = "paused"
    LOST = "lost"
    CLOSED = "closed"


class ControllerKind(StrEnum):
    AUTOMATION = "automation"
    OPERATOR = "operator"


class NameMatch(StrEnum):
    EXACT = "exact"
    CASEFOLD = "casefold"


def _require_dict(value: Any, *, name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"{name} must be an object")
    return value


def _check_fields(
    value: dict[str, Any],
    *,
    name: str,
    required: set[str],
    allowed: set[str],
) -> None:
    missing = sorted(required - value.keys())
    unknown = sorted(value.keys() - allowed)
    if missing:
        raise ValueError(f"{name} is missing required fields: {', '.join(missing)}")
    if unknown:
        raise ValueError(f"{name} has unknown fields: {', '.join(unknown)}")


def _validate_contract_version(value: str) -> None:
    if value != BROWSER_CONTRACT_VERSION:
        raise ValueError(
            f"browser contract_version must be {BROWSER_CONTRACT_VERSION!r}, got {value!r}"
        )


def _validate_id(value: Any, *, name: str) -> None:
    if not isinstance(value, str) or not _ID_PATTERN.fullmatch(value):
        raise ValueError(f"{name} must be a non-empty opaque identifier")


def _validate_optional_text(value: Any, *, name: str) -> None:
    if value is not None and (not isinstance(value, str) or not value.strip()):
        raise ValueError(f"{name} must be null or a non-empty string")


def _validate_datetime(value: Any, *, name: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be an RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{name} must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{name} must include a UTC offset")
    return parsed


def _validate_url(value: Any, *, name: str, optional: bool = False) -> None:
    if optional and value is None:
        return
    if not isinstance(value, str):
        raise ValueError(f"{name} must be an http(s) URL")
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError(f"{name} must be an http(s) URL without credentials")


def _validate_counter(value: Any, *, name: str, minimum: int = 0) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{name} must be an integer greater than or equal to {minimum}")


def _is_json_value(value: Any) -> bool:
    if value is None or isinstance(value, (str, bool, int)):
        return True
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, list):
        return all(_is_json_value(item) for item in value)
    if isinstance(value, dict):
        return all(
            isinstance(key, str) and _is_json_value(item) for key, item in value.items()
        )
    return False


def _content_hash(value: Any) -> str:
    if not _is_json_value(value):
        raise ValueError("content hashing requires a JSON-compatible value")
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ControllerLeaseView:
    session_id: str
    lease_id: str
    controller_id: str
    kind: ControllerKind
    generation: int
    expires_at: str
    contract_version: str = BROWSER_CONTRACT_VERSION

    def validate(self) -> None:
        _validate_contract_version(self.contract_version)
        _validate_id(self.session_id, name="session_id")
        _validate_id(self.lease_id, name="lease_id")
        _validate_id(self.controller_id, name="controller_id")
        if not isinstance(self.kind, ControllerKind):
            raise ValueError("kind must be a ControllerKind")
        _validate_counter(self.generation, name="generation", minimum=1)
        _validate_datetime(self.expires_at, name="expires_at")

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> ControllerLeaseView:
        fields = _require_dict(value, name="ControllerLeaseView")
        allowed = {
            "contract_version",
            "session_id",
            "lease_id",
            "controller_id",
            "kind",
            "generation",
            "expires_at",
        }
        _check_fields(fields, name="ControllerLeaseView", required=allowed, allowed=allowed)
        try:
            kind = ControllerKind(fields["kind"])
        except (TypeError, ValueError) as exc:
            raise ValueError("kind must be 'automation' or 'operator'") from exc
        view = cls(
            session_id=fields["session_id"],
            lease_id=fields["lease_id"],
            controller_id=fields["controller_id"],
            kind=kind,
            generation=fields["generation"],
            expires_at=fields["expires_at"],
            contract_version=fields["contract_version"],
        )
        view.validate()
        return view

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        value = asdict(self)
        value["kind"] = self.kind.value
        return value


@dataclass(frozen=True, slots=True)
class ControllerLease:
    """A controller lease whose fencing token is runtime-only secret state."""

    session_id: str
    lease_id: str
    controller_id: str
    kind: ControllerKind
    fencing_token: str = field(repr=False, compare=False)
    generation: int
    expires_at: str
    contract_version: str = BROWSER_CONTRACT_VERSION

    def validate(self) -> None:
        self.public_view().validate()
        if not isinstance(self.fencing_token, str) or not self.fencing_token:
            raise ValueError("fencing_token must be a non-empty runtime secret")

    @classmethod
    def from_dict(
        cls, value: dict[str, Any], *, fencing_token: str
    ) -> ControllerLease:
        """Rehydrate a public lease only when its separately stored token is supplied."""
        view = ControllerLeaseView.from_dict(value)
        lease = cls(
            session_id=view.session_id,
            lease_id=view.lease_id,
            controller_id=view.controller_id,
            kind=view.kind,
            fencing_token=fencing_token,
            generation=view.generation,
            expires_at=view.expires_at,
            contract_version=view.contract_version,
        )
        lease.validate()
        return lease

    def public_view(self) -> ControllerLeaseView:
        return ControllerLeaseView(
            session_id=self.session_id,
            lease_id=self.lease_id,
            controller_id=self.controller_id,
            kind=self.kind,
            generation=self.generation,
            expires_at=self.expires_at,
            contract_version=self.contract_version,
        )

    def to_public_dict(self) -> dict[str, Any]:
        self.validate()
        return self.public_view().to_dict()

    def to_dict(self) -> dict[str, Any]:
        """Return the safe public representation; the fencing token is never serialized."""
        return self.to_public_dict()


@dataclass(slots=True)
class BrowserSession:
    session_id: str
    owner_run_id: str
    engine: str
    worker_id: str
    worker_session_id: str
    profile_id: str
    data_class: DataClass
    allowed_domains: list[str]
    state: SessionState
    revision: int
    epoch: int
    current_url: str | None
    created_at: str
    updated_at: str
    expires_at: str
    controller_lease: ControllerLeaseView | None = None
    contract_version: str = BROWSER_CONTRACT_VERSION

    def validate(self) -> None:
        _validate_contract_version(self.contract_version)
        for name in (
            "session_id",
            "owner_run_id",
            "engine",
            "worker_id",
            "worker_session_id",
            "profile_id",
        ):
            _validate_id(getattr(self, name), name=name)
        if not isinstance(self.data_class, DataClass):
            raise ValueError("data_class must be a DataClass")
        if not isinstance(self.state, SessionState):
            raise ValueError("state must be a SessionState")
        if (
            not isinstance(self.allowed_domains, list)
            or not self.allowed_domains
            or any(
                not isinstance(domain, str)
                or domain != domain.strip().lower()
                or not DOMAIN_NAME_PATTERN.fullmatch(domain)
                for domain in self.allowed_domains
            )
            or len(set(self.allowed_domains)) != len(self.allowed_domains)
        ):
            raise ValueError(
                "allowed_domains must contain one or more unique normalized domain names"
            )
        _validate_counter(self.revision, name="revision")
        _validate_counter(self.epoch, name="epoch", minimum=1)
        _validate_url(self.current_url, name="current_url", optional=True)
        created_at = _validate_datetime(self.created_at, name="created_at")
        updated_at = _validate_datetime(self.updated_at, name="updated_at")
        expires_at = _validate_datetime(self.expires_at, name="expires_at")
        if updated_at < created_at or expires_at <= created_at:
            raise ValueError(
                "session timestamps require updated_at >= created_at and expires_at > created_at"
            )
        if self.controller_lease is not None:
            if not isinstance(self.controller_lease, ControllerLeaseView):
                raise ValueError("controller_lease must be a redacted ControllerLeaseView")
            self.controller_lease.validate()
            if self.controller_lease.session_id != self.session_id:
                raise ValueError("controller_lease session_id must match the browser session")
            lease_expiry = _validate_datetime(
                self.controller_lease.expires_at, name="controller_lease.expires_at"
            )
            if lease_expiry > expires_at:
                raise ValueError("controller lease cannot outlive the browser session")

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> BrowserSession:
        fields = _require_dict(value, name="BrowserSession")
        allowed = {
            "contract_version",
            "session_id",
            "owner_run_id",
            "engine",
            "worker_id",
            "worker_session_id",
            "profile_id",
            "data_class",
            "allowed_domains",
            "state",
            "revision",
            "epoch",
            "current_url",
            "created_at",
            "updated_at",
            "expires_at",
            "controller_lease",
        }
        _check_fields(fields, name="BrowserSession", required=allowed, allowed=allowed)
        try:
            data_class = DataClass(fields["data_class"])
            state = SessionState(fields["state"])
        except (TypeError, ValueError) as exc:
            raise ValueError("BrowserSession contains an invalid enum value") from exc
        domains = fields["allowed_domains"]
        if not isinstance(domains, list):
            raise ValueError("allowed_domains must be an array")
        raw_lease = fields["controller_lease"]
        lease = None if raw_lease is None else ControllerLeaseView.from_dict(raw_lease)
        session = cls(
            session_id=fields["session_id"],
            owner_run_id=fields["owner_run_id"],
            engine=fields["engine"],
            worker_id=fields["worker_id"],
            worker_session_id=fields["worker_session_id"],
            profile_id=fields["profile_id"],
            data_class=data_class,
            allowed_domains=list(domains),
            state=state,
            revision=fields["revision"],
            epoch=fields["epoch"],
            current_url=fields["current_url"],
            created_at=fields["created_at"],
            updated_at=fields["updated_at"],
            expires_at=fields["expires_at"],
            controller_lease=lease,
            contract_version=fields["contract_version"],
        )
        session.validate()
        return session

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "session_id": self.session_id,
            "owner_run_id": self.owner_run_id,
            "engine": self.engine,
            "worker_id": self.worker_id,
            "worker_session_id": self.worker_session_id,
            "profile_id": self.profile_id,
            "data_class": self.data_class.value,
            "allowed_domains": list(self.allowed_domains),
            "state": self.state.value,
            "revision": self.revision,
            "epoch": self.epoch,
            "current_url": self.current_url,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "expires_at": self.expires_at,
            "controller_lease": (
                None if self.controller_lease is None else self.controller_lease.to_dict()
            ),
            "contract_version": self.contract_version,
        }


@dataclass(frozen=True, slots=True)
class ObservedElement:
    ref: str
    role: str
    name: str | None = None
    test_id: str | None = None
    state: str | None = None

    def validate(self) -> None:
        _validate_id(self.ref, name="ref")
        if not isinstance(self.role, str) or not _ROLE_PATTERN.fullmatch(self.role):
            raise ValueError("role must be a normalized accessibility role")
        _validate_optional_text(self.name, name="name")
        _validate_optional_text(self.test_id, name="test_id")
        if self.state is not None and (
            not isinstance(self.state, str) or not _STATE_PATTERN.fullmatch(self.state)
        ):
            raise ValueError("state must be null or a normalized state name")

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> ObservedElement:
        fields = _require_dict(value, name="ObservedElement")
        allowed = {"ref", "role", "name", "test_id", "state"}
        _check_fields(
            fields,
            name="ObservedElement",
            required={"ref", "role", "name", "test_id", "state"},
            allowed=allowed,
        )
        element = cls(**fields)
        element.validate()
        return element

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return asdict(self)


@dataclass(frozen=True, slots=True)
class SemanticLocator:
    role: str | None = None
    name: str | None = None
    name_match: NameMatch = NameMatch.EXACT
    test_id: str | None = None
    required_state: str | None = None
    ordinal: int | None = None
    contract_version: str = BROWSER_CONTRACT_VERSION

    def validate(self) -> None:
        _validate_contract_version(self.contract_version)
        if self.role is not None and (
            not isinstance(self.role, str) or not _ROLE_PATTERN.fullmatch(self.role)
        ):
            raise ValueError("role must be null or a normalized accessibility role")
        _validate_optional_text(self.name, name="name")
        if not isinstance(self.name_match, NameMatch):
            raise ValueError("name_match must be a NameMatch")
        _validate_optional_text(self.test_id, name="test_id")
        if self.required_state is not None and (
            not isinstance(self.required_state, str)
            or not _STATE_PATTERN.fullmatch(self.required_state)
        ):
            raise ValueError("required_state must be null or a normalized state name")
        if self.ordinal is not None:
            _validate_counter(self.ordinal, name="ordinal")
        if self.role is None and self.name is None and self.test_id is None:
            raise ValueError("SemanticLocator requires role, name, or test_id")
        if self.name is None and self.name_match is not NameMatch.EXACT:
            raise ValueError("name_match can only be changed when name is present")

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> SemanticLocator:
        fields = _require_dict(value, name="SemanticLocator")
        allowed = {
            "contract_version",
            "role",
            "name",
            "name_match",
            "test_id",
            "required_state",
            "ordinal",
        }
        _check_fields(fields, name="SemanticLocator", required=allowed, allowed=allowed)
        try:
            name_match = NameMatch(fields["name_match"])
        except (TypeError, ValueError) as exc:
            raise ValueError("name_match must be 'exact' or 'casefold'") from exc
        locator = cls(
            role=fields["role"],
            name=fields["name"],
            name_match=name_match,
            test_id=fields["test_id"],
            required_state=fields["required_state"],
            ordinal=fields["ordinal"],
            contract_version=fields["contract_version"],
        )
        locator.validate()
        return locator

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        value = asdict(self)
        value["name_match"] = self.name_match.value
        return value

    @property
    def locator_hash(self) -> str:
        return _content_hash(self.to_dict())


@dataclass(slots=True)
class Observation:
    observation_id: str
    session_id: str
    session_revision: int
    session_epoch: int
    capture_id: str
    captured_at: str
    url: str
    title: str | None
    elements: list[ObservedElement]
    accessibility_snapshot: Any
    artifact_refs: list[str]
    observation_hash: str
    contract_version: str = BROWSER_CONTRACT_VERSION

    @classmethod
    def create(
        cls,
        *,
        observation_id: str,
        session_id: str,
        session_revision: int,
        session_epoch: int,
        capture_id: str,
        captured_at: str,
        url: str,
        title: str | None,
        elements: list[ObservedElement],
        accessibility_snapshot: Any,
        artifact_refs: list[str] | None = None,
    ) -> Observation:
        observation = cls(
            observation_id=observation_id,
            session_id=session_id,
            session_revision=session_revision,
            session_epoch=session_epoch,
            capture_id=capture_id,
            captured_at=captured_at,
            url=url,
            title=title,
            elements=list(elements),
            accessibility_snapshot=accessibility_snapshot,
            artifact_refs=list(artifact_refs or []),
            observation_hash="",
        )
        observation.observation_hash = observation.compute_hash()
        observation.validate()
        return observation

    def _hash_basis(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "session_revision": self.session_revision,
            "session_epoch": self.session_epoch,
            "capture_id": self.capture_id,
            "url": self.url,
            "title": self.title,
            "elements": [element.to_dict() for element in self.elements],
            "accessibility_snapshot": self.accessibility_snapshot,
            "artifact_refs": list(self.artifact_refs),
        }

    def compute_hash(self) -> str:
        return _content_hash(self._hash_basis())

    def validate(self) -> None:
        _validate_contract_version(self.contract_version)
        _validate_id(self.observation_id, name="observation_id")
        _validate_id(self.session_id, name="session_id")
        _validate_counter(self.session_revision, name="session_revision")
        _validate_counter(self.session_epoch, name="session_epoch", minimum=1)
        _validate_id(self.capture_id, name="capture_id")
        _validate_datetime(self.captured_at, name="captured_at")
        _validate_url(self.url, name="url")
        _validate_optional_text(self.title, name="title")
        if not isinstance(self.elements, list) or any(
            not isinstance(element, ObservedElement) for element in self.elements
        ):
            raise ValueError("elements must be an array of ObservedElement values")
        for element in self.elements:
            element.validate()
        refs = [element.ref for element in self.elements]
        if len(refs) != len(set(refs)):
            raise ValueError("element refs must be unique within an observation")
        if not _is_json_value(self.accessibility_snapshot):
            raise ValueError("accessibility_snapshot must be JSON-compatible")
        if (
            not isinstance(self.artifact_refs, list)
            or any(not isinstance(ref, str) or not ref for ref in self.artifact_refs)
            or len(self.artifact_refs) != len(set(self.artifact_refs))
        ):
            raise ValueError("artifact_refs must contain unique non-empty strings")
        if not isinstance(self.observation_hash, str) or not _HASH_PATTERN.fullmatch(
            self.observation_hash
        ):
            raise ValueError("observation_hash must be a sha256 digest")
        if self.compute_hash() != self.observation_hash:
            raise ValueError("observation_hash does not match observation content")

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> Observation:
        fields = _require_dict(value, name="Observation")
        allowed = {
            "contract_version",
            "observation_id",
            "session_id",
            "session_revision",
            "session_epoch",
            "capture_id",
            "captured_at",
            "url",
            "title",
            "elements",
            "accessibility_snapshot",
            "artifact_refs",
            "observation_hash",
        }
        _check_fields(fields, name="Observation", required=allowed, allowed=allowed)
        raw_elements = fields["elements"]
        raw_artifacts = fields["artifact_refs"]
        if not isinstance(raw_elements, list):
            raise ValueError("elements must be an array")
        if not isinstance(raw_artifacts, list):
            raise ValueError("artifact_refs must be an array")
        observation = cls(
            observation_id=fields["observation_id"],
            session_id=fields["session_id"],
            session_revision=fields["session_revision"],
            session_epoch=fields["session_epoch"],
            capture_id=fields["capture_id"],
            captured_at=fields["captured_at"],
            url=fields["url"],
            title=fields["title"],
            elements=[ObservedElement.from_dict(element) for element in raw_elements],
            accessibility_snapshot=fields["accessibility_snapshot"],
            artifact_refs=list(raw_artifacts),
            observation_hash=fields["observation_hash"],
            contract_version=fields["contract_version"],
        )
        observation.validate()
        return observation

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "observation_id": self.observation_id,
            "session_id": self.session_id,
            "session_revision": self.session_revision,
            "session_epoch": self.session_epoch,
            "capture_id": self.capture_id,
            "captured_at": self.captured_at,
            "url": self.url,
            "title": self.title,
            "elements": [element.to_dict() for element in self.elements],
            "accessibility_snapshot": self.accessibility_snapshot,
            "artifact_refs": list(self.artifact_refs),
            "observation_hash": self.observation_hash,
            "contract_version": self.contract_version,
        }


@dataclass(frozen=True, slots=True)
class ResolvedTarget:
    observation_id: str
    session_id: str
    session_revision: int
    session_epoch: int
    element_ref: str
    role: str
    name: str | None
    test_id: str | None
    state: str | None
    locator_hash: str
    contract_version: str = BROWSER_CONTRACT_VERSION

    def validate(self) -> None:
        _validate_contract_version(self.contract_version)
        _validate_id(self.observation_id, name="observation_id")
        _validate_id(self.session_id, name="session_id")
        _validate_counter(self.session_revision, name="session_revision")
        _validate_counter(self.session_epoch, name="session_epoch", minimum=1)
        ObservedElement(
            ref=self.element_ref,
            role=self.role,
            name=self.name,
            test_id=self.test_id,
            state=self.state,
        ).validate()
        if not isinstance(self.locator_hash, str) or not _HASH_PATTERN.fullmatch(
            self.locator_hash
        ):
            raise ValueError("locator_hash must be a sha256 digest")

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> ResolvedTarget:
        fields = _require_dict(value, name="ResolvedTarget")
        allowed = {
            "contract_version",
            "observation_id",
            "session_id",
            "session_revision",
            "session_epoch",
            "element_ref",
            "role",
            "name",
            "test_id",
            "state",
            "locator_hash",
        }
        _check_fields(fields, name="ResolvedTarget", required=allowed, allowed=allowed)
        target = cls(**fields)
        target.validate()
        return target

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return asdict(self)
