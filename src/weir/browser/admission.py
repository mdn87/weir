from __future__ import annotations

import os
import sys
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Callable, Protocol

from weir.contract import (
    canonical_digest,
    is_sha256,
    parse_timestamp,
    validate_identifier,
)
from weir.engines.base import EnginePolicyBlocked

PRODUCTION_ADMISSION_SCHEMA_VERSION = 1
ADMISSION_CLOCK_SKEW_SECONDS = 5
MAX_PRODUCTION_ATTESTATION_LIFETIME = timedelta(minutes=5)
MIN_WORKER_MEMORY_BYTES = 64 * 1024 * 1024
MAX_WORKER_MEMORY_BYTES = 64 * 1024 * 1024 * 1024
MAX_WORKER_PROCESS_COUNT = 128
_SUPPORTED_PLATFORMS = frozenset({"windows", "linux"})


def current_platform() -> str:
    if os.name == "nt":
        return "windows"
    if sys.platform.startswith("linux"):
        return "linux"
    return "unsupported"


@dataclass(frozen=True, slots=True)
class WorkerResourceLimits:
    memory_bytes: int
    process_count: int

    def validate(self) -> None:
        if (
            type(self.memory_bytes) is not int
            or not MIN_WORKER_MEMORY_BYTES
            <= self.memory_bytes
            <= MAX_WORKER_MEMORY_BYTES
        ):
            raise ValueError("worker memory limit is outside the supported range")
        if (
            type(self.process_count) is not int
            or not 1 <= self.process_count <= MAX_WORKER_PROCESS_COUNT
        ):
            raise ValueError("worker process limit is outside the supported range")

    def to_dict(self) -> dict[str, int]:
        self.validate()
        return {
            "memory_bytes": self.memory_bytes,
            "process_count": self.process_count,
        }

    @classmethod
    def from_dict(cls, value: object) -> WorkerResourceLimits:
        if not isinstance(value, dict) or set(value) != {
            "memory_bytes",
            "process_count",
        }:
            raise ValueError("worker resource limits have missing or unknown fields")
        limits = cls(
            memory_bytes=value["memory_bytes"],
            process_count=value["process_count"],
        )
        limits.validate()
        return limits


@dataclass(frozen=True, slots=True)
class WorkerContainmentEvidence:
    platform: str
    process_id: int
    process_tree_enforced: bool
    kill_on_supervisor_exit: bool
    resource_limits: WorkerResourceLimits | None
    resource_limits_enforced: bool

    def validate(self) -> None:
        if self.platform not in _SUPPORTED_PLATFORMS:
            raise ValueError("worker containment platform is unsupported")
        if type(self.process_id) is not int or self.process_id < 1:
            raise ValueError("worker containment process ID is invalid")
        if type(self.process_tree_enforced) is not bool:
            raise ValueError("worker process-tree evidence is invalid")
        if type(self.kill_on_supervisor_exit) is not bool:
            raise ValueError("worker parent-death evidence is invalid")
        if self.resource_limits is not None:
            self.resource_limits.validate()
        if type(self.resource_limits_enforced) is not bool:
            raise ValueError("worker resource-limit evidence is invalid")
        if self.resource_limits_enforced != (self.resource_limits is not None):
            raise ValueError("worker resource-limit evidence is inconsistent")

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "platform": self.platform,
            "process_id": self.process_id,
            "process_tree_enforced": self.process_tree_enforced,
            "kill_on_supervisor_exit": self.kill_on_supervisor_exit,
            "resource_limits": (
                None
                if self.resource_limits is None
                else self.resource_limits.to_dict()
            ),
            "resource_limits_enforced": self.resource_limits_enforced,
        }

    @classmethod
    def from_dict(cls, value: object) -> WorkerContainmentEvidence:
        required = {
            "platform",
            "process_id",
            "process_tree_enforced",
            "kill_on_supervisor_exit",
            "resource_limits",
            "resource_limits_enforced",
        }
        if not isinstance(value, dict) or set(value) != required:
            raise ValueError("worker containment evidence has missing or unknown fields")
        limits = value["resource_limits"]
        evidence = cls(
            platform=value["platform"],
            process_id=value["process_id"],
            process_tree_enforced=value["process_tree_enforced"],
            kill_on_supervisor_exit=value["kill_on_supervisor_exit"],
            resource_limits=(
                None if limits is None else WorkerResourceLimits.from_dict(limits)
            ),
            resource_limits_enforced=value["resource_limits_enforced"],
        )
        evidence.validate()
        return evidence


@dataclass(frozen=True, slots=True)
class CredentialProtectionEvidence:
    caller_id: str
    source_id: str
    acl_policy_digest: str
    protected: bool

    def validate(self) -> None:
        validate_identifier(self.caller_id, "caller_id", max_length=64)
        validate_identifier(self.source_id, "credential_source_id")
        if not is_sha256(self.acl_policy_digest):
            raise ValueError("credential ACL policy digest is invalid")
        if type(self.protected) is not bool:
            raise ValueError("credential protection marker is invalid")

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "caller_id": self.caller_id,
            "source_id": self.source_id,
            "acl_policy_digest": self.acl_policy_digest,
            "protected": self.protected,
        }

    @classmethod
    def from_dict(cls, value: object) -> CredentialProtectionEvidence:
        required = {"caller_id", "source_id", "acl_policy_digest", "protected"}
        if not isinstance(value, dict) or set(value) != required:
            raise ValueError(
                "credential protection evidence has missing or unknown fields"
            )
        evidence = cls(**value)
        evidence.validate()
        return evidence


@dataclass(frozen=True, slots=True)
class ProductionControlEvidence:
    attestation_id: str
    platform: str
    service_identity: str
    worker_identity: str
    worker_id: str
    worker_instance_id: str
    containment: WorkerContainmentEvidence
    restricted_identity: bool
    credential_protection: tuple[CredentialProtectionEvidence, ...]
    lifecycle_supervisor: str
    lifecycle_instance_id: str
    lifecycle_healthy: bool
    egress_policy_id: str
    egress_policy_digest: str
    egress_enforced: bool
    verified_at: str
    expires_at: str
    attestation_hash: str = ""
    schema_version: int = PRODUCTION_ADMISSION_SCHEMA_VERSION

    @classmethod
    def create(
        cls,
        *,
        attestation_id: str,
        platform: str,
        service_identity: str,
        worker_identity: str,
        worker_id: str,
        worker_instance_id: str,
        containment: WorkerContainmentEvidence,
        restricted_identity: bool,
        credential_protection: tuple[CredentialProtectionEvidence, ...],
        lifecycle_supervisor: str,
        lifecycle_instance_id: str,
        lifecycle_healthy: bool,
        egress_policy_id: str,
        egress_policy_digest: str,
        egress_enforced: bool,
        verified_at: str,
        expires_at: str,
    ) -> ProductionControlEvidence:
        evidence = cls(
            attestation_id=attestation_id,
            platform=platform,
            service_identity=service_identity,
            worker_identity=worker_identity,
            worker_id=worker_id,
            worker_instance_id=worker_instance_id,
            containment=containment,
            restricted_identity=restricted_identity,
            credential_protection=credential_protection,
            lifecycle_supervisor=lifecycle_supervisor,
            lifecycle_instance_id=lifecycle_instance_id,
            lifecycle_healthy=lifecycle_healthy,
            egress_policy_id=egress_policy_id,
            egress_policy_digest=egress_policy_digest,
            egress_enforced=egress_enforced,
            verified_at=verified_at,
            expires_at=expires_at,
        )
        evidence = replace(
            evidence, attestation_hash=canonical_digest(evidence._hash_basis())
        )
        evidence.validate()
        return evidence

    def validate(self) -> None:
        if self.schema_version != PRODUCTION_ADMISSION_SCHEMA_VERSION:
            raise ValueError("unsupported production-control evidence version")
        validate_identifier(self.attestation_id, "attestation_id")
        if self.platform not in _SUPPORTED_PLATFORMS:
            raise ValueError("production-control platform is unsupported")
        validate_identifier(self.service_identity, "service_identity")
        validate_identifier(self.worker_identity, "worker_identity")
        if self.worker_identity != self.service_identity:
            raise ValueError("worker identity does not match the restricted service")
        validate_identifier(self.worker_id, "worker_id")
        validate_identifier(self.worker_instance_id, "worker_instance_id")
        if not isinstance(self.containment, WorkerContainmentEvidence):
            raise ValueError("production-control containment evidence is invalid")
        self.containment.validate()
        if self.containment.platform != self.platform:
            raise ValueError("worker containment platform does not match the host")
        if type(self.restricted_identity) is not bool:
            raise ValueError("restricted service identity marker is invalid")
        if (
            not isinstance(self.credential_protection, tuple)
            or not self.credential_protection
        ):
            raise ValueError("per-caller credential evidence is required")
        for item in self.credential_protection:
            if not isinstance(item, CredentialProtectionEvidence):
                raise ValueError("per-caller credential evidence is invalid")
            item.validate()
        caller_ids = [item.caller_id for item in self.credential_protection]
        if len(set(caller_ids)) != len(caller_ids):
            raise ValueError("per-caller credential evidence must be unique")
        validate_identifier(self.lifecycle_supervisor, "lifecycle_supervisor")
        validate_identifier(self.lifecycle_instance_id, "lifecycle_instance_id")
        if type(self.lifecycle_healthy) is not bool:
            raise ValueError("lifecycle health evidence is invalid")
        validate_identifier(self.egress_policy_id, "egress_policy_id")
        if not is_sha256(self.egress_policy_digest):
            raise ValueError("egress policy digest is invalid")
        if type(self.egress_enforced) is not bool:
            raise ValueError("egress enforcement marker is invalid")
        verified = parse_timestamp(self.verified_at, "verified_at")
        expires = parse_timestamp(self.expires_at, "expires_at")
        if expires <= verified:
            raise ValueError("production-control evidence expiry is invalid")
        if expires - verified > MAX_PRODUCTION_ATTESTATION_LIFETIME:
            raise ValueError("production-control evidence lifetime is too long")
        if not is_sha256(self.attestation_hash):
            raise ValueError("production-control attestation hash is invalid")
        if self.attestation_hash != canonical_digest(self._hash_basis()):
            raise ValueError("production-control attestation hash does not match")

    def require_current(
        self,
        now: datetime,
        *,
        caller_id: str,
        expected_platform: str | None = None,
    ) -> None:
        self.validate()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise ValueError("production admission clock must be timezone-aware")
        authoritative_now = now.astimezone(timezone.utc)
        skew = timedelta(seconds=ADMISSION_CLOCK_SKEW_SECONDS)
        verified = parse_timestamp(self.verified_at, "verified_at")
        expires = parse_timestamp(self.expires_at, "expires_at")
        if authoritative_now + skew < verified or authoritative_now - skew > expires:
            raise EnginePolicyBlocked("production-control evidence is not current")
        platform = expected_platform or current_platform()
        if platform not in _SUPPORTED_PLATFORMS or self.platform != platform:
            raise EnginePolicyBlocked("production-control evidence is for another host")
        if (
            not self.restricted_identity
            or not self.containment.process_tree_enforced
            or not self.containment.kill_on_supervisor_exit
            or not self.containment.resource_limits_enforced
            or not self.lifecycle_healthy
            or not self.egress_enforced
        ):
            raise EnginePolicyBlocked("production host controls are incomplete")
        selected = [
            item for item in self.credential_protection if item.caller_id == caller_id
        ]
        if len(selected) != 1 or not selected[0].protected:
            raise EnginePolicyBlocked("caller credential protection is not attested")

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {
            **self._hash_basis(),
            "attestation_hash": self.attestation_hash,
        }

    def _hash_basis(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "attestation_id": self.attestation_id,
            "platform": self.platform,
            "service_identity": self.service_identity,
            "worker_identity": self.worker_identity,
            "worker_id": self.worker_id,
            "worker_instance_id": self.worker_instance_id,
            "containment": self.containment.to_dict(),
            "restricted_identity": self.restricted_identity,
            "credential_protection": [
                item.to_dict() for item in self.credential_protection
            ],
            "lifecycle_supervisor": self.lifecycle_supervisor,
            "lifecycle_instance_id": self.lifecycle_instance_id,
            "lifecycle_healthy": self.lifecycle_healthy,
            "egress_policy_id": self.egress_policy_id,
            "egress_policy_digest": self.egress_policy_digest,
            "egress_enforced": self.egress_enforced,
            "verified_at": self.verified_at,
            "expires_at": self.expires_at,
        }

    @classmethod
    def from_dict(cls, value: object) -> ProductionControlEvidence:
        required = {
            "schema_version",
            "attestation_id",
            "platform",
            "service_identity",
            "worker_identity",
            "worker_id",
            "worker_instance_id",
            "containment",
            "restricted_identity",
            "credential_protection",
            "lifecycle_supervisor",
            "lifecycle_instance_id",
            "lifecycle_healthy",
            "egress_policy_id",
            "egress_policy_digest",
            "egress_enforced",
            "verified_at",
            "expires_at",
            "attestation_hash",
        }
        if not isinstance(value, dict) or set(value) != required:
            raise ValueError(
                "production-control evidence has missing or unknown fields"
            )
        credential_value = value["credential_protection"]
        if not isinstance(credential_value, list):
            raise ValueError("per-caller credential evidence must be an array")
        evidence = cls(
            schema_version=value["schema_version"],
            attestation_id=value["attestation_id"],
            platform=value["platform"],
            service_identity=value["service_identity"],
            worker_identity=value["worker_identity"],
            worker_id=value["worker_id"],
            worker_instance_id=value["worker_instance_id"],
            containment=WorkerContainmentEvidence.from_dict(value["containment"]),
            restricted_identity=value["restricted_identity"],
            credential_protection=tuple(
                CredentialProtectionEvidence.from_dict(item)
                for item in credential_value
            ),
            lifecycle_supervisor=value["lifecycle_supervisor"],
            lifecycle_instance_id=value["lifecycle_instance_id"],
            lifecycle_healthy=value["lifecycle_healthy"],
            egress_policy_id=value["egress_policy_id"],
            egress_policy_digest=value["egress_policy_digest"],
            egress_enforced=value["egress_enforced"],
            verified_at=value["verified_at"],
            expires_at=value["expires_at"],
            attestation_hash=value["attestation_hash"],
        )
        evidence.validate()
        return evidence


class ProductionEvidenceProvider(Protocol):
    def __call__(self) -> ProductionControlEvidence: ...


class ProductionAdmission:
    """Live fail-closed gate for browser and authenticated action admission."""

    def __init__(
        self,
        provider: ProductionEvidenceProvider,
        *,
        clock: Callable[[], datetime] | None = None,
        expected_platform: str | None = None,
    ) -> None:
        if not callable(provider):
            raise TypeError("production evidence provider must be callable")
        platform = expected_platform or current_platform()
        if platform not in _SUPPORTED_PLATFORMS:
            raise ValueError("production admission is unsupported on this platform")
        self._provider = provider
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._expected_platform = platform

    def require_browser_worker(self, worker: object, *, caller_id: str) -> None:
        evidence = self._evidence(caller_id)
        containment = getattr(worker, "containment_evidence", None)
        descriptor = getattr(worker, "descriptor", None)
        if (
            not getattr(worker, "production_process_transport", False)
            or not isinstance(containment, WorkerContainmentEvidence)
            or descriptor is None
            or evidence.worker_id != getattr(descriptor, "worker_id", None)
            or evidence.worker_instance_id != getattr(descriptor, "instance_id", None)
            or evidence.containment.to_dict() != containment.to_dict()
        ):
            raise EnginePolicyBlocked(
                "production browser admission requires the attested process transport"
            )

    def require_external_action(
        self,
        *,
        caller_id: str,
        action_driver: object,
    ) -> None:
        evidence = self._evidence(caller_id)
        worker = getattr(action_driver, "worker", None)
        containment = getattr(worker, "containment_evidence", None)
        if (
            not getattr(worker, "production_process_transport", False)
            or not isinstance(containment, WorkerContainmentEvidence)
            or evidence.worker_id != getattr(worker, "worker_id", None)
            or evidence.worker_instance_id
            != getattr(worker, "worker_instance_id", None)
            or evidence.containment.to_dict() != containment.to_dict()
        ):
            raise EnginePolicyBlocked(
                "production action admission requires an attested process worker"
            )

    def _evidence(self, caller_id: str) -> ProductionControlEvidence:
        validate_identifier(caller_id, "caller_id", max_length=64)
        try:
            evidence = self._provider()
        except Exception as exc:
            raise EnginePolicyBlocked(
                "production-control evidence is unavailable"
            ) from exc
        if not isinstance(evidence, ProductionControlEvidence):
            raise EnginePolicyBlocked("production-control evidence is invalid")
        try:
            evidence.require_current(
                self._clock(),
                caller_id=caller_id,
                expected_platform=self._expected_platform,
            )
        except EnginePolicyBlocked:
            raise
        except Exception as exc:
            raise EnginePolicyBlocked(
                "production-control evidence is invalid"
            ) from exc
        return evidence


@dataclass(frozen=True, slots=True)
class LocalSyntheticActionAdmission:
    """Explicit source-canary gate; never valid for non-loopback production policy."""

    authorization_ref: str

    def __post_init__(self) -> None:
        validate_identifier(self.authorization_ref, "authorization_ref")

    def require_external_action(
        self,
        *,
        caller_id: str,
        action_driver: object,
    ) -> None:
        from weir.browser.effect_driver import SyntheticFixtureEffectPolicy

        validate_identifier(caller_id, "caller_id", max_length=64)
        if not isinstance(
            getattr(action_driver, "policy", None), SyntheticFixtureEffectPolicy
        ):
            raise EnginePolicyBlocked(
                "local canary admission accepts only the synthetic fixture policy"
            )


class ActionAdmission(Protocol):
    def require_external_action(
        self,
        *,
        caller_id: str,
        action_driver: object,
    ) -> None: ...


__all__ = [
    "ActionAdmission",
    "CredentialProtectionEvidence",
    "LocalSyntheticActionAdmission",
    "MAX_PRODUCTION_ATTESTATION_LIFETIME",
    "PRODUCTION_ADMISSION_SCHEMA_VERSION",
    "ProductionAdmission",
    "ProductionControlEvidence",
    "ProductionEvidenceProvider",
    "WorkerContainmentEvidence",
    "WorkerResourceLimits",
    "current_platform",
]
