from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any

from weir.contract import (
    ContractViolation,
    canonical_digest,
    canonical_json_bytes,
    is_portable_json_value,
    is_sha256,
    parse_timestamp,
    validate_contract_size,
    validate_identifier,
)
from weir.models import CONTRACT_VERSION as WEB_CONTRACT_VERSION
from weir.models import DataClass, TrustLabel, WebCapture, WebRequest
from weir.persistence import ARTIFACT_REF_PREFIX
from weir.work_context import WorkContext

EVIDENCE_REFERENCE_VERSION = "0.1"
ACQUISITION_ENVELOPE_VERSION = "0.1"
MAX_EVIDENCE_REFERENCE_BYTES = 8 * 1024
MAX_ACQUISITION_ENVELOPE_BYTES = 128 * 1024
MAX_ACQUISITION_DEPTH = 32
CAPTURE_POLICIES = frozenset({"metadata", "content", "full_evidence"})
CANONICAL_CONTENT_MEDIA_TYPE = "application/json"


@dataclass(frozen=True, slots=True)
class EvidenceReference:
    """Context-specific binding to a reusable, context-free WebCapture."""

    evidence_ref_id: str
    work_context_hash: str
    request_id: str
    capture_id: str
    capture_contract_version: str
    content_hash: str
    artifact_ref: str | None
    media_type: str | None
    capture_policy: str
    data_class: DataClass
    trust: TrustLabel
    created_at: str
    reference_hash: str
    contract_version: str = EVIDENCE_REFERENCE_VERSION

    def _hash_basis(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "evidence_ref_id": self.evidence_ref_id,
            "work_context_hash": self.work_context_hash,
            "request_id": self.request_id,
            "capture_id": self.capture_id,
            "capture_contract_version": self.capture_contract_version,
            "content_hash": self.content_hash,
            "artifact_ref": self.artifact_ref,
            "media_type": self.media_type,
            "capture_policy": self.capture_policy,
            "data_class": self.data_class.value,
            "trust": self.trust.value,
            "created_at": self.created_at,
        }

    @classmethod
    def create(
        cls,
        *,
        evidence_ref_id: str,
        work_context: WorkContext,
        request: WebRequest,
        capture: WebCapture,
        created_at: str | None = None,
        artifact_ref: str | None = None,
    ) -> EvidenceReference:
        work_context.validate()
        request.validate()
        if request.run_id != work_context.run_id:
            raise ContractViolation(
                "acquisition_run_mismatch",
                "WebRequest.run_id must match WorkContext.run_id",
            )
        if request.request_id != work_context.correlation_id:
            raise ContractViolation(
                "acquisition_correlation_mismatch",
                "WebRequest.request_id must match WorkContext.correlation_id",
            )
        if capture.request_id != request.request_id:
            raise ContractViolation(
                "capture_request_mismatch",
                "WebCapture.request_id must match WebRequest.request_id",
            )
        retained_ref = capture.raw_artifact_ref if artifact_ref is None else artifact_ref
        if request.capture_policy == "metadata":
            retained_ref = None
        reference = cls(
            evidence_ref_id=evidence_ref_id,
            work_context_hash=work_context.context_hash,
            request_id=request.request_id,
            capture_id=capture.capture_id,
            capture_contract_version=capture.contract_version,
            content_hash=capture.content_hash,
            artifact_ref=retained_ref,
            media_type=(CANONICAL_CONTENT_MEDIA_TYPE if retained_ref else None),
            capture_policy=request.capture_policy,
            data_class=request.data_class,
            trust=capture.trust,
            created_at=created_at or datetime.now(timezone.utc).isoformat(),
            reference_hash="",
        )
        reference = replace(
            reference, reference_hash=canonical_digest(reference._hash_basis())
        )
        reference.validate()
        return reference

    def validate(self) -> None:
        if self.contract_version != EVIDENCE_REFERENCE_VERSION:
            raise ValueError("unsupported EvidenceReference contract version")
        for name in ("evidence_ref_id", "request_id", "capture_id"):
            validate_identifier(getattr(self, name), name)
        if self.capture_contract_version != WEB_CONTRACT_VERSION:
            raise ValueError("unsupported WebCapture contract version")
        for name in ("work_context_hash", "content_hash", "reference_hash"):
            if not is_sha256(getattr(self, name)):
                raise ValueError(f"{name} must be a sha256 digest")
        if self.capture_policy not in CAPTURE_POLICIES:
            raise ValueError("capture_policy is invalid")
        if not isinstance(self.data_class, DataClass) or not isinstance(
            self.trust, TrustLabel
        ):
            raise ValueError("EvidenceReference classification or trust is invalid")
        parse_timestamp(self.created_at, "created_at")
        if self.artifact_ref is None:
            if self.media_type is not None:
                raise ContractViolation(
                    "artifact_metadata_mismatch",
                    "media_type must be null when artifact_ref is null",
                )
        else:
            expected_ref = ARTIFACT_REF_PREFIX + self.content_hash.removeprefix(
                "sha256:"
            )
            if self.artifact_ref != expected_ref:
                raise ContractViolation(
                    "artifact_hash_mismatch",
                    "artifact_ref must address the exact content_hash bytes",
                )
            if self.media_type != CANONICAL_CONTENT_MEDIA_TYPE:
                raise ContractViolation(
                    "artifact_metadata_mismatch",
                    "retained capture content must be materialized as application/json",
                )
        if self.capture_policy == "metadata" and self.artifact_ref is not None:
            raise ContractViolation(
                "metadata_policy_has_content",
                "metadata-policy evidence cannot carry a content artifact",
            )
        if self.reference_hash != canonical_digest(self._hash_basis()):
            raise ContractViolation(
                "reference_hash_mismatch",
                "reference_hash does not match the EvidenceReference",
            )
        validate_contract_size(
            {**self._hash_basis(), "reference_hash": self.reference_hash},
            MAX_EVIDENCE_REFERENCE_BYTES,
            "EvidenceReference",
        )

    def require_materialized_content(self) -> None:
        self.validate()
        if self.capture_policy == "metadata" or self.artifact_ref is None:
            raise ContractViolation(
                "evidence_content_unavailable",
                "this EvidenceReference cannot satisfy a content evidence input",
            )

    def verify_materialized_artifact(self, payload: bytes) -> Any:
        self.require_materialized_content()
        if not isinstance(payload, bytes):
            raise TypeError("materialized evidence must be bytes")
        if "sha256:" + hashlib.sha256(payload).hexdigest() != self.content_hash:
            raise ContractViolation(
                "artifact_hash_mismatch",
                "materialized evidence does not match content_hash",
            )
        try:
            value = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ContractViolation(
                "artifact_not_canonical_json",
                "materialized capture content must be UTF-8 JSON",
            ) from exc
        if canonical_json_bytes(value) != payload:
            raise ContractViolation(
                "artifact_not_canonical_json",
                "materialized capture content is not exact WEIR canonical JSON",
            )
        return value

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> EvidenceReference:
        required = {
            "contract_version",
            "evidence_ref_id",
            "work_context_hash",
            "request_id",
            "capture_id",
            "capture_contract_version",
            "content_hash",
            "artifact_ref",
            "media_type",
            "capture_policy",
            "data_class",
            "trust",
            "created_at",
            "reference_hash",
        }
        if not isinstance(value, dict) or set(value) != required:
            raise ValueError("EvidenceReference has missing or unknown fields")
        try:
            reference = cls(
                contract_version=value["contract_version"],
                evidence_ref_id=value["evidence_ref_id"],
                work_context_hash=value["work_context_hash"],
                request_id=value["request_id"],
                capture_id=value["capture_id"],
                capture_contract_version=value["capture_contract_version"],
                content_hash=value["content_hash"],
                artifact_ref=value["artifact_ref"],
                media_type=value["media_type"],
                capture_policy=value["capture_policy"],
                data_class=DataClass(value["data_class"]),
                trust=TrustLabel(value["trust"]),
                created_at=value["created_at"],
                reference_hash=value["reference_hash"],
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("EvidenceReference enum field is invalid") from exc
        reference.validate()
        return reference

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {**self._hash_basis(), "reference_hash": self.reference_hash}


@dataclass(frozen=True, slots=True)
class AcquisitionEnvelope:
    work_context: WorkContext
    request: WebRequest
    envelope_hash: str
    contract_version: str = ACQUISITION_ENVELOPE_VERSION

    def _hash_basis(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "work_context": self.work_context.to_dict(),
            "request": self.request.to_dict(),
        }

    @classmethod
    def create(
        cls, *, work_context: WorkContext, request: WebRequest
    ) -> AcquisitionEnvelope:
        envelope = cls(work_context=work_context, request=request, envelope_hash="")
        envelope = replace(
            envelope, envelope_hash=canonical_digest(envelope._hash_basis())
        )
        envelope.validate()
        return envelope

    def validate(self) -> None:
        if self.contract_version != ACQUISITION_ENVELOPE_VERSION:
            raise ValueError("unsupported AcquisitionEnvelope contract version")
        if not isinstance(self.work_context, WorkContext) or not isinstance(
            self.request, WebRequest
        ):
            raise ValueError("AcquisitionEnvelope members have invalid types")
        self.work_context.validate()
        self.request.validate()
        if self.request.maximum_depth > MAX_ACQUISITION_DEPTH or not is_portable_json_value(
            self.request.constraints
        ):
            raise ContractViolation(
                "acquisition_request_not_portable",
                "AcquisitionEnvelope request constraints must use portable bounded JSON",
            )
        if self.request.run_id != self.work_context.run_id:
            raise ContractViolation(
                "acquisition_run_mismatch",
                "WebRequest.run_id must match WorkContext.run_id",
            )
        if self.request.request_id != self.work_context.correlation_id:
            raise ContractViolation(
                "acquisition_correlation_mismatch",
                "WebRequest.request_id must match WorkContext.correlation_id",
            )
        if self.envelope_hash != canonical_digest(self._hash_basis()):
            raise ContractViolation(
                "envelope_hash_mismatch",
                "envelope_hash does not match the AcquisitionEnvelope",
            )
        validate_contract_size(
            {**self._hash_basis(), "envelope_hash": self.envelope_hash},
            MAX_ACQUISITION_ENVELOPE_BYTES,
            "AcquisitionEnvelope",
        )

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> AcquisitionEnvelope:
        required = {"contract_version", "work_context", "request", "envelope_hash"}
        if not isinstance(value, dict) or set(value) != required:
            raise ValueError("AcquisitionEnvelope has missing or unknown fields")
        envelope = cls(
            contract_version=value["contract_version"],
            work_context=WorkContext.from_dict(value["work_context"]),
            request=WebRequest.from_dict(value["request"]),
            envelope_hash=value["envelope_hash"],
        )
        envelope.validate()
        return envelope

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {**self._hash_basis(), "envelope_hash": self.envelope_hash}


__all__ = [
    "ACQUISITION_ENVELOPE_VERSION",
    "CANONICAL_CONTENT_MEDIA_TYPE",
    "EVIDENCE_REFERENCE_VERSION",
    "MAX_ACQUISITION_ENVELOPE_BYTES",
    "MAX_ACQUISITION_DEPTH",
    "MAX_EVIDENCE_REFERENCE_BYTES",
    "AcquisitionEnvelope",
    "EvidenceReference",
]
