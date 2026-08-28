from __future__ import annotations

import ipaddress
import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Protocol
from urllib.parse import quote, urlsplit

from weir.broker import AcquisitionBroker, AcquisitionResult
from weir.browser.store import CommandStatus, SQLiteSessionStore
from weir.contract import canonical_json_bytes, validate_contract_size
from weir.evidence import AcquisitionEnvelope, EvidenceReference
from weir.models import WebCapture
from weir.persistence import EVIDENCE_REF_PREFIX, CaptureStore

SERVICE_CONTRACT_VERSION = "0.1"
MAX_SERVICE_REQUEST_BYTES = 256 * 1024
MAX_SERVICE_RESPONSE_BYTES = 6 * 1024 * 1024
MAX_ERROR_RESPONSE_BYTES = 64 * 1024
_CLIENT_ID = re.compile(r"[a-z][a-z0-9_.-]{0,63}")
_CREDENTIAL = re.compile(r"[A-Za-z0-9._~-]{32,256}")


@dataclass(frozen=True, slots=True)
class AcquisitionResponse:
    """Transport-stable subset of a context-bound broker result."""

    acquisition: AcquisitionEnvelope
    capture: WebCapture
    evidence_reference: EvidenceReference
    evidence_reference_ref: str
    cache_status: str | None
    source_capture_id: str | None
    contract_version: str = SERVICE_CONTRACT_VERSION

    @classmethod
    def from_result(cls, result: AcquisitionResult) -> AcquisitionResponse:
        response = cls(
            acquisition=result.acquisition,
            capture=result.capture,
            evidence_reference=result.evidence_reference,
            evidence_reference_ref=result.evidence_reference_ref,
            cache_status=None if result.cache is None else result.cache.status,
            source_capture_id=(
                None if result.cache is None else result.cache.source_capture_id
            ),
        )
        response.validate()
        return response

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> AcquisitionResponse:
        required = {
            "contract_version",
            "acquisition",
            "capture",
            "evidence_reference",
            "evidence_reference_ref",
            "cache_status",
            "source_capture_id",
        }
        if not isinstance(value, dict) or set(value) != required:
            raise ValueError("acquisition response has missing or unknown fields")
        response = cls(
            contract_version=value["contract_version"],
            acquisition=AcquisitionEnvelope.from_dict(value["acquisition"]),
            capture=WebCapture.from_dict(value["capture"]),
            evidence_reference=EvidenceReference.from_dict(value["evidence_reference"]),
            evidence_reference_ref=value["evidence_reference_ref"],
            cache_status=value["cache_status"],
            source_capture_id=value["source_capture_id"],
        )
        response.validate()
        return response

    def validate(self) -> None:
        if self.contract_version != SERVICE_CONTRACT_VERSION:
            raise ValueError("unsupported acquisition-response contract version")
        self.acquisition.validate()
        WebCapture.from_dict(self.capture.to_dict())
        self.evidence_reference.validate()
        reference = self.evidence_reference
        if reference.work_context_hash != self.acquisition.work_context.context_hash:
            raise ValueError("evidence reference belongs to another work context")
        if reference.request_id != self.acquisition.request.request_id:
            raise ValueError("evidence reference belongs to another acquisition request")
        if (
            reference.capture_id != self.capture.capture_id
            or reference.capture_contract_version != self.capture.contract_version
            or reference.content_hash != self.capture.content_hash
            or reference.trust is not self.capture.trust
        ):
            raise ValueError("evidence reference does not match the returned capture")
        if (
            reference.capture_policy != self.acquisition.request.capture_policy
            or reference.data_class is not self.acquisition.request.data_class
            or reference.artifact_ref != self.capture.raw_artifact_ref
        ):
            raise ValueError("evidence reference does not match acquisition policy")
        expected_ref = EVIDENCE_REF_PREFIX + reference.evidence_ref_id
        if self.evidence_reference_ref != expected_ref:
            raise ValueError("evidence reference handle does not match its identifier")
        if self.cache_status not in {None, "disabled", "bypass", "miss", "hit"}:
            raise ValueError("acquisition response cache status is invalid")
        if self.source_capture_id is not None and (
            not isinstance(self.source_capture_id, str)
            or not self.source_capture_id
            or self.source_capture_id != self.capture.capture_id
        ):
            raise ValueError("source_capture_id must identify the returned capture")
        if (self.cache_status == "hit") != (self.source_capture_id is not None):
            raise ValueError("only a cache hit may name a source capture")
        validate_contract_size(
            self._to_dict(), MAX_SERVICE_RESPONSE_BYTES, "AcquisitionResponse"
        )

    def _to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "acquisition": self.acquisition.to_dict(),
            "capture": self.capture.to_dict(),
            "evidence_reference": self.evidence_reference.to_dict(),
            "evidence_reference_ref": self.evidence_reference_ref,
            "cache_status": self.cache_status,
            "source_capture_id": self.source_capture_id,
        }

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return self._to_dict()


@dataclass(frozen=True, slots=True)
class MaterializedEvidence:
    reference: EvidenceReference
    payload: bytes

    @classmethod
    def create(
        cls, reference: EvidenceReference, payload: bytes
    ) -> MaterializedEvidence:
        if len(payload) > MAX_SERVICE_RESPONSE_BYTES:
            raise ValueError("materialized evidence exceeds the service response limit")
        reference.verify_materialized_artifact(payload)
        return cls(reference=reference, payload=payload)

    @property
    def content(self) -> Any:
        return self.reference.verify_materialized_artifact(self.payload)


class WeirClient(Protocol):
    def read(self, acquisition: AcquisitionEnvelope) -> AcquisitionResponse: ...

    def search(self, acquisition: AcquisitionEnvelope) -> AcquisitionResponse: ...

    def enrich(self, acquisition: AcquisitionEnvelope) -> AcquisitionResponse: ...

    def get_evidence(self, reference_id: str) -> EvidenceReference: ...

    def materialize_evidence(self, reference_id: str) -> MaterializedEvidence: ...

    def get_command_status(self, command_id: str) -> CommandStatus | None: ...


class InProcessWeirClient:
    """Trusted local client used by tests and the standalone CLI transition."""

    def __init__(
        self,
        broker: AcquisitionBroker,
        store: CaptureStore,
        *,
        command_store: SQLiteSessionStore | None = None,
    ) -> None:
        if broker.store is not store:
            raise ValueError("in-process client and broker must share one CaptureStore")
        self.broker = broker
        self.store = store
        self.command_store = command_store

    def read(self, acquisition: AcquisitionEnvelope) -> AcquisitionResponse:
        return AcquisitionResponse.from_result(self.broker.read(acquisition))

    def search(self, acquisition: AcquisitionEnvelope) -> AcquisitionResponse:
        return AcquisitionResponse.from_result(self.broker.search(acquisition))

    def enrich(self, acquisition: AcquisitionEnvelope) -> AcquisitionResponse:
        return AcquisitionResponse.from_result(self.broker.enrich(acquisition))

    def get_evidence(self, reference_id: str) -> EvidenceReference:
        return self.store.load_evidence_reference(reference_id)

    def materialize_evidence(self, reference_id: str) -> MaterializedEvidence:
        reference = self.get_evidence(reference_id)
        payload = self.store.materialize_evidence_bytes(reference)
        return MaterializedEvidence.create(reference, payload)

    def get_command_status(self, command_id: str) -> CommandStatus | None:
        if self.command_store is None:
            raise WeirClientError(
                501, "command_status_unavailable", "command status is not configured"
            )
        return self.command_store.command_status(command_id)


class WeirClientError(RuntimeError):
    def __init__(self, status: int, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.reason_code = reason_code


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_: Any, **__: Any) -> None:
        return None


class HttpWeirClient:
    """Authenticated loopback client with bounded requests, responses, and deadlines."""

    def __init__(
        self,
        base_url: str,
        client_id: str,
        credential: str,
        *,
        timeout_seconds: float = 10.0,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        parsed = urlsplit(base_url)
        try:
            parsed.port
        except ValueError as exc:
            raise ValueError("WEIR service URL has an invalid port") from exc
        if (
            parsed.scheme != "http"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ValueError("WEIR service URL must be an HTTP loopback origin")
        try:
            is_loopback = ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError as exc:
            raise ValueError("WEIR service host must be a loopback IP literal") from exc
        if not is_loopback:
            raise ValueError("WEIR service host must be loopback")
        if not isinstance(client_id, str) or not _CLIENT_ID.fullmatch(client_id):
            raise ValueError("client_id must be a normalized service identity")
        if not isinstance(credential, str) or not _CREDENTIAL.fullmatch(credential):
            raise ValueError(
                "WEIR client credential must contain 32-256 safe opaque characters"
            )
        if not 0 < timeout_seconds <= 30:
            raise ValueError("WEIR client timeout must be between 0 and 30 seconds")
        self.base_url = base_url.rstrip("/")
        self.client_id = client_id
        self._credential = credential
        self.timeout_seconds = timeout_seconds
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirectHandler()
        )

    def read(self, acquisition: AcquisitionEnvelope) -> AcquisitionResponse:
        return self._acquire("/v1/acquisition/read", acquisition)

    def search(self, acquisition: AcquisitionEnvelope) -> AcquisitionResponse:
        return self._acquire("/v1/acquisition/search", acquisition)

    def enrich(self, acquisition: AcquisitionEnvelope) -> AcquisitionResponse:
        return self._acquire("/v1/acquisition/enrich", acquisition)

    def _acquire(
        self, path: str, acquisition: AcquisitionEnvelope
    ) -> AcquisitionResponse:
        acquisition.validate()
        payload, headers = self._request(
            "POST", path, canonical_json_bytes(acquisition.to_dict())
        )
        value = self._json_payload(payload, headers)
        try:
            return AcquisitionResponse.from_dict(value)
        except (TypeError, ValueError) as exc:
            raise WeirClientError(
                502,
                "invalid_service_response",
                "WEIR returned an invalid acquisition response",
            ) from exc

    def get_evidence(self, reference_id: str) -> EvidenceReference:
        payload, headers = self._request(
            "GET", f"/v1/evidence/{quote(reference_id, safe='')}", None
        )
        try:
            return EvidenceReference.from_dict(self._json_payload(payload, headers))
        except (TypeError, ValueError) as exc:
            raise WeirClientError(
                502,
                "invalid_service_response",
                "WEIR returned an invalid evidence reference",
            ) from exc

    def materialize_evidence(self, reference_id: str) -> MaterializedEvidence:
        reference = self.get_evidence(reference_id)
        payload, headers = self._request(
            "GET", f"/v1/evidence/{quote(reference_id, safe='')}/content", None
        )
        if (
            headers.get_content_type() != "application/json"
            or headers.get("X-Weir-Content-Hash") != reference.content_hash
            or headers.get("X-Weir-Reference-Hash") != reference.reference_hash
        ):
            raise WeirClientError(
                502,
                "service_binding_mismatch",
                "WEIR materialization headers do not match the evidence reference",
            )
        try:
            return MaterializedEvidence.create(reference, payload)
        except (TypeError, ValueError) as exc:
            raise WeirClientError(
                502,
                "service_binding_mismatch",
                "WEIR materialization does not match the evidence reference",
            ) from exc

    def get_command_status(self, command_id: str) -> CommandStatus | None:
        try:
            payload, headers = self._request(
                "GET", f"/v1/commands/{quote(command_id, safe='')}", None
            )
        except WeirClientError as exc:
            if exc.status == 404 and exc.reason_code == "command_not_found":
                return None
            raise
        try:
            return CommandStatus.from_dict(self._json_payload(payload, headers))
        except (TypeError, ValueError) as exc:
            raise WeirClientError(
                502,
                "invalid_service_response",
                "WEIR returned an invalid command status",
            ) from exc

    @staticmethod
    def _json_payload(payload: bytes, headers: Any) -> dict[str, Any]:
        if headers.get_content_type() != "application/json":
            raise WeirClientError(
                502,
                "invalid_service_response",
                "WEIR response does not contain JSON",
            )
        try:
            value = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WeirClientError(
                502, "invalid_service_response", "WEIR returned invalid JSON"
            ) from exc
        if not isinstance(value, dict):
            raise WeirClientError(
                502, "invalid_service_response", "WEIR response must be a JSON object"
            )
        return value

    def _request(
        self, method: str, path: str, body: bytes | None
    ) -> tuple[bytes, Any]:
        if body is not None and len(body) > MAX_SERVICE_REQUEST_BYTES:
            raise WeirClientError(
                413, "request_too_large", "WEIR request exceeds the client limit"
            )
        now = self.clock().astimezone(timezone.utc)
        deadline = now + timedelta(seconds=self.timeout_seconds)
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self._credential}",
            "X-Weir-Client-Id": self.client_id,
            "X-Weir-Deadline": deadline.isoformat(),
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.base_url + path,
            data=body,
            headers=headers,
            method=method,
        )
        try:
            with self._opener.open(request, timeout=self.timeout_seconds) as response:
                payload = response.read(MAX_SERVICE_RESPONSE_BYTES + 1)
                if len(payload) > MAX_SERVICE_RESPONSE_BYTES:
                    raise WeirClientError(
                        502,
                        "response_too_large",
                        "WEIR response exceeds the client limit",
                    )
                if response.status != 200:
                    raise WeirClientError(
                        502,
                        "invalid_service_response",
                        "WEIR returned an unexpected success status",
                    )
                return payload, response.headers
        except urllib.error.HTTPError as exc:
            payload = exc.read(MAX_ERROR_RESPONSE_BYTES + 1)
            if len(payload) > MAX_ERROR_RESPONSE_BYTES:
                raise WeirClientError(
                    exc.code, "invalid_error_response", "WEIR error response is too large"
                ) from None
            try:
                value = json.loads(payload)
                error = value["error"]
                reason_code = str(error["reason_code"])
                message = str(error["message"])
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                reason_code = "invalid_error_response"
                message = "WEIR returned an invalid error response"
            raise WeirClientError(exc.code, reason_code, message) from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise WeirClientError(
                0, "service_unavailable", "WEIR service is unavailable"
            ) from exc


__all__ = [
    "MAX_ERROR_RESPONSE_BYTES",
    "MAX_SERVICE_REQUEST_BYTES",
    "MAX_SERVICE_RESPONSE_BYTES",
    "SERVICE_CONTRACT_VERSION",
    "AcquisitionResponse",
    "HttpWeirClient",
    "InProcessWeirClient",
    "MaterializedEvidence",
    "WeirClient",
    "WeirClientError",
]
