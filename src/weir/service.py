from __future__ import annotations

import hmac
import ipaddress
import json
import re
import socket
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from typing import Any, Callable, Mapping
from urllib.parse import unquote, urlsplit

from weir.actions import ActionProposal, ExecutionPermit
from weir.broker import AcquisitionFailed
from weir.browser.effect_driver import (
    FADE_AUTHORITY_ID,
    ActionExecutionStatus,
    BrowserActionDriver,
)
from weir.browser.admission import ActionAdmission
from weir.browser.store import (
    DEAD_WORKER_RETIREMENT_DISPOSITION,
    SessionNotFound,
    SessionRevisionConflict,
    SQLiteSessionStore,
)
from weir.client import (
    MAX_EVIDENCE_ROUTE_IDENTIFIER,
    MAX_SERVICE_REQUEST_BYTES,
    MAX_SERVICE_RESPONSE_BYTES,
    AcquisitionResponse,
    MaterializedEvidence,
    WeirClient,
    WeirClientError,
)
from weir.contract import (
    ContractViolation,
    canonical_json_bytes,
    is_sha256,
    parse_timestamp,
)
from weir.engines.base import (
    ControllerConflict,
    EnginePolicyBlocked,
    IdempotencyConflict,
    WeirEngineError,
)
from weir.evidence import AcquisitionEnvelope
from weir.models import DataClass
from weir.persistence import CacheIntegrityError
from weir.proposals import ActionProposalStore, ProposalNotFound

ACQUISITION_READ_SCOPE = "acquisition:read"
EVIDENCE_READ_SCOPE = "evidence:read"
COMMAND_READ_SCOPE = "command:read"
PROPOSAL_WRITE_SCOPE = "proposal:write"
PROPOSAL_READ_FULL_SCOPE = "proposal:read:full"
PROPOSAL_READ_REDACTED_SCOPE = "proposal:read:redacted"
PROFILE_RETIRE_SCOPE = "profile:retire"
ACTION_EXECUTE_SCOPE = "action:execute"
ACTION_STATUS_SCOPE = "action:status"
SERVICE_SCOPES = frozenset(
    {
        ACQUISITION_READ_SCOPE,
        EVIDENCE_READ_SCOPE,
        COMMAND_READ_SCOPE,
        PROPOSAL_WRITE_SCOPE,
        PROPOSAL_READ_FULL_SCOPE,
        PROPOSAL_READ_REDACTED_SCOPE,
        PROFILE_RETIRE_SCOPE,
        ACTION_EXECUTE_SCOPE,
        ACTION_STATUS_SCOPE,
    }
)
MAX_SERVICE_DEADLINE = timedelta(seconds=30)
_CLIENT_ID = re.compile(r"[a-z][a-z0-9_.-]{0,63}")
_CREDENTIAL = re.compile(r"[A-Za-z0-9._~-]{32,256}")
_ROUTE_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]*")


@dataclass(frozen=True, slots=True)
class ClientCredential:
    client_id: str
    credential: str = field(repr=False)
    scopes: frozenset[str] = frozenset()
    data_classes: frozenset[DataClass] = frozenset({DataClass.PUBLIC})

    def validate(self) -> None:
        if not isinstance(self.client_id, str) or not _CLIENT_ID.fullmatch(
            self.client_id
        ):
            raise ValueError("client_id must be a normalized service identity")
        if not isinstance(self.credential, str) or not _CREDENTIAL.fullmatch(
            self.credential
        ):
            raise ValueError(
                "client credential must contain 32-256 safe opaque characters"
            )
        if (
            not isinstance(self.scopes, frozenset)
            or not self.scopes
            or not self.scopes <= SERVICE_SCOPES
        ):
            raise ValueError("client credential has an invalid or empty scope set")
        if (
            not isinstance(self.data_classes, frozenset)
            or not self.data_classes
            or any(not isinstance(item, DataClass) for item in self.data_classes)
        ):
            raise ValueError("client credential has an invalid data-class allowlist")


@dataclass(frozen=True, slots=True)
class ClientPrincipal:
    client_id: str
    scopes: frozenset[str]
    data_classes: frozenset[DataClass]

    def require_scope(self, scope: str) -> None:
        if scope not in self.scopes:
            raise ServiceRequestError(
                HTTPStatus.FORBIDDEN,
                "scope_denied",
                "client identity does not have the required WEIR scope",
            )

    def require_data_class(self, data_class: DataClass) -> None:
        if data_class not in self.data_classes:
            raise ServiceRequestError(
                HTTPStatus.FORBIDDEN,
                "data_class_denied",
                "client identity cannot access this evidence data class",
            )


class ClientRegistry:
    """In-memory named-client registry; credentials are never serialized or logged."""

    def __init__(self, credentials: list[ClientCredential]) -> None:
        if not credentials:
            raise ValueError("WEIR service requires at least one named client")
        for credential in credentials:
            credential.validate()
        if len({item.client_id for item in credentials}) != len(credentials):
            raise ValueError("WEIR client IDs must be unique")
        if len({item.credential for item in credentials}) != len(credentials):
            raise ValueError("WEIR clients may not share credentials")
        self._credentials = tuple(credentials)

    def authenticate(self, headers: Mapping[str, str]) -> ClientPrincipal:
        supplied_id = headers.get("X-Weir-Client-Id", "")
        authorization = headers.get("Authorization", "")
        if (
            not authorization.startswith("Bearer ")
            or len(authorization) > 300
            or len(supplied_id) > 64
        ):
            raise ServiceRequestError(
                HTTPStatus.UNAUTHORIZED, "unauthorized", "invalid WEIR client identity"
            )
        supplied_credential = authorization.removeprefix("Bearer ")
        if not _CLIENT_ID.fullmatch(supplied_id) or not _CREDENTIAL.fullmatch(
            supplied_credential
        ):
            raise ServiceRequestError(
                HTTPStatus.UNAUTHORIZED, "unauthorized", "invalid WEIR client identity"
            )
        selected: ClientCredential | None = None
        # Scan every entry and compare both fields so unknown IDs follow the same
        # basic path as known IDs with a wrong credential.
        for candidate in self._credentials:
            id_matches = hmac.compare_digest(candidate.client_id, supplied_id)
            credential_matches = hmac.compare_digest(
                candidate.credential, supplied_credential
            )
            if id_matches and credential_matches:
                selected = candidate
        if selected is None:
            raise ServiceRequestError(
                HTTPStatus.UNAUTHORIZED, "unauthorized", "invalid WEIR client identity"
            )
        return ClientPrincipal(
            selected.client_id, selected.scopes, selected.data_classes
        )


class ServiceRequestError(RuntimeError):
    def __init__(self, status: HTTPStatus, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class ServiceResponse:
    status: HTTPStatus
    body: bytes
    content_type: str = "application/json"
    headers: tuple[tuple[str, str], ...] = ()


class WeirServiceApplication:
    """Transport-independent authenticated service dispatcher."""

    def __init__(
        self,
        backend: WeirClient,
        clients: ClientRegistry,
        *,
        proposal_store: ActionProposalStore | None = None,
        session_store: SQLiteSessionStore | None = None,
        action_driver: BrowserActionDriver | None = None,
        action_admission: ActionAdmission | None = None,
        clock: Callable[[], datetime] | None = None,
        max_response_bytes: int = MAX_SERVICE_RESPONSE_BYTES,
    ) -> None:
        if not 512 <= max_response_bytes <= MAX_SERVICE_RESPONSE_BYTES:
            raise ValueError("service response limit must be between 512 bytes and 6 MiB")
        self.backend = backend
        self.clients = clients
        self.proposal_store = proposal_store
        self.session_store = session_store
        self.action_driver = action_driver
        self.action_admission = action_admission
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.max_response_bytes = max_response_bytes

    def handle(
        self,
        method: str,
        target: str,
        headers: Mapping[str, str],
        body: bytes | None,
    ) -> ServiceResponse:
        route, identifier = self._route(method, target)
        principal = self.clients.authenticate(headers)
        deadline = self._deadline(headers)

        if route in {"read", "search", "enrich"}:
            principal.require_scope(ACQUISITION_READ_SCOPE)
            acquisition = self._parse_acquisition(body)
            principal.require_data_class(acquisition.request.data_class)
            operation = getattr(self.backend, route)
            response = self._backend_call(operation, acquisition)
            if not isinstance(response, AcquisitionResponse):
                raise ServiceRequestError(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    "invalid_backend_response",
                    "WEIR backend returned an invalid acquisition response",
                )
            result = self._json(response.to_dict())
        elif route == "evidence":
            principal.require_scope(EVIDENCE_READ_SCOPE)
            reference = self._backend_call(self.backend.get_evidence, identifier)
            principal.require_data_class(reference.data_class)
            result = self._json(reference.to_dict())
        elif route == "evidence_content":
            principal.require_scope(EVIDENCE_READ_SCOPE)
            reference = self._backend_call(self.backend.get_evidence, identifier)
            principal.require_data_class(reference.data_class)
            materialized = self._backend_call(
                self.backend.materialize_evidence, identifier
            )
            if not isinstance(materialized, MaterializedEvidence):
                raise ServiceRequestError(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    "invalid_backend_response",
                    "WEIR backend returned invalid materialized evidence",
                )
            if materialized.reference.to_dict() != reference.to_dict():
                raise ServiceRequestError(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    "invalid_backend_response",
                    "WEIR backend changed the evidence binding during materialization",
                )
            result = ServiceResponse(
                HTTPStatus.OK,
                materialized.payload,
                headers=(
                    ("X-Weir-Content-Hash", materialized.reference.content_hash),
                    ("X-Weir-Reference-Hash", materialized.reference.reference_hash),
                ),
            )
        elif route == "command":
            principal.require_scope(COMMAND_READ_SCOPE)
            command = self._backend_call(self.backend.get_command_status, identifier)
            if command is None:
                raise ServiceRequestError(
                    HTTPStatus.NOT_FOUND,
                    "command_not_found",
                    "WEIR command was not found",
                )
            result = self._json(command.to_dict())
        elif route == "proposal_register":
            principal.require_scope(PROPOSAL_WRITE_SCOPE)
            proposal = self._parse_proposal(body)
            data_classes = self._backend_call(
                self._proposals().registration_data_classes, proposal
            )
            for data_class in data_classes:
                principal.require_data_class(data_class)
            registered = self._backend_call(
                self._proposals().register, proposal
            )
            result = self._json(registered.to_dict())
        elif route == "proposal":
            principal.require_scope(PROPOSAL_READ_FULL_SCOPE)
            data_classes = self._backend_call(
                self._proposals().required_data_classes, identifier
            )
            for data_class in data_classes:
                principal.require_data_class(data_class)
            record = self._backend_call(self._proposals().load_record, identifier)
            result = self._json(record.proposal.to_dict())
        elif route == "proposal_projection":
            principal.require_scope(PROPOSAL_READ_REDACTED_SCOPE)
            projection = self._backend_call(
                self._proposals().load_projection, identifier
            )
            result = self._json(projection.to_dict())
        elif route == "profile_retirement":
            principal.require_scope(PROFILE_RETIRE_SCOPE)
            request = self._parse_profile_retirement(body)
            session = self._backend_call(
                self._sessions().get_session, request["session_id"]
            )
            principal.require_data_class(session.data_class)
            closed = self._backend_call(
                self._sessions().retire_dead_worker_reservation,
                request["session_id"],
                retirement_id=request["retirement_id"],
                expected_session_epoch=request["expected_session_epoch"],
                expected_worker_id=request["expected_worker_id"],
                expected_worker_instance_id=request[
                    "expected_worker_instance_id"
                ],
                expected_credential_binding_id=request[
                    "expected_credential_binding_id"
                ],
                attestation_hash=request["attestation_hash"],
                disposition=request["disposition"],
                disposition_actor_id=principal.client_id,
                disposition_ref=request["disposition_ref"],
            )
            reservation = self._backend_call(
                self._sessions().profile_reservation,
                request["session_id"],
            )
            result = self._json(
                {
                    "retirement_id": request["retirement_id"],
                    "session_id": closed.session_id,
                    "session_state": closed.state.value,
                    "session_revision": closed.revision,
                    "reservation_state": reservation.state,
                }
            )
        elif route == "action_execute":
            self._require_fade_action_principal(principal, ACTION_EXECUTE_SCOPE)
            action_driver = self._actions()
            self._require_action_admission(principal, action_driver)
            request = self._parse_action_execution(body)
            for data_class in self._backend_call(
                self._proposals().required_data_classes,
                request["proposal"].proposal_hash,
            ):
                principal.require_data_class(data_class)
            status = self._backend_call(
                action_driver.execute,
                command_id=request["command_id"],
                request_digest=request["request_digest"],
                submitted_proposal=request["proposal"],
                permit=request["permit"],
            )
            if not isinstance(status, ActionExecutionStatus):
                raise ServiceRequestError(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    "invalid_action_status",
                    "WEIR action driver returned an invalid status",
                )
            result = self._json(status.to_dict())
        elif route == "action_status":
            self._require_fade_action_principal(principal, ACTION_STATUS_SCOPE)
            action_driver = self._actions()
            try:
                data_classes = action_driver.required_data_classes(identifier)
            except KeyError as exc:
                raise ServiceRequestError(
                    HTTPStatus.NOT_FOUND,
                    "action_command_not_found",
                    "WEIR action command was not found",
                ) from exc
            for data_class in data_classes:
                principal.require_data_class(data_class)
            status = self._backend_call(action_driver.status, identifier)
            if status is None:
                raise ServiceRequestError(
                    HTTPStatus.NOT_FOUND,
                    "action_command_not_found",
                    "WEIR action command was not found",
                )
            result = self._json(status.to_dict())
        else:  # pragma: no cover - _route is exhaustive
            raise AssertionError(route)

        if self.clock().astimezone(timezone.utc) > deadline:
            raise ServiceRequestError(
                HTTPStatus.GATEWAY_TIMEOUT,
                "deadline_exceeded",
                "WEIR operation exceeded the caller deadline",
            )
        if len(result.body) > self.max_response_bytes:
            raise ServiceRequestError(
                HTTPStatus.BAD_GATEWAY,
                "response_too_large",
                "WEIR response exceeds the configured service limit",
            )
        return result

    def _route(self, method: str, target: str) -> tuple[str, str]:
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
            raise ServiceRequestError(
                HTTPStatus.BAD_REQUEST,
                "invalid_route",
                "WEIR routes do not accept query strings or fragments",
            )
        path = parsed.path
        acquisition_routes = {
            ("POST", "/v1/acquisition/read"): "read",
            ("POST", "/v1/acquisition/search"): "search",
            ("POST", "/v1/acquisition/enrich"): "enrich",
        }
        route = acquisition_routes.get((method, path))
        if route is not None:
            return route, ""
        if method == "POST" and path == "/v1/proposals":
            return "proposal_register", ""
        if method == "POST" and path == "/v1/browser/profile-retirements":
            return "profile_retirement", ""
        if method == "POST" and path == "/v1/actions/execute":
            return "action_execute", ""
        segments = path.strip("/").split("/")
        if method == "GET" and len(segments) in {3, 4} and segments[:2] == [
            "v1",
            "evidence",
        ]:
            identifier = self._identifier(
                segments[2],
                "evidence reference",
                max_length=MAX_EVIDENCE_ROUTE_IDENTIFIER,
            )
            if len(segments) == 3:
                return "evidence", identifier
            if segments[3] == "content":
                return "evidence_content", identifier
        if method == "GET" and len(segments) == 3 and segments[:2] == [
            "v1",
            "commands",
        ]:
            return "command", self._identifier(
                segments[2], "command", max_length=128
            )
        if method == "GET" and len(segments) in {3, 4} and segments[:2] == [
            "v1",
            "proposals",
        ]:
            identifier = self._identifier(
                segments[2], "proposal", max_length=128
            )
            if len(segments) == 3:
                return "proposal", identifier
            if segments[3] == "projection":
                return "proposal_projection", identifier
        if method == "GET" and len(segments) == 4 and segments[:3] == [
            "v1",
            "actions",
            "commands",
        ]:
            return "action_status", self._identifier(
                segments[3], "action command", max_length=128
            )
        raise ServiceRequestError(
            HTTPStatus.NOT_FOUND, "route_not_found", "WEIR route was not found"
        )

    @staticmethod
    def _identifier(value: str, name: str, *, max_length: int) -> str:
        decoded = unquote(value)
        if len(decoded) > max_length or not _ROUTE_IDENTIFIER.fullmatch(decoded):
            raise ServiceRequestError(
                HTTPStatus.BAD_REQUEST,
                "invalid_identifier",
                f"{name} identifier is invalid",
            )
        return decoded

    def _deadline(self, headers: Mapping[str, str]) -> datetime:
        try:
            deadline = parse_timestamp(headers.get("X-Weir-Deadline"), "deadline")
        except ValueError as exc:
            raise ServiceRequestError(
                HTTPStatus.BAD_REQUEST,
                "invalid_deadline",
                "X-Weir-Deadline must be an RFC 3339 timestamp",
            ) from exc
        now = self.clock().astimezone(timezone.utc)
        if deadline <= now:
            raise ServiceRequestError(
                HTTPStatus.REQUEST_TIMEOUT,
                "deadline_expired",
                "WEIR request deadline has expired",
            )
        if deadline - now > MAX_SERVICE_DEADLINE:
            raise ServiceRequestError(
                HTTPStatus.BAD_REQUEST,
                "deadline_too_far",
                "WEIR request deadline exceeds the service maximum",
            )
        return deadline

    @staticmethod
    def _parse_acquisition(body: bytes | None) -> AcquisitionEnvelope:
        if body is None:
            raise ServiceRequestError(
                HTTPStatus.BAD_REQUEST,
                "request_body_required",
                "acquisition request body is required",
            )
        try:
            value = json.loads(body)
            if not isinstance(value, dict):
                raise ValueError("acquisition request must be an object")
            return AcquisitionEnvelope.from_dict(value)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ServiceRequestError(
                HTTPStatus.BAD_REQUEST,
                getattr(exc, "reason_code", "invalid_acquisition"),
                "WEIR acquisition envelope was rejected",
            ) from exc

    @staticmethod
    def _parse_proposal(body: bytes | None) -> ActionProposal:
        if body is None:
            raise ServiceRequestError(
                HTTPStatus.BAD_REQUEST,
                "request_body_required",
                "proposal registration body is required",
            )
        try:
            value = json.loads(body)
            if not isinstance(value, dict):
                raise ValueError("action proposal must be an object")
            return ActionProposal.from_dict(value)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ServiceRequestError(
                HTTPStatus.BAD_REQUEST,
                getattr(exc, "reason_code", "invalid_proposal"),
                "WEIR action proposal was rejected",
            ) from exc

    @staticmethod
    def _parse_profile_retirement(body: bytes | None) -> dict[str, Any]:
        if body is None:
            raise ServiceRequestError(
                HTTPStatus.BAD_REQUEST,
                "request_body_required",
                "profile retirement body is required",
            )
        try:
            value = json.loads(body)
            if not isinstance(value, dict) or set(value) != {
                "session_id",
                "retirement_id",
                "expected_session_epoch",
                "expected_worker_id",
                "expected_worker_instance_id",
                "expected_credential_binding_id",
                "attestation_hash",
                "disposition",
                "disposition_ref",
            }:
                raise ValueError(
                    "profile retirement has missing or unknown fields"
                )
            for name in (
                "session_id",
                "retirement_id",
                "expected_worker_id",
                "expected_worker_instance_id",
                "expected_credential_binding_id",
                "attestation_hash",
                "disposition_ref",
            ):
                item = value[name]
                if (
                    not isinstance(item, str)
                    or not item
                    or len(item) > 128
                ):
                    raise ValueError(f"profile retirement {name} is invalid")
            if (
                type(value["expected_session_epoch"]) is not int
                or value["expected_session_epoch"] < 1
            ):
                raise ValueError(
                    "profile retirement expected_session_epoch is invalid"
                )
            if not is_sha256(value["attestation_hash"]):
                raise ValueError("profile retirement attestation_hash is invalid")
            if value["disposition"] != DEAD_WORKER_RETIREMENT_DISPOSITION:
                raise ValueError("profile retirement disposition is invalid")
            return value
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ServiceRequestError(
                HTTPStatus.BAD_REQUEST,
                "invalid_profile_retirement",
                "WEIR profile retirement was rejected",
            ) from exc

    @staticmethod
    def _parse_action_execution(body: bytes | None) -> dict[str, Any]:
        if body is None:
            raise ServiceRequestError(
                HTTPStatus.BAD_REQUEST,
                "request_body_required",
                "action execution body is required",
            )
        try:
            value = json.loads(body)
            if not isinstance(value, dict) or set(value) != {
                "schema_version",
                "command_id",
                "request_digest",
                "proposal",
                "permit",
            }:
                raise ValueError("action execution has missing or unknown fields")
            if type(value["schema_version"]) is not int or value["schema_version"] != 1:
                raise ValueError("action execution schema_version must be 1")
            command_id = value["command_id"]
            if (
                not isinstance(command_id, str)
                or len(command_id) > 128
                or _ROUTE_IDENTIFIER.fullmatch(command_id) is None
            ):
                raise ValueError("action command_id is invalid")
            if not is_sha256(value["request_digest"]):
                raise ValueError("action request_digest is invalid")
            return {
                "command_id": command_id,
                "request_digest": value["request_digest"],
                "proposal": ActionProposal.from_dict(value["proposal"]),
                "permit": ExecutionPermit.from_dict(value["permit"]),
            }
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ServiceRequestError(
                HTTPStatus.BAD_REQUEST,
                getattr(exc, "reason_code", "invalid_action_execution"),
                "WEIR action execution request was rejected",
            ) from exc

    def _proposals(self) -> ActionProposalStore:
        if self.proposal_store is None:
            raise ServiceRequestError(
                HTTPStatus.NOT_IMPLEMENTED,
                "proposal_store_unavailable",
                "WEIR proposal storage is not configured",
            )
        return self.proposal_store

    def _sessions(self) -> SQLiteSessionStore:
        if self.session_store is None:
            raise ServiceRequestError(
                HTTPStatus.NOT_IMPLEMENTED,
                "session_store_unavailable",
                "WEIR browser-session storage is not configured",
            )
        return self.session_store

    def _actions(self) -> BrowserActionDriver:
        if self.action_driver is None:
            raise ServiceRequestError(
                HTTPStatus.NOT_IMPLEMENTED,
                "action_driver_unavailable",
                "WEIR action execution is disabled",
            )
        return self.action_driver

    def _require_action_admission(
        self,
        principal: ClientPrincipal,
        action_driver: BrowserActionDriver,
    ) -> None:
        if self.action_admission is None:
            raise ServiceRequestError(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "action_admission_unavailable",
                "WEIR action execution has no current host-control admission",
            )
        try:
            self.action_admission.require_external_action(
                caller_id=principal.client_id,
                action_driver=action_driver,
            )
        except EnginePolicyBlocked as exc:
            raise ServiceRequestError(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "production_admission_denied",
                "WEIR host controls did not admit action execution",
            ) from exc
        except Exception as exc:
            raise ServiceRequestError(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "production_admission_unavailable",
                "WEIR could not verify current host-control admission",
            ) from exc

    @staticmethod
    def _require_fade_action_principal(
        principal: ClientPrincipal,
        scope: str,
    ) -> None:
        if principal.client_id != FADE_AUTHORITY_ID:
            raise ServiceRequestError(
                HTTPStatus.FORBIDDEN,
                "action_identity_denied",
                "only Fade's authority identity may use WEIR action routes",
            )
        principal.require_scope(scope)

    def _backend_call(
        self, operation: Callable[..., Any], *args: Any, **kwargs: Any
    ) -> Any:
        try:
            return operation(*args, **kwargs)
        except ServiceRequestError:
            raise
        except WeirClientError as exc:
            try:
                status = (
                    HTTPStatus(exc.status)
                    if exc.status
                    else HTTPStatus.SERVICE_UNAVAILABLE
                )
            except ValueError:
                status = HTTPStatus.BAD_GATEWAY
            raise ServiceRequestError(
                status,
                exc.reason_code,
                "WEIR backend request failed",
            ) from exc
        except EnginePolicyBlocked as exc:
            raise ServiceRequestError(
                HTTPStatus.FORBIDDEN,
                exc.failure_class.value,
                "WEIR acquisition policy rejected the request",
            ) from exc
        except ControllerConflict as exc:
            raise ServiceRequestError(
                HTTPStatus.CONFLICT,
                "reservation_conflict",
                "WEIR credential reservation rejected the request",
            ) from exc
        except IdempotencyConflict as exc:
            raise ServiceRequestError(
                HTTPStatus.CONFLICT,
                exc.failure_class.value,
                "WEIR action idempotency binding rejected the request",
            ) from exc
        except SessionRevisionConflict as exc:
            raise ServiceRequestError(
                HTTPStatus.CONFLICT,
                "stale_reference",
                "WEIR action proposal is stale",
            ) from exc
        except SessionNotFound as exc:
            raise ServiceRequestError(
                HTTPStatus.NOT_FOUND,
                "browser_session_not_found",
                "WEIR browser session was not found",
            ) from exc
        except AcquisitionFailed as exc:
            raise ServiceRequestError(
                HTTPStatus.BAD_GATEWAY,
                exc.failure_class.value,
                "WEIR acquisition failed",
            ) from exc
        except WeirEngineError as exc:
            raise ServiceRequestError(
                HTTPStatus.BAD_GATEWAY,
                exc.failure_class.value,
                "WEIR acquisition engine failed",
            ) from exc
        except (CacheIntegrityError, ContractViolation) as exc:
            raise ServiceRequestError(
                HTTPStatus.CONFLICT,
                getattr(exc, "reason_code", "integrity_check_failed"),
                "WEIR durable state failed an integrity check",
            ) from exc
        except ProposalNotFound as exc:
            raise ServiceRequestError(
                HTTPStatus.NOT_FOUND,
                "proposal_not_found",
                "WEIR action proposal was not found",
            ) from exc
        except FileNotFoundError as exc:
            raise ServiceRequestError(
                HTTPStatus.NOT_FOUND,
                "evidence_not_found",
                "WEIR evidence was not found",
            ) from exc
        except (OSError, TypeError, ValueError) as exc:
            raise ServiceRequestError(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "backend_rejected",
                "WEIR backend could not satisfy the request",
            ) from exc

    @staticmethod
    def _json(value: dict[str, Any]) -> ServiceResponse:
        return ServiceResponse(HTTPStatus.OK, canonical_json_bytes(value))


class _WeirHTTPServer(ThreadingHTTPServer):
    daemon_threads = True


class _WeirIPv6HTTPServer(_WeirHTTPServer):
    address_family = socket.AF_INET6


class WeirService(AbstractContextManager["WeirService"]):
    """A disabled-by-default HTTP wrapper that binds only to an IP loopback literal."""

    def __init__(
        self,
        application: WeirServiceApplication,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        try:
            address = ipaddress.ip_address(host)
        except ValueError as exc:
            raise ValueError("WEIR service host must be a loopback IP literal") from exc
        if not address.is_loopback:
            raise ValueError("WEIR service must bind to loopback")
        if type(port) is not int or not 0 <= port <= 65_535:
            raise ValueError("WEIR service port is invalid")
        server_type = _WeirIPv6HTTPServer if address.version == 6 else _WeirHTTPServer
        self.application = application
        self._server = server_type((host, port), self._handler_type())
        self._thread: Thread | None = None

    @property
    def address(self) -> tuple[str, int]:
        host, port = self._server.server_address[:2]
        return str(host), int(port)

    def __enter__(self) -> WeirService:
        self._thread = Thread(
            target=self._server.serve_forever,
            name="weir-loopback-service",
            daemon=True,
        )
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def serve_forever(self) -> None:
        self._server.serve_forever()

    def close(self) -> None:
        self._server.server_close()

    def _handler_type(self) -> type[BaseHTTPRequestHandler]:
        application = self.application

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def handle_expect_100(self) -> bool:
                raw_length = self.headers.get("Content-Length")
                try:
                    length = int(raw_length or "")
                except ValueError:
                    length = -1
                if not 0 < length <= MAX_SERVICE_REQUEST_BYTES:
                    self.close_connection = True
                    self._send(
                        ServiceResponse(
                            HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                            canonical_json_bytes(
                                {
                                    "error": {
                                        "reason_code": "request_too_large",
                                        "message": (
                                            "WEIR request body exceeds the service limit"
                                        ),
                                    }
                                }
                            ),
                        )
                    )
                    return False
                self.send_response_only(HTTPStatus.CONTINUE)
                self.end_headers()
                return True

            def do_GET(self) -> None:
                self._dispatch("GET")

            def do_POST(self) -> None:
                self._dispatch("POST")

            def _dispatch(self, method: str) -> None:
                try:
                    body = self._request_body(method)
                    response = application.handle(method, self.path, self.headers, body)
                except ServiceRequestError as exc:
                    response = ServiceResponse(
                        exc.status,
                        canonical_json_bytes(
                            {
                                "error": {
                                    "reason_code": exc.reason_code,
                                    "message": str(exc),
                                }
                            }
                        ),
                    )
                except Exception:
                    response = ServiceResponse(
                        HTTPStatus.INTERNAL_SERVER_ERROR,
                        canonical_json_bytes(
                            {
                                "error": {
                                    "reason_code": "internal_error",
                                    "message": "WEIR service failed safely",
                                }
                            }
                        ),
                    )
                self._send(response)

            def _request_body(self, method: str) -> bytes | None:
                if self.headers.get("Transfer-Encoding") is not None:
                    raise ServiceRequestError(
                        HTTPStatus.BAD_REQUEST,
                        "unsupported_transfer_encoding",
                        "WEIR service does not accept transfer encoding",
                    )
                raw_length = self.headers.get("Content-Length")
                if method == "GET":
                    if raw_length not in {None, "0"}:
                        raise ServiceRequestError(
                            HTTPStatus.BAD_REQUEST,
                            "unexpected_request_body",
                            "GET routes do not accept a request body",
                        )
                    return None
                if self.headers.get_content_type() != "application/json":
                    raise ServiceRequestError(
                        HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                        "unsupported_media_type",
                        "WEIR POST routes require application/json",
                    )
                try:
                    length = int(raw_length or "")
                except ValueError as exc:
                    raise ServiceRequestError(
                        HTTPStatus.LENGTH_REQUIRED,
                        "invalid_content_length",
                        "WEIR POST routes require Content-Length",
                    ) from exc
                if not 0 < length <= MAX_SERVICE_REQUEST_BYTES:
                    self.close_connection = True
                    raise ServiceRequestError(
                        HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                        "request_too_large",
                        "WEIR request body exceeds the service limit",
                    )
                body = self.rfile.read(length)
                if len(body) != length:
                    raise ServiceRequestError(
                        HTTPStatus.BAD_REQUEST,
                        "incomplete_request_body",
                        "WEIR request body was incomplete",
                    )
                return body

            def _send(self, response: ServiceResponse) -> None:
                self.send_response(response.status)
                self.send_header("Content-Type", response.content_type)
                self.send_header("Content-Length", str(len(response.body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                for name, value in response.headers:
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(response.body)

            def log_message(self, *_: object) -> None:
                return

        return Handler


__all__ = [
    "ACQUISITION_READ_SCOPE",
    "ACTION_EXECUTE_SCOPE",
    "ACTION_STATUS_SCOPE",
    "COMMAND_READ_SCOPE",
    "EVIDENCE_READ_SCOPE",
    "MAX_SERVICE_DEADLINE",
    "PROPOSAL_READ_FULL_SCOPE",
    "PROPOSAL_READ_REDACTED_SCOPE",
    "PROPOSAL_WRITE_SCOPE",
    "PROFILE_RETIRE_SCOPE",
    "SERVICE_SCOPES",
    "ClientCredential",
    "ClientPrincipal",
    "ClientRegistry",
    "ServiceRequestError",
    "ServiceResponse",
    "WeirService",
    "WeirServiceApplication",
]
