from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from weir.actions import ActionProposal, ActionType, Risk
from weir.contract import (
    contains_forbidden_key,
    is_sha256,
    parse_timestamp,
    validate_contract_size,
    validate_identifier,
)
from weir.models import DataClass

CORRELATION_HEADER_SCHEMA_VERSION = 1
WEIR_ACTION_EVENT_SCHEMA_VERSION = 1
MAX_CORRELATION_HEADER_BYTES = 4 * 1024
MAX_WEIR_ACTION_EVENT_BYTES = 16 * 1024


class ActionEventState(StrEnum):
    PROPOSED = "proposed"
    PERMIT_RECEIVED = "permit_received"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"
    OUTCOME_UNKNOWN = "outcome_unknown"
    QUARANTINE_CLEARED = "quarantine_cleared"


@dataclass(frozen=True, slots=True)
class CorrelationHeader:
    event_id: str
    occurred_at: str
    producer: str
    run_id: str
    assignment_id: str | None
    correlation_id: str
    work_context_hash: str
    schema_version: int = CORRELATION_HEADER_SCHEMA_VERSION

    def validate(self) -> None:
        if self.schema_version != CORRELATION_HEADER_SCHEMA_VERSION or type(
            self.schema_version
        ) is not int:
            raise ValueError("unsupported correlation-header schema version")
        for name in ("event_id", "producer", "run_id", "correlation_id"):
            validate_identifier(getattr(self, name), name)
        if self.assignment_id is not None:
            validate_identifier(self.assignment_id, "assignment_id")
        if not is_sha256(self.work_context_hash):
            raise ValueError("work_context_hash must be a sha256 digest")
        parse_timestamp(self.occurred_at, "occurred_at")
        validate_contract_size(
            self._to_dict(), MAX_CORRELATION_HEADER_BYTES, "CorrelationHeader"
        )

    def _to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "schema_version": self.schema_version,
            "occurred_at": self.occurred_at,
            "producer": self.producer,
            "run_id": self.run_id,
            "assignment_id": self.assignment_id,
            "correlation_id": self.correlation_id,
            "work_context_hash": self.work_context_hash,
        }

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return self._to_dict()

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> CorrelationHeader:
        required = {
            "event_id",
            "schema_version",
            "occurred_at",
            "producer",
            "run_id",
            "assignment_id",
            "correlation_id",
            "work_context_hash",
        }
        if not isinstance(value, dict) or set(value) != required:
            raise ValueError("CorrelationHeader has missing or unknown fields")
        header = cls(
            event_id=value["event_id"],
            schema_version=value["schema_version"],
            occurred_at=value["occurred_at"],
            producer=value["producer"],
            run_id=value["run_id"],
            assignment_id=value["assignment_id"],
            correlation_id=value["correlation_id"],
            work_context_hash=value["work_context_hash"],
        )
        header.validate()
        return header


@dataclass(frozen=True, slots=True)
class WeirActionEvent:
    """Public-safe WEIR action metadata for unauthenticated HUD read paths."""

    header: CorrelationHeader
    event_type: str
    state: ActionEventState
    action_id: str
    session_id: str
    action_type: ActionType
    risk: Risk
    proposal_hash: str
    permit_hash: str | None
    receipt_id: str | None
    evidence_ref_count: int
    parameter_data_class: DataClass
    reason_code: str | None
    schema_version: int = WEIR_ACTION_EVENT_SCHEMA_VERSION

    @classmethod
    def from_proposal(
        cls,
        *,
        header: CorrelationHeader,
        proposal: ActionProposal,
    ) -> WeirActionEvent:
        proposal.validate()
        if (
            header.run_id != proposal.owner_run_id
            or header.assignment_id != proposal.assignment_id
            or header.correlation_id != proposal.correlation_id
            or header.work_context_hash != proposal.work_context_hash
        ):
            raise ValueError("correlation header does not match ActionProposal identity")
        event = cls(
            header=header,
            event_type="weir.action.proposed",
            state=ActionEventState.PROPOSED,
            action_id=proposal.action_id,
            session_id=proposal.session_id,
            action_type=proposal.action_type,
            risk=proposal.risk,
            proposal_hash=proposal.proposal_hash,
            permit_hash=None,
            receipt_id=None,
            evidence_ref_count=len(proposal.evidence_refs),
            parameter_data_class=proposal.parameter_data_class,
            reason_code=None,
        )
        event.validate()
        return event

    def validate(self) -> None:
        if self.schema_version != WEIR_ACTION_EVENT_SCHEMA_VERSION or type(
            self.schema_version
        ) is not int:
            raise ValueError("unsupported WEIR action-event schema version")
        if not isinstance(self.header, CorrelationHeader):
            raise ValueError("action event requires a CorrelationHeader")
        self.header.validate()
        if self.header.producer != "weir":
            raise ValueError("WEIR action events require producer=weir")
        for name in ("event_type", "action_id", "session_id"):
            validate_identifier(getattr(self, name), name)
        if not self.event_type.startswith("weir.action."):
            raise ValueError("action event_type must use the weir.action namespace")
        if not isinstance(self.state, ActionEventState):
            raise ValueError("action event state is invalid")
        if not isinstance(self.action_type, ActionType) or not isinstance(
            self.risk, Risk
        ):
            raise ValueError("action event type or risk is invalid")
        if not isinstance(self.parameter_data_class, DataClass):
            raise ValueError("action event parameter_data_class is invalid")
        if not is_sha256(self.proposal_hash):
            raise ValueError("proposal_hash must be a sha256 digest")
        if self.permit_hash is not None and not is_sha256(self.permit_hash):
            raise ValueError("permit_hash must be a sha256 digest or null")
        if self.receipt_id is not None:
            validate_identifier(self.receipt_id, "receipt_id")
        if type(self.evidence_ref_count) is not int or not (
            0 <= self.evidence_ref_count <= 64
        ):
            raise ValueError("evidence_ref_count must be an integer from zero to 64")
        if self.reason_code is not None:
            validate_identifier(self.reason_code, "reason_code", max_length=64)
        value = self._to_dict()
        if contains_forbidden_key(value):
            raise ValueError("public action event contains a forbidden field name")
        validate_contract_size(
            value, MAX_WEIR_ACTION_EVENT_BYTES, "WeirActionEvent"
        )

    def _to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "header": self.header.to_dict(),
            "event_type": self.event_type,
            "state": self.state.value,
            "action_id": self.action_id,
            "session_id": self.session_id,
            "action_type": self.action_type.value,
            "risk": self.risk.value,
            "proposal_hash": self.proposal_hash,
            "permit_hash": self.permit_hash,
            "receipt_id": self.receipt_id,
            "evidence_ref_count": self.evidence_ref_count,
            "parameter_data_class": self.parameter_data_class.value,
            "reason_code": self.reason_code,
        }

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return self._to_dict()

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> WeirActionEvent:
        required = {
            "schema_version",
            "header",
            "event_type",
            "state",
            "action_id",
            "session_id",
            "action_type",
            "risk",
            "proposal_hash",
            "permit_hash",
            "receipt_id",
            "evidence_ref_count",
            "parameter_data_class",
            "reason_code",
        }
        if not isinstance(value, dict) or set(value) != required:
            raise ValueError("WeirActionEvent has missing or unknown fields")
        try:
            event = cls(
                schema_version=value["schema_version"],
                header=CorrelationHeader.from_dict(value["header"]),
                event_type=value["event_type"],
                state=ActionEventState(value["state"]),
                action_id=value["action_id"],
                session_id=value["session_id"],
                action_type=ActionType(value["action_type"]),
                risk=Risk(value["risk"]),
                proposal_hash=value["proposal_hash"],
                permit_hash=value["permit_hash"],
                receipt_id=value["receipt_id"],
                evidence_ref_count=value["evidence_ref_count"],
                parameter_data_class=DataClass(value["parameter_data_class"]),
                reason_code=value["reason_code"],
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("WeirActionEvent field is invalid") from exc
        event.validate()
        return event


__all__ = [
    "CORRELATION_HEADER_SCHEMA_VERSION",
    "WEIR_ACTION_EVENT_SCHEMA_VERSION",
    "ActionEventState",
    "CorrelationHeader",
    "WeirActionEvent",
]
