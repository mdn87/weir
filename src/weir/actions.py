from __future__ import annotations

import math
import re
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Any, Protocol

from weir.browser.locators import (
    LocatorNotFoundError,
    LocatorResolutionError,
    resolve_locator,
)
from weir.browser.models import (
    Observation,
    ResolvedTarget,
    SemanticLocator,
)
from weir.contract import (
    ContractViolation,
    canonical_digest,
    contains_forbidden_key,
    is_portable_json_value,
    is_sha256,
    validate_contract_size,
    validate_identifier,
)
from weir.engines.base import FailureClass
from weir.models import DataClass

ACTION_PROPOSAL_VERSION = "0.3"
EXECUTION_PERMIT_VERSION = "0.1"
EXECUTION_RECEIPT_VERSION = "0.3"
QUARANTINE_RECORD_VERSION = "0.1"
MAX_ACTION_PROPOSAL_BYTES = 256 * 1024
MAX_ACTION_PARAMETERS_BYTES = 64 * 1024
MAX_EXECUTION_PERMIT_BYTES = 8 * 1024
MAX_EXECUTION_RECEIPT_BYTES = 32 * 1024
MAX_QUARANTINE_RECORD_BYTES = 8 * 1024
MAX_ACTION_CONDITIONS = 32
MAX_ACTION_EVIDENCE_REFS = 64
MAX_CLOCK_SKEW_SECONDS = 5
MIN_PERMIT_ISSUER_MARGIN_SECONDS = 15
MIN_PERMIT_LIFETIME_SECONDS = 30
MAX_PERMIT_LIFETIME_SECONDS = 300
MAX_ACTION_PROPOSAL_LIFETIME_SECONDS = 900
QUARANTINE_REF_PATTERN = re.compile(
    r"weir-quarantine:[A-Za-z0-9][A-Za-z0-9._-]{0,127}"
)


class Risk(StrEnum):
    READ_ONLY = "read_only"
    REVERSIBLE = "reversible"
    LOCAL_MUTATION = "local_mutation"
    EXTERNAL_UPLOAD = "external_upload"
    EXTERNAL_SUBMIT = "external_submit"
    MESSAGE_SEND = "message_send"
    PURCHASE = "purchase"
    ACCOUNT_CHANGE = "account_change"
    CREDENTIAL_CHANGE = "credential_change"
    DESTRUCTIVE = "destructive"
    UNKNOWN = "unknown"


class ActionType(StrEnum):
    CLICK = "click"
    FILL = "fill"
    SELECT = "select"
    CHECK = "check"
    UNCHECK = "uncheck"
    UPLOAD = "upload"
    SUBMIT = "submit"


class ConditionKind(StrEnum):
    URL_EQUALS = "url_equals"
    ELEMENT_PRESENT = "element_present"
    ELEMENT_STATE_EQUALS = "element_state_equals"
    OBSERVATION_HASH_EQUALS = "observation_hash_equals"


class ApprovalStatus(StrEnum):
    APPROVED = "approved"
    DENIED = "denied"


class ReceiptResult(StrEnum):
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"
    OUTCOME_UNKNOWN = "outcome_unknown"


class VerificationConfidence(StrEnum):
    VERIFIED = "verified"
    PROBABLE = "probable"
    UNCERTAIN = "uncertain"
    FAILED = "failed"
    BLOCKED = "blocked"


# Generic DOM primitives are semantically ambiguous. Clicks can submit or delete;
# input/change events from fill/select/check can autosave, mutate settings, or trigger
# network effects. Keep them UNKNOWN until an attested interaction mode or a more
# specific consequence-bearing action contract exists.
BASELINE_RISK: dict[ActionType, Risk] = {
    ActionType.CLICK: Risk.UNKNOWN,
    ActionType.FILL: Risk.UNKNOWN,
    ActionType.SELECT: Risk.UNKNOWN,
    ActionType.CHECK: Risk.UNKNOWN,
    ActionType.UNCHECK: Risk.UNKNOWN,
    ActionType.UPLOAD: Risk.EXTERNAL_UPLOAD,
    ActionType.SUBMIT: Risk.EXTERNAL_SUBMIT,
}

RISK_RANK: dict[Risk, int] = {
    Risk.READ_ONLY: 0,
    Risk.REVERSIBLE: 10,
    Risk.LOCAL_MUTATION: 20,
    Risk.EXTERNAL_UPLOAD: 30,
    Risk.EXTERNAL_SUBMIT: 40,
    Risk.MESSAGE_SEND: 50,
    Risk.PURCHASE: 60,
    Risk.ACCOUNT_CHANGE: 70,
    Risk.CREDENTIAL_CHANGE: 80,
    Risk.DESTRUCTIVE: 90,
    Risk.UNKNOWN: 100,
}


def _canonical_digest(value: Any) -> str:
    return canonical_digest(value)


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


def _parse_time(value: str, name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ValueError(f"{name} must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{name} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _is_sha256(value: object) -> bool:
    return is_sha256(value)


@dataclass(frozen=True, slots=True)
class ActionCondition:
    kind: ConditionKind
    expected: Any
    locator: SemanticLocator | None = None
    target: ResolvedTarget | None = None

    def validate(self) -> None:
        if not isinstance(self.kind, ConditionKind):
            raise ValueError("condition kind is invalid")
        if not _is_json_value(self.expected):
            raise ValueError("condition expected value must be JSON-compatible")
        needs_target = self.kind in {
            ConditionKind.ELEMENT_PRESENT,
            ConditionKind.ELEMENT_STATE_EQUALS,
        }
        if needs_target != (self.target is not None and self.locator is not None):
            raise ValueError(
                f"condition {self.kind.value!r} locator/target requirement is not met"
            )
        if not needs_target and (self.target is not None or self.locator is not None):
            raise ValueError(
                f"condition {self.kind.value!r} cannot carry an element binding"
            )
        if self.kind is ConditionKind.ELEMENT_PRESENT and not isinstance(
            self.expected, bool
        ):
            raise ValueError("element_present expected value must be a boolean")
        if self.kind is ConditionKind.ELEMENT_STATE_EQUALS and (
            self.expected is not None
            and (not isinstance(self.expected, str) or not self.expected)
        ):
            raise ValueError(
                "element_state_equals expected value must be null or a state string"
            )
        if self.kind is ConditionKind.URL_EQUALS and (
            not isinstance(self.expected, str) or not self.expected
        ):
            raise ValueError("url_equals expected value must be a non-empty string")
        if self.kind is ConditionKind.OBSERVATION_HASH_EQUALS and not _is_sha256(
            self.expected
        ):
            raise ValueError("observation_hash_equals expected value must be a digest")
        if self.locator is not None:
            if not isinstance(self.locator, SemanticLocator):
                raise ValueError("condition locator must be a SemanticLocator")
            self.locator.validate()
        if self.target is not None:
            if not isinstance(self.target, ResolvedTarget):
                raise ValueError("condition target must be a ResolvedTarget")
            self.target.validate()
            if self.target.locator_hash != self.locator.locator_hash:
                raise ValueError(
                    "condition target is bound to a different semantic locator"
                )

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "kind": self.kind.value,
            "expected": self.expected,
            "locator": None if self.locator is None else self.locator.to_dict(),
            "target": None if self.target is None else self.target.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> ActionCondition:
        required = {"kind", "expected", "locator", "target"}
        if not isinstance(value, dict) or set(value) != required:
            raise ValueError("action condition has missing or unknown fields")
        try:
            condition = cls(
                kind=ConditionKind(value["kind"]),
                expected=value["expected"],
                locator=(
                    None
                    if value["locator"] is None
                    else SemanticLocator.from_dict(value["locator"])
                ),
                target=(
                    None
                    if value["target"] is None
                    else ResolvedTarget.from_dict(value["target"])
                ),
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("action condition field is invalid") from exc
        condition.validate()
        return condition


@dataclass(slots=True)
class ActionProposal:
    action_id: str
    request_id: str
    owner_run_id: str
    work_context_hash: str
    correlation_id: str
    assignment_id: str | None
    session_id: str
    session_revision: int
    session_epoch: int
    observation_id: str
    observation_hash: str
    action_type: ActionType
    semantic_locator: SemanticLocator
    resolved_target: ResolvedTarget
    parameters: dict[str, Any]
    parameter_data_class: DataClass
    risk: Risk
    requires_approval: bool
    preconditions: list[ActionCondition]
    expected_postconditions: list[ActionCondition]
    evidence_refs: list[str]
    created_at: str
    expires_at: str
    proposal_hash: str
    contract_version: str = ACTION_PROPOSAL_VERSION

    def _hash_basis(self) -> dict[str, Any]:
        value = self.to_dict(validate=False)
        value.pop("proposal_hash")
        return value

    def compute_hash(self) -> str:
        return _canonical_digest(self._hash_basis())

    def validate(self) -> None:
        if self.contract_version != ACTION_PROPOSAL_VERSION:
            raise ValueError("unsupported action-proposal contract version")
        for name in (
            "action_id",
            "request_id",
            "owner_run_id",
            "correlation_id",
            "session_id",
            "observation_id",
        ):
            validate_identifier(getattr(self, name), name)
        if self.assignment_id is not None:
            validate_identifier(self.assignment_id, "assignment_id")
        if not _is_sha256(self.work_context_hash):
            raise ValueError("work_context_hash must be a sha256 digest")
        if (
            type(self.session_revision) is not int
            or self.session_revision < 0
            or type(self.session_epoch) is not int
            or self.session_epoch < 1
        ):
            raise ValueError("session revision or epoch is invalid")
        if not isinstance(self.semantic_locator, SemanticLocator):
            raise ValueError("semantic_locator must be a SemanticLocator")
        if not isinstance(self.resolved_target, ResolvedTarget):
            raise ValueError("resolved_target must be a ResolvedTarget")
        self.semantic_locator.validate()
        self.resolved_target.validate()
        if self.resolved_target.locator_hash != self.semantic_locator.locator_hash:
            raise ValueError("resolved target is bound to a different semantic locator")
        if self.resolved_target.session_id != self.session_id:
            raise ValueError("resolved target belongs to a different session")
        if self.resolved_target.observation_id != self.observation_id:
            raise ValueError("resolved target belongs to a different observation")
        if (
            self.resolved_target.session_revision != self.session_revision
            or self.resolved_target.session_epoch != self.session_epoch
        ):
            raise ValueError("resolved target belongs to a different session revision")
        if not _is_sha256(self.observation_hash):
            raise ValueError("observation_hash must be a sha256 digest")
        if not isinstance(self.action_type, ActionType) or not isinstance(self.risk, Risk):
            raise ValueError("action type or risk is invalid")
        if RISK_RANK[self.risk] < RISK_RANK[BASELINE_RISK[self.action_type]]:
            raise ValueError("action risk cannot be lower than its baseline classification")
        if self.requires_approval is not True:
            raise ValueError("action proposals require approval")
        if not isinstance(self.parameters, dict) or not is_portable_json_value(
            self.parameters, reject_fade_keys=True
        ):
            raise ValueError(
                "action parameters must be a portable bounded JSON object with safe field names"
            )
        if not isinstance(self.parameter_data_class, DataClass):
            raise ValueError("parameter_data_class is invalid")
        validate_contract_size(
            self.parameters, MAX_ACTION_PARAMETERS_BYTES, "action parameters"
        )
        if not isinstance(self.preconditions, list) or not isinstance(
            self.expected_postconditions, list
        ):
            raise ValueError("proposal conditions must be arrays")
        if (
            len(self.preconditions) > MAX_ACTION_CONDITIONS
            or len(self.expected_postconditions) > MAX_ACTION_CONDITIONS
        ):
            raise ValueError(
                f"proposal condition arrays cannot exceed {MAX_ACTION_CONDITIONS} items"
            )
        for condition in [*self.preconditions, *self.expected_postconditions]:
            if not isinstance(condition, ActionCondition):
                raise ValueError("proposal conditions must be ActionCondition values")
            condition.validate()
            if condition.target is not None and (
                condition.target.session_id != self.session_id
                or condition.target.observation_id != self.observation_id
                or condition.target.session_revision != self.session_revision
                or condition.target.session_epoch != self.session_epoch
            ):
                raise ValueError(
                    "condition target belongs to a different session observation"
                )
        if not isinstance(self.evidence_refs, list) or not self.evidence_refs:
            raise ValueError("evidence_refs must contain at least one reference")
        if len(self.evidence_refs) > MAX_ACTION_EVIDENCE_REFS:
            raise ValueError(
                f"evidence_refs cannot exceed {MAX_ACTION_EVIDENCE_REFS} references"
            )
        if len(set(self.evidence_refs)) != len(self.evidence_refs) or any(
            not isinstance(item, str) or not item or len(item) > 512
            for item in self.evidence_refs
        ):
            raise ValueError("evidence_refs must contain unique non-empty references")
        created = _parse_time(self.created_at, "created_at")
        expires = _parse_time(self.expires_at, "expires_at")
        if expires <= created:
            raise ValueError("action proposal must expire after it is created")
        if expires - created > timedelta(seconds=MAX_ACTION_PROPOSAL_LIFETIME_SECONDS):
            raise ValueError("action proposal lifetime exceeds the contract maximum")
        if self.proposal_hash != self.compute_hash():
            raise ContractViolation(
                "proposal_hash_mismatch",
                "proposal_hash does not match the ActionProposal",
            )
        validate_contract_size(
            self.to_dict(validate=False),
            MAX_ACTION_PROPOSAL_BYTES,
            "ActionProposal",
        )

    def to_dict(self, *, validate: bool = True) -> dict[str, Any]:
        if validate:
            self.validate()
        return {
            "contract_version": self.contract_version,
            "action_id": self.action_id,
            "request_id": self.request_id,
            "owner_run_id": self.owner_run_id,
            "work_context_hash": self.work_context_hash,
            "correlation_id": self.correlation_id,
            "assignment_id": self.assignment_id,
            "session_id": self.session_id,
            "session_revision": self.session_revision,
            "session_epoch": self.session_epoch,
            "observation_id": self.observation_id,
            "observation_hash": self.observation_hash,
            "action_type": self.action_type.value,
            "semantic_locator": self.semantic_locator.to_dict(),
            "resolved_target": self.resolved_target.to_dict(),
            "parameters": self.parameters,
            "parameter_data_class": self.parameter_data_class.value,
            "risk": self.risk.value,
            "requires_approval": self.requires_approval,
            "preconditions": [item.to_dict() for item in self.preconditions],
            "expected_postconditions": [
                item.to_dict() for item in self.expected_postconditions
            ],
            "evidence_refs": list(self.evidence_refs),
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "proposal_hash": self.proposal_hash,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> ActionProposal:
        required = {
            "contract_version",
            "action_id",
            "request_id",
            "owner_run_id",
            "work_context_hash",
            "correlation_id",
            "assignment_id",
            "session_id",
            "session_revision",
            "session_epoch",
            "observation_id",
            "observation_hash",
            "action_type",
            "semantic_locator",
            "resolved_target",
            "parameters",
            "parameter_data_class",
            "risk",
            "requires_approval",
            "preconditions",
            "expected_postconditions",
            "evidence_refs",
            "created_at",
            "expires_at",
            "proposal_hash",
        }
        if not isinstance(value, dict) or set(value) != required:
            raise ValueError("ActionProposal has missing or unknown fields")
        try:
            proposal = cls(
                contract_version=value["contract_version"],
                action_id=value["action_id"],
                request_id=value["request_id"],
                owner_run_id=value["owner_run_id"],
                work_context_hash=value["work_context_hash"],
                correlation_id=value["correlation_id"],
                assignment_id=value["assignment_id"],
                session_id=value["session_id"],
                session_revision=value["session_revision"],
                session_epoch=value["session_epoch"],
                observation_id=value["observation_id"],
                observation_hash=value["observation_hash"],
                action_type=ActionType(value["action_type"]),
                semantic_locator=SemanticLocator.from_dict(value["semantic_locator"]),
                resolved_target=ResolvedTarget.from_dict(value["resolved_target"]),
                parameters=value["parameters"],
                parameter_data_class=DataClass(value["parameter_data_class"]),
                risk=Risk(value["risk"]),
                requires_approval=value["requires_approval"],
                preconditions=[
                    ActionCondition.from_dict(item) for item in value["preconditions"]
                ],
                expected_postconditions=[
                    ActionCondition.from_dict(item)
                    for item in value["expected_postconditions"]
                ],
                evidence_refs=value["evidence_refs"],
                created_at=value["created_at"],
                expires_at=value["expires_at"],
                proposal_hash=value["proposal_hash"],
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("ActionProposal field is invalid") from exc
        proposal.validate()
        return proposal


class ActionCompiler:
    """Compile evidence into a proposal; this class deliberately cannot execute it."""

    def propose(
        self,
        *,
        action_id: str,
        request_id: str,
        owner_run_id: str,
        work_context_hash: str,
        correlation_id: str,
        assignment_id: str | None,
        observation: Observation,
        locator: SemanticLocator,
        action_type: ActionType,
        parameters: dict[str, Any] | None,
        parameter_data_class: DataClass,
        created_at: str,
        expires_at: str,
        risk: Risk | None = None,
        expected_postconditions: list[ActionCondition] | None = None,
    ) -> ActionProposal:
        observation.validate()
        if not isinstance(action_type, ActionType):
            raise ValueError("action_type must be an ActionType")
        if risk is not None and not isinstance(risk, Risk):
            raise ValueError("risk must be a Risk or null")
        target = resolve_locator(
            locator,
            observation,
            expected_session_id=observation.session_id,
            expected_revision=observation.session_revision,
            expected_epoch=observation.session_epoch,
        )
        baseline = BASELINE_RISK[action_type]
        selected_risk = risk or baseline
        if RISK_RANK[selected_risk] < RISK_RANK[baseline]:
            raise ValueError(
                f"{action_type.value} requires risk {baseline.value!r} or higher"
            )
        preconditions = [
            ActionCondition(
                ConditionKind.OBSERVATION_HASH_EQUALS, observation.observation_hash
            ),
            ActionCondition(
                ConditionKind.ELEMENT_PRESENT,
                True,
                locator=locator,
                target=target,
            ),
        ]
        proposal = ActionProposal(
            action_id=action_id,
            request_id=request_id,
            owner_run_id=owner_run_id,
            work_context_hash=work_context_hash,
            correlation_id=correlation_id,
            assignment_id=assignment_id,
            session_id=observation.session_id,
            session_revision=observation.session_revision,
            session_epoch=observation.session_epoch,
            observation_id=observation.observation_id,
            observation_hash=observation.observation_hash,
            action_type=action_type,
            semantic_locator=locator,
            resolved_target=target,
            parameters=dict(parameters or {}),
            parameter_data_class=parameter_data_class,
            risk=selected_risk,
            requires_approval=selected_risk is not Risk.READ_ONLY,
            preconditions=preconditions,
            expected_postconditions=list(expected_postconditions or []),
            evidence_refs=[observation.capture_id, *observation.artifact_refs],
            created_at=created_at,
            expires_at=expires_at,
            proposal_hash="",
        )
        proposal.proposal_hash = proposal.compute_hash()
        proposal.validate()
        return proposal


@dataclass(frozen=True, slots=True)
class ApprovalDecision:
    proposal_hash: str
    status: ApprovalStatus
    authority: str
    decided_at: str
    approval_ref: str | None = None
    reason: str | None = None

    def validate(self) -> None:
        if not _is_sha256(self.proposal_hash):
            raise ValueError("approval decision requires a proposal hash")
        if not isinstance(self.status, ApprovalStatus):
            raise ValueError("approval decision status is invalid")
        if self.status is ApprovalStatus.APPROVED and not self.approval_ref:
            raise ValueError("approved decisions require an approval reference")
        if not isinstance(self.authority, str) or not self.authority:
            raise ValueError("approval decision requires an authority")
        for name in ("approval_ref", "reason"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or not value):
                raise ValueError(f"approval decision {name} must be non-empty or null")
        _parse_time(self.decided_at, "decided_at")


@dataclass(frozen=True, slots=True)
class ExecutionPermit:
    """One-use Fade-issued authority bound to one exact WEIR proposal."""

    permit_id: str
    proposal_hash: str
    work_context_hash: str
    owner_run_id: str
    session_id: str
    session_epoch: int
    action_type: ActionType
    risk: Risk
    approval_ref: str
    issuer_id: str
    issued_at: str
    expires_at: str
    use_limit: int
    permit_hash: str
    contract_version: str = EXECUTION_PERMIT_VERSION

    def _hash_basis(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "permit_id": self.permit_id,
            "proposal_hash": self.proposal_hash,
            "work_context_hash": self.work_context_hash,
            "owner_run_id": self.owner_run_id,
            "session_id": self.session_id,
            "session_epoch": self.session_epoch,
            "action_type": self.action_type.value,
            "risk": self.risk.value,
            "approval_ref": self.approval_ref,
            "issuer_id": self.issuer_id,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "use_limit": self.use_limit,
        }

    @classmethod
    def create(
        cls,
        *,
        permit_id: str,
        proposal_hash: str,
        work_context_hash: str,
        owner_run_id: str,
        session_id: str,
        session_epoch: int,
        action_type: ActionType,
        risk: Risk,
        approval_ref: str,
        issuer_id: str,
        issued_at: str,
        expires_at: str,
    ) -> ExecutionPermit:
        permit = cls(
            permit_id=permit_id,
            proposal_hash=proposal_hash,
            work_context_hash=work_context_hash,
            owner_run_id=owner_run_id,
            session_id=session_id,
            session_epoch=session_epoch,
            action_type=action_type,
            risk=risk,
            approval_ref=approval_ref,
            issuer_id=issuer_id,
            issued_at=issued_at,
            expires_at=expires_at,
            use_limit=1,
            permit_hash="",
        )
        permit = replace(permit, permit_hash=canonical_digest(permit._hash_basis()))
        permit.validate()
        return permit

    def validate(self) -> None:
        if self.contract_version != EXECUTION_PERMIT_VERSION:
            raise ValueError("unsupported ExecutionPermit contract version")
        for name in (
            "permit_id",
            "owner_run_id",
            "session_id",
            "approval_ref",
            "issuer_id",
        ):
            validate_identifier(getattr(self, name), name)
        for name in ("proposal_hash", "work_context_hash", "permit_hash"):
            if not _is_sha256(getattr(self, name)):
                raise ValueError(f"{name} must be a sha256 digest")
        if type(self.session_epoch) is not int or self.session_epoch < 1:
            raise ValueError("session_epoch must be a positive integer")
        if not isinstance(self.action_type, ActionType) or not isinstance(
            self.risk, Risk
        ):
            raise ValueError("permit action type or risk is invalid")
        if self.use_limit != 1 or type(self.use_limit) is not int:
            raise ValueError("ExecutionPermit.use_limit must equal one")
        issued = _parse_time(self.issued_at, "issued_at")
        expires = _parse_time(self.expires_at, "expires_at")
        lifetime = (expires - issued).total_seconds()
        if lifetime < MIN_PERMIT_LIFETIME_SECONDS:
            raise ContractViolation(
                "permit_lifetime_too_short",
                f"ExecutionPermit lifetime must be at least {MIN_PERMIT_LIFETIME_SECONDS} seconds",
            )
        if lifetime > MAX_PERMIT_LIFETIME_SECONDS:
            raise ContractViolation(
                "permit_lifetime_too_long",
                f"ExecutionPermit lifetime cannot exceed {MAX_PERMIT_LIFETIME_SECONDS} seconds",
            )
        if self.permit_hash != canonical_digest(self._hash_basis()):
            raise ContractViolation(
                "permit_hash_mismatch", "permit_hash does not match the ExecutionPermit"
            )
        value = {**self._hash_basis(), "permit_hash": self.permit_hash}
        if contains_forbidden_key(value):
            raise ContractViolation(
                "fade_forbidden_field",
                "ExecutionPermit uses a field name rejected by Fade",
            )
        validate_contract_size(
            value, MAX_EXECUTION_PERMIT_BYTES, "ExecutionPermit"
        )

    def validate_at(self, now: datetime) -> None:
        self.validate()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("WEIR validation clock must include a timezone")
        authoritative_now = now.astimezone(timezone.utc)
        issued = _parse_time(self.issued_at, "issued_at")
        expires = _parse_time(self.expires_at, "expires_at")
        if authoritative_now + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS) < issued:
            raise ContractViolation(
                "permit_not_yet_valid",
                "permit issued_at is beyond WEIR's tolerated clock skew",
            )
        if authoritative_now >= expires:
            raise ContractViolation("permit_expired", "permit has expired by WEIR's clock")
        if expires - authoritative_now < timedelta(
            seconds=MIN_PERMIT_ISSUER_MARGIN_SECONDS
        ):
            raise ContractViolation(
                "permit_expiry_margin",
                "permit does not leave the minimum dispatch margin",
            )

    def validate_for(self, proposal: ActionProposal, now: datetime) -> None:
        self.validate_at(now)
        proposal.validate()
        bindings = {
            "proposal_hash": proposal.proposal_hash,
            "work_context_hash": proposal.work_context_hash,
            "owner_run_id": proposal.owner_run_id,
            "session_id": proposal.session_id,
            "session_epoch": proposal.session_epoch,
            "action_type": proposal.action_type,
            "risk": proposal.risk,
        }
        for name, expected in bindings.items():
            if getattr(self, name) != expected:
                raise ContractViolation(
                    "permit_binding_mismatch",
                    f"ExecutionPermit.{name} does not match the ActionProposal",
                )

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> ExecutionPermit:
        required = {
            "contract_version",
            "permit_id",
            "proposal_hash",
            "work_context_hash",
            "owner_run_id",
            "session_id",
            "session_epoch",
            "action_type",
            "risk",
            "approval_ref",
            "issuer_id",
            "issued_at",
            "expires_at",
            "use_limit",
            "permit_hash",
        }
        if not isinstance(value, dict) or set(value) != required:
            raise ValueError("ExecutionPermit has missing or unknown fields")
        try:
            permit = cls(
                contract_version=value["contract_version"],
                permit_id=value["permit_id"],
                proposal_hash=value["proposal_hash"],
                work_context_hash=value["work_context_hash"],
                owner_run_id=value["owner_run_id"],
                session_id=value["session_id"],
                session_epoch=value["session_epoch"],
                action_type=ActionType(value["action_type"]),
                risk=Risk(value["risk"]),
                approval_ref=value["approval_ref"],
                issuer_id=value["issuer_id"],
                issued_at=value["issued_at"],
                expires_at=value["expires_at"],
                use_limit=value["use_limit"],
                permit_hash=value["permit_hash"],
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("ExecutionPermit field is invalid") from exc
        permit.validate()
        return permit

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {**self._hash_basis(), "permit_hash": self.permit_hash}


class ApprovalAuthority(Protocol):
    def evaluate(self, proposal: ActionProposal) -> ApprovalDecision: ...


class DenyAllApprovalAuthority:
    """Safe default until Fade/Operator owns an authenticated approval handoff."""

    def evaluate(self, proposal: ActionProposal) -> ApprovalDecision:
        proposal.validate()
        return ApprovalDecision(
            proposal_hash=proposal.proposal_hash,
            status=ApprovalStatus.DENIED,
            authority="weir-default-deny",
            decided_at=datetime.now(timezone.utc).isoformat(),
            reason="no external approval authority is configured",
        )


@dataclass(frozen=True, slots=True)
class Verification:
    method: str | None
    confidence: VerificationConfidence
    supporting_evidence_refs: tuple[str, ...]
    verified_capture_index: int | None = None

    def validate(self) -> None:
        if self.method is not None and (
            not isinstance(self.method, str) or not self.method
        ):
            raise ValueError("verification method must be null or a non-empty string")
        if not isinstance(self.confidence, VerificationConfidence):
            raise ValueError("verification confidence is invalid")
        if not isinstance(self.supporting_evidence_refs, tuple):
            raise ValueError("verification supporting_evidence_refs must be a tuple")
        if len(self.supporting_evidence_refs) > MAX_ACTION_EVIDENCE_REFS:
            raise ValueError(
                f"verification evidence cannot exceed {MAX_ACTION_EVIDENCE_REFS} references"
            )
        if len(set(self.supporting_evidence_refs)) != len(
            self.supporting_evidence_refs
        ) or any(
            not isinstance(reference, str) or not reference or len(reference) > 512
            for reference in self.supporting_evidence_refs
        ):
            raise ValueError(
                "verification supporting_evidence_refs must be unique non-empty references"
            )
        if self.verified_capture_index is not None and (
            isinstance(self.verified_capture_index, bool)
            or not isinstance(self.verified_capture_index, int)
            or self.verified_capture_index < 0
        ):
            raise ValueError("verified_capture_index must be null or non-negative")
        if self.confidence is VerificationConfidence.VERIFIED and (
            not self.method
            or not self.supporting_evidence_refs
            or self.verified_capture_index != 1
        ):
            raise ValueError(
                "verified results require a method, evidence, and capture index 1"
            )
        if self.confidence is not VerificationConfidence.VERIFIED and (
            self.verified_capture_index is not None
        ):
            raise ValueError("only verified results can name a verified capture index")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "method": self.method,
            "confidence": self.confidence.value,
            "supporting_evidence_refs": list(self.supporting_evidence_refs),
            "verified_capture_index": self.verified_capture_index,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> Verification:
        required = {
            "method",
            "confidence",
            "supporting_evidence_refs",
            "verified_capture_index",
        }
        if not isinstance(value, dict) or set(value) != required:
            raise ValueError("Verification has missing or unknown fields")
        try:
            verification = cls(
                method=value["method"],
                confidence=VerificationConfidence(value["confidence"]),
                supporting_evidence_refs=tuple(value["supporting_evidence_refs"]),
                verified_capture_index=value["verified_capture_index"],
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("Verification field is invalid") from exc
        verification.validate()
        return verification


class PostconditionVerifier:
    """Re-resolve proposal locators against one newer immutable observation."""

    def verify(
        self,
        proposal: ActionProposal,
        after_observation: Observation,
    ) -> Verification:
        proposal.validate()
        after_observation.validate()
        if after_observation.session_id != proposal.session_id:
            raise ValueError("after observation belongs to a different session")
        if after_observation.session_epoch != proposal.session_epoch:
            raise ValueError("after observation belongs to a different session epoch")
        if after_observation.session_revision <= proposal.session_revision:
            raise ValueError("after observation must have a newer session revision")
        evidence = tuple(
            dict.fromkeys(
                [after_observation.capture_id, *after_observation.artifact_refs]
            )
        )
        if not proposal.expected_postconditions:
            return Verification(
                "semantic_postconditions",
                VerificationConfidence.FAILED,
                evidence,
            )
        if not all(
            self._condition_holds(condition, after_observation)
            for condition in proposal.expected_postconditions
        ):
            return Verification(
                "semantic_postconditions",
                VerificationConfidence.FAILED,
                evidence,
            )
        return Verification(
            "semantic_postconditions",
            VerificationConfidence.VERIFIED,
            evidence,
            verified_capture_index=1,
        )

    @staticmethod
    def _condition_holds(
        condition: ActionCondition,
        observation: Observation,
    ) -> bool:
        condition.validate()
        if condition.kind is ConditionKind.URL_EQUALS:
            return observation.url == condition.expected
        if condition.kind is ConditionKind.OBSERVATION_HASH_EQUALS:
            return observation.observation_hash == condition.expected
        if condition.locator is None:
            return False
        try:
            target = resolve_locator(
                condition.locator,
                observation,
                expected_session_id=observation.session_id,
                expected_epoch=observation.session_epoch,
            )
        except LocatorNotFoundError:
            return (
                condition.kind is ConditionKind.ELEMENT_PRESENT
                and condition.expected is False
            )
        except LocatorResolutionError:
            return False
        if condition.kind is ConditionKind.ELEMENT_PRESENT:
            return condition.expected is True
        if condition.kind is ConditionKind.ELEMENT_STATE_EQUALS:
            return target.state == condition.expected
        return False


class QuarantineState(StrEnum):
    ACTIVE = "active"
    CLEARED = "cleared"


@dataclass(frozen=True, slots=True)
class QuarantineRecord:
    """Append-only state record; only an operator-authored successor clears it."""

    quarantine_id: str
    session_id: str
    session_epoch: int
    work_context_hash: str
    permit_id: str
    command_id: str
    receipt_id: str
    state: QuarantineState
    reason_code: str
    recorded_at: str
    supersedes_hash: str | None
    disposition_actor_id: str | None
    disposition_ref: str | None
    record_hash: str
    contract_version: str = QUARANTINE_RECORD_VERSION

    def _hash_basis(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "quarantine_id": self.quarantine_id,
            "session_id": self.session_id,
            "session_epoch": self.session_epoch,
            "work_context_hash": self.work_context_hash,
            "permit_id": self.permit_id,
            "command_id": self.command_id,
            "receipt_id": self.receipt_id,
            "state": self.state.value,
            "reason_code": self.reason_code,
            "recorded_at": self.recorded_at,
            "supersedes_hash": self.supersedes_hash,
            "disposition_actor_id": self.disposition_actor_id,
            "disposition_ref": self.disposition_ref,
        }

    @classmethod
    def create_active(
        cls,
        *,
        quarantine_id: str,
        session_id: str,
        session_epoch: int,
        work_context_hash: str,
        permit_id: str,
        command_id: str,
        receipt_id: str,
        recorded_at: str,
    ) -> QuarantineRecord:
        record = cls(
            quarantine_id=quarantine_id,
            session_id=session_id,
            session_epoch=session_epoch,
            work_context_hash=work_context_hash,
            permit_id=permit_id,
            command_id=command_id,
            receipt_id=receipt_id,
            state=QuarantineState.ACTIVE,
            reason_code="outcome_unknown",
            recorded_at=recorded_at,
            supersedes_hash=None,
            disposition_actor_id=None,
            disposition_ref=None,
            record_hash="",
        )
        record = replace(record, record_hash=canonical_digest(record._hash_basis()))
        record.validate()
        return record

    def clear(
        self,
        *,
        disposition_actor_id: str,
        disposition_ref: str,
        recorded_at: str,
    ) -> QuarantineRecord:
        self.validate()
        if self.state is not QuarantineState.ACTIVE:
            raise ContractViolation(
                "quarantine_already_cleared", "only an active quarantine can be cleared"
            )
        if _parse_time(recorded_at, "recorded_at") < _parse_time(
            self.recorded_at, "active recorded_at"
        ):
            raise ContractViolation(
                "quarantine_disposition_time_invalid",
                "operator disposition cannot precede the active quarantine record",
            )
        successor = replace(
            self,
            state=QuarantineState.CLEARED,
            recorded_at=recorded_at,
            supersedes_hash=self.record_hash,
            disposition_actor_id=disposition_actor_id,
            disposition_ref=disposition_ref,
            record_hash="",
        )
        successor = replace(
            successor, record_hash=canonical_digest(successor._hash_basis())
        )
        successor.validate()
        return successor

    def validate(self) -> None:
        if self.contract_version != QUARANTINE_RECORD_VERSION:
            raise ValueError("unsupported QuarantineRecord contract version")
        for name in (
            "quarantine_id",
            "session_id",
            "permit_id",
            "command_id",
            "receipt_id",
        ):
            validate_identifier(getattr(self, name), name)
        if type(self.session_epoch) is not int or self.session_epoch < 1:
            raise ValueError("session_epoch must be a positive integer")
        if not _is_sha256(self.work_context_hash) or not _is_sha256(self.record_hash):
            raise ValueError("quarantine hashes must be sha256 digests")
        if self.supersedes_hash is not None and not _is_sha256(self.supersedes_hash):
            raise ValueError("supersedes_hash must be a sha256 digest or null")
        if not isinstance(self.state, QuarantineState):
            raise ValueError("quarantine state is invalid")
        if self.reason_code != "outcome_unknown":
            raise ValueError("quarantine reason_code must be outcome_unknown")
        _parse_time(self.recorded_at, "recorded_at")
        if self.state is QuarantineState.ACTIVE:
            if any(
                value is not None
                for value in (
                    self.supersedes_hash,
                    self.disposition_actor_id,
                    self.disposition_ref,
                )
            ):
                raise ValueError("active quarantine cannot carry a disposition")
        else:
            if not self.supersedes_hash:
                raise ValueError("cleared quarantine must supersede its active record")
            validate_identifier(self.disposition_actor_id, "disposition_actor_id")
            validate_identifier(self.disposition_ref, "disposition_ref")
        if self.record_hash != canonical_digest(self._hash_basis()):
            raise ContractViolation(
                "quarantine_record_hash_mismatch",
                "record_hash does not match the QuarantineRecord",
            )
        validate_contract_size(
            {**self._hash_basis(), "record_hash": self.record_hash},
            MAX_QUARANTINE_RECORD_BYTES,
            "QuarantineRecord",
        )

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> QuarantineRecord:
        required = {
            "contract_version",
            "quarantine_id",
            "session_id",
            "session_epoch",
            "work_context_hash",
            "permit_id",
            "command_id",
            "receipt_id",
            "state",
            "reason_code",
            "recorded_at",
            "supersedes_hash",
            "disposition_actor_id",
            "disposition_ref",
            "record_hash",
        }
        if not isinstance(value, dict) or set(value) != required:
            raise ValueError("QuarantineRecord has missing or unknown fields")
        try:
            record = cls(
                contract_version=value["contract_version"],
                quarantine_id=value["quarantine_id"],
                session_id=value["session_id"],
                session_epoch=value["session_epoch"],
                work_context_hash=value["work_context_hash"],
                permit_id=value["permit_id"],
                command_id=value["command_id"],
                receipt_id=value["receipt_id"],
                state=QuarantineState(value["state"]),
                reason_code=value["reason_code"],
                recorded_at=value["recorded_at"],
                supersedes_hash=value["supersedes_hash"],
                disposition_actor_id=value["disposition_actor_id"],
                disposition_ref=value["disposition_ref"],
                record_hash=value["record_hash"],
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("QuarantineRecord field is invalid") from exc
        record.validate()
        return record

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {**self._hash_basis(), "record_hash": self.record_hash}


@dataclass(frozen=True, slots=True)
class ExecutionReceipt:
    receipt_id: str
    action_id: str
    proposal_hash: str
    permit_id: str
    work_context_hash: str
    command_id: str
    reservation_ref: str
    session_id: str
    session_epoch: int
    lease_generation: int
    executed_by: str
    executed_at: str
    result: ReceiptResult
    approval_ref: str | None
    capture_ids: tuple[str, ...]
    failure_class: FailureClass | None
    verification: Verification
    quarantine_ref: str | None
    receipt_hash: str
    contract_version: str = EXECUTION_RECEIPT_VERSION

    def _hash_basis(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "receipt_id": self.receipt_id,
            "action_id": self.action_id,
            "proposal_hash": self.proposal_hash,
            "permit_id": self.permit_id,
            "work_context_hash": self.work_context_hash,
            "command_id": self.command_id,
            "reservation_ref": self.reservation_ref,
            "session_id": self.session_id,
            "session_epoch": self.session_epoch,
            "lease_generation": self.lease_generation,
            "executed_by": self.executed_by,
            "executed_at": self.executed_at,
            "result": self.result.value,
            "approval_ref": self.approval_ref,
            "capture_ids": list(self.capture_ids),
            "failure_class": (
                None if self.failure_class is None else self.failure_class.value
            ),
            "verification": self.verification.to_dict(),
            "quarantine_ref": self.quarantine_ref,
        }

    @classmethod
    def create(
        cls,
        *,
        receipt_id: str,
        action_id: str,
        proposal_hash: str,
        permit_id: str,
        work_context_hash: str,
        command_id: str,
        reservation_ref: str,
        session_id: str,
        session_epoch: int,
        lease_generation: int,
        executed_by: str,
        executed_at: str,
        result: ReceiptResult,
        approval_ref: str | None,
        capture_ids: tuple[str, ...],
        failure_class: FailureClass | None,
        verification: Verification,
        quarantine_ref: str | None = None,
    ) -> ExecutionReceipt:
        receipt = cls(
            receipt_id=receipt_id,
            action_id=action_id,
            proposal_hash=proposal_hash,
            permit_id=permit_id,
            work_context_hash=work_context_hash,
            command_id=command_id,
            reservation_ref=reservation_ref,
            session_id=session_id,
            session_epoch=session_epoch,
            lease_generation=lease_generation,
            executed_by=executed_by,
            executed_at=executed_at,
            result=result,
            approval_ref=approval_ref,
            capture_ids=capture_ids,
            failure_class=failure_class,
            verification=verification,
            quarantine_ref=quarantine_ref,
            receipt_hash="",
        )
        receipt = replace(receipt, receipt_hash=canonical_digest(receipt._hash_basis()))
        receipt.validate()
        return receipt

    def validate(self) -> None:
        if self.contract_version != EXECUTION_RECEIPT_VERSION:
            raise ValueError("unsupported execution-receipt contract version")
        for name in (
            "receipt_id",
            "action_id",
            "permit_id",
            "command_id",
            "reservation_ref",
            "session_id",
            "executed_by",
        ):
            validate_identifier(getattr(self, name), name)
        for name in ("proposal_hash", "work_context_hash", "receipt_hash"):
            if not _is_sha256(getattr(self, name)):
                raise ValueError(f"{name} must be a sha256 digest")
        if not isinstance(self.result, ReceiptResult):
            raise ValueError("receipt result is invalid")
        if self.failure_class is not None and not isinstance(
            self.failure_class, FailureClass
        ):
            raise ValueError("receipt failure_class is invalid")
        for name in ("approval_ref", "quarantine_ref"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or not value):
                raise ValueError(f"{name} must be null or a non-empty string")
        if self.approval_ref is not None:
            validate_identifier(self.approval_ref, "approval_ref")
        if self.quarantine_ref is not None and QUARANTINE_REF_PATTERN.fullmatch(
            self.quarantine_ref
        ) is None:
            raise ValueError("quarantine_ref must be an opaque WEIR quarantine reference")
        if (
            not isinstance(self.capture_ids, tuple)
            or len(self.capture_ids) > 2
            or len(set(self.capture_ids)) != len(self.capture_ids)
            or any(
                not isinstance(value, str) or not value or len(value) > 128
                for value in self.capture_ids
            )
        ):
            raise ValueError(
                "capture_ids must contain at most two distinct non-empty identifiers"
            )
        if (
            type(self.session_epoch) is not int
            or self.session_epoch < 1
            or type(self.lease_generation) is not int
            or self.lease_generation < 1
        ):
            raise ValueError("receipt epoch and lease generation must be positive")
        _parse_time(self.executed_at, "executed_at")
        if not isinstance(self.verification, Verification):
            raise ValueError("receipt verification must be a Verification")
        self.verification.validate()
        if (
            self.result is not ReceiptResult.OUTCOME_UNKNOWN
            and self.verification.confidence is VerificationConfidence.VERIFIED
            and len(self.capture_ids) != 2
        ):
            raise ValueError("verified receipts require before and after captures")
        if self.result is ReceiptResult.COMPLETED:
            if len(self.capture_ids) != 2:
                raise ValueError("completed actions require before and after evidence")
            if not self.approval_ref:
                raise ValueError("completed actions require an approval reference")
            if self.verification.confidence is not VerificationConfidence.VERIFIED:
                raise ValueError("completed actions require verified post-state evidence")
            if self.failure_class is not None:
                raise ValueError("completed actions cannot carry a failure class")
            if self.quarantine_ref is not None:
                raise ValueError("completed actions cannot carry a quarantine reference")
        elif self.result is ReceiptResult.OUTCOME_UNKNOWN:
            if len(self.capture_ids) != 1:
                raise ContractViolation(
                    "unknown_outcome_post_state_claim",
                    "outcome_unknown retains only the pre-effect capture",
                )
            if not self.approval_ref:
                raise ValueError("outcome_unknown requires its approval reference")
            if self.failure_class is not FailureClass.OUTCOME_UNKNOWN:
                raise ValueError("outcome_unknown requires its exact failure class")
            if (
                self.verification.method is not None
                or self.verification.confidence is not VerificationConfidence.UNCERTAIN
                or self.verification.supporting_evidence_refs
                or self.verification.verified_capture_index is not None
            ):
                raise ContractViolation(
                    "unknown_outcome_verification_claim",
                    "outcome_unknown cannot claim verification or post-state evidence",
                )
            if self.quarantine_ref is None:
                raise ContractViolation(
                    "unknown_outcome_without_quarantine",
                    "outcome_unknown requires a durable quarantine reference",
                )
        else:
            if self.failure_class is None and self.result in {
                ReceiptResult.FAILED,
                ReceiptResult.BLOCKED,
            }:
                raise ValueError("failed or blocked actions require a failure class")
            if self.failure_class is FailureClass.OUTCOME_UNKNOWN:
                raise ValueError(
                    "outcome_unknown failure class requires outcome_unknown result"
                )
            if self.quarantine_ref is not None:
                raise ValueError(
                    "only outcome_unknown receipts can carry a quarantine reference"
                )
        if self.receipt_hash != canonical_digest(self._hash_basis()):
            raise ContractViolation(
                "receipt_hash_mismatch",
                "receipt_hash does not match the ExecutionReceipt",
            )
        validate_contract_size(
            {**self._hash_basis(), "receipt_hash": self.receipt_hash},
            MAX_EXECUTION_RECEIPT_BYTES,
            "ExecutionReceipt",
        )

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> ExecutionReceipt:
        required = {
            "contract_version",
            "receipt_id",
            "action_id",
            "proposal_hash",
            "permit_id",
            "work_context_hash",
            "command_id",
            "reservation_ref",
            "session_id",
            "session_epoch",
            "lease_generation",
            "executed_by",
            "executed_at",
            "result",
            "approval_ref",
            "capture_ids",
            "failure_class",
            "verification",
            "quarantine_ref",
            "receipt_hash",
        }
        if not isinstance(value, dict) or set(value) != required:
            raise ValueError("ExecutionReceipt has missing or unknown fields")
        try:
            receipt = cls(
                contract_version=value["contract_version"],
                receipt_id=value["receipt_id"],
                action_id=value["action_id"],
                proposal_hash=value["proposal_hash"],
                permit_id=value["permit_id"],
                work_context_hash=value["work_context_hash"],
                command_id=value["command_id"],
                reservation_ref=value["reservation_ref"],
                session_id=value["session_id"],
                session_epoch=value["session_epoch"],
                lease_generation=value["lease_generation"],
                executed_by=value["executed_by"],
                executed_at=value["executed_at"],
                result=ReceiptResult(value["result"]),
                approval_ref=value["approval_ref"],
                capture_ids=tuple(value["capture_ids"]),
                failure_class=(
                    None
                    if value["failure_class"] is None
                    else FailureClass(value["failure_class"])
                ),
                verification=Verification.from_dict(value["verification"]),
                quarantine_ref=value["quarantine_ref"],
                receipt_hash=value["receipt_hash"],
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("ExecutionReceipt field is invalid") from exc
        receipt.validate()
        return receipt

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {**self._hash_basis(), "receipt_hash": self.receipt_hash}


__all__ = [
    "ACTION_PROPOSAL_VERSION",
    "EXECUTION_PERMIT_VERSION",
    "EXECUTION_RECEIPT_VERSION",
    "MAX_CLOCK_SKEW_SECONDS",
    "MIN_PERMIT_ISSUER_MARGIN_SECONDS",
    "QUARANTINE_RECORD_VERSION",
    "ActionCompiler",
    "ActionCondition",
    "ActionProposal",
    "ActionType",
    "ApprovalAuthority",
    "ApprovalDecision",
    "ApprovalStatus",
    "ConditionKind",
    "DenyAllApprovalAuthority",
    "ExecutionPermit",
    "ExecutionReceipt",
    "PostconditionVerifier",
    "QuarantineRecord",
    "QuarantineState",
    "ReceiptResult",
    "Risk",
    "Verification",
    "VerificationConfidence",
]
