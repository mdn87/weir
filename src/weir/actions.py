from __future__ import annotations

import hashlib
import json
import math
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Protocol

from weir.browser.locators import (
    LocatorNotFoundError,
    LocatorResolutionError,
    resolve_locator,
)
from weir.browser.models import (
    BROWSER_CONTRACT_VERSION,
    Observation,
    ResolvedTarget,
    SemanticLocator,
)
from weir.engines.base import FailureClass


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
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


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
    return (
        isinstance(value, str)
        and value.startswith("sha256:")
        and len(value) == 71
        and all(character in "0123456789abcdef" for character in value[7:])
    )


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


@dataclass(slots=True)
class ActionProposal:
    action_id: str
    request_id: str
    owner_run_id: str
    session_id: str
    session_revision: int
    session_epoch: int
    observation_id: str
    observation_hash: str
    action_type: ActionType
    semantic_locator: SemanticLocator
    resolved_target: ResolvedTarget
    parameters: dict[str, Any]
    risk: Risk
    requires_approval: bool
    preconditions: list[ActionCondition]
    expected_postconditions: list[ActionCondition]
    evidence_refs: list[str]
    created_at: str
    expires_at: str
    proposal_hash: str
    contract_version: str = BROWSER_CONTRACT_VERSION

    def _hash_basis(self) -> dict[str, Any]:
        value = self.to_dict(validate=False)
        value.pop("proposal_hash")
        return value

    def compute_hash(self) -> str:
        return _canonical_digest(self._hash_basis())

    def validate(self) -> None:
        if self.contract_version != BROWSER_CONTRACT_VERSION:
            raise ValueError("unsupported action-proposal contract version")
        for name in (
            "action_id",
            "request_id",
            "owner_run_id",
            "session_id",
            "observation_id",
        ):
            if not isinstance(getattr(self, name), str) or not getattr(self, name):
                raise ValueError(f"{name} cannot be empty")
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
        if not isinstance(self.parameters, dict) or not _is_json_value(self.parameters):
            raise ValueError("action parameters must be a JSON-compatible object")
        if not isinstance(self.preconditions, list) or not isinstance(
            self.expected_postconditions, list
        ):
            raise ValueError("proposal conditions must be arrays")
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
        if len(set(self.evidence_refs)) != len(self.evidence_refs) or any(
            not isinstance(item, str) or not item for item in self.evidence_refs
        ):
            raise ValueError("evidence_refs must contain unique non-empty references")
        if _parse_time(self.expires_at, "expires_at") <= _parse_time(
            self.created_at, "created_at"
        ):
            raise ValueError("action proposal must expire after it is created")
        if self.proposal_hash != self.compute_hash():
            raise ValueError("proposal_hash does not match the proposal")

    def to_dict(self, *, validate: bool = True) -> dict[str, Any]:
        if validate:
            self.validate()
        return {
            "contract_version": self.contract_version,
            "action_id": self.action_id,
            "request_id": self.request_id,
            "owner_run_id": self.owner_run_id,
            "session_id": self.session_id,
            "session_revision": self.session_revision,
            "session_epoch": self.session_epoch,
            "observation_id": self.observation_id,
            "observation_hash": self.observation_hash,
            "action_type": self.action_type.value,
            "semantic_locator": self.semantic_locator.to_dict(),
            "resolved_target": self.resolved_target.to_dict(),
            "parameters": self.parameters,
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


class ActionCompiler:
    """Compile evidence into a proposal; this class deliberately cannot execute it."""

    def propose(
        self,
        *,
        action_id: str,
        request_id: str,
        owner_run_id: str,
        observation: Observation,
        locator: SemanticLocator,
        action_type: ActionType,
        parameters: dict[str, Any] | None,
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
            session_id=observation.session_id,
            session_revision=observation.session_revision,
            session_epoch=observation.session_epoch,
            observation_id=observation.observation_id,
            observation_hash=observation.observation_hash,
            action_type=action_type,
            semantic_locator=locator,
            resolved_target=target,
            parameters=dict(parameters or {}),
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
        if len(set(self.supporting_evidence_refs)) != len(
            self.supporting_evidence_refs
        ) or any(
            not isinstance(reference, str) or not reference
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


@dataclass(frozen=True, slots=True)
class ExecutionReceipt:
    receipt_id: str
    action_id: str
    proposal_hash: str
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
    contract_version: str = BROWSER_CONTRACT_VERSION

    def validate(self) -> None:
        if self.contract_version != BROWSER_CONTRACT_VERSION:
            raise ValueError("unsupported execution-receipt contract version")
        for name in ("receipt_id", "action_id", "session_id", "executed_by"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} cannot be empty")
        if not _is_sha256(self.proposal_hash):
            raise ValueError("proposal_hash must be a sha256 digest")
        if not isinstance(self.result, ReceiptResult):
            raise ValueError("receipt result is invalid")
        if self.failure_class is not None and not isinstance(
            self.failure_class, FailureClass
        ):
            raise ValueError("receipt failure_class is invalid")
        for name in ("approval_ref",):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or not value):
                raise ValueError(f"{name} must be null or a non-empty string")
        if (
            not isinstance(self.capture_ids, tuple)
            or len(self.capture_ids) > 2
            or len(set(self.capture_ids)) != len(self.capture_ids)
            or any(not isinstance(value, str) or not value for value in self.capture_ids)
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
            self.verification.confidence is VerificationConfidence.VERIFIED
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
        elif self.failure_class is None and self.result in {
            ReceiptResult.FAILED,
            ReceiptResult.BLOCKED,
        }:
            raise ValueError("failed or blocked actions require a failure class")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        value = asdict(self)
        value["result"] = self.result.value
        value["failure_class"] = (
            None if self.failure_class is None else self.failure_class.value
        )
        value["verification"] = self.verification.to_dict()
        value["capture_ids"] = list(self.capture_ids)
        return value


__all__ = [
    "ActionCompiler",
    "ActionCondition",
    "ActionProposal",
    "ActionType",
    "ApprovalAuthority",
    "ApprovalDecision",
    "ApprovalStatus",
    "ConditionKind",
    "DenyAllApprovalAuthority",
    "ExecutionReceipt",
    "PostconditionVerifier",
    "ReceiptResult",
    "Risk",
    "Verification",
    "VerificationConfidence",
]
