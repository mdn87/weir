from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import RLock
from typing import Callable, Protocol
from urllib.parse import urlsplit

from weir.actions import (
    MAX_ACTION_PARAMETERS_BYTES,
    ActionProposal,
    ActionType,
    ConditionKind,
    ExecutionPermit,
    ExecutionReceipt,
    PostconditionVerifier,
    QuarantineRecord,
    ReceiptResult,
    Risk,
    Verification,
    VerificationConfidence,
)
from weir.browser.locators import (
    LocatorAmbiguousError,
    LocatorNotFoundError,
    LocatorResolutionError,
    StaleObservationError,
    resolve_locator,
)
from weir.browser.models import (
    ControllerLease,
    Observation,
    ResolvedTarget,
    SessionState,
)
from weir.browser.store import (
    ActionExecutionReservation,
    SQLiteSessionStore,
)
from weir.contract import (
    ContractViolation,
    canonical_digest,
    canonical_json_bytes,
    is_sha256,
    is_portable_json_value,
    validate_identifier,
)
from weir.engines.base import (
    ControllerConflict,
    EnginePolicyBlocked,
    FailureClass,
    IdempotencyConflict,
)
from weir.models import DataClass
from weir.proposals import ActionProposalStore

ACTION_EFFECT_PROTOCOL_VERSION = "0.1"
ACTION_STATUS_SCHEMA_VERSION = 1
FADE_AUTHORITY_ID = "fade-weir-authority"
MAX_EFFECT_PARAMETER_TEXT = 4096
_TERMINAL_STATES = frozenset(item.value for item in ReceiptResult)
_EFFECT_COMMAND_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_REVERSIBLE_FIXTURE_ACTIONS = frozenset(
    {ActionType.FILL, ActionType.SELECT, ActionType.CHECK, ActionType.UNCHECK}
)
_EXPECTED_ROLES = {
    ActionType.FILL: frozenset({"textbox", "searchbox"}),
    ActionType.SELECT: frozenset({"combobox", "listbox"}),
    ActionType.CHECK: frozenset({"checkbox", "switch"}),
    ActionType.UNCHECK: frozenset({"checkbox", "switch"}),
}


@dataclass(frozen=True, slots=True, repr=False)
class PrivateEffectCommand:
    """Bound worker input whose full parameters never enter public projections."""

    command_id: str
    request_digest: str
    reservation_ref: str
    worker_id: str
    worker_instance_id: str
    session_id: str
    session_epoch: int
    session_revision: int
    lease_generation: int
    action_type: ActionType
    target: ResolvedTarget
    parameter_data_class: DataClass
    _parameters_json: bytes = field(repr=False)
    protocol_version: str = ACTION_EFFECT_PROTOCOL_VERSION

    @classmethod
    def create(
        cls,
        *,
        command_id: str,
        request_digest: str,
        reservation_ref: str,
        worker_id: str,
        worker_instance_id: str,
        session_id: str,
        session_epoch: int,
        session_revision: int,
        lease_generation: int,
        action_type: ActionType,
        target: ResolvedTarget,
        parameter_data_class: DataClass,
        parameters: dict[str, object],
    ) -> PrivateEffectCommand:
        payload = canonical_json_bytes(parameters)
        command = cls(
            command_id=command_id,
            request_digest=request_digest,
            reservation_ref=reservation_ref,
            worker_id=worker_id,
            worker_instance_id=worker_instance_id,
            session_id=session_id,
            session_epoch=session_epoch,
            session_revision=session_revision,
            lease_generation=lease_generation,
            action_type=action_type,
            target=target,
            parameter_data_class=parameter_data_class,
            _parameters_json=payload,
        )
        command.validate()
        return command

    def validate(self) -> None:
        if self.protocol_version != ACTION_EFFECT_PROTOCOL_VERSION:
            raise ValueError("unsupported private effect protocol version")
        for name in (
            "command_id",
            "reservation_ref",
            "worker_id",
            "worker_instance_id",
            "session_id",
        ):
            validate_identifier(getattr(self, name), name)
        if _EFFECT_COMMAND_ID.fullmatch(self.command_id) is None:
            raise ValueError("effect command_id exceeds the private worker limit")
        if not is_sha256(self.request_digest):
            raise ValueError("effect request_digest must be a sha256 digest")
        if (
            type(self.session_epoch) is not int
            or self.session_epoch < 1
            or type(self.session_revision) is not int
            or self.session_revision < 0
            or type(self.lease_generation) is not int
            or self.lease_generation < 1
        ):
            raise ValueError("effect session and lease counters are invalid")
        if not isinstance(self.action_type, ActionType):
            raise ValueError("effect action_type is invalid")
        if not isinstance(self.target, ResolvedTarget):
            raise ValueError("effect target must be a ResolvedTarget")
        self.target.validate()
        if (
            self.target.session_id != self.session_id
            or self.target.session_epoch != self.session_epoch
            or self.target.session_revision != self.session_revision
        ):
            raise ValueError("effect target does not match the command session")
        if not isinstance(self.parameter_data_class, DataClass):
            raise ValueError("effect parameter_data_class is invalid")
        if (
            not isinstance(self._parameters_json, bytes)
            or len(self._parameters_json) > MAX_ACTION_PARAMETERS_BYTES
        ):
            raise ValueError("effect parameters exceed the private worker limit")
        try:
            value = json.loads(self._parameters_json)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("effect parameters are not canonical JSON") from exc
        if (
            not isinstance(value, dict)
            or not is_portable_json_value(value, reject_fade_keys=True)
            or canonical_json_bytes(value) != self._parameters_json
        ):
            raise ValueError("effect parameters must be a canonical JSON object")

    def parameters(self) -> dict[str, object]:
        """Return a fresh private-channel copy for the worker adapter only."""

        self.validate()
        value = json.loads(self._parameters_json)
        assert isinstance(value, dict)
        return value

    def __repr__(self) -> str:
        return (
            "PrivateEffectCommand("
            f"command_id={self.command_id!r}, worker_id={self.worker_id!r}, "
            f"worker_instance_id={self.worker_instance_id!r}, "
            f"session_id={self.session_id!r}, "
            f"action_type={self.action_type.value!r}, parameters=<redacted>)"
        )


@dataclass(frozen=True, slots=True)
class EffectResult:
    worker_id: str
    worker_instance_id: str
    applied: bool | None
    failure_class: FailureClass | None = None

    def validate(self) -> None:
        validate_identifier(self.worker_id, "worker_id")
        validate_identifier(self.worker_instance_id, "worker_instance_id")
        if self.applied is not None and type(self.applied) is not bool:
            raise ValueError("effect applied marker must be true, false, or null")
        if self.failure_class is not None and not isinstance(
            self.failure_class, FailureClass
        ):
            raise ValueError("effect failure_class is invalid")
        if self.applied is True and self.failure_class is not None:
            raise ValueError("an applied effect cannot carry a failure class")
        if self.applied is False and (
            self.failure_class is None
            or self.failure_class is FailureClass.OUTCOME_UNKNOWN
        ):
            raise ValueError("a disproved effect requires a definite failure class")
        if self.applied is None and self.failure_class is not FailureClass.OUTCOME_UNKNOWN:
            raise ValueError("an ambiguous effect requires outcome_unknown")


class EffectWorker(Protocol):
    """Trusted adapter seam; implementations must persist observations before return."""

    @property
    def worker_id(self) -> str: ...

    @property
    def worker_instance_id(self) -> str: ...

    def observe(
        self,
        session_id: str,
        *,
        command_id: str,
        stage: str,
    ) -> Observation: ...

    def apply(self, command: PrivateEffectCommand) -> EffectResult: ...


@dataclass(frozen=True, slots=True)
class SyntheticFixtureEffectPolicy:
    """Narrow source-only allowlist for a loopback synthetic page."""

    site_profile_id: str
    origin: str
    allowed_actions: frozenset[ActionType] = _REVERSIBLE_FIXTURE_ACTIONS

    def __post_init__(self) -> None:
        validate_identifier(self.site_profile_id, "site_profile_id")
        normalized = _loopback_origin(self.origin)
        object.__setattr__(self, "origin", normalized)
        if (
            not isinstance(self.allowed_actions, frozenset)
            or not self.allowed_actions
            or not self.allowed_actions <= _REVERSIBLE_FIXTURE_ACTIONS
        ):
            raise ValueError("fixture policy contains a non-reversible action type")

    def validate(
        self,
        proposal: ActionProposal,
        store: SQLiteSessionStore,
    ) -> None:
        proposal.validate()
        if proposal.action_type not in self.allowed_actions:
            raise EnginePolicyBlocked("action type is outside the synthetic allowlist")
        if proposal.risk is not Risk.UNKNOWN:
            raise EnginePolicyBlocked("generic fixture effects must retain risk=unknown")
        if proposal.parameter_data_class is not DataClass.PUBLIC:
            raise EnginePolicyBlocked("synthetic fixture parameters must be public")
        binding = store.profile_binding(proposal.session_id)
        session = store.get_session(proposal.session_id)
        if binding.site_profile_id != self.site_profile_id:
            raise EnginePolicyBlocked("browser session is not bound to the fixture profile")
        if session.state is not SessionState.ACTIVE:
            raise EnginePolicyBlocked("synthetic action requires an active session")
        if session.current_url is None or (
            _origin(session.current_url) != self.origin
        ):
            raise EnginePolicyBlocked("browser session is outside the fixture origin")
        _validate_fixture_parameters(proposal)

    def validate_observation(self, observation: Observation) -> None:
        observation.validate()
        if _origin(observation.url) != self.origin:
            raise EnginePolicyBlocked("action observation left the fixture origin")


@dataclass(frozen=True, slots=True)
class ActionExecutionStatus:
    command_id: str
    permit_id: str
    request_digest: str
    state: str
    receipt: ExecutionReceipt | None
    schema_version: int = ACTION_STATUS_SCHEMA_VERSION

    def validate(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise ValueError("unsupported action status schema version")
        validate_identifier(self.command_id, "command_id")
        validate_identifier(self.permit_id, "permit_id")
        if not is_sha256(self.request_digest):
            raise ValueError("action status request_digest must be a sha256 digest")
        if self.state not in {"reserved", "executing", *_TERMINAL_STATES}:
            raise ValueError("action status state is invalid")
        terminal = self.state in _TERMINAL_STATES
        if terminal != (self.receipt is not None):
            raise ValueError("terminal action status requires exactly one receipt")
        if self.receipt is not None:
            self.receipt.validate()
            if self.receipt.result.value != self.state:
                raise ValueError("action status differs from its receipt result")
            if (
                self.receipt.command_id != self.command_id
                or self.receipt.permit_id != self.permit_id
            ):
                raise ValueError("action status receipt binding is invalid")

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "command_id": self.command_id,
            "permit_id": self.permit_id,
            "request_digest": self.request_digest,
            "state": self.state,
            "receipt": None if self.receipt is None else self.receipt.to_dict(),
        }


class BrowserActionDriver:
    """Permit-bound effect coordinator; no production worker is registered by default."""

    def __init__(
        self,
        store: SQLiteSessionStore,
        proposal_store: ActionProposalStore,
        worker: EffectWorker,
        policy: SyntheticFixtureEffectPolicy,
        *,
        clock: Callable[[], datetime] | None = None,
        verifier: PostconditionVerifier | None = None,
        driver_id: str = "weir-synthetic-effect-driver",
    ) -> None:
        if proposal_store.session_store is not store:
            raise ValueError("action driver stores must share one session ledger")
        validate_identifier(driver_id, "driver_id")
        worker_id = worker.worker_id
        worker_instance_id = worker.worker_instance_id
        validate_identifier(worker_id, "worker_id")
        validate_identifier(worker_instance_id, "worker_instance_id")
        if not isinstance(policy, SyntheticFixtureEffectPolicy):
            raise TypeError("action driver requires an explicit synthetic fixture policy")
        self.store = store
        self.proposal_store = proposal_store
        self.worker = worker
        self.worker_id = worker_id
        self.worker_instance_id = worker_instance_id
        self.policy = policy
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.verifier = verifier or PostconditionVerifier()
        self.driver_id = driver_id
        self._lock = RLock()

    def execute(
        self,
        *,
        command_id: str,
        request_digest: str,
        submitted_proposal: ActionProposal,
        permit: ExecutionPermit,
    ) -> ActionExecutionStatus:
        with self._lock:
            validate_identifier(command_id, "command_id")
            if not is_sha256(request_digest):
                raise ValueError("action request_digest must be a sha256 digest")
            submitted_proposal.validate()
            permit.validate()
            expected_digest = action_request_digest(
                command_id, submitted_proposal, permit
            )
            if request_digest != expected_digest:
                raise ContractViolation(
                    "action_request_digest_mismatch",
                    "action request digest does not match the submitted authority bundle",
                )
            if permit.issuer_id != FADE_AUTHORITY_ID:
                raise ContractViolation(
                    "permit_issuer_mismatch",
                    "execution permit was not issued by Fade's authority identity",
                )
            proposal = self.proposal_store.load(submitted_proposal.proposal_hash)
            if proposal.to_dict() != submitted_proposal.to_dict():
                raise ContractViolation(
                    "proposal_binding_mismatch",
                    "submitted proposal differs from WEIR's immutable proposal",
                )
            existing = self.store.action_reservation(permit.permit_id)
            if existing is not None:
                self._require_replay_binding(
                    existing,
                    proposal=proposal,
                    permit=permit,
                    command_id=command_id,
                    request_digest=request_digest,
                )
                return self._recover(
                    existing,
                    approval_ref=permit.approval_ref,
                )
            permit.validate_for(proposal, self._now())
            self.policy.validate(proposal, self.store)
            self._require_bound_worker()
            lease = self._owning_lease(proposal)
            start = self.store.reserve_action_execution(
                permit,
                proposal,
                request_digest=request_digest,
                command_id=command_id,
                worker_id=self.worker_id,
                worker_instance_id=self.worker_instance_id,
                required_lease=lease,
            )
            if start.replay:
                return self._recover(
                    start.reservation,
                    approval_ref=permit.approval_ref,
                )
            if start.lease is None:
                raise ControllerConflict(
                    "new action reservation did not return its exclusive lease"
                )
            return self._execute_reserved(
                start.reservation, proposal, permit, start.lease
            )

    def status(
        self,
        command_id: str,
        *,
        recover: bool = True,
    ) -> ActionExecutionStatus | None:
        with self._lock:
            reservation = self.store.action_reservation_by_command(command_id)
            if reservation is None:
                return None
            if recover and self.store.load_receipt(reservation.action_id) is None:
                return self._recover(reservation, approval_ref=None)
            return self._status(reservation)

    def required_data_classes(self, command_id: str) -> frozenset[DataClass]:
        reservation = self.store.action_reservation_by_command(command_id)
        if reservation is None:
            raise KeyError(command_id)
        return self.proposal_store.required_data_classes(reservation.proposal_hash)

    def _execute_reserved(
        self,
        reservation: ActionExecutionReservation,
        proposal: ActionProposal,
        permit: ExecutionPermit,
        lease: ControllerLease,
    ) -> ActionExecutionStatus:
        before: Observation | None = None
        try:
            self._require_bound_worker()
            before = self.worker.observe(
                proposal.session_id,
                command_id=_phase_command_id(reservation.command_id, "before"),
                stage="before",
            )
            self._validate_before(proposal, before)
            target = resolve_locator(
                proposal.semantic_locator,
                before,
                expected_session_id=proposal.session_id,
                expected_revision=before.session_revision,
                expected_epoch=proposal.session_epoch,
            )
            self._require_preconditions(proposal, before)
            lease = self._same_fence(reservation, proposal, lease)
            command = PrivateEffectCommand.create(
                command_id=reservation.command_id,
                request_digest=reservation.request_digest,
                reservation_ref=reservation.reservation_ref,
                worker_id=self.worker_id,
                worker_instance_id=self.worker_instance_id,
                session_id=proposal.session_id,
                session_epoch=proposal.session_epoch,
                session_revision=before.session_revision,
                lease_generation=lease.generation,
                action_type=proposal.action_type,
                target=target,
                parameter_data_class=proposal.parameter_data_class,
                parameters=proposal.parameters,
            )
            self.store.mark_action_dispatching(
                reservation.reservation_ref,
                before_capture_id=before.capture_id,
                approval_ref=permit.approval_ref,
                worker_id=self.worker_id,
                worker_instance_id=self.worker_instance_id,
                permit=permit,
                proposal=proposal,
                expected_session_revision=before.session_revision,
                required_lease=lease,
            )
        except Exception as exc:
            terminal = self._existing_status(reservation)
            if terminal is not None:
                return terminal
            return self._finalize_definite(
                reservation,
                approval_ref=permit.approval_ref,
                result=ReceiptResult.BLOCKED,
                failure_class=_failure_class(exc),
                before=before,
                executed_by=self.driver_id,
            )

        try:
            self._require_bound_worker()
            result = self.worker.apply(command)
            if not isinstance(result, EffectResult):
                raise TypeError("effect worker returned an invalid result")
            result.validate()
            if (
                result.worker_id != self.worker_id
                or result.worker_instance_id != self.worker_instance_id
            ):
                raise ValueError(
                    "effect result worker identity does not match the bound adapter"
                )
            if result.applied is None:
                return self._finalize_unknown(
                    reservation,
                    permit.approval_ref,
                    before.capture_id,
                    result.worker_id,
                )
            if result.applied is False:
                assert result.failure_class is not None
                return self._finalize_definite(
                    reservation,
                    approval_ref=permit.approval_ref,
                    result=ReceiptResult.FAILED,
                    failure_class=result.failure_class,
                    before=before,
                    executed_by=result.worker_id,
                )
            self._require_bound_worker()
            after = self.worker.observe(
                proposal.session_id,
                command_id=_phase_command_id(reservation.command_id, "after"),
                stage="after",
            )
            self._validate_after(proposal, before, after)
            verification = self.verifier.verify(proposal, after)
            if verification.confidence is VerificationConfidence.VERIFIED:
                return self._finalize_verified(
                    reservation, permit, before, after, result.worker_id, verification
                )
            return self._finalize_definite(
                reservation,
                approval_ref=permit.approval_ref,
                result=ReceiptResult.FAILED,
                failure_class=FailureClass.VERIFICATION_FAILED,
                before=before,
                after=after,
                executed_by=result.worker_id,
                verification=verification,
            )
        except Exception:
            terminal = self._existing_status(reservation)
            if terminal is not None:
                return terminal
            return self._finalize_unknown(
                reservation,
                permit.approval_ref,
                before.capture_id,
                self.worker_id,
            )

    def _validate_before(
        self, proposal: ActionProposal, observation: Observation
    ) -> None:
        self.policy.validate_observation(observation)
        self.proposal_store.verify_observation_evidence(
            observation, proposal=proposal
        )
        session = self.store.get_session(proposal.session_id)
        if (
            session.state is not SessionState.PAUSED
            or session.epoch != proposal.session_epoch
            or session.revision != observation.session_revision
            or session.current_url != observation.url
            or observation.session_revision <= proposal.session_revision
        ):
            raise StaleObservationError(
                "reacquired action pre-state is not the current newer session state"
            )

    def _validate_after(
        self,
        proposal: ActionProposal,
        before: Observation,
        after: Observation,
    ) -> None:
        self.policy.validate_observation(after)
        self.proposal_store.verify_observation_evidence(after, proposal=proposal)
        session = self.store.get_session(proposal.session_id)
        if (
            session.state is not SessionState.PAUSED
            or session.epoch != proposal.session_epoch
            or session.revision != after.session_revision
            or session.current_url != after.url
            or after.session_revision <= before.session_revision
        ):
            raise StaleObservationError(
                "action post-state is not the current newer session state"
            )

    def _require_preconditions(
        self, proposal: ActionProposal, observation: Observation
    ) -> None:
        for condition in proposal.preconditions:
            # This condition binds the approved proposal to its retained source
            # observation. A newly captured pre-state has a different capture ID and
            # therefore a different observation hash even when the page is unchanged.
            if condition.kind is ConditionKind.OBSERVATION_HASH_EQUALS:
                holds = condition.expected == proposal.observation_hash
            else:
                holds = self.verifier.condition_holds(condition, observation)
            if not holds:
                raise StaleObservationError(
                    "reacquired action pre-state no longer satisfies the proposal"
                )

    def _owning_lease(self, proposal: ActionProposal) -> ControllerLease:
        lease = self.store.active_lease(proposal.session_id)
        if lease is None:
            raise ControllerConflict("action execution has no active controller lease")
        if lease.controller_id != proposal.owner_run_id:
            raise ControllerConflict("action execution has the wrong controller owner")
        return lease

    def _require_bound_worker(self) -> None:
        if (
            self.worker.worker_id != self.worker_id
            or self.worker.worker_instance_id != self.worker_instance_id
        ):
            raise ControllerConflict(
                "effect worker identity changed after the driver was constructed"
            )

    def _same_fence(
        self,
        reservation: ActionExecutionReservation,
        proposal: ActionProposal,
        reserved_lease: ControllerLease,
    ) -> ControllerLease:
        lease = self._owning_lease(proposal)
        if (
            lease.generation != reservation.controller_generation
            or lease.generation != reserved_lease.generation
            or lease.lease_id != reserved_lease.lease_id
            or lease.fencing_token != reserved_lease.fencing_token
        ):
            raise ControllerConflict("action controller fence changed before dispatch")
        return lease

    @staticmethod
    def _require_replay_binding(
        reservation: ActionExecutionReservation,
        *,
        proposal: ActionProposal,
        permit: ExecutionPermit,
        command_id: str,
        request_digest: str,
    ) -> None:
        expected = {
            "permit_hash": permit.permit_hash,
            "action_id": proposal.action_id,
            "request_digest": request_digest,
            "proposal_hash": proposal.proposal_hash,
            "work_context_hash": proposal.work_context_hash,
            "command_id": command_id,
            "session_id": proposal.session_id,
            "session_epoch": proposal.session_epoch,
        }
        if any(getattr(reservation, name) != value for name, value in expected.items()):
            raise IdempotencyConflict(
                "execution permit is bound to a different action request"
            )

    def _recover(
        self,
        reservation: ActionExecutionReservation,
        *,
        approval_ref: str | None,
    ) -> ActionExecutionStatus:
        terminal = self._existing_status(reservation)
        if terminal is not None:
            return terminal
        marker = self.store.action_dispatch_marker(reservation.reservation_ref)
        if marker is None:
            return self._finalize_definite(
                reservation,
                approval_ref=None,
                result=ReceiptResult.CANCELLED,
                failure_class=None,
                before=None,
                executed_by=self.driver_id,
            )
        if approval_ref is not None and approval_ref != marker.approval_ref:
            raise ContractViolation(
                "approval_binding_mismatch",
                "replayed permit approval differs from the dispatch marker",
            )
        return self._finalize_unknown(
            reservation,
            marker.approval_ref,
            marker.before_capture_id,
            marker.worker_id,
        )

    def _finalize_verified(
        self,
        reservation: ActionExecutionReservation,
        permit: ExecutionPermit,
        before: Observation,
        after: Observation,
        executed_by: str,
        verification: Verification,
    ) -> ActionExecutionStatus:
        receipt = self._receipt(
            reservation,
            approval_ref=permit.approval_ref,
            result=ReceiptResult.COMPLETED,
            capture_ids=(before.capture_id, after.capture_id),
            failure_class=None,
            executed_by=executed_by,
            verification=verification,
        )
        self.store.finalize_action_execution(receipt)
        return self._status(reservation)

    def _finalize_definite(
        self,
        reservation: ActionExecutionReservation,
        *,
        approval_ref: str | None,
        result: ReceiptResult,
        failure_class: FailureClass | None,
        before: Observation | None,
        executed_by: str,
        after: Observation | None = None,
        verification: Verification | None = None,
    ) -> ActionExecutionStatus:
        captures = tuple(
            item.capture_id for item in (before, after) if item is not None
        )
        evidence = tuple(captures)
        receipt = self._receipt(
            reservation,
            approval_ref=approval_ref,
            result=result,
            capture_ids=captures,
            failure_class=failure_class,
            executed_by=executed_by,
            verification=verification
            or Verification(None, VerificationConfidence.BLOCKED, evidence),
        )
        try:
            self.store.finalize_action_execution(receipt)
        except IdempotencyConflict:
            terminal = self._existing_status(reservation)
            if terminal is None:
                raise
            return terminal
        return self._status(reservation)

    def _finalize_unknown(
        self,
        reservation: ActionExecutionReservation,
        approval_ref: str,
        before_capture_id: str,
        executed_by: str,
    ) -> ActionExecutionStatus:
        receipt_id = _derived_id(
            "receipt", reservation.reservation_ref, ReceiptResult.OUTCOME_UNKNOWN.value
        )
        quarantine_id = _derived_id(
            "quarantine", reservation.reservation_ref, "outcome-unknown"
        )
        quarantine_ref = f"weir-quarantine:{quarantine_id}"
        receipt = ExecutionReceipt.create(
            receipt_id=receipt_id,
            action_id=reservation.action_id,
            proposal_hash=reservation.proposal_hash,
            permit_id=reservation.permit_id,
            work_context_hash=reservation.work_context_hash,
            command_id=reservation.command_id,
            reservation_ref=reservation.reservation_ref,
            session_id=reservation.session_id,
            session_epoch=reservation.session_epoch,
            lease_generation=reservation.controller_generation,
            executed_by=executed_by,
            executed_at=self._now().isoformat(),
            result=ReceiptResult.OUTCOME_UNKNOWN,
            approval_ref=approval_ref,
            capture_ids=(before_capture_id,),
            failure_class=FailureClass.OUTCOME_UNKNOWN,
            verification=Verification(
                None, VerificationConfidence.UNCERTAIN, ()
            ),
            quarantine_ref=quarantine_ref,
        )
        quarantine = QuarantineRecord.create_active(
            quarantine_id=quarantine_id,
            session_id=reservation.session_id,
            session_epoch=reservation.session_epoch,
            work_context_hash=reservation.work_context_hash,
            permit_id=reservation.permit_id,
            command_id=reservation.command_id,
            receipt_id=receipt_id,
            recorded_at=self._now().isoformat(),
        )
        try:
            self.store.finalize_action_execution(receipt, quarantine=quarantine)
        except IdempotencyConflict:
            terminal = self._existing_status(reservation)
            if terminal is None:
                raise
            return terminal
        return self._status(reservation)

    def _receipt(
        self,
        reservation: ActionExecutionReservation,
        *,
        approval_ref: str | None,
        result: ReceiptResult,
        capture_ids: tuple[str, ...],
        failure_class: FailureClass | None,
        executed_by: str,
        verification: Verification,
    ) -> ExecutionReceipt:
        return ExecutionReceipt.create(
            receipt_id=_derived_id(
                "receipt", reservation.reservation_ref, result.value
            ),
            action_id=reservation.action_id,
            proposal_hash=reservation.proposal_hash,
            permit_id=reservation.permit_id,
            work_context_hash=reservation.work_context_hash,
            command_id=reservation.command_id,
            reservation_ref=reservation.reservation_ref,
            session_id=reservation.session_id,
            session_epoch=reservation.session_epoch,
            lease_generation=reservation.controller_generation,
            executed_by=executed_by,
            executed_at=self._now().isoformat(),
            result=result,
            approval_ref=approval_ref,
            capture_ids=capture_ids,
            failure_class=failure_class,
            verification=verification,
        )

    def _existing_status(
        self, reservation: ActionExecutionReservation
    ) -> ActionExecutionStatus | None:
        return (
            self._status(reservation)
            if self.store.load_receipt(reservation.action_id) is not None
            else None
        )

    def _status(
        self, reservation: ActionExecutionReservation
    ) -> ActionExecutionStatus:
        receipt_value = self.store.load_receipt(reservation.action_id)
        receipt = (
            None
            if receipt_value is None
            else ExecutionReceipt.from_dict(receipt_value)
        )
        state = (
            receipt.result.value
            if receipt is not None
            else (
                "executing"
                if self.store.action_dispatch_capture(reservation.reservation_ref)
                is not None
                else "reserved"
            )
        )
        status = ActionExecutionStatus(
            command_id=reservation.command_id,
            permit_id=reservation.permit_id,
            request_digest=reservation.request_digest,
            state=state,
            receipt=receipt,
        )
        status.validate()
        return status

    def _now(self) -> datetime:
        value = self.clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise ValueError("action driver clock must return an aware datetime")
        return value.astimezone(timezone.utc)


def action_request_digest(
    command_id: str,
    proposal: ActionProposal,
    permit: ExecutionPermit,
) -> str:
    validate_identifier(command_id, "command_id")
    proposal.validate()
    permit.validate()
    return canonical_digest(
        {
            "schema_version": 1,
            "command_id": command_id,
            "proposal": proposal.to_dict(),
            "permit": permit.to_dict(),
        }
    )


def _phase_command_id(command_id: str, phase: str) -> str:
    suffix = canonical_digest({"command_id": command_id, "phase": phase})[7:39]
    return f"effect-{phase}-{suffix}"


def _derived_id(prefix: str, reservation_ref: str, purpose: str) -> str:
    suffix = canonical_digest(
        {"reservation_ref": reservation_ref, "purpose": purpose}
    )[7:47]
    return f"{prefix}-{suffix}"


def _failure_class(exc: Exception) -> FailureClass:
    if isinstance(exc, LocatorAmbiguousError):
        return FailureClass.AMBIGUOUS_TARGET
    if isinstance(
        exc, (LocatorNotFoundError, StaleObservationError, LocatorResolutionError)
    ):
        return FailureClass.STALE_REFERENCE
    if isinstance(exc, ControllerConflict):
        return FailureClass.CONTROLLER_CONFLICT
    if isinstance(exc, EnginePolicyBlocked):
        return FailureClass.POLICY_BLOCKED
    if isinstance(exc, ContractViolation):
        return FailureClass.VERIFICATION_FAILED
    return FailureClass.ENGINE_FAILURE


def _validate_fixture_parameters(proposal: ActionProposal) -> None:
    parameters = proposal.parameters
    if proposal.action_type in {ActionType.FILL, ActionType.SELECT}:
        if set(parameters) != {"value"} or not isinstance(parameters["value"], str):
            raise EnginePolicyBlocked(
                "fixture fill/select parameters require one string value"
            )
        if len(parameters["value"]) > MAX_EFFECT_PARAMETER_TEXT:
            raise EnginePolicyBlocked("fixture parameter value is too large")
    elif parameters:
        raise EnginePolicyBlocked("fixture check actions do not accept parameters")
    if proposal.resolved_target.role not in _EXPECTED_ROLES[proposal.action_type]:
        raise EnginePolicyBlocked("fixture target role does not match the action type")


def _loopback_origin(value: str) -> str:
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("fixture origin has an invalid port") from exc
    if (
        parsed.scheme != "http"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError("fixture origin must be an HTTP loopback origin")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise ValueError("fixture origin must use a loopback IP literal") from exc
    if not address.is_loopback:
        raise ValueError("fixture origin must use a loopback address")
    host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    return f"http://{host}" + ("" if port is None else f":{port}")


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise EnginePolicyBlocked("action URL has an invalid port") from exc
    if (
        parsed.scheme != "http"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise EnginePolicyBlocked("action URL is not a safe fixture URL")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise EnginePolicyBlocked("action URL must use a loopback IP literal") from exc
    if not address.is_loopback:
        raise EnginePolicyBlocked("action URL left the loopback fixture")
    host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    return f"http://{host}" + ("" if port is None else f":{port}")


__all__ = [
    "ACTION_EFFECT_PROTOCOL_VERSION",
    "ACTION_STATUS_SCHEMA_VERSION",
    "FADE_AUTHORITY_ID",
    "ActionExecutionStatus",
    "BrowserActionDriver",
    "EffectResult",
    "EffectWorker",
    "PrivateEffectCommand",
    "SyntheticFixtureEffectPolicy",
    "action_request_digest",
]
