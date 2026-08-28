from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from weir.actions import ActionProposal, ConditionKind
from weir.browser.locators import LocatorResolutionError, resolve_locator
from weir.browser.models import Observation, SessionState
from weir.browser.store import SQLiteSessionStore
from weir.contract import (
    ContractViolation,
    canonical_digest,
    canonical_json_bytes,
    is_sha256,
    parse_timestamp,
)
from weir.events import CorrelationHeader, WeirActionEvent
from weir.models import DataClass
from weir.persistence import CaptureStore, _write_immutable
from weir.work_context import WorkContext

PROPOSAL_STORE_VERSION = 1
MAX_PROPOSAL_STORE_DOCUMENT_BYTES = 512 * 1024


class ProposalNotFound(FileNotFoundError):
    pass


@dataclass(frozen=True, slots=True)
class ProposalRecord:
    proposal: ActionProposal
    projection: WeirActionEvent
    observation_capture_id: str
    session_data_class: DataClass

    @property
    def required_data_classes(self) -> frozenset[DataClass]:
        return frozenset(
            {self.session_data_class, self.proposal.parameter_data_class}
        )


class ActionProposalStore:
    """Immutable proposal registry bound to durable browser observations."""

    def __init__(
        self,
        root: Path,
        capture_store: CaptureStore,
        session_store: SQLiteSessionStore,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.root = root
        self.capture_store = capture_store
        self.session_store = session_store
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = threading.RLock()

    def register(self, proposal: ActionProposal) -> ActionProposal:
        self._require_live_proposal(proposal)
        observation, session_data_class = self._verify_observation_binding(
            proposal, require_current=True
        )
        projection = self._projection(proposal)
        metadata = self._metadata(
            proposal,
            projection=projection,
            observation_capture_id=observation.capture_id,
            session_data_class=session_data_class,
        )

        with self._lock:
            self._write_action_index(proposal.action_id, metadata)
            self._write_document(
                self._proposal_path(proposal.proposal_hash), proposal.to_dict()
            )
            self._write_document(
                self._projection_path(proposal.proposal_hash), projection.to_dict()
            )
            self._write_document(
                self._registration_path(proposal.proposal_hash), metadata
            )

        return self.load(proposal.proposal_hash)

    def load(self, proposal_hash: str) -> ActionProposal:
        return self.load_record(proposal_hash).proposal

    def load_by_action(self, action_id: str) -> ActionProposal:
        metadata = self._read_document(
            self._action_path(action_id),
            reason_code="proposal_not_found",
            missing_message="WEIR action proposal was not found",
        )
        if metadata.get("action_id") != action_id:
            raise ContractViolation(
                "proposal_store_corrupt",
                "proposal action index does not match its lookup key",
            )
        proposal_hash = metadata.get("proposal_hash")
        if not is_sha256(proposal_hash):
            raise ContractViolation(
                "proposal_store_corrupt",
                "proposal action index has an invalid proposal hash",
            )
        return self.load(proposal_hash)

    def load_projection(self, proposal_hash: str) -> WeirActionEvent:
        _require_proposal_hash(proposal_hash)
        with self._lock:
            metadata = self._read_document(
                self._registration_path(proposal_hash),
                reason_code="proposal_not_found",
                missing_message="WEIR action proposal was not found",
            )
            action_id = metadata.get("action_id")
            if not isinstance(action_id, str):
                raise ContractViolation(
                    "proposal_store_corrupt",
                    "proposal registration has no action identifier",
                )
            action_metadata = self._read_document(
                self._action_path(action_id),
                reason_code="proposal_store_corrupt",
                missing_message="registered proposal action index is incomplete",
            )
            try:
                projection = WeirActionEvent.from_dict(
                    self._read_document(
                        self._projection_path(proposal_hash),
                        reason_code="proposal_store_corrupt",
                        missing_message="registered proposal projection is incomplete",
                    )
                )
            except (TypeError, ValueError) as exc:
                raise ContractViolation(
                    "proposal_store_corrupt",
                    "registered proposal projection failed validation",
                ) from exc
        if (
            metadata != action_metadata
            or metadata.get("store_version") != PROPOSAL_STORE_VERSION
            or metadata.get("proposal_hash") != proposal_hash
            or projection.proposal_hash != proposal_hash
            or projection.action_id != action_id
            or projection.parameter_data_class.value
            != metadata.get("parameter_data_class")
            or canonical_digest(projection.to_dict())
            != metadata.get("projection_hash")
        ):
            raise ContractViolation(
                "proposal_store_corrupt",
                "stored proposal projection failed its redaction integrity check",
            )
        return projection

    def registration_data_classes(
        self, proposal: ActionProposal
    ) -> frozenset[DataClass]:
        self._require_live_proposal(proposal)
        try:
            session = self.session_store.get_session(proposal.session_id)
            context = self.session_store.work_context(proposal.session_id)
        except (KeyError, TypeError, ValueError) as exc:
            raise ContractViolation(
                "proposal_context_mismatch",
                "action proposal does not name a durable browser session",
            ) from exc
        if (
            proposal.owner_run_id != session.owner_run_id
            or proposal.work_context_hash != context.context_hash
            or proposal.owner_run_id != context.run_id
            or proposal.correlation_id != context.correlation_id
            or proposal.assignment_id != context.assignment_id
        ):
            raise ContractViolation(
                "proposal_context_mismatch",
                "action proposal does not match the durable work context",
            )
        return frozenset({session.data_class, proposal.parameter_data_class})

    def required_data_classes(self, proposal_hash: str) -> frozenset[DataClass]:
        _require_proposal_hash(proposal_hash)
        metadata = self._read_document(
            self._registration_path(proposal_hash),
            reason_code="proposal_not_found",
            missing_message="WEIR action proposal was not found",
        )
        if (
            metadata.get("store_version") != PROPOSAL_STORE_VERSION
            or metadata.get("proposal_hash") != proposal_hash
        ):
            raise ContractViolation(
                "proposal_store_corrupt",
                "proposal registration metadata failed its lookup check",
            )
        try:
            return frozenset(
                {
                    DataClass(metadata["session_data_class"]),
                    DataClass(metadata["parameter_data_class"]),
                }
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ContractViolation(
                "proposal_store_corrupt",
                "proposal registration has invalid data classifications",
            ) from exc

    def load_record(self, proposal_hash: str) -> ProposalRecord:
        _require_proposal_hash(proposal_hash)
        with self._lock:
            metadata = self._read_document(
                self._registration_path(proposal_hash),
                reason_code="proposal_not_found",
                missing_message="WEIR action proposal was not found",
            )
            try:
                proposal = ActionProposal.from_dict(
                    self._read_document(
                        self._proposal_path(proposal_hash),
                        reason_code="proposal_store_corrupt",
                        missing_message="registered action proposal is incomplete",
                    )
                )
            except (TypeError, ValueError) as exc:
                raise ContractViolation(
                    "proposal_store_corrupt",
                    "registered proposal documents failed validation",
                ) from exc
            action_metadata = self._read_document(
                self._action_path(proposal.action_id),
                reason_code="proposal_store_corrupt",
                missing_message="registered proposal action index is incomplete",
            )

        if proposal.proposal_hash != proposal_hash:
            raise ContractViolation(
                "proposal_store_corrupt",
                "stored action proposal does not match its lookup hash",
            )
        projection = self.load_projection(proposal_hash)
        observation, session_data_class = self._verify_observation_binding(
            proposal, require_current=False
        )
        expected_metadata = self._metadata(
            proposal,
            projection=projection,
            observation_capture_id=observation.capture_id,
            session_data_class=session_data_class,
        )
        if metadata != expected_metadata or action_metadata != expected_metadata:
            raise ContractViolation(
                "proposal_store_corrupt",
                "proposal registration metadata failed its integrity check",
            )
        if projection.to_dict() != self._projection(proposal).to_dict():
            raise ContractViolation(
                "proposal_store_corrupt",
                "stored proposal projection failed its redaction integrity check",
            )
        return ProposalRecord(
            proposal=proposal,
            projection=projection,
            observation_capture_id=observation.capture_id,
            session_data_class=session_data_class,
        )

    def _verify_observation_binding(
        self, proposal: ActionProposal, *, require_current: bool
    ) -> tuple[Observation, DataClass]:
        capture_id = proposal.evidence_refs[0]
        try:
            capture = self.capture_store.load_capture(capture_id)
            self.capture_store.verify_capture(capture)
        except (FileNotFoundError, TypeError, ValueError) as exc:
            raise ContractViolation(
                "proposal_observation_not_found",
                "action proposal does not name a durable browser observation",
            ) from exc
        content = capture.content
        if (
            not isinstance(content, dict)
            or content.get("kind") != "browser_observation"
            or not isinstance(content.get("observation"), dict)
            or not isinstance(content.get("work_context"), dict)
        ):
            raise ContractViolation(
                "proposal_observation_mismatch",
                "action proposal evidence is not a durable browser observation",
            )
        try:
            observation = Observation.from_dict(content["observation"])
            captured_context = WorkContext.from_dict(content["work_context"])
            session = self.session_store.get_session(proposal.session_id)
            session_context = self.session_store.work_context(proposal.session_id)
        except (KeyError, TypeError, ValueError) as exc:
            raise ContractViolation(
                "proposal_observation_mismatch",
                "durable observation identity could not be verified",
            ) from exc

        observation_identity = (
            observation.observation_id,
            observation.observation_hash,
            observation.session_id,
            observation.session_revision,
            observation.session_epoch,
        )
        proposal_identity = (
            proposal.observation_id,
            proposal.observation_hash,
            proposal.session_id,
            proposal.session_revision,
            proposal.session_epoch,
        )
        if (
            capture.capture_id != observation.capture_id
            or observation_identity != proposal_identity
            or proposal.evidence_refs
            != [observation.capture_id, *observation.artifact_refs]
            or capture.screenshot_artifact_ref
            != (observation.artifact_refs[0] if observation.artifact_refs else None)
        ):
            raise ContractViolation(
                "proposal_observation_mismatch",
                "action proposal does not match its durable observation",
            )

        try:
            for artifact_ref in observation.artifact_refs:
                self.capture_store.load_blob(artifact_ref)
            resolved = resolve_locator(
                proposal.semantic_locator,
                observation,
                expected_session_id=proposal.session_id,
                expected_revision=proposal.session_revision,
                expected_epoch=proposal.session_epoch,
            )
        except (FileNotFoundError, LocatorResolutionError, TypeError, ValueError) as exc:
            raise ContractViolation(
                "proposal_observation_mismatch",
                "action proposal supporting evidence failed verification",
            ) from exc
        has_hash_precondition = any(
            condition.kind is ConditionKind.OBSERVATION_HASH_EQUALS
            and condition.expected == observation.observation_hash
            and condition.locator is None
            and condition.target is None
            for condition in proposal.preconditions
        )
        has_target_precondition = any(
            condition.kind is ConditionKind.ELEMENT_PRESENT
            and condition.expected is True
            and condition.locator == proposal.semantic_locator
            and condition.target == resolved
            for condition in proposal.preconditions
        )
        if (
            proposal.resolved_target != resolved
            or not has_hash_precondition
            or not has_target_precondition
        ):
            raise ContractViolation(
                "proposal_observation_mismatch",
                "action proposal target was not compiled from the durable observation",
            )

        if captured_context.to_dict() != session_context.to_dict():
            raise ContractViolation(
                "proposal_context_mismatch",
                "browser observation and session have different work contexts",
            )
        if (
            proposal.work_context_hash != session_context.context_hash
            or proposal.owner_run_id != session_context.run_id
            or proposal.correlation_id != session_context.correlation_id
            or proposal.assignment_id != session_context.assignment_id
            or proposal.owner_run_id != session.owner_run_id
        ):
            raise ContractViolation(
                "proposal_context_mismatch",
                "action proposal does not match the durable work context",
            )
        if require_current and (
            session.state is not SessionState.ACTIVE
            or session.revision != proposal.session_revision
            or session.epoch != proposal.session_epoch
            or session.current_url != observation.url
        ):
            raise ContractViolation(
                "proposal_observation_stale",
                "action proposal observation is no longer the active session state",
            )
        return observation, session.data_class

    def _require_live_proposal(self, proposal: ActionProposal) -> None:
        proposal.validate()
        if parse_timestamp(proposal.expires_at, "expires_at") <= _utc_now(self.clock):
            raise ContractViolation(
                "proposal_expired",
                "an expired action proposal cannot be registered",
            )

    @staticmethod
    def _projection(proposal: ActionProposal) -> WeirActionEvent:
        header = CorrelationHeader(
            event_id=f"weir-proposal-{proposal.proposal_hash.removeprefix('sha256:')}",
            occurred_at=proposal.created_at,
            producer="weir",
            run_id=proposal.owner_run_id,
            assignment_id=proposal.assignment_id,
            correlation_id=proposal.correlation_id,
            work_context_hash=proposal.work_context_hash,
        )
        return WeirActionEvent.from_proposal(header=header, proposal=proposal)

    @staticmethod
    def _metadata(
        proposal: ActionProposal,
        *,
        projection: WeirActionEvent,
        observation_capture_id: str,
        session_data_class: DataClass,
    ) -> dict[str, Any]:
        return {
            "store_version": PROPOSAL_STORE_VERSION,
            "action_id": proposal.action_id,
            "proposal_hash": proposal.proposal_hash,
            "projection_hash": canonical_digest(projection.to_dict()),
            "observation_capture_id": observation_capture_id,
            "session_data_class": session_data_class.value,
            "parameter_data_class": proposal.parameter_data_class.value,
        }

    def _write_action_index(self, action_id: str, metadata: dict[str, Any]) -> None:
        path = self._action_path(action_id)
        try:
            _write_immutable(path, _document_bytes(metadata))
        except OSError as exc:
            try:
                existing = self._read_document(
                    path,
                    reason_code="proposal_store_corrupt",
                    missing_message="proposal action index disappeared during registration",
                )
            except ProposalNotFound:
                raise ContractViolation(
                    "proposal_store_corrupt",
                    "proposal action index could not be published safely",
                ) from exc
            if existing != metadata:
                raise ContractViolation(
                    "proposal_action_conflict",
                    "action_id is already bound to another action proposal",
                ) from exc

    @staticmethod
    def _write_document(path: Path, value: dict[str, Any]) -> None:
        try:
            _write_immutable(path, _document_bytes(value))
        except OSError as exc:
            raise ContractViolation(
                "proposal_store_corrupt",
                "immutable proposal document collided with different content",
            ) from exc

    def _read_document(
        self,
        path: Path,
        *,
        reason_code: str,
        missing_message: str,
    ) -> dict[str, Any]:
        try:
            payload = path.read_bytes()
        except FileNotFoundError as exc:
            if reason_code == "proposal_not_found":
                raise ProposalNotFound(missing_message) from exc
            raise ContractViolation(reason_code, missing_message) from exc
        if len(payload) > MAX_PROPOSAL_STORE_DOCUMENT_BYTES:
            raise ContractViolation(reason_code, "proposal store document is too large")
        try:
            value = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ContractViolation(reason_code, "proposal store document is invalid") from exc
        try:
            canonical = canonical_json_bytes(value) + b"\n"
        except (TypeError, ValueError) as exc:
            raise ContractViolation(
                reason_code, "proposal store document is not portable JSON"
            ) from exc
        if not isinstance(value, dict) or payload != canonical:
            raise ContractViolation(
                reason_code, "proposal store document is not canonical JSON"
            )
        return value

    def _proposal_path(self, proposal_hash: str) -> Path:
        digest = _proposal_digest(proposal_hash)
        return self.root / "by-hash" / digest[:2] / f"{digest}.proposal.json"

    def _projection_path(self, proposal_hash: str) -> Path:
        digest = _proposal_digest(proposal_hash)
        return self.root / "by-hash" / digest[:2] / f"{digest}.projection.json"

    def _registration_path(self, proposal_hash: str) -> Path:
        digest = _proposal_digest(proposal_hash)
        return self.root / "by-hash" / digest[:2] / f"{digest}.registered.json"

    def _action_path(self, action_id: str) -> Path:
        if not isinstance(action_id, str) or not action_id or len(action_id) > 128:
            raise ValueError("action_id must be a non-empty string up to 128 characters")
        digest = hashlib.sha256(action_id.encode("utf-8")).hexdigest()
        return self.root / "by-action" / digest[:2] / f"{digest}.json"


def _document_bytes(value: dict[str, Any]) -> bytes:
    return canonical_json_bytes(value) + b"\n"


def _require_proposal_hash(proposal_hash: str) -> None:
    if not is_sha256(proposal_hash):
        raise ValueError("proposal_hash must be a sha256 digest")


def _proposal_digest(proposal_hash: str) -> str:
    _require_proposal_hash(proposal_hash)
    return proposal_hash.removeprefix("sha256:")


def _utc_now(clock: Callable[[], datetime]) -> datetime:
    value = clock()
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("proposal-store clock must return a timezone-aware datetime")
    return value.astimezone(timezone.utc)


__all__ = [
    "MAX_PROPOSAL_STORE_DOCUMENT_BYTES",
    "PROPOSAL_STORE_VERSION",
    "ActionProposalStore",
    "ProposalNotFound",
    "ProposalRecord",
]
