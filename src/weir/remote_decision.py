from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from weir.contract import (
    ContractViolation,
    canonical_digest,
    canonical_json_bytes,
    is_sha256,
    parse_timestamp,
    validate_contract_size,
    validate_identifier,
)

REMOTE_DECISION_CAPSULE_SCHEMA = "weir.remote-decision-capsule/v1"
REMOTE_DECISION_ACK_SCHEMA = "weir.remote-decision-ack/v1"
REMOTE_DECISION_QUEUE_STATE_SCHEMA = "weir.remote-decision-queue-state/v1"
REMOTE_DECISION_REVOCATION_SCHEMA = "weir.remote-decision-revocation/v1"
REMOTE_DECISION_AUDIT_SCHEMA = "weir.remote-decision-audit/v1"

MAX_REMOTE_DECISION_CAPSULE_BYTES = 8 * 1024
MAX_REMOTE_DECISION_RECORD_BYTES = 8 * 1024
MAX_REMOTE_DECISION_LIFETIME_SECONDS = 120
MAX_REMOTE_DECISION_CLOCK_SKEW_SECONDS = 5
MAX_REMOTE_DECISION_LIVE_ENTRIES = 1024

_SIGNATURE_BYTES = 64
_NONCE_BYTES = 16


class RemoteDecision(StrEnum):
    APPROVE = "approve"
    DENY = "deny"


class RemoteQueueState(StrEnum):
    QUEUED = "queued"
    CLAIMED = "claimed"
    ACKNOWLEDGED = "acknowledged"
    DENIED = "denied"
    EXPIRED = "expired"
    REVOKED = "revoked"


class RemoteDecisionOutcome(StrEnum):
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"
    OUTCOME_UNKNOWN = "outcome_unknown"
    DENIED = "denied"
    EXPIRED = "expired"
    REVOKED = "revoked"


class RemoteRevocationReason(StrEnum):
    OPERATOR_WITHDREW = "operator_withdrew"
    DEVICE_REVOKED = "device_revoked"
    PROPOSAL_SUPERSEDED = "proposal_superseded"
    POLICY_CHANGED = "policy_changed"
    SECURITY_RESPONSE = "security_response"


_TERMINAL_QUEUE_STATES = frozenset(
    {
        RemoteQueueState.ACKNOWLEDGED,
        RemoteQueueState.DENIED,
        RemoteQueueState.EXPIRED,
        RemoteQueueState.REVOKED,
    }
)
_EFFECT_OUTCOMES = frozenset(
    {
        RemoteDecisionOutcome.COMPLETED,
        RemoteDecisionOutcome.FAILED,
        RemoteDecisionOutcome.BLOCKED,
        RemoteDecisionOutcome.CANCELLED,
        RemoteDecisionOutcome.OUTCOME_UNKNOWN,
    }
)
_QUEUE_TRANSITIONS = {
    RemoteQueueState.QUEUED: frozenset(
        {
            RemoteQueueState.CLAIMED,
            RemoteQueueState.DENIED,
            RemoteQueueState.EXPIRED,
            RemoteQueueState.REVOKED,
        }
    ),
    RemoteQueueState.CLAIMED: frozenset(
        {
            RemoteQueueState.QUEUED,
            RemoteQueueState.ACKNOWLEDGED,
            RemoteQueueState.EXPIRED,
            RemoteQueueState.REVOKED,
        }
    ),
}


def _exact(value: object, required: set[str], name: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != required:
        raise ContractViolation(
            "remote_contract_shape_invalid",
            f"{name} has missing or unknown fields",
        )
    return value


def _enum(enum_type: type[StrEnum], value: object, name: str) -> StrEnum:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise ContractViolation(
            "remote_contract_value_invalid", f"{name} is invalid"
        ) from exc


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: object, *, size: int, name: str) -> bytes:
    if not isinstance(value, str) or "=" in value:
        raise ContractViolation("remote_encoding_invalid", f"{name} is not base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError) as exc:
        raise ContractViolation(
            "remote_encoding_invalid", f"{name} is not base64url"
        ) from exc
    if len(decoded) != size or _b64url_encode(decoded) != value:
        raise ContractViolation(
            "remote_encoding_invalid", f"{name} has invalid length or encoding"
        )
    return decoded


def _validate_hash(value: object, name: str) -> None:
    if not is_sha256(value):
        raise ContractViolation("remote_contract_value_invalid", f"{name} is invalid")


def _validate_nullable_hash(value: object, name: str) -> None:
    if value is not None:
        _validate_hash(value, name)


def _validate_hash_record(
    document: dict[str, object], hash_field: str, maximum: int
) -> None:
    validate_contract_size(document, maximum, document["schema"])
    expected = document[hash_field]
    _validate_hash(expected, hash_field)
    basis = dict(document)
    basis.pop(hash_field)
    if canonical_digest(basis) != expected:
        raise ContractViolation(
            "remote_record_hash_mismatch", f"{hash_field} does not match"
        )


@dataclass(frozen=True, slots=True)
class RemoteDecisionCapsule:
    key_id: str
    issuer_id: str
    capsule_id: str
    command_id: str
    actor_id: str
    audience: str
    device_id: str
    decision: RemoteDecision
    proposal_hash: str
    action_id: str
    work_context_hash: str
    issued_at: str
    expires_at: str
    nonce: str
    step_up_ref: str
    signature: str
    schema: str = REMOTE_DECISION_CAPSULE_SCHEMA

    @classmethod
    def create(
        cls,
        *,
        key_id: str,
        issuer_id: str,
        capsule_id: str,
        command_id: str,
        actor_id: str,
        audience: str,
        device_id: str,
        decision: RemoteDecision,
        proposal_hash: str,
        action_id: str,
        work_context_hash: str,
        issued_at: str,
        expires_at: str,
        nonce: str,
        step_up_ref: str,
        private_key: Ed25519PrivateKey,
    ) -> RemoteDecisionCapsule:
        if not isinstance(private_key, Ed25519PrivateKey):
            raise TypeError("private_key must be an Ed25519PrivateKey")
        capsule = cls(
            key_id=key_id,
            issuer_id=issuer_id,
            capsule_id=capsule_id,
            command_id=command_id,
            actor_id=actor_id,
            audience=audience,
            device_id=device_id,
            decision=decision,
            proposal_hash=proposal_hash,
            action_id=action_id,
            work_context_hash=work_context_hash,
            issued_at=issued_at,
            expires_at=expires_at,
            nonce=nonce,
            step_up_ref=step_up_ref,
            signature="",
        )
        capsule._validate_unsigned()
        signature = _b64url_encode(private_key.sign(capsule.signing_bytes()))
        capsule = replace(capsule, signature=signature)
        capsule.validate()
        return capsule

    def _validate_unsigned(self) -> None:
        if self.schema != REMOTE_DECISION_CAPSULE_SCHEMA:
            raise ContractViolation(
                "unsupported_remote_schema", "unsupported decision capsule schema"
            )
        for name in (
            "key_id",
            "issuer_id",
            "capsule_id",
            "command_id",
            "actor_id",
            "audience",
            "device_id",
            "action_id",
        ):
            validate_identifier(getattr(self, name), name)
        if not isinstance(self.decision, RemoteDecision):
            raise ContractViolation(
                "remote_contract_value_invalid", "decision is invalid"
            )
        _validate_hash(self.proposal_hash, "proposal_hash")
        _validate_hash(self.work_context_hash, "work_context_hash")
        _validate_hash(self.step_up_ref, "step_up_ref")
        _b64url_decode(self.nonce, size=_NONCE_BYTES, name="nonce")
        issued = parse_timestamp(self.issued_at, "issued_at")
        expires = parse_timestamp(self.expires_at, "expires_at")
        if expires <= issued:
            raise ContractViolation(
                "remote_expiry_invalid", "capsule expiry must follow issue time"
            )
        if (expires - issued).total_seconds() > MAX_REMOTE_DECISION_LIFETIME_SECONDS:
            raise ContractViolation(
                "remote_lifetime_too_long", "capsule lifetime exceeds the maximum"
            )
        validate_contract_size(
            self._unsigned_dict(),
            MAX_REMOTE_DECISION_CAPSULE_BYTES,
            "remote decision capsule",
        )

    def validate(self) -> None:
        self._validate_unsigned()
        _b64url_decode(self.signature, size=_SIGNATURE_BYTES, name="signature")
        validate_contract_size(
            self.to_dict(),
            MAX_REMOTE_DECISION_CAPSULE_BYTES,
            "remote decision capsule",
        )

    def validate_at(
        self,
        now: datetime,
        *,
        expected_issuer_id: str,
        expected_audience: str,
        expected_device_id: str,
        public_keys: Mapping[str, Ed25519PublicKey],
    ) -> None:
        self.validate()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise ValueError("remote decision clock must be timezone-aware")
        public_key = public_keys.get(self.key_id)
        if not isinstance(public_key, Ed25519PublicKey):
            raise ContractViolation("remote_key_unknown", "capsule key is not trusted")
        try:
            public_key.verify(
                _b64url_decode(
                    self.signature, size=_SIGNATURE_BYTES, name="signature"
                ),
                self.signing_bytes(),
            )
        except InvalidSignature as exc:
            raise ContractViolation(
                "remote_signature_invalid", "capsule signature is invalid"
            ) from exc
        if self.issuer_id != expected_issuer_id:
            raise ContractViolation(
                "remote_issuer_mismatch", "capsule issuer does not match"
            )
        if self.audience != expected_audience:
            raise ContractViolation(
                "remote_audience_mismatch", "capsule audience does not match"
            )
        if self.device_id != expected_device_id:
            raise ContractViolation(
                "remote_device_mismatch", "capsule device does not match"
            )
        issued = parse_timestamp(self.issued_at, "issued_at")
        expires = parse_timestamp(self.expires_at, "expires_at")
        authoritative_now = now.astimezone(timezone.utc)
        if authoritative_now < issued:
            raise ContractViolation(
                "remote_not_yet_valid", "capsule issue time is in the future"
            )
        if authoritative_now > expires + timedelta(
            seconds=MAX_REMOTE_DECISION_CLOCK_SKEW_SECONDS
        ):
            raise ContractViolation("remote_expired", "capsule has expired")

    def signing_bytes(self) -> bytes:
        self._validate_unsigned()
        return canonical_json_bytes(self._unsigned_dict())

    @property
    def capsule_hash(self) -> str:
        self.validate()
        return canonical_digest(self.to_dict())

    def _unsigned_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "key_id": self.key_id,
            "issuer_id": self.issuer_id,
            "capsule_id": self.capsule_id,
            "command_id": self.command_id,
            "actor_id": self.actor_id,
            "audience": self.audience,
            "device_id": self.device_id,
            "decision": self.decision.value,
            "proposal_hash": self.proposal_hash,
            "action_id": self.action_id,
            "work_context_hash": self.work_context_hash,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
            "step_up_ref": self.step_up_ref,
        }

    def to_dict(self) -> dict[str, object]:
        return {**self._unsigned_dict(), "signature": self.signature}

    @classmethod
    def from_dict(cls, value: object) -> RemoteDecisionCapsule:
        required = {
            "schema",
            "key_id",
            "issuer_id",
            "capsule_id",
            "command_id",
            "actor_id",
            "audience",
            "device_id",
            "decision",
            "proposal_hash",
            "action_id",
            "work_context_hash",
            "issued_at",
            "expires_at",
            "nonce",
            "step_up_ref",
            "signature",
        }
        document = _exact(value, required, "remote decision capsule")
        validate_contract_size(
            document, MAX_REMOTE_DECISION_CAPSULE_BYTES, "remote decision capsule"
        )
        capsule = cls(
            schema=document["schema"],
            key_id=document["key_id"],
            issuer_id=document["issuer_id"],
            capsule_id=document["capsule_id"],
            command_id=document["command_id"],
            actor_id=document["actor_id"],
            audience=document["audience"],
            device_id=document["device_id"],
            decision=_enum(RemoteDecision, document["decision"], "decision"),
            proposal_hash=document["proposal_hash"],
            action_id=document["action_id"],
            work_context_hash=document["work_context_hash"],
            issued_at=document["issued_at"],
            expires_at=document["expires_at"],
            nonce=document["nonce"],
            step_up_ref=document["step_up_ref"],
            signature=document["signature"],
        )
        capsule.validate()
        return capsule

    @classmethod
    def from_bytes(cls, payload: bytes) -> RemoteDecisionCapsule:
        if not isinstance(payload, bytes):
            raise TypeError("remote decision payload must be bytes")
        if len(payload) > MAX_REMOTE_DECISION_CAPSULE_BYTES:
            raise ContractViolation(
                "contract_too_large", "remote decision capsule exceeds 8192 bytes"
            )
        try:
            document = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ContractViolation(
                "remote_encoding_invalid", "remote decision capsule is not UTF-8 JSON"
            ) from exc
        capsule = cls.from_dict(document)
        if payload != canonical_json_bytes(capsule.to_dict()):
            raise ContractViolation(
                "remote_encoding_not_canonical",
                "remote decision capsule is not canonical WEIR JSON",
            )
        return capsule


@dataclass(frozen=True, slots=True)
class RemoteDecisionAcknowledgement:
    acknowledgement_id: str
    capsule_id: str
    command_id: str
    actor_id: str
    device_id: str
    transport_principal: str
    outcome: RemoteDecisionOutcome
    receipt_hash: str | None
    acknowledged_at: str
    acknowledgement_hash: str = ""
    schema: str = REMOTE_DECISION_ACK_SCHEMA

    @classmethod
    def create(cls, **values: object) -> RemoteDecisionAcknowledgement:
        record = cls(**values)
        record = replace(
            record, acknowledgement_hash=canonical_digest(record._hash_basis())
        )
        record.validate()
        return record

    def validate(self) -> None:
        if self.schema != REMOTE_DECISION_ACK_SCHEMA:
            raise ContractViolation(
                "unsupported_remote_schema", "unsupported acknowledgement schema"
            )
        for name in (
            "acknowledgement_id",
            "capsule_id",
            "command_id",
            "actor_id",
            "device_id",
            "transport_principal",
        ):
            validate_identifier(getattr(self, name), name)
        if not isinstance(self.outcome, RemoteDecisionOutcome):
            raise ContractViolation(
                "remote_contract_value_invalid", "acknowledgement outcome is invalid"
            )
        _validate_nullable_hash(self.receipt_hash, "receipt_hash")
        if self.actor_id == self.transport_principal:
            raise ContractViolation(
                "remote_identity_collapsed",
                "human actor and relay transport principal must remain distinct",
            )
        if (self.outcome in _EFFECT_OUTCOMES) != (self.receipt_hash is not None):
            raise ContractViolation(
                "remote_ack_receipt_mismatch",
                "effect acknowledgement receipt binding is inconsistent",
            )
        parse_timestamp(self.acknowledged_at, "acknowledged_at")
        _validate_hash_record(
            self.to_dict(), "acknowledgement_hash", MAX_REMOTE_DECISION_RECORD_BYTES
        )

    def _hash_basis(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "acknowledgement_id": self.acknowledgement_id,
            "capsule_id": self.capsule_id,
            "command_id": self.command_id,
            "actor_id": self.actor_id,
            "device_id": self.device_id,
            "transport_principal": self.transport_principal,
            "outcome": self.outcome.value,
            "receipt_hash": self.receipt_hash,
            "acknowledged_at": self.acknowledged_at,
        }

    def to_dict(self) -> dict[str, object]:
        return {**self._hash_basis(), "acknowledgement_hash": self.acknowledgement_hash}

    @classmethod
    def from_dict(cls, value: object) -> RemoteDecisionAcknowledgement:
        required = {
            "schema",
            "acknowledgement_id",
            "capsule_id",
            "command_id",
            "actor_id",
            "device_id",
            "transport_principal",
            "outcome",
            "receipt_hash",
            "acknowledged_at",
            "acknowledgement_hash",
        }
        document = _exact(value, required, "remote decision acknowledgement")
        record = cls(
            schema=document["schema"],
            acknowledgement_id=document["acknowledgement_id"],
            capsule_id=document["capsule_id"],
            command_id=document["command_id"],
            actor_id=document["actor_id"],
            device_id=document["device_id"],
            transport_principal=document["transport_principal"],
            outcome=_enum(
                RemoteDecisionOutcome, document["outcome"], "acknowledgement outcome"
            ),
            receipt_hash=document["receipt_hash"],
            acknowledged_at=document["acknowledged_at"],
            acknowledgement_hash=document["acknowledgement_hash"],
        )
        record.validate()
        return record


@dataclass(frozen=True, slots=True)
class RemoteDecisionQueueRecord:
    record_id: str
    capsule_id: str
    command_id: str
    state: RemoteQueueState
    revision: int
    claim_device_id: str | None
    claim_expires_at: str | None
    outcome: RemoteDecisionOutcome | None
    recorded_at: str
    previous_record_hash: str | None
    record_hash: str = ""
    schema: str = REMOTE_DECISION_QUEUE_STATE_SCHEMA

    @classmethod
    def create(cls, **values: object) -> RemoteDecisionQueueRecord:
        record = cls(**values)
        record = replace(record, record_hash=canonical_digest(record._hash_basis()))
        record.validate()
        return record

    def validate(self) -> None:
        if self.schema != REMOTE_DECISION_QUEUE_STATE_SCHEMA:
            raise ContractViolation(
                "unsupported_remote_schema", "unsupported queue-state schema"
            )
        for name in ("record_id", "capsule_id", "command_id"):
            validate_identifier(getattr(self, name), name)
        if not isinstance(self.state, RemoteQueueState):
            raise ContractViolation("remote_contract_value_invalid", "queue state is invalid")
        if type(self.revision) is not int or self.revision < 1:
            raise ContractViolation(
                "remote_contract_value_invalid", "queue revision is invalid"
            )
        if self.claim_device_id is not None:
            validate_identifier(self.claim_device_id, "claim_device_id")
        if self.claim_expires_at is not None:
            parse_timestamp(self.claim_expires_at, "claim_expires_at")
        if self.outcome is not None and not isinstance(
            self.outcome, RemoteDecisionOutcome
        ):
            raise ContractViolation(
                "remote_contract_value_invalid", "queue outcome is invalid"
            )
        if self.state is RemoteQueueState.CLAIMED:
            if self.claim_device_id is None or self.claim_expires_at is None:
                raise ContractViolation(
                    "remote_queue_claim_invalid", "claimed state requires a claim lease"
                )
            if parse_timestamp(
                self.claim_expires_at, "claim_expires_at"
            ) <= parse_timestamp(self.recorded_at, "recorded_at"):
                raise ContractViolation(
                    "remote_queue_claim_invalid",
                    "claim lease must expire after the claim record",
                )
        elif self.claim_device_id is not None or self.claim_expires_at is not None:
            raise ContractViolation(
                "remote_queue_claim_invalid", "only claimed state may carry a claim lease"
            )
        if (
            self.state is RemoteQueueState.ACKNOWLEDGED
            and self.outcome not in _EFFECT_OUTCOMES
        ) or (
            self.state is not RemoteQueueState.ACKNOWLEDGED
            and self.outcome is not None
        ):
            raise ContractViolation(
                "remote_queue_outcome_invalid",
                "only acknowledged state carries an outcome",
            )
        if self.revision == 1:
            if self.previous_record_hash is not None:
                raise ContractViolation(
                    "remote_queue_chain_invalid", "initial queue record has a predecessor"
                )
            if self.state is not RemoteQueueState.QUEUED:
                raise ContractViolation(
                    "remote_queue_initial_invalid", "initial queue state must be queued"
                )
        else:
            _validate_hash(self.previous_record_hash, "previous_record_hash")
        parse_timestamp(self.recorded_at, "recorded_at")
        _validate_hash_record(
            self.to_dict(), "record_hash", MAX_REMOTE_DECISION_RECORD_BYTES
        )

    def require_successor(
        self,
        previous: RemoteDecisionQueueRecord,
        *,
        capsule: RemoteDecisionCapsule | None = None,
    ) -> None:
        self.validate()
        previous.validate()
        if previous.state in _TERMINAL_QUEUE_STATES:
            raise ContractViolation(
                "remote_queue_terminal", "terminal queue state has no successor"
            )
        if (
            self.capsule_id != previous.capsule_id
            or self.command_id != previous.command_id
            or self.revision != previous.revision + 1
            or self.previous_record_hash != previous.record_hash
        ):
            raise ContractViolation(
                "remote_queue_chain_invalid", "queue successor binding is invalid"
            )
        if self.state not in _QUEUE_TRANSITIONS[previous.state]:
            raise ContractViolation(
                "remote_queue_transition_invalid", "queue transition is not allowed"
            )
        recorded_at = parse_timestamp(self.recorded_at, "recorded_at")
        if recorded_at < parse_timestamp(previous.recorded_at, "recorded_at"):
            raise ContractViolation(
                "remote_queue_time_invalid", "queue successor predates its predecessor"
            )
        if (
            previous.state is RemoteQueueState.CLAIMED
            and self.state is RemoteQueueState.QUEUED
        ):
            if capsule is None:
                raise ContractViolation(
                    "remote_queue_retry_context_required",
                    "claim retry requires the bound capsule",
                )
            capsule.validate()
            if (
                capsule.capsule_id != self.capsule_id
                or capsule.command_id != self.command_id
            ):
                raise ContractViolation(
                    "remote_queue_chain_invalid",
                    "claim retry capsule binding is invalid",
                )
            assert previous.claim_expires_at is not None
            if recorded_at < parse_timestamp(
                previous.claim_expires_at, "claim_expires_at"
            ):
                raise ContractViolation(
                    "remote_queue_claim_active", "claim lease is still active"
                )
            if recorded_at > parse_timestamp(
                capsule.expires_at, "expires_at"
            ) + timedelta(seconds=MAX_REMOTE_DECISION_CLOCK_SKEW_SECONDS):
                raise ContractViolation(
                    "remote_queue_retry_expired", "expired capsule cannot be re-queued"
                )

    def _hash_basis(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "record_id": self.record_id,
            "capsule_id": self.capsule_id,
            "command_id": self.command_id,
            "state": self.state.value,
            "revision": self.revision,
            "claim_device_id": self.claim_device_id,
            "claim_expires_at": self.claim_expires_at,
            "outcome": None if self.outcome is None else self.outcome.value,
            "recorded_at": self.recorded_at,
            "previous_record_hash": self.previous_record_hash,
        }

    def to_dict(self) -> dict[str, object]:
        return {**self._hash_basis(), "record_hash": self.record_hash}

    @classmethod
    def from_dict(cls, value: object) -> RemoteDecisionQueueRecord:
        required = {
            "schema",
            "record_id",
            "capsule_id",
            "command_id",
            "state",
            "revision",
            "claim_device_id",
            "claim_expires_at",
            "outcome",
            "recorded_at",
            "previous_record_hash",
            "record_hash",
        }
        document = _exact(value, required, "remote decision queue state")
        record = cls(
            schema=document["schema"],
            record_id=document["record_id"],
            capsule_id=document["capsule_id"],
            command_id=document["command_id"],
            state=_enum(RemoteQueueState, document["state"], "queue state"),
            revision=document["revision"],
            claim_device_id=document["claim_device_id"],
            claim_expires_at=document["claim_expires_at"],
            outcome=(
                None
                if document["outcome"] is None
                else _enum(RemoteDecisionOutcome, document["outcome"], "queue outcome")
            ),
            recorded_at=document["recorded_at"],
            previous_record_hash=document["previous_record_hash"],
            record_hash=document["record_hash"],
        )
        record.validate()
        return record


@dataclass(frozen=True, slots=True)
class RemoteDecisionRevocation:
    revocation_id: str
    capsule_id: str
    command_id: str
    actor_id: str
    reason_code: RemoteRevocationReason
    revoked_at: str
    revocation_hash: str = ""
    schema: str = REMOTE_DECISION_REVOCATION_SCHEMA

    @classmethod
    def create(cls, **values: object) -> RemoteDecisionRevocation:
        record = cls(**values)
        record = replace(record, revocation_hash=canonical_digest(record._hash_basis()))
        record.validate()
        return record

    def validate(self) -> None:
        if self.schema != REMOTE_DECISION_REVOCATION_SCHEMA:
            raise ContractViolation(
                "unsupported_remote_schema", "unsupported revocation schema"
            )
        for name in (
            "revocation_id",
            "capsule_id",
            "command_id",
            "actor_id",
        ):
            validate_identifier(getattr(self, name), name)
        if not isinstance(self.reason_code, RemoteRevocationReason):
            raise ContractViolation(
                "remote_contract_value_invalid", "revocation reason is invalid"
            )
        parse_timestamp(self.revoked_at, "revoked_at")
        _validate_hash_record(
            self.to_dict(), "revocation_hash", MAX_REMOTE_DECISION_RECORD_BYTES
        )

    def _hash_basis(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "revocation_id": self.revocation_id,
            "capsule_id": self.capsule_id,
            "command_id": self.command_id,
            "actor_id": self.actor_id,
            "reason_code": self.reason_code.value,
            "revoked_at": self.revoked_at,
        }

    def to_dict(self) -> dict[str, object]:
        return {**self._hash_basis(), "revocation_hash": self.revocation_hash}

    @classmethod
    def from_dict(cls, value: object) -> RemoteDecisionRevocation:
        required = {
            "schema",
            "revocation_id",
            "capsule_id",
            "command_id",
            "actor_id",
            "reason_code",
            "revoked_at",
            "revocation_hash",
        }
        document = _exact(value, required, "remote decision revocation")
        record = cls(
            schema=document["schema"],
            revocation_id=document["revocation_id"],
            capsule_id=document["capsule_id"],
            command_id=document["command_id"],
            actor_id=document["actor_id"],
            reason_code=_enum(
                RemoteRevocationReason, document["reason_code"], "revocation reason"
            ),
            revoked_at=document["revoked_at"],
            revocation_hash=document["revocation_hash"],
        )
        record.validate()
        return record


@dataclass(frozen=True, slots=True)
class RemoteDecisionAuditRecord:
    audit_id: str
    capsule_hash: str
    nonce_hash: str
    capsule_id: str
    command_id: str
    actor_id: str
    device_id: str
    transport_principal: str | None
    decision: RemoteDecision
    queue_state: RemoteQueueState
    outcome: RemoteDecisionOutcome | None
    issued_at: str
    terminal_at: str | None
    recorded_at: str
    audit_hash: str = ""
    schema: str = REMOTE_DECISION_AUDIT_SCHEMA

    @classmethod
    def create(cls, **values: object) -> RemoteDecisionAuditRecord:
        record = cls(**values)
        record = replace(record, audit_hash=canonical_digest(record._hash_basis()))
        record.validate()
        return record

    def validate(self) -> None:
        if self.schema != REMOTE_DECISION_AUDIT_SCHEMA:
            raise ContractViolation(
                "unsupported_remote_schema", "unsupported audit schema"
            )
        for name in (
            "audit_id",
            "capsule_id",
            "command_id",
            "actor_id",
            "device_id",
        ):
            validate_identifier(getattr(self, name), name)
        if self.transport_principal is not None:
            validate_identifier(self.transport_principal, "transport_principal")
        _validate_hash(self.capsule_hash, "capsule_hash")
        _validate_hash(self.nonce_hash, "nonce_hash")
        if not isinstance(self.decision, RemoteDecision):
            raise ContractViolation("remote_contract_value_invalid", "decision is invalid")
        if not isinstance(self.queue_state, RemoteQueueState):
            raise ContractViolation("remote_contract_value_invalid", "queue state is invalid")
        if self.outcome is not None and not isinstance(
            self.outcome, RemoteDecisionOutcome
        ):
            raise ContractViolation("remote_contract_value_invalid", "outcome is invalid")
        issued = parse_timestamp(self.issued_at, "issued_at")
        recorded = parse_timestamp(self.recorded_at, "recorded_at")
        terminal = (
            None
            if self.terminal_at is None
            else parse_timestamp(self.terminal_at, "terminal_at")
        )
        is_terminal = self.queue_state in _TERMINAL_QUEUE_STATES
        if recorded < issued:
            raise ContractViolation(
                "remote_audit_time_invalid", "audit record predates capsule issuance"
            )
        if is_terminal != (terminal is not None):
            raise ContractViolation(
                "remote_audit_terminal_invalid",
                "terminal queue state and terminal time are inconsistent",
            )
        if (
            self.queue_state is RemoteQueueState.ACKNOWLEDGED
            and self.outcome not in _EFFECT_OUTCOMES
        ) or (
            self.queue_state is not RemoteQueueState.ACKNOWLEDGED
            and self.outcome is not None
        ):
            raise ContractViolation(
                "remote_audit_outcome_invalid",
                "only acknowledged audit state carries an outcome",
            )
        if self.queue_state in {
            RemoteQueueState.CLAIMED,
            RemoteQueueState.ACKNOWLEDGED,
        } and self.transport_principal is None:
            raise ContractViolation(
                "remote_audit_transport_missing",
                "claimed or acknowledged audit state requires a transport principal",
            )
        if self.transport_principal == self.actor_id:
            raise ContractViolation(
                "remote_identity_collapsed",
                "human actor and relay transport principal must remain distinct",
            )
        if terminal is not None and (terminal < issued or recorded < terminal):
            raise ContractViolation(
                "remote_audit_time_invalid", "audit timestamps are inconsistent"
            )
        _validate_hash_record(
            self.to_dict(), "audit_hash", MAX_REMOTE_DECISION_RECORD_BYTES
        )

    def _hash_basis(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "audit_id": self.audit_id,
            "capsule_hash": self.capsule_hash,
            "nonce_hash": self.nonce_hash,
            "capsule_id": self.capsule_id,
            "command_id": self.command_id,
            "actor_id": self.actor_id,
            "device_id": self.device_id,
            "transport_principal": self.transport_principal,
            "decision": self.decision.value,
            "queue_state": self.queue_state.value,
            "outcome": None if self.outcome is None else self.outcome.value,
            "issued_at": self.issued_at,
            "terminal_at": self.terminal_at,
            "recorded_at": self.recorded_at,
        }

    def to_dict(self) -> dict[str, object]:
        return {**self._hash_basis(), "audit_hash": self.audit_hash}

    @classmethod
    def from_dict(cls, value: object) -> RemoteDecisionAuditRecord:
        required = {
            "schema",
            "audit_id",
            "capsule_hash",
            "nonce_hash",
            "capsule_id",
            "command_id",
            "actor_id",
            "device_id",
            "transport_principal",
            "decision",
            "queue_state",
            "outcome",
            "issued_at",
            "terminal_at",
            "recorded_at",
            "audit_hash",
        }
        document = _exact(value, required, "remote decision audit record")
        record = cls(
            schema=document["schema"],
            audit_id=document["audit_id"],
            capsule_hash=document["capsule_hash"],
            nonce_hash=document["nonce_hash"],
            capsule_id=document["capsule_id"],
            command_id=document["command_id"],
            actor_id=document["actor_id"],
            device_id=document["device_id"],
            transport_principal=document["transport_principal"],
            decision=_enum(RemoteDecision, document["decision"], "decision"),
            queue_state=_enum(RemoteQueueState, document["queue_state"], "queue state"),
            outcome=(
                None
                if document["outcome"] is None
                else _enum(RemoteDecisionOutcome, document["outcome"], "outcome")
            ),
            issued_at=document["issued_at"],
            terminal_at=document["terminal_at"],
            recorded_at=document["recorded_at"],
            audit_hash=document["audit_hash"],
        )
        record.validate()
        return record


__all__ = [
    "MAX_REMOTE_DECISION_CAPSULE_BYTES",
    "MAX_REMOTE_DECISION_CLOCK_SKEW_SECONDS",
    "MAX_REMOTE_DECISION_LIFETIME_SECONDS",
    "MAX_REMOTE_DECISION_LIVE_ENTRIES",
    "RemoteDecision",
    "RemoteDecisionAcknowledgement",
    "RemoteDecisionAuditRecord",
    "RemoteDecisionCapsule",
    "RemoteDecisionOutcome",
    "RemoteDecisionQueueRecord",
    "RemoteDecisionRevocation",
    "RemoteQueueState",
    "RemoteRevocationReason",
]
