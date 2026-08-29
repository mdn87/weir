from __future__ import annotations

import copy
import json
import unittest
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from weir.contract import ContractViolation, canonical_digest, canonical_json_bytes
from weir.remote_decision import (
    MAX_REMOTE_DECISION_CAPSULE_BYTES,
    RemoteDecision,
    RemoteDecisionAcknowledgement,
    RemoteDecisionAuditRecord,
    RemoteDecisionCapsule,
    RemoteDecisionOutcome,
    RemoteDecisionQueueRecord,
    RemoteDecisionRevocation,
    RemoteQueueState,
    RemoteRevocationReason,
)

NOW = datetime(2026, 8, 28, 20, 0, tzinfo=timezone.utc)
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
PUBLIC_KEYS = {"relay-key-2026-08": PRIVATE_KEY.public_key()}


def _capsule(**overrides: object) -> RemoteDecisionCapsule:
    values: dict[str, object] = {
        "key_id": "relay-key-2026-08",
        "issuer_id": "lugos-relay-issuer",
        "capsule_id": "capsule-fixture-1",
        "command_id": "command-fixture-1",
        "actor_id": "mc:user:42",
        "audience": "fade-weir-remote-decision",
        "device_id": "workstation-4070pc",
        "decision": RemoteDecision.APPROVE,
        "proposal_hash": canonical_digest({"proposal": 1}),
        "action_id": "action-fixture-1",
        "work_context_hash": canonical_digest({"context": 1}),
        "issued_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(seconds=60)).isoformat(),
        "nonce": "AAECAwQFBgcICQoLDA0ODw",
        "step_up_ref": canonical_digest({"webauthn_assertion": "fixture"}),
        "private_key": PRIVATE_KEY,
    }
    values.update(overrides)
    return RemoteDecisionCapsule.create(**values)  # type: ignore[arg-type]


def replace_queue_time(
    record: RemoteDecisionQueueRecord, recorded_at: datetime
) -> RemoteDecisionQueueRecord:
    return RemoteDecisionQueueRecord.create(
        record_id=record.record_id,
        capsule_id=record.capsule_id,
        command_id=record.command_id,
        state=record.state,
        revision=record.revision,
        claim_device_id=record.claim_device_id,
        claim_expires_at=record.claim_expires_at,
        outcome=record.outcome,
        recorded_at=recorded_at.isoformat(),
        previous_record_hash=record.previous_record_hash,
    )


class RemoteDecisionCapsuleTests(unittest.TestCase):
    def test_signed_capsule_round_trip_and_time_boundary(self) -> None:
        capsule = _capsule()
        restored = RemoteDecisionCapsule.from_dict(capsule.to_dict())
        self.assertEqual(restored, capsule)
        self.assertEqual(
            RemoteDecisionCapsule.from_bytes(canonical_json_bytes(capsule.to_dict())),
            capsule,
        )
        for offset in (0, 60, 65):
            capsule.validate_at(
                NOW + timedelta(seconds=offset),
                expected_issuer_id=capsule.issuer_id,
                expected_audience=capsule.audience,
                expected_device_id=capsule.device_id,
                public_keys=PUBLIC_KEYS,
            )
        with self.assertRaisesRegex(ContractViolation, "expired"):
            capsule.validate_at(
                NOW + timedelta(seconds=66),
                expected_issuer_id=capsule.issuer_id,
                expected_audience=capsule.audience,
                expected_device_id=capsule.device_id,
                public_keys=PUBLIC_KEYS,
            )
        with self.assertRaisesRegex(ContractViolation, "future"):
            capsule.validate_at(
                NOW - timedelta(seconds=1),
                expected_issuer_id=capsule.issuer_id,
                expected_audience=capsule.audience,
                expected_device_id=capsule.device_id,
                public_keys=PUBLIC_KEYS,
            )

    def test_signature_audience_device_and_key_fail_closed(self) -> None:
        capsule = _capsule()
        checks = (
            ("different-issuer", capsule.audience, capsule.device_id, PUBLIC_KEYS, "issuer"),
            (capsule.issuer_id, "different-audience", capsule.device_id, PUBLIC_KEYS, "audience"),
            (capsule.issuer_id, capsule.audience, "different-device", PUBLIC_KEYS, "device"),
            (capsule.issuer_id, capsule.audience, capsule.device_id, {}, "key"),
        )
        for issuer, audience, device, keys, message in checks:
            with self.subTest(message=message), self.assertRaisesRegex(
                ContractViolation, message
            ):
                capsule.validate_at(
                    NOW,
                    expected_issuer_id=issuer,
                    expected_audience=audience,
                    expected_device_id=device,
                    public_keys=keys,
                )

        tampered = copy.deepcopy(capsule.to_dict())
        tampered["proposal_hash"] = canonical_digest({"proposal": 2})
        with self.assertRaisesRegex(ContractViolation, "signature"):
            RemoteDecisionCapsule.from_dict(tampered).validate_at(
                NOW,
                expected_issuer_id=capsule.issuer_id,
                expected_audience=capsule.audience,
                expected_device_id=capsule.device_id,
                public_keys=PUBLIC_KEYS,
            )

    def test_exact_parameter_free_shape_and_canonical_transport(self) -> None:
        capsule = _capsule()
        forbidden = {
            "parameters",
            "payload",
            "dom",
            "prompt",
            "credentials",
            "cookies",
            "permit",
            "profile_id",
        }
        self.assertTrue(forbidden.isdisjoint(capsule.to_dict()))
        with self.assertRaisesRegex(ContractViolation, "unknown fields"):
            RemoteDecisionCapsule.from_dict({**capsule.to_dict(), "parameters": {}})

        pretty = json.dumps(capsule.to_dict(), indent=2).encode("utf-8")
        with self.assertRaisesRegex(ContractViolation, "canonical"):
            RemoteDecisionCapsule.from_bytes(pretty)

        with self.assertRaisesRegex(ContractViolation, "8192"):
            RemoteDecisionCapsule.from_bytes(b"{" + b" " * MAX_REMOTE_DECISION_CAPSULE_BYTES)

    def test_lifetime_nonce_and_signature_encodings_are_bounded(self) -> None:
        with self.assertRaisesRegex(ContractViolation, "lifetime"):
            _capsule(expires_at=(NOW + timedelta(seconds=121)).isoformat())
        with self.assertRaisesRegex(ContractViolation, "nonce"):
            _capsule(nonce="too-short")
        capsule = _capsule()
        with self.assertRaisesRegex(ContractViolation, "signature"):
            RemoteDecisionCapsule.from_dict({**capsule.to_dict(), "signature": "bad"})


class RemoteDecisionRecordTests(unittest.TestCase):
    def test_queue_chain_enforces_claim_retry_and_terminal_state(self) -> None:
        queued = RemoteDecisionQueueRecord.create(
            record_id="queue-fixture-1",
            capsule_id="capsule-fixture-1",
            command_id="command-fixture-1",
            state=RemoteQueueState.QUEUED,
            revision=1,
            claim_device_id=None,
            claim_expires_at=None,
            outcome=None,
            recorded_at=NOW.isoformat(),
            previous_record_hash=None,
        )
        claimed = RemoteDecisionQueueRecord.create(
            record_id="queue-fixture-2",
            capsule_id=queued.capsule_id,
            command_id=queued.command_id,
            state=RemoteQueueState.CLAIMED,
            revision=2,
            claim_device_id="workstation-4070pc",
            claim_expires_at=(NOW + timedelta(seconds=10)).isoformat(),
            outcome=None,
            recorded_at=(NOW + timedelta(seconds=1)).isoformat(),
            previous_record_hash=queued.record_hash,
        )
        acknowledged = RemoteDecisionQueueRecord.create(
            record_id="queue-fixture-3",
            capsule_id=queued.capsule_id,
            command_id=queued.command_id,
            state=RemoteQueueState.ACKNOWLEDGED,
            revision=3,
            claim_device_id=None,
            claim_expires_at=None,
            outcome=RemoteDecisionOutcome.COMPLETED,
            recorded_at=(NOW + timedelta(seconds=2)).isoformat(),
            previous_record_hash=claimed.record_hash,
        )
        claimed.require_successor(queued)
        acknowledged.require_successor(claimed)
        self.assertEqual(
            RemoteDecisionQueueRecord.from_dict(acknowledged.to_dict()), acknowledged
        )
        terminal_successor = RemoteDecisionQueueRecord.create(
            record_id="queue-fixture-4",
            capsule_id=acknowledged.capsule_id,
            command_id=acknowledged.command_id,
            state=RemoteQueueState.REVOKED,
            revision=4,
            claim_device_id=None,
            claim_expires_at=None,
            outcome=None,
            recorded_at=(NOW + timedelta(seconds=3)).isoformat(),
            previous_record_hash=acknowledged.record_hash,
        )
        with self.assertRaisesRegex(ContractViolation, "no successor"):
            terminal_successor.require_successor(acknowledged)

        requeued = RemoteDecisionQueueRecord.create(
            record_id="queue-fixture-retry",
            capsule_id=claimed.capsule_id,
            command_id=claimed.command_id,
            state=RemoteQueueState.QUEUED,
            revision=3,
            claim_device_id=None,
            claim_expires_at=None,
            outcome=None,
            recorded_at=(NOW + timedelta(seconds=11)).isoformat(),
            previous_record_hash=claimed.record_hash,
        )
        with self.assertRaisesRegex(ContractViolation, "bound capsule"):
            requeued.require_successor(claimed)
        requeued.require_successor(claimed, capsule=_capsule())

        early_retry = replace_queue_time(requeued, NOW + timedelta(seconds=2))
        with self.assertRaisesRegex(ContractViolation, "still active"):
            early_retry.require_successor(claimed, capsule=_capsule())
        expired_retry = replace_queue_time(requeued, NOW + timedelta(seconds=66))
        with self.assertRaisesRegex(ContractViolation, "expired capsule"):
            expired_retry.require_successor(claimed, capsule=_capsule())

    def test_actor_and_transport_identity_remain_distinct(self) -> None:
        acknowledgement = RemoteDecisionAcknowledgement.create(
            acknowledgement_id="ack-fixture-1",
            capsule_id="capsule-fixture-1",
            command_id="command-fixture-1",
            actor_id="mc:user:42",
            device_id="workstation-4070pc",
            transport_principal="relay-device:4070pc",
            outcome=RemoteDecisionOutcome.COMPLETED,
            receipt_hash=canonical_digest({"receipt": 1}),
            acknowledged_at=NOW.isoformat(),
        )
        self.assertNotEqual(
            acknowledgement.actor_id, acknowledgement.transport_principal
        )
        self.assertEqual(
            RemoteDecisionAcknowledgement.from_dict(acknowledgement.to_dict()),
            acknowledgement,
        )
        with self.assertRaisesRegex(ContractViolation, "receipt"):
            RemoteDecisionAcknowledgement.create(
                acknowledgement_id="ack-fixture-2",
                capsule_id="capsule-fixture-1",
                command_id="command-fixture-1",
                actor_id="mc:user:42",
                device_id="workstation-4070pc",
                transport_principal="relay-device:4070pc",
                outcome=RemoteDecisionOutcome.COMPLETED,
                receipt_hash=None,
                acknowledged_at=NOW.isoformat(),
            )
        with self.assertRaisesRegex(ContractViolation, "remain distinct"):
            RemoteDecisionAcknowledgement.create(
                acknowledgement_id="ack-fixture-3",
                capsule_id="capsule-fixture-1",
                command_id="command-fixture-1",
                actor_id="shared-principal",
                device_id="workstation-4070pc",
                transport_principal="shared-principal",
                outcome=RemoteDecisionOutcome.DENIED,
                receipt_hash=None,
                acknowledged_at=NOW.isoformat(),
            )

    def test_revocation_and_redacted_audit_round_trip(self) -> None:
        capsule = _capsule()
        revocation = RemoteDecisionRevocation.create(
            revocation_id="revocation-fixture-1",
            capsule_id=capsule.capsule_id,
            command_id=capsule.command_id,
            actor_id="mc:user:42",
            reason_code=RemoteRevocationReason.OPERATOR_WITHDREW,
            revoked_at=(NOW + timedelta(seconds=2)).isoformat(),
        )
        self.assertEqual(
            RemoteDecisionRevocation.from_dict(revocation.to_dict()), revocation
        )
        audit = RemoteDecisionAuditRecord.create(
            audit_id="audit-fixture-1",
            capsule_hash=capsule.capsule_hash,
            nonce_hash=canonical_digest({"nonce": capsule.nonce}),
            capsule_id=capsule.capsule_id,
            command_id=capsule.command_id,
            actor_id=capsule.actor_id,
            device_id=capsule.device_id,
            transport_principal="relay-device:4070pc",
            decision=capsule.decision,
            queue_state=RemoteQueueState.REVOKED,
            outcome=None,
            issued_at=capsule.issued_at,
            terminal_at=revocation.revoked_at,
            recorded_at=(NOW + timedelta(seconds=3)).isoformat(),
        )
        serialized = json.dumps(audit.to_dict(), sort_keys=True)
        for prohibited in (
            "parameters",
            "form_values",
            "raw_dom",
            "page_body",
            "prompt",
            "credentials",
            "cookies",
            "profile_id",
            "permit",
        ):
            self.assertNotIn(prohibited, serialized)
        self.assertEqual(RemoteDecisionAuditRecord.from_dict(audit.to_dict()), audit)


if __name__ == "__main__":
    unittest.main()
