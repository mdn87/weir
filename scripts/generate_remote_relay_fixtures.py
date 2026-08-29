from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from weir.contract import canonical_digest  # noqa: E402
from weir.remote_decision import (  # noqa: E402
    MAX_REMOTE_DECISION_CAPSULE_BYTES,
    MAX_REMOTE_DECISION_CLOCK_SKEW_SECONDS,
    MAX_REMOTE_DECISION_LIFETIME_SECONDS,
    MAX_REMOTE_DECISION_LIVE_ENTRIES,
    RemoteDecision,
    RemoteDecisionAcknowledgement,
    RemoteDecisionAuditRecord,
    RemoteDecisionCapsule,
    RemoteDecisionOutcome,
    RemoteDecisionQueueRecord,
    RemoteDecisionRevocation,
    RemoteQueueState,
    RemoteRevocationReason,
    _b64url_encode,
)

OUTPUT = ROOT / "contracts" / "fixtures" / "remote-relay-v1.json"
DIGEST_OUTPUT = ROOT / "contracts" / "fixtures" / "remote-relay-v1.sha256"
SCHEMAS = (
    "remote-decision-capsule.schema.json",
    "remote-decision-ack.schema.json",
    "remote-decision-queue-state.schema.json",
    "remote-decision-revocation.schema.json",
    "remote-decision-audit.schema.json",
)
NOW = datetime(2026, 8, 28, 20, 0, tzinfo=timezone.utc)


def _positive(name: str, schema: str, document: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": name,
        "schema": schema,
        "canonical_sha256": canonical_digest(document),
        "document": document,
    }


def _negative(
    name: str,
    schema: str,
    validator: str,
    reason_code: str,
    document: dict[str, Any],
    **metadata: Any,
) -> dict[str, Any]:
    return {
        "name": name,
        "schema": schema,
        "validator": validator,
        "reason_code": reason_code,
        "document": document,
        **metadata,
    }


def build_manifest() -> dict[str, Any]:
    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    capsule = RemoteDecisionCapsule.create(
        key_id="relay-key-2026-08",
        issuer_id="lugos-relay-issuer",
        capsule_id="capsule-fixture-approve",
        command_id="command-fixture-approve",
        actor_id="mc:user:42",
        audience="fade-weir-remote-decision",
        device_id="workstation-4070pc",
        decision=RemoteDecision.APPROVE,
        proposal_hash=canonical_digest({"proposal": "fixture"}),
        action_id="action-fixture-1",
        work_context_hash=canonical_digest({"context": "fixture"}),
        issued_at=NOW.isoformat(),
        expires_at=(NOW + timedelta(seconds=60)).isoformat(),
        nonce="AAECAwQFBgcICQoLDA0ODw",
        step_up_ref=canonical_digest({"webauthn_assertion": "approve-fixture"}),
        private_key=private_key,
    )
    denied_capsule = RemoteDecisionCapsule.create(
        key_id="relay-key-2026-08",
        issuer_id="lugos-relay-issuer",
        capsule_id="capsule-fixture-deny",
        command_id="command-fixture-deny",
        actor_id="mc:user:84",
        audience="fade-weir-remote-decision",
        device_id="workstation-4070pc",
        decision=RemoteDecision.DENY,
        proposal_hash=capsule.proposal_hash,
        action_id=capsule.action_id,
        work_context_hash=capsule.work_context_hash,
        issued_at=NOW.isoformat(),
        expires_at=(NOW + timedelta(seconds=60)).isoformat(),
        nonce="EBESExQVFhcYGRobHB0eHw",
        step_up_ref=canonical_digest({"webauthn_assertion": "deny-fixture"}),
        private_key=private_key,
    )
    queued = RemoteDecisionQueueRecord.create(
        record_id="queue-fixture-1",
        capsule_id=capsule.capsule_id,
        command_id=capsule.command_id,
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
        capsule_id=capsule.capsule_id,
        command_id=capsule.command_id,
        state=RemoteQueueState.CLAIMED,
        revision=2,
        claim_device_id=capsule.device_id,
        claim_expires_at=(NOW + timedelta(seconds=10)).isoformat(),
        outcome=None,
        recorded_at=(NOW + timedelta(seconds=1)).isoformat(),
        previous_record_hash=queued.record_hash,
    )
    acknowledgement = RemoteDecisionAcknowledgement.create(
        acknowledgement_id="ack-fixture-1",
        capsule_id=capsule.capsule_id,
        command_id=capsule.command_id,
        actor_id=capsule.actor_id,
        device_id=capsule.device_id,
        transport_principal="relay-device:4070pc",
        outcome=RemoteDecisionOutcome.COMPLETED,
        receipt_hash=canonical_digest({"receipt": "fixture"}),
        acknowledged_at=(NOW + timedelta(seconds=2)).isoformat(),
    )
    acknowledged = RemoteDecisionQueueRecord.create(
        record_id="queue-fixture-3",
        capsule_id=capsule.capsule_id,
        command_id=capsule.command_id,
        state=RemoteQueueState.ACKNOWLEDGED,
        revision=3,
        claim_device_id=None,
        claim_expires_at=None,
        outcome=acknowledgement.outcome,
        recorded_at=acknowledgement.acknowledged_at,
        previous_record_hash=claimed.record_hash,
    )
    revocation = RemoteDecisionRevocation.create(
        revocation_id="revocation-fixture-1",
        capsule_id=denied_capsule.capsule_id,
        command_id=denied_capsule.command_id,
        actor_id="mc:user:84",
        reason_code=RemoteRevocationReason.OPERATOR_WITHDREW,
        revoked_at=(NOW + timedelta(seconds=2)).isoformat(),
    )
    audit = RemoteDecisionAuditRecord.create(
        audit_id="audit-fixture-1",
        capsule_hash=capsule.capsule_hash,
        nonce_hash=canonical_digest({"nonce": capsule.nonce}),
        capsule_id=capsule.capsule_id,
        command_id=capsule.command_id,
        actor_id=capsule.actor_id,
        device_id=capsule.device_id,
        transport_principal=acknowledgement.transport_principal,
        decision=capsule.decision,
        queue_state=RemoteQueueState.ACKNOWLEDGED,
        outcome=acknowledgement.outcome,
        issued_at=capsule.issued_at,
        terminal_at=acknowledgement.acknowledged_at,
        recorded_at=(NOW + timedelta(seconds=3)).isoformat(),
    )

    parameter_leak = {**capsule.to_dict(), "parameters": {"value": "forbidden"}}
    signature_tamper = copy.deepcopy(capsule.to_dict())
    signature_tamper["action_id"] = "action-substituted"
    oversized = copy.deepcopy(capsule.to_dict())
    oversized["actor_id"] = "a" * MAX_REMOTE_DECISION_CAPSULE_BYTES
    audit_leak = {**audit.to_dict(), "payload": {"parameters": {}}}

    positive = [
        _positive(
            "remote_capsule.approve",
            "remote-decision-capsule.schema.json",
            capsule.to_dict(),
        ),
        _positive(
            "remote_capsule.deny",
            "remote-decision-capsule.schema.json",
            denied_capsule.to_dict(),
        ),
        _positive(
            "remote_queue.queued",
            "remote-decision-queue-state.schema.json",
            queued.to_dict(),
        ),
        _positive(
            "remote_queue.claimed",
            "remote-decision-queue-state.schema.json",
            claimed.to_dict(),
        ),
        _positive(
            "remote_queue.acknowledged",
            "remote-decision-queue-state.schema.json",
            acknowledged.to_dict(),
        ),
        _positive(
            "remote_ack.completed",
            "remote-decision-ack.schema.json",
            acknowledgement.to_dict(),
        ),
        _positive(
            "remote_revocation.operator",
            "remote-decision-revocation.schema.json",
            revocation.to_dict(),
        ),
        _positive(
            "remote_audit.redacted",
            "remote-decision-audit.schema.json",
            audit.to_dict(),
        ),
    ]
    negative = [
        _negative(
            "remote_capsule.parameter_channel",
            "remote-decision-capsule.schema.json",
            "schema",
            "remote_contract_shape_invalid",
            parameter_leak,
        ),
        _negative(
            "remote_capsule.signature_tamper",
            "remote-decision-capsule.schema.json",
            "capsule_signature",
            "remote_signature_invalid",
            signature_tamper,
            validation_time=NOW.isoformat(),
        ),
        _negative(
            "remote_capsule.wrong_issuer",
            "remote-decision-capsule.schema.json",
            "capsule_runtime",
            "remote_issuer_mismatch",
            capsule.to_dict(),
            validation_time=NOW.isoformat(),
            expected_issuer_id="another-issuer",
            expected_audience=capsule.audience,
            expected_device_id=capsule.device_id,
        ),
        _negative(
            "remote_capsule.wrong_audience",
            "remote-decision-capsule.schema.json",
            "capsule_runtime",
            "remote_audience_mismatch",
            capsule.to_dict(),
            validation_time=NOW.isoformat(),
            expected_issuer_id=capsule.issuer_id,
            expected_audience="another-audience",
            expected_device_id=capsule.device_id,
        ),
        _negative(
            "remote_capsule.wrong_device",
            "remote-decision-capsule.schema.json",
            "capsule_runtime",
            "remote_device_mismatch",
            capsule.to_dict(),
            validation_time=NOW.isoformat(),
            expected_issuer_id=capsule.issuer_id,
            expected_audience=capsule.audience,
            expected_device_id="workstation-other",
        ),
        _negative(
            "remote_capsule.unknown_key",
            "remote-decision-capsule.schema.json",
            "capsule_unknown_key",
            "remote_key_unknown",
            capsule.to_dict(),
            validation_time=NOW.isoformat(),
        ),
        _negative(
            "remote_capsule.expired_beyond_skew",
            "remote-decision-capsule.schema.json",
            "capsule_runtime",
            "remote_expired",
            capsule.to_dict(),
            validation_time=(NOW + timedelta(seconds=66)).isoformat(),
            expected_issuer_id=capsule.issuer_id,
            expected_audience=capsule.audience,
            expected_device_id=capsule.device_id,
        ),
        _negative(
            "remote_capsule.not_yet_issued",
            "remote-decision-capsule.schema.json",
            "capsule_runtime",
            "remote_not_yet_valid",
            capsule.to_dict(),
            validation_time=(NOW - timedelta(seconds=1)).isoformat(),
            expected_issuer_id=capsule.issuer_id,
            expected_audience=capsule.audience,
            expected_device_id=capsule.device_id,
        ),
        _negative(
            "remote_capsule.oversized",
            "remote-decision-capsule.schema.json",
            "capsule_parse",
            "contract_too_large",
            oversized,
        ),
        _negative(
            "remote_audit.payload_channel",
            "remote-decision-audit.schema.json",
            "schema",
            "remote_contract_shape_invalid",
            audit_leak,
        ),
    ]
    schema_digests = {
        name: canonical_digest(
            json.loads((ROOT / "contracts" / name).read_text(encoding="utf-8"))
        )
        for name in SCHEMAS
    }
    return {
        "fixture_version": 1,
        "status": "frozen",
        "topology": "signed outbound pull; Fade and WEIR remain loopback-only",
        "feature_flags": {
            "MC_REMOTE_DECISIONS_ENABLED": False,
            "LUGOS_RELAY_ISSUER_ENABLED": False,
            "FADE_REMOTE_RELAY_ENABLED": False,
            "FADE_WEIR_RELAY_INGRESS_ENABLED": False,
        },
        "canonical_json": {
            "encoding": "UTF-8",
            "key_order": "recursive lexicographic",
            "whitespace": "none",
            "signature_basis": "complete capsule object except signature",
            "signature_algorithm": "Ed25519",
            "hash_algorithm": "SHA-256",
        },
        "limits": {
            "capsule_canonical_bytes": MAX_REMOTE_DECISION_CAPSULE_BYTES,
            "maximum_live_queue_entries": MAX_REMOTE_DECISION_LIVE_ENTRIES,
            "maximum_capsule_lifetime_seconds": MAX_REMOTE_DECISION_LIFETIME_SECONDS,
        },
        "clock": {
            "authority": "relay verifier",
            "not_before_skew_seconds": 0,
            "expiry_skew_seconds": MAX_REMOTE_DECISION_CLOCK_SKEW_SECONDS,
        },
        "state_machine": {
            "initial": "queued",
            "claim_is_authority": False,
            "terminal": ["acknowledged", "denied", "expired", "revoked"],
            "claim_retry": "claimed may return to queued only while capsule is live",
            "outcome_unknown_replay": False,
        },
        "uniqueness": {
            "capsule_id": "durable global uniqueness",
            "command_id": "durable global uniqueness and conflicting reuse rejection",
            "nonce_hash": "durable global uniqueness retained after capsule-body purge",
        },
        "redaction": {
            "capsule_forbidden": [
                "parameters",
                "generic payload",
                "DOM",
                "prompt text",
                "credentials",
                "cookies",
                "private profile IDs",
                "permits",
            ],
            "audit_retains": [
                "capsule hash",
                "nonce hash",
                "capsule and command IDs",
                "actor and device IDs",
                "transport principal when observed",
                "timestamps",
                "decision, terminal state, and outcome",
            ],
            "capsule_body_purge_deadline": "deployment decision required before enablement",
        },
        "test_public_keys": {
            "relay-key-2026-08": _b64url_encode(public_key),
        },
        "schema_digests": schema_digests,
        "positive": positive,
        "negative": negative,
    }


def render() -> bytes:
    return (
        json.dumps(build_manifest(), indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    ).encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    payload = render()
    digest_line = hashlib.sha256(payload).hexdigest() + "  remote-relay-v1.json\n"
    if args.write:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_bytes(payload)
        DIGEST_OUTPUT.write_text(digest_line, encoding="ascii", newline="\n")
        return 0
    if not OUTPUT.exists() or OUTPUT.read_bytes() != payload:
        print(f"{OUTPUT.relative_to(ROOT)} is stale; run this script with --write")
        return 1
    if not DIGEST_OUTPUT.exists() or DIGEST_OUTPUT.read_text(encoding="ascii") != digest_line:
        print(f"{DIGEST_OUTPUT.relative_to(ROOT)} is stale; run this script with --write")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
