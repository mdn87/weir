from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from weir.actions import (  # noqa: E402
    MAX_ACTION_PARAMETERS_BYTES,
    MAX_ACTION_PROPOSAL_BYTES,
    MAX_CLOCK_SKEW_SECONDS,
    MAX_EXECUTION_PERMIT_BYTES,
    MAX_EXECUTION_RECEIPT_BYTES,
    MAX_PERMIT_LIFETIME_SECONDS,
    MAX_QUARANTINE_RECORD_BYTES,
    MIN_PERMIT_ISSUER_MARGIN_SECONDS,
    MIN_PERMIT_LIFETIME_SECONDS,
    ActionCompiler,
    ActionType,
    ExecutionPermit,
    ExecutionReceipt,
    QuarantineRecord,
    ReceiptResult,
    Verification,
    VerificationConfidence,
)
from weir.browser.models import Observation, ObservedElement, SemanticLocator  # noqa: E402
from weir.contract import (  # noqa: E402
    FADE_FORBIDDEN_KEYS,
    canonical_digest,
)
from weir.engines.base import FailureClass  # noqa: E402
from weir.events import CorrelationHeader, WeirActionEvent  # noqa: E402
from weir.evidence import (  # noqa: E402
    MAX_ACQUISITION_ENVELOPE_BYTES,
    MAX_EVIDENCE_REFERENCE_BYTES,
    AcquisitionEnvelope,
    EvidenceReference,
)
from weir.models import DataClass, ReaderResult, RequestMode, WebCapture, WebRequest  # noqa: E402
from weir.persistence import ARTIFACT_REF_PREFIX  # noqa: E402
from weir.work_context import (  # noqa: E402
    MAX_INPUT_EVIDENCE_REFS,
    MAX_WORK_CONTEXT_BYTES,
    WorkContext,
    WorkContextSource,
)

OUTPUT = ROOT / "contracts" / "fixtures" / "batch-0-v1.json"
DIGEST_OUTPUT = ROOT / "contracts" / "fixtures" / "batch-0-v1.sha256"
SCHEMAS = (
    "work-context.schema.json",
    "web-request.schema.json",
    "acquisition-envelope.schema.json",
    "evidence-reference.schema.json",
    "action-proposal.schema.json",
    "execution-permit.schema.json",
    "execution-receipt.schema.json",
    "quarantine-record.schema.json",
    "correlation-header.schema.json",
    "weir-action-event.schema.json",
    "legacy/action-proposal-v0.2.schema.json",
    "legacy/execution-receipt-v0.2.schema.json",
)


def _rehash(document: dict[str, Any], hash_field: str) -> None:
    basis = copy.deepcopy(document)
    basis.pop(hash_field)
    document[hash_field] = canonical_digest(basis)


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
    context = WorkContext.create(
        context_id="context-fixture-1",
        objective_id="objective-fixture-1",
        run_id="run-fixture-1",
        assignment_id="assignment-fixture-1",
        correlation_id="request-fixture-1",
        source=WorkContextSource.AUTOWORK,
        evidence_refs=[],
        created_at="2026-08-27T12:00:00+00:00",
    )
    request = WebRequest(
        request_id="request-fixture-1",
        run_id="run-fixture-1",
        mode=RequestMode.READ,
        data_class=DataClass.PUBLIC,
        auth_context="none",
        intent="Read the deterministic contract fixture",
        url="https://example.test/fixture",
        query=None,
        source=None,
        constraints={},
        profile_id=None,
        allowed_domains=["example.test"],
        preferred_engine="http",
        maximum_depth=0,
        evidence_required=True,
        side_effects_allowed=False,
        capture_policy="content",
    )
    capture = WebCapture.from_reader_result(
        ReaderResult(
            engine="http",
            requested_url=request.url or "",
            final_url=request.url or "",
            content={"items": [{"id": "listing-1", "price_minor": 2500}]},
            title="Contract fixture",
            http_status=200,
            engine_version="fixture-1",
        ),
        request,
        capture_id="webcap-fixture-1",
        captured_at="2026-08-27T12:00:01+00:00",
    )
    artifact_ref = ARTIFACT_REF_PREFIX + capture.content_hash.removeprefix("sha256:")
    reference = EvidenceReference.create(
        evidence_ref_id="evidence-fixture-1",
        work_context=context,
        request=request,
        capture=capture,
        artifact_ref=artifact_ref,
        created_at="2026-08-27T12:00:02+00:00",
    )
    envelope = AcquisitionEnvelope.create(work_context=context, request=request)

    observation = Observation.create(
        observation_id="observation-fixture-1",
        session_id="session-fixture-1",
        session_revision=2,
        session_epoch=1,
        capture_id="webcap-browser-before",
        captured_at="2026-08-27T12:00:03+00:00",
        url="https://example.test/form",
        title="Fixture form",
        elements=[
            ObservedElement(
                "element-fixture-1",
                "textbox",
                "Shipping address",
                "shipping_address",
                "enabled",
            )
        ],
        accessibility_snapshot='- textbox "Shipping address"',
    )
    proposal = ActionCompiler().propose(
        action_id="action-fixture-1",
        request_id=request.request_id,
        owner_run_id=context.run_id,
        work_context_hash=context.context_hash,
        correlation_id=context.correlation_id,
        assignment_id=context.assignment_id,
        observation=observation,
        locator=SemanticLocator(role="textbox", name="Shipping address"),
        action_type=ActionType.FILL,
        parameters={"value": "123 Fixture Street"},
        parameter_data_class=DataClass.PERSONAL,
        created_at="2026-08-27T12:00:04+00:00",
        expires_at="2026-08-27T12:05:04+00:00",
    )
    permit = ExecutionPermit.create(
        permit_id="permit-fixture-1",
        proposal_hash=proposal.proposal_hash,
        work_context_hash=proposal.work_context_hash,
        owner_run_id=proposal.owner_run_id,
        session_id=proposal.session_id,
        session_epoch=proposal.session_epoch,
        action_type=proposal.action_type,
        risk=proposal.risk,
        approval_ref="approval-fixture-1",
        issuer_id="fade-weir-authority",
        issued_at="2026-08-27T12:00:10+00:00",
        expires_at="2026-08-27T12:01:10+00:00",
    )
    completed = ExecutionReceipt.create(
        receipt_id="receipt-fixture-completed",
        action_id=proposal.action_id,
        proposal_hash=proposal.proposal_hash,
        permit_id=permit.permit_id,
        work_context_hash=proposal.work_context_hash,
        command_id="command-fixture-completed",
        reservation_ref="reservation-fixture-completed",
        session_id=proposal.session_id,
        session_epoch=proposal.session_epoch,
        lease_generation=3,
        executed_by="weir-worker-fixture-1",
        executed_at="2026-08-27T12:00:30+00:00",
        result=ReceiptResult.COMPLETED,
        approval_ref=permit.approval_ref,
        capture_ids=("webcap-browser-before", "webcap-browser-after"),
        failure_class=None,
        verification=Verification(
            "semantic_postconditions",
            VerificationConfidence.VERIFIED,
            ("webcap-browser-after",),
            1,
        ),
    )
    unknown = ExecutionReceipt.create(
        receipt_id="receipt-fixture-unknown",
        action_id=proposal.action_id,
        proposal_hash=proposal.proposal_hash,
        permit_id=permit.permit_id,
        work_context_hash=proposal.work_context_hash,
        command_id="command-fixture-unknown",
        reservation_ref="reservation-fixture-unknown",
        session_id=proposal.session_id,
        session_epoch=proposal.session_epoch,
        lease_generation=4,
        executed_by="weir-worker-fixture-1",
        executed_at="2026-08-27T12:00:31+00:00",
        result=ReceiptResult.OUTCOME_UNKNOWN,
        approval_ref=permit.approval_ref,
        capture_ids=("webcap-browser-before",),
        failure_class=FailureClass.OUTCOME_UNKNOWN,
        verification=Verification(None, VerificationConfidence.UNCERTAIN, ()),
        quarantine_ref="weir-quarantine:quarantine-fixture-1",
    )
    quarantine = QuarantineRecord.create_active(
        quarantine_id="quarantine-fixture-1",
        session_id=proposal.session_id,
        session_epoch=proposal.session_epoch,
        work_context_hash=proposal.work_context_hash,
        permit_id=permit.permit_id,
        command_id=unknown.command_id,
        receipt_id=unknown.receipt_id,
        recorded_at="2026-08-27T12:00:32+00:00",
    )
    cleared = quarantine.clear(
        disposition_actor_id="operator-fixture-1",
        disposition_ref="disposition-fixture-1",
        recorded_at="2026-08-27T13:00:00+00:00",
    )
    header = CorrelationHeader(
        event_id="event-fixture-1",
        occurred_at="2026-08-27T12:00:05+00:00",
        producer="weir",
        run_id=context.run_id,
        assignment_id=context.assignment_id,
        correlation_id=context.correlation_id,
        work_context_hash=context.context_hash,
    )
    event = WeirActionEvent.from_proposal(header=header, proposal=proposal)

    metadata_request = WebRequest.from_dict(
        {**request.to_dict(), "capture_policy": "metadata"}
    )
    metadata_reference = EvidenceReference.create(
        evidence_ref_id="evidence-fixture-metadata",
        work_context=context,
        request=metadata_request,
        capture=capture,
        created_at="2026-08-27T12:00:02+00:00",
    )

    mutated_context = copy.deepcopy(context.to_dict())
    mutated_context["evidence_refs"] = ["weir-capture:late-output"]

    bad_artifact = copy.deepcopy(reference.to_dict())
    bad_artifact["artifact_ref"] = ARTIFACT_REF_PREFIX + "f" * 64
    _rehash(bad_artifact, "reference_hash")

    mismatched_envelope = copy.deepcopy(envelope.to_dict())
    mismatched_envelope["request"]["run_id"] = "run-other"
    _rehash(mismatched_envelope, "envelope_hash")

    nonportable_envelope = copy.deepcopy(envelope.to_dict())
    nonportable_envelope["request"]["constraints"] = {"ratio": 1.5}
    _rehash(nonportable_envelope, "envelope_hash")

    forbidden_parameter = copy.deepcopy(proposal.to_dict())
    forbidden_parameter["parameters"] = {"password": "fixture-value"}
    _rehash(forbidden_parameter, "proposal_hash")

    forbidden_permit = copy.deepcopy(permit.to_dict())
    forbidden_permit["token"] = "not-a-real-credential"

    unknown_claim = copy.deepcopy(unknown.to_dict())
    unknown_claim["capture_ids"] = ["webcap-browser-before", "webcap-browser-after"]
    unknown_claim["verification"] = {
        "method": "semantic_postconditions",
        "confidence": "verified",
        "supporting_evidence_refs": ["webcap-browser-after"],
        "verified_capture_index": 1,
    }
    _rehash(unknown_claim, "receipt_hash")

    unknown_verification = copy.deepcopy(unknown.to_dict())
    unknown_verification["verification"] = {
        "method": "semantic_postconditions",
        "confidence": "verified",
        "supporting_evidence_refs": ["webcap-browser-before"],
        "verified_capture_index": 1,
    }
    _rehash(unknown_verification, "receipt_hash")

    unknown_without_quarantine = copy.deepcopy(unknown.to_dict())
    unknown_without_quarantine["quarantine_ref"] = None
    _rehash(unknown_without_quarantine, "receipt_hash")

    leaked_event = copy.deepcopy(event.to_dict())
    leaked_event["parameters"] = {"value": "must-not-reach-HUD"}

    legacy_proposal = copy.deepcopy(proposal.to_dict())
    legacy_proposal["contract_version"] = "0.2"
    for field in (
        "work_context_hash",
        "correlation_id",
        "assignment_id",
        "parameter_data_class",
    ):
        legacy_proposal.pop(field)
    _rehash(legacy_proposal, "proposal_hash")

    legacy_receipt = copy.deepcopy(completed.to_dict())
    legacy_receipt["contract_version"] = "0.2"
    for field in (
        "permit_id",
        "work_context_hash",
        "command_id",
        "reservation_ref",
        "quarantine_ref",
        "receipt_hash",
    ):
        legacy_receipt.pop(field)

    positive = [
        _positive("work_context.empty_fixed_inputs", "work-context.schema.json", context.to_dict()),
        _positive(
            "acquisition_envelope.bound",
            "acquisition-envelope.schema.json",
            envelope.to_dict(),
        ),
        _positive(
            "evidence_reference.content",
            "evidence-reference.schema.json",
            reference.to_dict(),
        ),
        _positive(
            "action_proposal.full_authority",
            "action-proposal.schema.json",
            proposal.to_dict(),
        ),
        _positive("execution_permit.one_use", "execution-permit.schema.json", permit.to_dict()),
        _positive(
            "execution_receipt.completed",
            "execution-receipt.schema.json",
            completed.to_dict(),
        ),
        _positive(
            "execution_receipt.outcome_unknown",
            "execution-receipt.schema.json",
            unknown.to_dict(),
        ),
        _positive("quarantine.active", "quarantine-record.schema.json", quarantine.to_dict()),
        _positive(
            "quarantine.operator_cleared",
            "quarantine-record.schema.json",
            cleared.to_dict(),
        ),
        _positive("correlation_header", "correlation-header.schema.json", header.to_dict()),
        _positive("weir_action_event.redacted", "weir-action-event.schema.json", event.to_dict()),
        _positive(
            "action_proposal.legacy_v0_2_read",
            "legacy/action-proposal-v0.2.schema.json",
            legacy_proposal,
        ),
        _positive(
            "execution_receipt.legacy_v0_2_read",
            "legacy/execution-receipt-v0.2.schema.json",
            legacy_receipt,
        ),
    ]
    negative = [
        _negative(
            "work_context.late_evidence_mutation",
            "work-context.schema.json",
            "work_context_runtime",
            "context_hash_mismatch",
            mutated_context,
        ),
        _negative(
            "evidence_reference.metadata_as_content_input",
            "evidence-reference.schema.json",
            "evidence_input_runtime",
            "evidence_content_unavailable",
            metadata_reference.to_dict(),
        ),
        _negative(
            "evidence_reference.artifact_digest_substitution",
            "evidence-reference.schema.json",
            "evidence_reference_runtime",
            "artifact_hash_mismatch",
            bad_artifact,
        ),
        _negative(
            "acquisition_envelope.run_mismatch",
            "acquisition-envelope.schema.json",
            "acquisition_envelope_runtime",
            "acquisition_run_mismatch",
            mismatched_envelope,
        ),
        _negative(
            "acquisition_envelope.nonportable_constraints",
            "acquisition-envelope.schema.json",
            "acquisition_envelope_runtime",
            "acquisition_request_not_portable",
            nonportable_envelope,
        ),
        _negative(
            "action_proposal.fade_forbidden_parameter_key",
            "action-proposal.schema.json",
            "schema",
            "fade_forbidden_field",
            forbidden_parameter,
        ),
        _negative(
            "execution_permit.expired",
            "execution-permit.schema.json",
            "permit_clock_runtime",
            "permit_expired",
            permit.to_dict(),
            validation_time="2026-08-27T12:01:11+00:00",
        ),
        _negative(
            "execution_permit.insufficient_dispatch_margin",
            "execution-permit.schema.json",
            "permit_clock_runtime",
            "permit_expiry_margin",
            permit.to_dict(),
            validation_time="2026-08-27T12:00:56+00:00",
        ),
        _negative(
            "execution_permit.fade_forbidden_field",
            "execution-permit.schema.json",
            "schema",
            "fade_forbidden_field",
            forbidden_permit,
        ),
        _negative(
            "execution_receipt.unknown_with_post_state_claim",
            "execution-receipt.schema.json",
            "execution_receipt_runtime",
            "unknown_outcome_post_state_claim",
            unknown_claim,
        ),
        _negative(
            "execution_receipt.unknown_without_quarantine",
            "execution-receipt.schema.json",
            "execution_receipt_runtime",
            "unknown_outcome_without_quarantine",
            unknown_without_quarantine,
        ),
        _negative(
            "execution_receipt.unknown_with_verification_claim",
            "execution-receipt.schema.json",
            "execution_receipt_runtime",
            "unknown_outcome_verification_claim",
            unknown_verification,
        ),
        _negative(
            "weir_action_event.parameter_leak",
            "weir-action-event.schema.json",
            "schema",
            "projection_sensitive_field",
            leaked_event,
        ),
    ]

    schema_digests: dict[str, str] = {}
    for schema_name in SCHEMAS:
        schema = json.loads((ROOT / "contracts" / schema_name).read_text(encoding="utf-8"))
        schema_digests[schema_name] = canonical_digest(schema)

    return {
        "fixture_version": 1,
        "status": "frozen",
        "canonical_json": {
            "encoding": "UTF-8",
            "key_order": "recursive lexicographic order; extension keys are lowercase ASCII",
            "whitespace": "none",
            "numbers": "integers only in extension values, bounded to IEEE-754 safe range",
            "hash_algorithm": "SHA-256",
            "hash_prefix": "sha256:",
            "hash_basis": "the complete contract object except its own *_hash field",
        },
        "artifact_materialization": {
            "format": "exact WEIR canonical JSON bytes of WebCapture.content after truncation",
            "media_type": "application/json",
            "rehash": "SHA-256 over materialized bytes equals EvidenceReference.content_hash",
            "artifact_ref": "weir-artifact:sha256:<content digest>",
            "metadata_policy_satisfies_content_input": False,
            "cache_key_fields": ["capture_policy", "max_capture_bytes"],
        },
        "limits": {
            "work_context_canonical_bytes": MAX_WORK_CONTEXT_BYTES,
            "work_context_input_evidence_refs": MAX_INPUT_EVIDENCE_REFS,
            "acquisition_envelope_canonical_bytes": MAX_ACQUISITION_ENVELOPE_BYTES,
            "evidence_reference_canonical_bytes": MAX_EVIDENCE_REFERENCE_BYTES,
            "action_proposal_canonical_bytes": MAX_ACTION_PROPOSAL_BYTES,
            "action_parameters_canonical_bytes": MAX_ACTION_PARAMETERS_BYTES,
            "execution_permit_canonical_bytes": MAX_EXECUTION_PERMIT_BYTES,
            "execution_receipt_canonical_bytes": MAX_EXECUTION_RECEIPT_BYTES,
            "quarantine_record_canonical_bytes": MAX_QUARANTINE_RECORD_BYTES,
        },
        "permit_clock": {
            "authority": "weir",
            "maximum_tolerated_skew_seconds": MAX_CLOCK_SKEW_SECONDS,
            "minimum_issuer_margin_seconds": MIN_PERMIT_ISSUER_MARGIN_SECONDS,
            "minimum_lifetime_seconds": MIN_PERMIT_LIFETIME_SECONDS,
            "maximum_lifetime_seconds": MAX_PERMIT_LIFETIME_SECONDS,
        },
        "retention": {
            "evidence_reference_minimum_days": 90,
            "referenced_artifact_minimum": (
                "same as its live EvidenceReference unless a stricter data policy "
                "forbids persistence"
            ),
            "permit_minimum_days": 400,
            "receipt_minimum_days": 400,
            "active_unknown_outcome": (
                "until operator disposition; restart, retry, timeout, and expiry "
                "never clear it"
            ),
            "cleared_quarantine_minimum_days": 400,
        },
        "redaction": {
            "construction_boundary": "WEIR producer before any HUD or Mission Control transport",
            "hud_read_authentication_assumption": "none",
            "full_authority_only_fields": ["parameters"],
            "forbidden_public_content": [
                "action parameters",
                "form values",
                "raw DOM",
                "page bodies",
                "prompt text",
                "credentials",
                "cookies",
                "private profile IDs",
                "reusable permits",
            ],
        },
        "service_authentication": {
            "mode": "per_client_secret",
            "credentials_in_contracts_or_logs": False,
            "required_named_clients": ["lugos-mcp", "fade-weir-authority"],
            "fade_aire_credential_reuse": False,
        },
        "integration_invariants": {
            "work_context_evidence_refs": "caller input only and fixed at root creation",
            "autowork_assignment_binding": ["correlation_id", "assignment_id"],
            "autowork_request_run_id": "absent; orchestrator attests run linkage after parse",
            "apu_attribution": {
                "cwd_selection": "unique active candidate among exact normalized-cwd matches",
                "explicit_id_cwd_mismatch": "reject",
                "no_attribution": {"kind": "no_attribution", "cli_exit": "nonzero"},
            },
            "mission_control_before_hud_registration": True,
            "dias_v2": "separate schemas and version dispatch; v1 silent-drop canary required",
            "autowork_v5": "breaking exact-set migration; no silent field loss",
            "fade_weir_authority": (
                "second server, port, credential, run directory, and ID namespace"
            ),
            "lugos_mcp_context": (
                "authenticated origin established upstream of create_server and both "
                "dispatch paths"
            ),
            "apu_evidence": "schema version bump and watcher deployment approval required",
        },
        "reason_codes": sorted(
            {
                "acquisition_correlation_mismatch",
                "acquisition_request_not_portable",
                "acquisition_run_mismatch",
                "artifact_metadata_mismatch",
                "artifact_hash_mismatch",
                "artifact_not_canonical_json",
                "capacity_pressure",
                "capture_request_mismatch",
                "contract_too_large",
                "context_hash_mismatch",
                "cwd_mismatch",
                "evidence_content_unavailable",
                "envelope_hash_mismatch",
                "fade_forbidden_field",
                "metadata_policy_has_content",
                "no_attribution",
                "outcome_unknown",
                "permit_binding_mismatch",
                "permit_expired",
                "permit_expiry_margin",
                "permit_hash_mismatch",
                "permit_lifetime_too_long",
                "permit_lifetime_too_short",
                "permit_not_yet_valid",
                "permit_reused",
                "projection_sensitive_field",
                "proposal_hash_mismatch",
                "quarantine_already_cleared",
                "quarantine_disposition_time_invalid",
                "quarantine_record_hash_mismatch",
                "receipt_hash_mismatch",
                "reference_hash_mismatch",
                "reservation_conflict",
                "session_quarantined",
                "unknown_outcome_post_state_claim",
                "unknown_outcome_verification_claim",
                "unknown_outcome_without_quarantine",
                "unsupported_schema_version",
            }
        ),
        "fade_forbidden_keys": sorted(FADE_FORBIDDEN_KEYS),
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
    digest_line = hashlib.sha256(payload).hexdigest() + "  batch-0-v1.json\n"
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
