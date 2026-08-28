import json
import unittest
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from jsonschema import FormatChecker, ValidationError
from jsonschema.validators import Draft202012Validator
from weir.actions import (
    ActionCompiler,
    ActionCondition,
    ActionType,
    ApprovalStatus,
    ConditionKind,
    DenyAllApprovalAuthority,
    ExecutionReceipt,
    PostconditionVerifier,
    ReceiptResult,
    Risk,
    Verification,
    VerificationConfidence,
)
from weir.browser.locators import resolve_locator
from weir.browser.models import Observation, ObservedElement, SemanticLocator
from weir.engines.base import FailureClass
from weir.models import DataClass

CONTRACTS = Path(__file__).resolve().parents[1] / "contracts"
WORK_CONTEXT_HASH = "sha256:" + "a" * 64


def _validator(name: str) -> Draft202012Validator:
    schema = json.loads((CONTRACTS / name).read_text(encoding="utf-8"))
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _observation() -> Observation:
    return Observation.create(
        observation_id="obs-1",
        session_id="session-1",
        session_revision=2,
        session_epoch=1,
        capture_id="webcap-1",
        captured_at="2026-08-27T12:00:00+00:00",
        url="https://example.com/form",
        title="Example",
        elements=[ObservedElement("e1", "button", "Save", "save", "enabled")],
        accessibility_snapshot="- button \"Save\"",
    )


def _proposal(risk: Risk | None = None):
    return ActionCompiler().propose(
        action_id="action-1",
        request_id="request-1",
        owner_run_id="run-1",
        work_context_hash=WORK_CONTEXT_HASH,
        correlation_id="request-1",
        assignment_id="assignment-1",
        observation=_observation(),
        locator=SemanticLocator(role="button", name="Save"),
        action_type=ActionType.CLICK,
        parameters={},
        parameter_data_class=DataClass.PUBLIC,
        risk=risk,
        created_at="2026-08-27T12:00:01+00:00",
        expires_at="2026-08-27T12:01:01+00:00",
    )


class ActionFoundationTests(unittest.TestCase):
    def test_compiler_binds_proposal_to_fresh_evidence_and_schema(self):
        proposal = _proposal()
        proposal.validate()
        _validator("action-proposal.schema.json").validate(proposal.to_dict())
        self.assertEqual(proposal.observation_hash, _observation().observation_hash)
        self.assertEqual(proposal.resolved_target.element_ref, "e1")
        self.assertTrue(proposal.requires_approval)

    def test_caller_cannot_downclassify_an_action(self):
        with self.assertRaisesRegex(ValueError, "requires risk"):
            _proposal(Risk.READ_ONLY)

    def test_generic_dom_primitives_remain_unknown_until_effects_are_attested(self):
        for action_type in (
            ActionType.CLICK,
            ActionType.FILL,
            ActionType.SELECT,
            ActionType.CHECK,
            ActionType.UNCHECK,
        ):
            with self.subTest(action_type=action_type):
                with self.assertRaisesRegex(ValueError, "requires risk 'unknown'"):
                    ActionCompiler().propose(
                        action_id=f"action-{action_type.value}",
                        request_id="request-risk",
                        owner_run_id="run-1",
                        work_context_hash=WORK_CONTEXT_HASH,
                        correlation_id="request-risk",
                        assignment_id="assignment-1",
                        observation=_observation(),
                        locator=SemanticLocator(role="button", name="Save"),
                        action_type=action_type,
                        parameters={},
                        parameter_data_class=DataClass.PUBLIC,
                        risk=Risk.LOCAL_MUTATION,
                        created_at="2026-08-27T12:00:01+00:00",
                        expires_at="2026-08-27T12:01:01+00:00",
                    )

    def test_action_schema_rejects_runtime_invalid_authority_fields(self):
        valid = _proposal().to_dict()
        cases = []

        no_approval = deepcopy(valid)
        no_approval["requires_approval"] = False
        cases.append(no_approval)

        downclassified_fill = deepcopy(valid)
        downclassified_fill["action_type"] = "fill"
        downclassified_fill["risk"] = "local_mutation"
        cases.append(downclassified_fill)

        empty_locator = deepcopy(valid)
        empty_locator["semantic_locator"].update(
            {"role": None, "name": None, "test_id": None}
        )
        cases.append(empty_locator)

        unnormalized_locator = deepcopy(valid)
        unnormalized_locator["semantic_locator"]["role"] = "Button"
        cases.append(unnormalized_locator)

        missing_condition_target = deepcopy(valid)
        missing_condition_target["preconditions"][1]["target"] = None
        cases.append(missing_condition_target)

        for value in cases:
            with self.subTest(value=value):
                with self.assertRaises(ValidationError):
                    _validator("action-proposal.schema.json").validate(value)

    def test_runtime_rejects_schema_invalid_boolean_counters_and_container_types(self):
        proposal = _proposal()
        proposal.session_revision = True
        with self.assertRaisesRegex(ValueError, "revision or epoch"):
            proposal.validate()

        proposal = _proposal()
        proposal.preconditions = "not-an-array"
        with self.assertRaisesRegex(ValueError, "conditions must be arrays"):
            proposal.validate()

    def test_proposal_cannot_bind_a_resolved_target_to_another_locator(self):
        proposal = _proposal()
        proposal.resolved_target = replace(
            proposal.resolved_target,
            locator_hash="sha256:" + "0" * 64,
        )
        proposal.proposal_hash = proposal.compute_hash()
        with self.assertRaisesRegex(ValueError, "different semantic locator"):
            proposal.validate()

    def test_proposal_condition_targets_share_the_observation_binding(self):
        proposal = _proposal()
        proposal.preconditions[1] = replace(
            proposal.preconditions[1],
            target=replace(proposal.preconditions[1].target, session_id="session-2"),
        )
        proposal.proposal_hash = proposal.compute_hash()
        with self.assertRaisesRegex(ValueError, "condition target"):
            proposal.validate()

    def test_condition_target_must_match_its_durable_locator(self):
        proposal = _proposal()
        condition = proposal.preconditions[1]
        proposal.preconditions[1] = replace(
            condition,
            locator=SemanticLocator(role="button", name="Other"),
        )
        with self.assertRaisesRegex(ValueError, "different semantic locator"):
            proposal.validate()

    def test_postcondition_verifier_re_resolves_locator_not_element_ref(self):
        before = _observation()
        locator = SemanticLocator(role="button", name="Save")
        target = resolve_locator(locator, before)
        proposal = ActionCompiler().propose(
            action_id="action-verify",
            request_id="request-verify",
            owner_run_id="run-1",
            work_context_hash=WORK_CONTEXT_HASH,
            correlation_id="request-verify",
            assignment_id="assignment-1",
            observation=before,
            locator=locator,
            action_type=ActionType.CLICK,
            parameters={},
            parameter_data_class=DataClass.PUBLIC,
            created_at="2026-08-27T12:00:01+00:00",
            expires_at="2026-08-27T12:01:01+00:00",
            expected_postconditions=[
                ActionCondition(
                    ConditionKind.ELEMENT_STATE_EQUALS,
                    "disabled",
                    locator=locator,
                    target=target,
                )
            ],
        )
        after = Observation.create(
            observation_id="obs-after",
            session_id=before.session_id,
            session_revision=before.session_revision + 1,
            session_epoch=before.session_epoch,
            capture_id="webcap-after",
            captured_at="2026-08-27T12:00:02+00:00",
            url=before.url,
            title=before.title,
            elements=[
                ObservedElement(
                    "different-ephemeral-ref",
                    "button",
                    "Save",
                    "save",
                    "disabled",
                )
            ],
            accessibility_snapshot='- button "Save" [disabled]',
        )

        verification = PostconditionVerifier().verify(proposal, after)

        self.assertEqual(verification.confidence, VerificationConfidence.VERIFIED)
        self.assertEqual(verification.verified_capture_index, 1)
        self.assertIn(after.capture_id, verification.supporting_evidence_refs)

    def test_postcondition_verifier_rejects_non_newer_observation(self):
        with self.assertRaisesRegex(ValueError, "newer session revision"):
            PostconditionVerifier().verify(_proposal(), _observation())

    def test_proposal_requires_evidence_at_runtime_and_in_schema(self):
        proposal = _proposal()
        proposal.evidence_refs = []
        proposal.proposal_hash = proposal.compute_hash()
        with self.assertRaisesRegex(ValueError, "at least one"):
            proposal.validate()
        with self.assertRaises(ValidationError):
            _validator("action-proposal.schema.json").validate(
                proposal.to_dict(validate=False)
            )

    def test_default_approval_authority_denies(self):
        decision = DenyAllApprovalAuthority().evaluate(_proposal())
        decision.validate()
        self.assertEqual(decision.status, ApprovalStatus.DENIED)
        self.assertIsNone(decision.approval_ref)

    def test_completed_receipt_requires_and_serializes_verified_evidence(self):
        proposal = _proposal()
        receipt = ExecutionReceipt.create(
            receipt_id="receipt-1",
            action_id=proposal.action_id,
            proposal_hash=proposal.proposal_hash,
            permit_id="permit-1",
            work_context_hash=proposal.work_context_hash,
            command_id="command-1",
            reservation_ref="reservation-1",
            session_id=proposal.session_id,
            session_epoch=proposal.session_epoch,
            lease_generation=3,
            executed_by="fade-worker-1",
            executed_at=datetime.now(timezone.utc).isoformat(),
            result=ReceiptResult.COMPLETED,
            approval_ref="approval-1",
            capture_ids=("webcap-before", "webcap-after"),
            failure_class=None,
            verification=Verification(
                "semantic_postcondition",
                VerificationConfidence.VERIFIED,
                ("webcap-after",),
                1,
            ),
        )
        _validator("execution-receipt.schema.json").validate(receipt.to_dict())

    def test_runtime_receipt_validation_matches_identifier_and_hash_schema(self):
        with self.assertRaisesRegex(ValueError, "receipt_id"):
            ExecutionReceipt.create(
                receipt_id="",
                action_id="action-1",
                proposal_hash="sha256:not-a-digest",
                permit_id="permit-1",
                work_context_hash=WORK_CONTEXT_HASH,
                command_id="command-1",
                reservation_ref="reservation-1",
                session_id="session-1",
                session_epoch=1,
                lease_generation=1,
                executed_by="worker",
                executed_at="2026-08-27T12:00:00+00:00",
                result=ReceiptResult.BLOCKED,
                approval_ref=None,
                capture_ids=(),
                failure_class=FailureClass.APPROVAL_REQUIRED,
                verification=Verification(None, VerificationConfidence.BLOCKED, ()),
            )

    def test_completed_receipt_cannot_claim_success_without_post_evidence(self):
        proposal = _proposal()
        with self.assertRaisesRegex(ValueError, "before and after"):
            ExecutionReceipt.create(
                receipt_id="receipt-1",
                action_id=proposal.action_id,
                proposal_hash=proposal.proposal_hash,
                permit_id="permit-1",
                work_context_hash=proposal.work_context_hash,
                command_id="command-1",
                reservation_ref="reservation-1",
                session_id=proposal.session_id,
                session_epoch=proposal.session_epoch,
                lease_generation=3,
                executed_by="fade-worker-1",
                executed_at=(
                    datetime.now(timezone.utc) + timedelta(seconds=1)
                ).isoformat(),
                result=ReceiptResult.COMPLETED,
                approval_ref="approval-1",
                capture_ids=("webcap-before",),
                failure_class=None,
                verification=Verification(
                    None, VerificationConfidence.PROBABLE, ("webcap-before",)
                ),
            )

    def test_verified_receipt_always_has_an_addressable_after_capture(self):
        proposal = _proposal()
        receipt = ExecutionReceipt.create(
            receipt_id="receipt-1",
            action_id=proposal.action_id,
            proposal_hash=proposal.proposal_hash,
            permit_id="permit-1",
            work_context_hash=proposal.work_context_hash,
            command_id="command-1",
            reservation_ref="reservation-1",
            session_id=proposal.session_id,
            session_epoch=proposal.session_epoch,
            lease_generation=3,
            executed_by="fade-worker-1",
            executed_at=datetime.now(timezone.utc).isoformat(),
            result=ReceiptResult.BLOCKED,
            approval_ref=None,
            capture_ids=("webcap-before", "webcap-after"),
            failure_class=FailureClass.APPROVAL_REQUIRED,
            verification=Verification(
                "semantic_postcondition",
                VerificationConfidence.VERIFIED,
                ("webcap-before",),
                1,
            ),
        )
        with self.assertRaisesRegex(ValueError, "before and after"):
            replace(receipt, capture_ids=("webcap-before",)).validate()
        schema_value = receipt.to_dict()
        schema_value["capture_ids"] = ["webcap-before"]
        with self.assertRaises(ValidationError):
            _validator("execution-receipt.schema.json").validate(schema_value)

    def test_schema_rejects_completed_receipt_with_failure(self):
        proposal = _proposal()
        value = ExecutionReceipt.create(
            receipt_id="receipt-1",
            action_id=proposal.action_id,
            proposal_hash=proposal.proposal_hash,
            permit_id="permit-1",
            work_context_hash=proposal.work_context_hash,
            command_id="command-1",
            reservation_ref="reservation-1",
            session_id=proposal.session_id,
            session_epoch=1,
            lease_generation=1,
            executed_by="worker",
            executed_at="2026-08-27T12:00:00+00:00",
            result=ReceiptResult.BLOCKED,
            approval_ref=None,
            capture_ids=("before",),
            failure_class=FailureClass.APPROVAL_REQUIRED,
            verification=Verification(
                None, VerificationConfidence.BLOCKED, ("before",)
            ),
        ).to_dict()
        value["result"] = "completed"
        with self.assertRaises(ValidationError):
            _validator("execution-receipt.schema.json").validate(value)

    def test_receipt_schema_rejects_false_verified_success(self):
        proposal = _proposal()
        valid = ExecutionReceipt.create(
            receipt_id="receipt-verified",
            action_id=proposal.action_id,
            proposal_hash=proposal.proposal_hash,
            permit_id="permit-1",
            work_context_hash=proposal.work_context_hash,
            command_id="command-1",
            reservation_ref="reservation-1",
            session_id=proposal.session_id,
            session_epoch=proposal.session_epoch,
            lease_generation=3,
            executed_by="fade-worker-1",
            executed_at=datetime.now(timezone.utc).isoformat(),
            result=ReceiptResult.COMPLETED,
            approval_ref="approval-1",
            capture_ids=("before", "after"),
            failure_class=None,
            verification=Verification(
                "semantic_postcondition",
                VerificationConfidence.VERIFIED,
                ("confirmation",),
                1,
            ),
        ).to_dict()
        cases = []

        identical_captures = deepcopy(valid)
        identical_captures["capture_ids"] = ["same", "same"]
        cases.append(identical_captures)

        missing_method = deepcopy(valid)
        missing_method["verification"]["method"] = None
        cases.append(missing_method)

        missing_evidence = deepcopy(valid)
        missing_evidence["verification"]["supporting_evidence_refs"] = []
        cases.append(missing_evidence)

        wrong_verified_capture = deepcopy(valid)
        wrong_verified_capture["verification"]["verified_capture_index"] = 0
        cases.append(wrong_verified_capture)

        for value in cases:
            with self.subTest(value=value):
                with self.assertRaises(ValidationError):
                    _validator("execution-receipt.schema.json").validate(value)


if __name__ == "__main__":
    unittest.main()
