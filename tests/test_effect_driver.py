from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from weir.actions import (
    ActionCompiler,
    ActionCondition,
    ActionType,
    ConditionKind,
    ExecutionPermit,
    Risk,
)
from weir.browser.effect_driver import (
    FADE_AUTHORITY_ID,
    BrowserActionDriver,
    EffectResult,
    PrivateEffectCommand,
    SyntheticFixtureEffectPolicy,
    action_request_digest,
)
from weir.browser.locators import resolve_locator
from weir.browser.models import (
    BrowserSession,
    ControllerKind,
    Observation,
    ObservedElement,
    SemanticLocator,
    SessionState,
)
from weir.browser.store import SQLiteSessionStore
from weir.contract import ContractViolation
from weir.engines.base import ControllerConflict, EnginePolicyBlocked, FailureClass
from weir.models import DataClass, ReaderResult, RequestMode, WebCapture, WebRequest
from weir.persistence import CaptureStore
from weir.proposals import ActionProposalStore
from weir.service import (
    ACTION_EXECUTE_SCOPE,
    ACTION_STATUS_SCOPE,
    ClientCredential,
    ClientRegistry,
    ServiceRequestError,
    WeirServiceApplication,
)
from weir.work_context import WorkContext, WorkContextSource

ORIGIN = "http://127.0.0.1:8765"
URL = ORIGIN + "/fixture-form"
FADE_CREDENTIAL = "fade-action-authority-" + "a" * 40
OTHER_CREDENTIAL = "other-action-client-" + "b" * 40


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 8, 27, 12, 0, 20, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now


def _persist_observation(
    capture_store: CaptureStore,
    context: WorkContext,
    session: BrowserSession,
    observation: Observation,
) -> None:
    request = WebRequest(
        request_id=f"observe-{observation.observation_id}",
        run_id=context.run_id,
        mode=RequestMode.OBSERVE,
        data_class=session.data_class,
        auth_context="browser_profile",
        intent="retain synthetic browser observation evidence",
        url=observation.url,
        profile_id=session.profile_id,
        allowed_domains=list(session.allowed_domains),
        preferred_engine=session.engine,
        evidence_required=True,
        side_effects_allowed=False,
        capture_policy="full_evidence",
    )
    capture = WebCapture.from_reader_result(
        ReaderResult(
            engine=session.engine,
            engine_version="synthetic-test",
            requested_url=observation.url,
            final_url=observation.url,
            title=observation.title,
            auth_scope=f"profile:{session.profile_id}",
            content={
                "kind": "browser_observation",
                "observation": observation.to_dict(),
                "work_context": context.to_dict(),
                "worker_notes": [],
            },
        ),
        request,
        capture_id=observation.capture_id,
        captured_at=observation.captured_at,
    )
    stored, persistence = capture_store.persist(capture, request)
    if not persistence.stored or stored.capture_id != observation.capture_id:
        raise AssertionError("synthetic observation was not retained")


class SyntheticWorker:
    worker_id = "synthetic-effect-worker"

    def __init__(
        self,
        store: SQLiteSessionStore,
        capture_store: CaptureStore,
        context: WorkContext,
        *,
        outcome: bool | None = True,
        before_state: str = "empty",
        after_state: str = "filled",
        raise_on_apply: bool = False,
        worker_instance_id: str = "worker-instance-synthetic-action",
    ) -> None:
        self.store = store
        self.capture_store = capture_store
        self.context = context
        self.outcome = outcome
        self.before_state = before_state
        self.after_state = after_state
        self.raise_on_apply = raise_on_apply
        self.worker_instance_id = worker_instance_id
        self.apply_calls = 0
        self.observation_calls = 0
        self.received_parameters: dict[str, object] | None = None
        self.state_during_apply: SessionState | None = None

    def observe(
        self,
        session_id: str,
        *,
        command_id: str,
        stage: str,
    ) -> Observation:
        if stage not in {"before", "after"}:
            raise ValueError("unexpected synthetic observation stage")
        session = self.store.get_session(session_id)
        revision = session.revision + 1
        self.observation_calls += 1
        state = self.after_state if stage == "after" else self.before_state
        observation = Observation.create(
            observation_id=f"observation-{stage}-{self.observation_calls}",
            session_id=session_id,
            session_revision=revision,
            session_epoch=session.epoch,
            capture_id=f"webcap-{stage}-{self.observation_calls}",
            captured_at="2026-08-27T12:00:21+00:00",
            url=URL,
            title="Synthetic fixture",
            elements=[
                ObservedElement(
                    f"element-{stage}-{self.observation_calls}",
                    "textbox",
                    "Fixture value",
                    "fixture-value",
                    state,
                )
            ],
            accessibility_snapshot={"stage": stage, "state": state},
        )
        with self.store._lock, self.store.database:
            self.store.database.execute(
                """UPDATE browser_sessions
                   SET revision = ?, current_url = ?, updated_at = ?
                   WHERE session_id = ?""",
                (
                    revision,
                    observation.url,
                    observation.captured_at,
                    session_id,
                ),
            )
        _persist_observation(
            self.capture_store,
            self.context,
            self.store.get_session(session_id),
            observation,
        )
        return observation

    def apply(self, command: PrivateEffectCommand) -> EffectResult:
        self.apply_calls += 1
        self.state_during_apply = self.store.get_session(command.session_id).state
        self.received_parameters = command.parameters()
        if self.raise_on_apply:
            raise TimeoutError("synthetic worker return was lost")
        if self.outcome is True:
            return EffectResult(self.worker_id, self.worker_instance_id, True)
        if self.outcome is False:
            return EffectResult(
                self.worker_id,
                self.worker_instance_id,
                False,
                FailureClass.ENGINE_FAILURE,
            )
        return EffectResult(
            self.worker_id,
            self.worker_instance_id,
            None,
            FailureClass.OUTCOME_UNKNOWN,
        )


class Fixture:
    def __init__(
        self,
        root: Path,
        *,
        outcome: bool | None = True,
        before_state: str = "empty",
        raise_on_apply: bool = False,
        worker_instance_id: str = "worker-instance-synthetic-action",
        proposal_expires_at: str = "2026-08-27T12:10:02+00:00",
        permit_expires_at: str = "2026-08-27T12:02:10+00:00",
    ) -> None:
        self.root = root
        self.clock = Clock()
        self.store_path = root / "browser.sqlite3"
        self.capture_store = CaptureStore(root / "captures")
        self.store = SQLiteSessionStore(self.store_path, clock=self.clock)
        self.context = WorkContext.create(
            context_id="context-synthetic-action",
            run_id="run-synthetic-action",
            correlation_id="correlation-synthetic-action",
            assignment_id="assignment-synthetic-action",
            source=WorkContextSource.AUTOWORK,
            created_at="2026-08-27T12:00:00+00:00",
        )
        session = BrowserSession(
            session_id="session-synthetic-action",
            owner_run_id=self.context.run_id,
            engine="synthetic-effect-worker",
            worker_id="synthetic-effect-worker",
            worker_session_id="worker-session-synthetic-action",
            profile_id="profile-synthetic-action",
            data_class=DataClass.PUBLIC,
            allowed_domains=["127.0.0.1"],
            state=SessionState.ACTIVE,
            revision=2,
            epoch=1,
            current_url=URL,
            created_at="2026-08-27T12:00:00+00:00",
            updated_at="2026-08-27T12:00:02+00:00",
            expires_at="2026-08-27T13:00:00+00:00",
        )
        self.store.create_session(
            session,
            work_context=self.context,
            site_profile_id="synthetic-action-fixture",
            credential_scope="fixture_only",
            profile_policy_digest="sha256:" + "a" * 64,
            credential_binding_id="credential-synthetic-action",
            worker_instance_id="worker-instance-synthetic-action",
        )
        initial = Observation.create(
            observation_id="observation-approved",
            session_id=session.session_id,
            session_revision=session.revision,
            session_epoch=session.epoch,
            capture_id="webcap-approved",
            captured_at="2026-08-27T12:00:02+00:00",
            url=URL,
            title="Synthetic fixture",
            elements=[
                ObservedElement(
                    "element-approved",
                    "textbox",
                    "Fixture value",
                    "fixture-value",
                    "empty",
                )
            ],
            accessibility_snapshot={"stage": "approved", "state": "empty"},
        )
        _persist_observation(self.capture_store, self.context, session, initial)
        locator = SemanticLocator(
            role="textbox",
            name="Fixture value",
            test_id="fixture-value",
        )
        target = resolve_locator(locator, initial)
        self.proposal = ActionCompiler().propose(
            action_id="action-synthetic-fill",
            request_id="request-synthetic-fill",
            owner_run_id=self.context.run_id,
            work_context_hash=self.context.context_hash,
            correlation_id=self.context.correlation_id,
            assignment_id=self.context.assignment_id,
            observation=initial,
            locator=locator,
            action_type=ActionType.FILL,
            parameters={"value": "fixture-value-after"},
            parameter_data_class=DataClass.PUBLIC,
            risk=Risk.UNKNOWN,
            expected_postconditions=[
                ActionCondition(
                    ConditionKind.ELEMENT_STATE_EQUALS,
                    "filled",
                    locator=locator,
                    target=target,
                )
            ],
            created_at="2026-08-27T12:00:02+00:00",
            expires_at=proposal_expires_at,
        )
        self.proposal.preconditions.append(
            ActionCondition(
                ConditionKind.ELEMENT_STATE_EQUALS,
                "empty",
                locator=locator,
                target=target,
            )
        )
        self.proposal.proposal_hash = self.proposal.compute_hash()
        self.proposal.validate()
        self.proposals = ActionProposalStore(
            root / "proposals",
            self.capture_store,
            self.store,
            clock=self.clock,
        )
        self.proposals.register(self.proposal)
        self.lease = self.store.acquire_lease(
            session.session_id,
            session.owner_run_id,
            ControllerKind.AUTOMATION,
            ttl=timedelta(minutes=2),
        )
        self.permit = ExecutionPermit.create(
            permit_id="permit-synthetic-fill",
            proposal_hash=self.proposal.proposal_hash,
            work_context_hash=self.proposal.work_context_hash,
            owner_run_id=self.proposal.owner_run_id,
            session_id=self.proposal.session_id,
            session_epoch=self.proposal.session_epoch,
            action_type=self.proposal.action_type,
            risk=self.proposal.risk,
            approval_ref="approval-synthetic-fill",
            issuer_id=FADE_AUTHORITY_ID,
            issued_at="2026-08-27T12:00:10+00:00",
            expires_at=permit_expires_at,
        )
        self.worker = SyntheticWorker(
            self.store,
            self.capture_store,
            self.context,
            outcome=outcome,
            before_state=before_state,
            raise_on_apply=raise_on_apply,
            worker_instance_id=worker_instance_id,
        )
        self.driver = BrowserActionDriver(
            self.store,
            self.proposals,
            self.worker,
            SyntheticFixtureEffectPolicy(
                "synthetic-action-fixture",
                ORIGIN,
            ),
            clock=self.clock,
        )
        self.command_id = "fade-command-synthetic-fill"
        self.request_digest = action_request_digest(
            self.command_id,
            self.proposal,
            self.permit,
        )

    def execute(self):
        return self.driver.execute(
            command_id=self.command_id,
            request_digest=self.request_digest,
            submitted_proposal=self.proposal,
            permit=self.permit,
        )

    def close(self) -> None:
        self.store.close()


class EffectDriverTests(unittest.TestCase):
    def test_verified_fixture_effect_executes_once_and_replays_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(Path(temp))
            try:
                status = fixture.execute()
                replay = fixture.execute()
                serialized = json.dumps(status.to_dict(), sort_keys=True)

                self.assertEqual(status.state, "completed")
                self.assertEqual(replay.to_dict(), status.to_dict())
                self.assertEqual(fixture.worker.apply_calls, 1)
                self.assertEqual(
                    fixture.worker.state_during_apply,
                    SessionState.PAUSED,
                )
                self.assertEqual(
                    fixture.store.get_session(fixture.proposal.session_id).state,
                    SessionState.ACTIVE,
                )
                self.assertEqual(fixture.worker.observation_calls, 2)
                self.assertEqual(
                    fixture.worker.received_parameters,
                    {"value": "fixture-value-after"},
                )
                self.assertEqual(len(status.receipt.capture_ids), 2)
                self.assertNotIn("fixture-value-after", serialized)
                self.assertNotIn('"parameters"', serialized)
                event_json = json.dumps(
                    [event.attributes for event in fixture.store.events()],
                    sort_keys=True,
                )
                self.assertNotIn("fixture-value-after", event_json)
                self.assertNotIn('"parameters"', event_json)
            finally:
                fixture.close()

    def test_authority_is_rechecked_after_slow_pre_observation(self) -> None:
        cases = (
            {
                "permit_expires_at": "2026-08-27T12:00:40+00:00",
                "advance_to": datetime(
                    2026, 8, 27, 12, 0, 40, tzinfo=timezone.utc
                ),
            },
            {
                "proposal_expires_at": "2026-08-27T12:00:35+00:00",
                "advance_to": datetime(
                    2026, 8, 27, 12, 0, 36, tzinfo=timezone.utc
                ),
            },
        )
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temp:
                fixture = Fixture(
                    Path(temp),
                    permit_expires_at=case.get(
                        "permit_expires_at", "2026-08-27T12:02:10+00:00"
                    ),
                    proposal_expires_at=case.get(
                        "proposal_expires_at", "2026-08-27T12:10:02+00:00"
                    ),
                )
                original_observe = fixture.worker.observe

                def slow_observe(*args, **kwargs):
                    observation = original_observe(*args, **kwargs)
                    fixture.clock.now = case["advance_to"]
                    return observation

                fixture.worker.observe = slow_observe
                try:
                    status = fixture.execute()
                    self.assertEqual(status.state, "blocked")
                    self.assertEqual(fixture.worker.apply_calls, 0)
                    self.assertEqual(
                        fixture.store.get_session(fixture.proposal.session_id).state,
                        SessionState.ACTIVE,
                    )
                    self.assertIsNone(
                        fixture.store.action_dispatch_capture(
                            status.receipt.reservation_ref
                        )
                    )
                finally:
                    fixture.close()

    def test_wrong_worker_instance_cannot_reserve_or_apply(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(
                Path(temp),
                worker_instance_id="worker-instance-not-the-holder",
            )
            try:
                with self.assertRaisesRegex(
                    ControllerConflict, "credential reservation"
                ):
                    fixture.execute()
                self.assertEqual(fixture.worker.apply_calls, 0)
                self.assertIsNone(
                    fixture.store.action_reservation(fixture.permit.permit_id)
                )
                self.assertEqual(
                    fixture.store.get_session(fixture.proposal.session_id).state,
                    SessionState.ACTIVE,
                )
            finally:
                fixture.close()

    def test_invalid_digest_issuer_and_stale_revision_cause_no_effect(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(Path(temp))
            try:
                with self.assertRaises(ContractViolation) as raised:
                    fixture.driver.execute(
                        command_id=fixture.command_id,
                        request_digest="sha256:" + "f" * 64,
                        submitted_proposal=fixture.proposal,
                        permit=fixture.permit,
                    )
                self.assertEqual(
                    raised.exception.reason_code,
                    "action_request_digest_mismatch",
                )
                wrong_issuer = ExecutionPermit.create(
                    permit_id="permit-wrong-issuer",
                    proposal_hash=fixture.proposal.proposal_hash,
                    work_context_hash=fixture.proposal.work_context_hash,
                    owner_run_id=fixture.proposal.owner_run_id,
                    session_id=fixture.proposal.session_id,
                    session_epoch=fixture.proposal.session_epoch,
                    action_type=fixture.proposal.action_type,
                    risk=fixture.proposal.risk,
                    approval_ref="approval-wrong-issuer",
                    issuer_id="some-other-authority",
                    issued_at=fixture.permit.issued_at,
                    expires_at=fixture.permit.expires_at,
                )
                with self.assertRaises(ContractViolation) as raised:
                    fixture.driver.execute(
                        command_id="fade-command-wrong-issuer",
                        request_digest=action_request_digest(
                            "fade-command-wrong-issuer",
                            fixture.proposal,
                            wrong_issuer,
                        ),
                        submitted_proposal=fixture.proposal,
                        permit=wrong_issuer,
                    )
                self.assertEqual(raised.exception.reason_code, "permit_issuer_mismatch")
                with fixture.store._lock, fixture.store.database:
                    fixture.store.database.execute(
                        """UPDATE browser_sessions SET revision = revision + 1
                           WHERE session_id = ?""",
                        (fixture.proposal.session_id,),
                    )
                with self.assertRaisesRegex(RuntimeError, "stale"):
                    fixture.execute()
                self.assertEqual(fixture.worker.apply_calls, 0)
            finally:
                fixture.close()

    def test_changed_pre_state_is_blocked_after_reservation_without_effect(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(Path(temp), before_state="disabled")
            try:
                status = fixture.execute()
                self.assertEqual(status.state, "blocked")
                self.assertEqual(
                    status.receipt.failure_class,
                    FailureClass.STALE_REFERENCE,
                )
                self.assertEqual(fixture.worker.apply_calls, 0)
                self.assertIsNone(
                    fixture.store.action_dispatch_capture(
                        status.receipt.reservation_ref
                    )
                )
            finally:
                fixture.close()

    def test_expired_missing_and_wrong_session_authority_cause_no_effect(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(Path(temp))
            try:
                fixture.clock.now = datetime(
                    2026, 8, 27, 12, 3, 0, tzinfo=timezone.utc
                )
                with self.assertRaises(ContractViolation) as expired:
                    fixture.execute()
                self.assertEqual(expired.exception.reason_code, "permit_expired")
                self.assertEqual(fixture.worker.apply_calls, 0)
            finally:
                fixture.close()

        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(Path(temp))
            try:
                missing = replace(
                    fixture.proposal,
                    action_id="action-not-registered",
                    proposal_hash="",
                )
                missing.proposal_hash = missing.compute_hash()
                missing.validate()
                command_id = "fade-command-missing-proposal"
                permit = ExecutionPermit.create(
                    permit_id="permit-missing-proposal",
                    proposal_hash=missing.proposal_hash,
                    work_context_hash=missing.work_context_hash,
                    owner_run_id=missing.owner_run_id,
                    session_id=missing.session_id,
                    session_epoch=missing.session_epoch,
                    action_type=missing.action_type,
                    risk=missing.risk,
                    approval_ref="approval-missing-proposal",
                    issuer_id=FADE_AUTHORITY_ID,
                    issued_at=fixture.permit.issued_at,
                    expires_at=fixture.permit.expires_at,
                )
                with self.assertRaises(FileNotFoundError):
                    fixture.driver.execute(
                        command_id=command_id,
                        request_digest=action_request_digest(
                            command_id, missing, permit
                        ),
                        submitted_proposal=missing,
                        permit=permit,
                    )
                self.assertEqual(fixture.worker.apply_calls, 0)
            finally:
                fixture.close()

        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(Path(temp))
            try:
                wrong_session = ExecutionPermit.create(
                    permit_id="permit-wrong-session",
                    proposal_hash=fixture.proposal.proposal_hash,
                    work_context_hash=fixture.proposal.work_context_hash,
                    owner_run_id=fixture.proposal.owner_run_id,
                    session_id="session-other",
                    session_epoch=fixture.proposal.session_epoch,
                    action_type=fixture.proposal.action_type,
                    risk=fixture.proposal.risk,
                    approval_ref="approval-wrong-session",
                    issuer_id=FADE_AUTHORITY_ID,
                    issued_at=fixture.permit.issued_at,
                    expires_at=fixture.permit.expires_at,
                )
                command_id = "fade-command-wrong-session"
                with self.assertRaises(ContractViolation) as mismatched:
                    fixture.driver.execute(
                        command_id=command_id,
                        request_digest=action_request_digest(
                            command_id,
                            fixture.proposal,
                            wrong_session,
                        ),
                        submitted_proposal=fixture.proposal,
                        permit=wrong_session,
                    )
                self.assertEqual(
                    mismatched.exception.reason_code,
                    "permit_binding_mismatch",
                )
                self.assertEqual(fixture.worker.apply_calls, 0)
            finally:
                fixture.close()

    def test_ambiguous_worker_result_quarantines_and_never_replays(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(Path(temp), outcome=None)
            try:
                status = fixture.execute()
                replay = fixture.execute()

                self.assertEqual(status.state, "outcome_unknown")
                self.assertEqual(replay.to_dict(), status.to_dict())
                self.assertEqual(fixture.worker.apply_calls, 1)
                self.assertEqual(
                    fixture.store.get_session(fixture.proposal.session_id).state,
                    SessionState.LOST,
                )
                self.assertEqual(
                    fixture.store.profile_reservation(
                        fixture.proposal.session_id
                    ).state,
                    "quarantined",
                )
            finally:
                fixture.close()

    def test_restart_status_recovery_uses_dispatch_marker_for_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fixture = Fixture(root)
            start = fixture.store.reserve_action_execution(
                fixture.permit,
                fixture.proposal,
                request_digest=fixture.request_digest,
                command_id=fixture.command_id,
                worker_id=fixture.worker.worker_id,
                worker_instance_id=fixture.worker.worker_instance_id,
                required_lease=fixture.lease,
            )
            reservation = start.reservation
            before = fixture.worker.observe(
                fixture.proposal.session_id,
                command_id="effect-before-restart",
                stage="before",
            )
            fixture.store.mark_action_dispatching(
                reservation.reservation_ref,
                before_capture_id=before.capture_id,
                approval_ref=fixture.permit.approval_ref,
                worker_id=fixture.worker.worker_id,
                worker_instance_id=fixture.worker.worker_instance_id,
                permit=fixture.permit,
                proposal=fixture.proposal,
                expected_session_revision=before.session_revision,
                required_lease=start.lease,
            )
            fixture.close()

            reopened = SQLiteSessionStore(fixture.store_path, clock=fixture.clock)
            proposals = ActionProposalStore(
                root / "proposals",
                CaptureStore(root / "captures"),
                reopened,
                clock=fixture.clock,
            )
            fixture.worker.store = reopened
            driver = BrowserActionDriver(
                reopened,
                proposals,
                fixture.worker,
                SyntheticFixtureEffectPolicy("synthetic-action-fixture", ORIGIN),
                clock=fixture.clock,
            )
            try:
                status = driver.status(fixture.command_id)
                self.assertIsNotNone(status)
                self.assertEqual(status.state, "outcome_unknown")
                self.assertEqual(fixture.worker.apply_calls, 0)
                self.assertEqual(
                    reopened.get_session(fixture.proposal.session_id).state,
                    SessionState.LOST,
                )
            finally:
                reopened.close()

    def test_status_recovery_cancels_reservation_when_dispatch_never_began(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(Path(temp))
            try:
                fixture.store.reserve_action_execution(
                    fixture.permit,
                    fixture.proposal,
                    request_digest=fixture.request_digest,
                    command_id=fixture.command_id,
                    worker_id=fixture.worker.worker_id,
                    worker_instance_id=fixture.worker.worker_instance_id,
                    required_lease=fixture.lease,
                )
                status = fixture.driver.status(fixture.command_id)
                self.assertEqual(status.state, "cancelled")
                self.assertEqual(fixture.worker.apply_calls, 0)
                self.assertIsNone(status.receipt.approval_ref)
            finally:
                fixture.close()

    def test_policy_and_private_command_remain_narrow_and_redacted(self) -> None:
        with self.assertRaisesRegex(ValueError, "loopback"):
            SyntheticFixtureEffectPolicy(
                "synthetic-action-fixture",
                "https://example.com",
            )
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(Path(temp))
            try:
                target = fixture.proposal.resolved_target
                command = PrivateEffectCommand.create(
                    command_id=fixture.command_id,
                    request_digest=fixture.request_digest,
                    reservation_ref="reservation-redaction-test",
                    worker_id=fixture.worker.worker_id,
                    worker_instance_id=fixture.worker.worker_instance_id,
                    session_id=target.session_id,
                    session_epoch=target.session_epoch,
                    session_revision=target.session_revision,
                    lease_generation=fixture.lease.generation,
                    action_type=fixture.proposal.action_type,
                    target=target,
                    parameter_data_class=DataClass.PUBLIC,
                    parameters={"value": "must-not-appear"},
                )
                self.assertNotIn("must-not-appear", repr(command))
                upload = replace(
                    fixture.proposal,
                    action_type=ActionType.UPLOAD,
                    risk=Risk.EXTERNAL_UPLOAD,
                    parameters={"value": "not-used"},
                    proposal_hash="",
                )
                upload.proposal_hash = upload.compute_hash()
                with self.assertRaises(EnginePolicyBlocked):
                    fixture.driver.policy.validate(upload, fixture.store)
            finally:
                fixture.close()


class ActionServiceTests(unittest.TestCase):
    @staticmethod
    def _headers(client_id: str, credential: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {credential}",
            "X-Weir-Client-Id": client_id,
            "X-Weir-Deadline": "2026-08-27T12:00:40+00:00",
        }

    @staticmethod
    def _body(fixture: Fixture) -> bytes:
        return json.dumps(
            {
                "schema_version": 1,
                "command_id": fixture.command_id,
                "request_digest": fixture.request_digest,
                "proposal": fixture.proposal.to_dict(),
                "permit": fixture.permit.to_dict(),
            }
        ).encode("utf-8")

    @staticmethod
    def _registry() -> ClientRegistry:
        scopes = frozenset({ACTION_EXECUTE_SCOPE, ACTION_STATUS_SCOPE})
        return ClientRegistry(
            [
                ClientCredential(
                    FADE_AUTHORITY_ID,
                    FADE_CREDENTIAL,
                    scopes,
                    frozenset({DataClass.PUBLIC}),
                ),
                ClientCredential(
                    "other-action-client",
                    OTHER_CREDENTIAL,
                    scopes,
                    frozenset({DataClass.PUBLIC}),
                ),
            ]
        )

    def test_fade_only_routes_execute_and_return_parameter_free_status(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(Path(temp))
            app = WeirServiceApplication(
                mock.Mock(),
                self._registry(),
                proposal_store=fixture.proposals,
                session_store=fixture.store,
                action_driver=fixture.driver,
                clock=fixture.clock,
            )
            try:
                response = app.handle(
                    "POST",
                    "/v1/actions/execute",
                    self._headers(FADE_AUTHORITY_ID, FADE_CREDENTIAL),
                    self._body(fixture),
                )
                status = app.handle(
                    "GET",
                    f"/v1/actions/commands/{fixture.command_id}",
                    self._headers(FADE_AUTHORITY_ID, FADE_CREDENTIAL),
                    None,
                )
                self.assertEqual(response.status, 200)
                self.assertEqual(status.status, 200)
                self.assertEqual(json.loads(response.body)["state"], "completed")
                self.assertEqual(response.body, status.body)
                self.assertNotIn(b"fixture-value-after", response.body)
                self.assertNotIn(b"parameters", response.body)
            finally:
                fixture.close()

    def test_action_routes_reject_other_identity_and_stay_disabled_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(Path(temp))
            disabled = WeirServiceApplication(
                mock.Mock(),
                self._registry(),
                proposal_store=fixture.proposals,
                session_store=fixture.store,
                clock=fixture.clock,
            )
            enabled = WeirServiceApplication(
                mock.Mock(),
                self._registry(),
                proposal_store=fixture.proposals,
                session_store=fixture.store,
                action_driver=fixture.driver,
                clock=fixture.clock,
            )
            try:
                with self.assertRaises(ServiceRequestError) as denied:
                    enabled.handle(
                        "POST",
                        "/v1/actions/execute",
                        self._headers("other-action-client", OTHER_CREDENTIAL),
                        self._body(fixture),
                    )
                self.assertEqual(denied.exception.status, 403)
                self.assertEqual(denied.exception.reason_code, "action_identity_denied")
                with self.assertRaises(ServiceRequestError) as unavailable:
                    disabled.handle(
                        "POST",
                        "/v1/actions/execute",
                        self._headers(FADE_AUTHORITY_ID, FADE_CREDENTIAL),
                        self._body(fixture),
                    )
                self.assertEqual(unavailable.exception.status, 501)
                self.assertEqual(
                    unavailable.exception.reason_code,
                    "action_driver_unavailable",
                )
                self.assertEqual(fixture.worker.apply_calls, 0)
            finally:
                fixture.close()

    def test_action_request_parser_rejects_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(Path(temp))
            app = WeirServiceApplication(
                mock.Mock(),
                self._registry(),
                proposal_store=fixture.proposals,
                session_store=fixture.store,
                action_driver=fixture.driver,
                clock=fixture.clock,
            )
            value = json.loads(self._body(fixture))
            value["extra"] = True
            try:
                with self.assertRaises(ServiceRequestError) as malformed:
                    app.handle(
                        "POST",
                        "/v1/actions/execute",
                        self._headers(FADE_AUTHORITY_ID, FADE_CREDENTIAL),
                        json.dumps(value).encode("utf-8"),
                    )
                self.assertEqual(malformed.exception.status, 400)
                self.assertEqual(
                    malformed.exception.reason_code,
                    "invalid_action_execution",
                )
                self.assertEqual(fixture.worker.apply_calls, 0)
            finally:
                fixture.close()


if __name__ == "__main__":
    unittest.main()
