import tempfile
import threading
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from tests.browser_fakes import ScriptedBrowserWorker
from weir.browser.broker import BrowserSessionBroker, SessionOwnershipError
from weir.browser.models import ControllerKind, SessionState
from weir.browser.process_worker import WorkerDeathAttestation
from weir.browser.profile_registry import (
    StaticProfileStateRegistry,
    VerifiedProfileState,
)
from weir.browser.protocol import StaleWorkerCommand
from weir.browser.store import (
    CommandAttemptSuperseded,
    CommandInDoubt,
    SessionRevisionConflict,
    SQLiteSessionStore,
)
from weir.engines.base import (
    ControllerConflict,
    EngineFailure,
    EnginePolicyBlocked,
    ProfileInUse,
)
from weir.models import DataClass, RequestMode, WebRequest
from weir.persistence import CaptureStore
from weir.work_context import WorkContext, WorkContextSource

from weir.profiles import SiteProfile, SiteProfileRegistry


class Ids:
    def __init__(self) -> None:
        self.value = 0

    def __call__(self, prefix: str) -> str:
        self.value += 1
        return f"{prefix}-{self.value}"


class BrowserBrokerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime.now(timezone.utc)
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.store = SQLiteSessionStore(root / "browser.sqlite3", clock=lambda: self.now)
        self.worker = ScriptedBrowserWorker()
        profile = SiteProfile.from_dict(
            {
                "contract_version": "0.1",
                "id": "test-portal",
                "domains": ["127.0.0.1"],
                "preferred_engines": ["fake-browser"],
                "auth_mode": "dedicated_profile",
                "allowed_modes": ["observe"],
                "approval_risks": ["external_submit"],
                "known_failures": {},
                "retention": {"screenshots": "full_evidence"},
                "browser_observation": {
                    "javascript": "disabled",
                    "network_methods": "get_head_only",
                    "credential_scope": "read_only",
                },
                "notes": ["Local authenticated test fixture."],
            }
        )
        self.profile_bindings = StaticProfileStateRegistry(
            [
                VerifiedProfileState(
                    profile_id="profile-1",
                    credential_binding_id="credential-binding-1",
                    site_profile_id="test-portal",
                    credential_scope="read_only",
                    storage_state={},
                )
            ]
        )
        self.broker = BrowserSessionBroker(
            [self.worker],
            store=self.store,
            capture_store=CaptureStore(root / "evidence"),
            profiles=SiteProfileRegistry([profile]),
            profile_bindings=self.profile_bindings,
            clock=lambda: self.now,
            id_factory=Ids(),
            controller_ttl=timedelta(minutes=5),
        )
        self.request = WebRequest(
            request_id="request-1",
            run_id="run-1",
            mode=RequestMode.OBSERVE,
            data_class=DataClass.BWA_INTERNAL,
            auth_context="browser",
            intent="observe the test portal",
            url="http://127.0.0.1:8765/start",
            profile_id="profile-1",
            allowed_domains=["127.0.0.1"],
            capture_policy="full_evidence",
        )
        self.context = WorkContext.create(
            context_id="context-1",
            objective_id="objective-1",
            run_id="run-1",
            assignment_id="assignment-1",
            correlation_id="request-1",
            source=WorkContextSource.OGMI,
            created_at=self.now.isoformat(),
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def _open(self):
        return self.broker.open(
            self.request,
            self.context,
            worker_id=self.worker.descriptor.worker_id,
            operation_id="open-1",
        )

    def test_external_operation_id_cannot_collide_with_worker_subcommands(self):
        with self.assertRaisesRegex(ValueError, "reserved"):
            self.broker.open(
                self.request,
                self.context,
                worker_id=self.worker.descriptor.worker_id,
                operation_id="open-1:rollback-close",
            )
        self.assertEqual(self.store.sessions(), [])
        self.assertEqual(self.worker.calls, [])

    def test_open_binds_context_profile_and_controller_durably(self):
        session = self._open()
        self.assertEqual(session.state, SessionState.ACTIVE)
        self.assertEqual(session.revision, 1)
        self.assertEqual(session.controller_lease.kind, ControllerKind.AUTOMATION)
        self.assertEqual(
            self.store.work_context(session.session_id).context_hash,
            self.context.context_hash,
        )
        replay = self._open()
        self.assertEqual(replay.session_id, session.session_id)
        self.assertEqual([call[0] for call in self.worker.calls], ["open"])
        binding = self.store.profile_binding(session.session_id)
        self.assertEqual(binding.site_profile_id, "test-portal")
        self.assertEqual(binding.credential_scope, "read_only")

    def test_worker_command_deadline_never_outlives_its_controller_lease(self):
        session = self._open()
        lease = session.controller_lease
        self.assertIsNotNone(lease)
        self.broker.command_timeout = timedelta(hours=1)
        command = self.broker._command(  # noqa: SLF001 - invariant fixture
            "deadline-check",
            "observe",
            session,
            lease,
            {"session_id": session.session_id},
        )
        self.assertEqual(
            datetime.fromisoformat(command.deadline_at),
            datetime.fromisoformat(lease.expires_at),
        )

    def test_open_retry_recovers_generated_session_after_creation_crash(self):
        original_create = self.store.create_session

        def crash_after_create(*args, **kwargs):
            original_create(*args, **kwargs)
            raise SystemExit("simulated process crash")

        self.store.create_session = crash_after_create
        try:
            with self.assertRaisesRegex(SystemExit, "simulated process crash"):
                self._open()
        finally:
            self.store.create_session = original_create

        opening = self.store.session_for_open_command("open-1")
        self.assertEqual(opening.state, SessionState.OPENING)
        self.now += self.broker.command_resume_after + timedelta(seconds=1)
        resumed = self._open()
        self.assertEqual(resumed.session_id, opening.session_id)
        self.assertEqual(resumed.state, SessionState.ACTIVE)
        self.assertEqual([call[0] for call in self.worker.calls], ["open"])

    def test_concurrent_duplicate_open_cannot_claim_live_attempt(self):
        entered = threading.Event()
        release = threading.Event()

        class BlockingOpenWorker(ScriptedBrowserWorker):
            def _open_session_serialized(self, spec, command):
                entered.set()
                if not release.wait(timeout=5):
                    raise RuntimeError("test open was not released")
                return super()._open_session_serialized(spec, command)

        worker = BlockingOpenWorker()
        self.worker = worker
        self.broker = BrowserSessionBroker(
            [worker],
            store=self.store,
            capture_store=self.broker.capture_store,
            profiles=self.broker.profiles,
            profile_bindings=self.profile_bindings,
            clock=lambda: self.now,
            id_factory=Ids(),
            controller_ttl=timedelta(minutes=5),
        )
        outcome = []

        def first_open():
            try:
                outcome.append(self._open())
            except Exception as exc:  # pragma: no cover - assertion reports it
                outcome.append(exc)

        thread = threading.Thread(target=first_open)
        thread.start()
        self.assertTrue(entered.wait(timeout=5))
        with self.assertRaises(CommandInDoubt):
            self._open()
        release.set()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(outcome), 1)
        self.assertEqual(outcome[0].state, SessionState.ACTIVE)
        self.assertEqual(self._open().session_id, outcome[0].session_id)

    def test_observation_and_screenshot_are_immutable_and_replayable(self):
        session = self._open()
        result = self.broker.observe(
            session.session_id,
            self.context,
            expected_revision=session.revision,
            expected_epoch=session.epoch,
            operation_id="observe-1",
            include_screenshot=True,
        )
        self.assertEqual(result.session.revision, 3)
        self.assertTrue(result.persistence.stored)
        self.assertEqual(result.capture.engine_version, "test")
        self.assertEqual(result.observation.session_revision, 3)
        self.assertEqual(len(result.observation.artifact_refs), 1)
        self.assertEqual(
            result.capture.screenshot_artifact_ref,
            result.observation.artifact_refs[0],
        )
        self.assertEqual(
            self.broker.capture_store.load_blob(result.observation.artifact_refs[0]),
            b"fake-png",
        )

        replay = self.broker.observe(
            session.session_id,
            self.context,
            expected_revision=session.revision,
            expected_epoch=session.epoch,
            operation_id="observe-1",
            include_screenshot=True,
        )
        self.assertEqual(replay.observation.to_dict(), result.observation.to_dict())
        self.assertEqual(
            [call[0] for call in self.worker.calls], ["open", "observe"]
        )

    def test_navigation_is_revision_guarded_and_domain_bounded(self):
        session = self._open()
        navigated = self.broker.navigate(
            session.session_id,
            self.context,
            "http://127.0.0.1:8765/next",
            expected_revision=session.revision,
            expected_epoch=session.epoch,
            operation_id="navigate-1",
        )
        self.assertEqual(navigated.committed_revision, 3)
        navigation_event = next(
            event
            for event in self.store.events()
            if event.event_type == "web.browser.navigate"
        )
        self.assertEqual(navigation_event.attributes["command_id"], "navigate-1")
        self.assertNotIn("current_url", navigation_event.attributes)
        self.assertNotIn("url", navigation_event.attributes)
        with self.assertRaises(SessionRevisionConflict):
            self.broker.navigate(
                session.session_id,
                self.context,
                "http://127.0.0.1:8765/stale",
                expected_revision=1,
                expected_epoch=1,
                operation_id="navigate-stale",
            )
        with self.assertRaises(EnginePolicyBlocked):
            self.broker.navigate(
                session.session_id,
                self.context,
                "https://example.com/escape",
                expected_revision=3,
                expected_epoch=1,
                operation_id="navigate-escape",
            )

    def test_playwright_subdomain_is_rejected_before_worker_dispatch(self):
        worker = ScriptedBrowserWorker(engine="playwright-observer")
        self.worker = worker
        self.broker = BrowserSessionBroker(
            [worker],
            store=self.store,
            capture_store=self.broker.capture_store,
            profiles=self.broker.profiles,
            profile_bindings=self.profile_bindings,
            clock=lambda: self.now,
            id_factory=Ids(),
            controller_ttl=timedelta(minutes=5),
        )
        session = self._open()
        with patch(
            "weir.browser.broker.check_browser_target_policy",
            return_value="sub.127.0.0.1",
        ):
            with self.assertRaisesRegex(EnginePolicyBlocked, "exact pinned"):
                self.broker.navigate(
                    session.session_id,
                    self.context,
                    "http://sub.127.0.0.1/",
                    expected_revision=session.revision,
                    expected_epoch=session.epoch,
                    operation_id="navigate-subdomain",
                )
        self.assertEqual([call[0] for call in worker.calls], ["open"])

    def test_takeover_pauses_automation_and_return_rotates_fence(self):
        session = self._open()
        paused, operator = self.broker.takeover(
            session.session_id,
            self.context,
            "operator-1",
            "approval-1",
            expected_revision=session.revision,
            operation_id="takeover-1",
        )
        self.assertEqual(paused.state, SessionState.PAUSED)
        with self.assertRaises(ControllerConflict):
            self.broker.observe(
                session.session_id,
                self.context,
                expected_revision=paused.revision,
                expected_epoch=paused.epoch,
                operation_id="observe-paused",
            )
        replayed, replayed_lease = self.broker.takeover(
            session.session_id,
            self.context,
            "operator-1",
            "approval-1",
            expected_revision=session.revision,
            operation_id="takeover-1",
        )
        self.assertEqual(replayed.state, SessionState.PAUSED)
        self.assertEqual(replayed_lease.generation, operator.generation)

        resumed, automation = self.broker.return_control(
            self.context,
            operator,
            "return-approval-1",
            expected_revision=paused.revision,
            operation_id="return-1",
        )
        self.assertEqual(resumed.state, SessionState.ACTIVE)
        self.assertGreater(automation.generation, operator.generation)
        self.assertEqual(
            [call[0] for call in self.worker.calls],
            ["open", "fence", "fence"],
        )

    def test_takeover_barrier_rejects_a_delayed_old_generation_command(self):
        session = self._open()
        old_lease = self.store.active_lease(session.session_id)
        self.assertIsNotNone(old_lease)
        delayed_url = "http://127.0.0.1:8765/delayed"
        delayed = self.broker._command(  # noqa: SLF001 - protocol regression fixture
            "delayed-old-command",
            "navigate",
            session,
            old_lease,
            {"session_id": session.session_id, "url": delayed_url},
        )
        self.broker.takeover(
            session.session_id,
            self.context,
            "operator-1",
            "approval-1",
            expected_revision=session.revision,
            operation_id="takeover-delayed",
        )
        with self.assertRaises(StaleWorkerCommand):
            self.worker.navigate(session.session_id, delayed_url, delayed)

    def test_takeover_retry_refences_after_receipt_crash(self):
        session = self._open()
        original_complete = self.store.complete_command_with_event

        def crash_before_receipt(*args, **kwargs):
            raise SystemExit("simulated receipt crash")

        self.store.complete_command_with_event = crash_before_receipt
        try:
            with self.assertRaisesRegex(SystemExit, "simulated receipt crash"):
                self.broker.takeover(
                    session.session_id,
                    self.context,
                    "operator-1",
                    "approval-1",
                    expected_revision=session.revision,
                    operation_id="takeover-crash",
                )
        finally:
            self.store.complete_command_with_event = original_complete

        self.now += self.broker.command_resume_after + timedelta(seconds=1)
        paused, operator = self.broker.takeover(
            session.session_id,
            self.context,
            "operator-1",
            "approval-1",
            expected_revision=session.revision,
            operation_id="takeover-crash",
        )
        self.assertEqual(paused.state, SessionState.PAUSED)
        self.assertEqual(operator.controller_id, "operator-1")
        fence_calls = [call for call in self.worker.calls if call[0] == "fence"]
        self.assertEqual(len(fence_calls), 2)
        self.assertEqual(len({call[1] for call in fence_calls}), 2)
        self.assertTrue(
            all(call[1].startswith("takeover-crash:fence:") for call in fence_calls)
        )

    def test_takeover_retry_cannot_consume_an_unrelated_paused_reservation(self):
        session = self._open()
        original_transfer = self.store.transfer_lease_and_transition

        def crash_before_transfer(*args, **kwargs):
            raise SystemExit("simulated pre-transfer crash")

        self.store.transfer_lease_and_transition = crash_before_transfer
        try:
            with self.assertRaisesRegex(SystemExit, "pre-transfer crash"):
                self.broker.takeover(
                    session.session_id,
                    self.context,
                    "operator-1",
                    "approval-1",
                    expected_revision=session.revision,
                    operation_id="takeover-orphan",
                )
        finally:
            self.store.transfer_lease_and_transition = original_transfer

        lease = self.store.active_lease(session.session_id)
        unrelated = self.store.begin_command(
            "navigate-unrelated", "navigate", "sha256:unrelated"
        )
        paused, _ = self.store.reserve_automation_command(
            lease,
            expected_revision=session.revision,
            expected_epoch=session.epoch,
            operation="navigate",
            command_id="navigate-unrelated",
            command_attempt_token=unrelated.attempt_token or "",
            ttl=timedelta(seconds=1),
        )
        self.now += self.broker.command_resume_after + timedelta(seconds=1)

        with self.assertRaisesRegex(CommandInDoubt, "expired or is no longer active"):
            self.broker.takeover(
                session.session_id,
                self.context,
                "operator-1",
                "approval-1",
                expected_revision=session.revision,
                operation_id="takeover-orphan",
            )
        self.assertEqual(self.store.get_session(session.session_id).state, SessionState.PAUSED)
        self.assertEqual(self.store.get_session(session.session_id).revision, paused.revision)
        self.assertIsNone(self.store.active_lease(session.session_id))
        self.assertEqual([call[0] for call in self.worker.calls], ["open"])

    def test_return_retry_cannot_consume_an_unrelated_transfer(self):
        session = self._open()
        paused, operator = self.broker.takeover(
            session.session_id,
            self.context,
            "operator-1",
            "approval-1",
            expected_revision=session.revision,
            operation_id="takeover-for-return-race",
        )
        original_transfer = self.store.transfer_paused_controller

        def crash_before_transfer(*args, **kwargs):
            raise SystemExit("simulated pre-return crash")

        self.store.transfer_paused_controller = crash_before_transfer
        try:
            with self.assertRaisesRegex(SystemExit, "pre-return crash"):
                self.broker.return_control(
                    self.context,
                    operator,
                    "return-approval-1",
                    expected_revision=paused.revision,
                    operation_id="return-orphan",
                )
        finally:
            self.store.transfer_paused_controller = original_transfer

        unrelated = self.store.begin_command(
            "return-unrelated", "return_control", "sha256:unrelated"
        )
        self.store.transfer_paused_controller(
            operator,
            session.owner_run_id,
            ControllerKind.AUTOMATION,
            expected_revision=paused.revision,
            ttl=timedelta(seconds=1),
            authorization_ref="unrelated-approval",
            command_id="return-unrelated",
            command_attempt_token=unrelated.attempt_token or "",
        )
        self.now += self.broker.command_resume_after + timedelta(seconds=1)

        with self.assertRaisesRegex(CommandInDoubt, "expired or is no longer active"):
            self.broker.return_control(
                self.context,
                operator,
                "return-approval-1",
                expected_revision=paused.revision,
                operation_id="return-orphan",
            )
        self.assertEqual(self.store.get_session(session.session_id).state, SessionState.PAUSED)
        self.assertIsNone(self.store.active_lease(session.session_id))
        self.assertEqual(
            [call[0] for call in self.worker.calls], ["open", "fence"]
        )

    def test_superseded_takeover_cannot_damage_recovery_attempt(self):
        first_fence_entered = threading.Event()
        second_fence_entered = threading.Event()
        release_first = threading.Event()

        class StaleFenceWorker(ScriptedBrowserWorker):
            def __init__(self):
                super().__init__()
                self.fence_calls = 0
                self.fence_lock = threading.Lock()

            def fence_session(self, session_id, command):
                with self.fence_lock:
                    self.fence_calls += 1
                    call_number = self.fence_calls
                if call_number == 1:
                    first_fence_entered.set()
                    if not release_first.wait(timeout=5):
                        raise RuntimeError("stale fence was not released")
                    raise RuntimeError("stale fence failed")
                second_fence_entered.set()
                return super().fence_session(session_id, command)

        worker = StaleFenceWorker()
        self.worker = worker
        self.broker = BrowserSessionBroker(
            [worker],
            store=self.store,
            capture_store=self.broker.capture_store,
            profiles=self.broker.profiles,
            profile_bindings=self.profile_bindings,
            clock=lambda: self.now,
            id_factory=Ids(),
            controller_ttl=timedelta(minutes=5),
        )
        session = self._open()
        first_outcome = []
        second_outcome = []

        def takeover(outcome):
            try:
                outcome.append(
                    self.broker.takeover(
                        session.session_id,
                        self.context,
                        "operator-1",
                        "approval-1",
                        expected_revision=session.revision,
                        operation_id="takeover-stale",
                    )
                )
            except Exception as exc:  # pragma: no cover - asserted below
                outcome.append(exc)

        first = threading.Thread(target=takeover, args=(first_outcome,))
        first.start()
        self.assertTrue(first_fence_entered.wait(timeout=5))
        self.now += self.broker.command_resume_after + timedelta(seconds=1)
        second = threading.Thread(target=takeover, args=(second_outcome,))
        second.start()
        self.assertTrue(second_fence_entered.wait(timeout=5))
        release_first.set()
        first.join(timeout=5)
        second.join(timeout=5)

        self.assertIsInstance(first_outcome[0], CommandAttemptSuperseded)
        self.assertFalse(isinstance(second_outcome[0], Exception))
        current = self.store.get_session(session.session_id)
        self.assertEqual(current.state, SessionState.PAUSED)
        self.assertEqual(self.store.active_lease(session.session_id).controller_id, "operator-1")

    def test_context_mismatch_cannot_attach_to_session(self):
        session = self._open()
        other = WorkContext.create(
            context_id="context-other",
            run_id="run-1",
            correlation_id="request-1",
            source=WorkContextSource.CALLER,
            created_at=self.now.isoformat(),
        )
        with self.assertRaises(SessionOwnershipError):
            self.broker.observe(
                session.session_id,
                other,
                expected_revision=session.revision,
                expected_epoch=session.epoch,
                operation_id="observe-other",
            )

    def test_lost_session_recovers_only_for_same_context(self):
        session = self._open()
        lost = self.broker.mark_lost(
            session.session_id,
            self.context,
            expected_revision=session.revision,
            detail="simulated worker heartbeat loss",
        )
        recovered = self.broker.recover(
            session.session_id,
            self.context,
            expected_revision=lost.revision,
            expected_epoch=lost.epoch,
            operation_id="recover-1",
        )
        self.assertEqual(recovered.state, SessionState.ACTIVE)
        self.assertEqual(recovered.epoch, 2)
        self.assertIn(("attach", "recover-1:attach"), self.worker.calls)
        replay = self.broker.recover(
            session.session_id,
            self.context,
            expected_revision=lost.revision,
            expected_epoch=lost.epoch,
            operation_id="recover-1",
        )
        self.assertEqual(replay.epoch, recovered.epoch)

    def test_recovery_rejects_a_replacement_worker_instance(self):
        session = self._open()
        lost = self.broker.mark_lost(
            session.session_id,
            self.context,
            expected_revision=session.revision,
            detail="worker identity changed",
        )
        replacement = ScriptedBrowserWorker(
            worker_id=self.worker.descriptor.worker_id,
        )
        replacement._descriptor = replace(
            replacement.descriptor,
            instance_id="fake-instance-replacement",
        )
        self.broker.workers[self.worker.descriptor.worker_id] = replacement
        with self.assertRaisesRegex(ControllerConflict, "does not hold"):
            self.broker.recover(
                session.session_id,
                self.context,
                expected_revision=lost.revision,
                expected_epoch=lost.epoch,
                operation_id="recover-replacement-worker",
            )
        self.assertEqual(replacement.calls, [])
        self.assertEqual(
            self.store.profile_reservation(session.session_id).state,
            "quarantined",
        )

    def test_recovery_rejects_a_worker_with_persisted_death_evidence(self):
        session = self._open()
        lost = self.broker.mark_lost(
            session.session_id,
            self.context,
            expected_revision=session.revision,
            detail="worker process died",
        )
        attestation = WorkerDeathAttestation.create(
            worker_id=self.worker.descriptor.worker_id,
            worker_instance_id=self.worker.descriptor.instance_id or "",
            process_id=4321,
            exit_code=1,
            reason="worker_exited",
            worker_exited_gracefully=False,
            process_tree_confirmed_dead=True,
        )
        self.store.record_worker_death_attestation(attestation)
        with self.assertRaisesRegex(ControllerConflict, "dead worker"):
            self.broker.recover(
                session.session_id,
                self.context,
                expected_revision=lost.revision,
                expected_epoch=lost.epoch,
                operation_id="recover-dead-worker",
            )
        self.assertEqual(
            self.store.profile_reservation(session.session_id).state,
            "quarantined",
        )

    def test_close_is_terminal_and_releases_profile_reservation(self):
        session = self._open()
        closed = self.broker.close(
            session.session_id,
            self.context,
            expected_revision=session.revision,
            expected_epoch=session.epoch,
            operation_id="close-1",
        )
        self.assertEqual(closed.state, SessionState.CLOSED)
        self.assertIsNone(closed.controller_lease)

        self.request.request_id = "request-2"
        self.context = WorkContext.create(
            context_id="context-2",
            run_id="run-1",
            correlation_id="request-2",
            source=WorkContextSource.CALLER,
            created_at=self.now.isoformat(),
        )
        replacement = self.broker.open(
            self.request,
            self.context,
            worker_id=self.worker.descriptor.worker_id,
            operation_id="open-2",
        )
        self.assertEqual(replacement.state, SessionState.ACTIVE)

    def test_failed_open_can_be_closed_and_releases_profile_reservation(self):
        self.worker.fail_open = True
        with self.assertRaisesRegex(RuntimeError, "scripted open failure"):
            self._open()
        lost = self.store.sessions()[0]
        self.assertEqual(lost.state, SessionState.LOST)

        closed = self.broker.close(
            lost.session_id,
            self.context,
            expected_revision=lost.revision,
            expected_epoch=lost.epoch,
            operation_id="close-failed-open",
        )
        self.assertEqual(closed.state, SessionState.CLOSED)

        self.worker.fail_open = False
        self.request.request_id = "request-after-failure"
        replacement_context = WorkContext.create(
            context_id="context-after-failure",
            run_id="run-1",
            correlation_id=self.request.request_id,
            source=WorkContextSource.CALLER,
            created_at=self.now.isoformat(),
        )
        replacement = self.broker.open(
            self.request,
            replacement_context,
            worker_id=self.worker.descriptor.worker_id,
            operation_id="open-after-failure",
        )
        self.assertEqual(replacement.state, SessionState.ACTIVE)

    def test_expired_controller_can_still_close_the_session(self):
        session = self._open()
        self.now += timedelta(minutes=6)
        self.assertIsNone(self.store.active_lease(session.session_id))
        closed = self.broker.close(
            session.session_id,
            self.context,
            expected_revision=session.revision,
            expected_epoch=session.epoch,
            operation_id="close-expired-controller",
        )
        self.assertEqual(closed.state, SessionState.CLOSED)

    def test_unconfirmed_worker_cleanup_keeps_profile_quarantined(self):
        session = self._open()
        lost = self.broker.mark_lost(
            session.session_id,
            self.context,
            expected_revision=session.revision,
            detail="worker health unknown",
        )
        self.worker.fail_close = True
        self.worker.death_attestation = WorkerDeathAttestation.create(
            worker_id=self.worker.descriptor.worker_id,
            worker_instance_id=self.worker.descriptor.instance_id or "",
            process_id=4321,
            exit_code=1,
            reason="worker_exited",
            worker_exited_gracefully=False,
            process_tree_confirmed_dead=True,
        )
        with self.assertRaisesRegex(EngineFailure, "quarantined"):
            self.broker.close(
                session.session_id,
                self.context,
                expected_revision=lost.revision,
                expected_epoch=lost.epoch,
                operation_id="close-unconfirmed",
            )
        quarantined = self.store.get_session(session.session_id)
        self.assertNotEqual(quarantined.state, SessionState.CLOSED)
        persisted_death = self.store.database.execute(
            """SELECT attestation_hash FROM browser_worker_death_attestations
               WHERE worker_id = ? AND worker_instance_id = ?""",
            (
                self.worker.descriptor.worker_id,
                self.worker.descriptor.instance_id,
            ),
        ).fetchone()
        self.assertEqual(
            persisted_death["attestation_hash"],
            self.worker.death_attestation.attestation_hash,
        )
        self.request.request_id = "request-while-quarantined"
        replacement_context = WorkContext.create(
            context_id="context-while-quarantined",
            run_id="run-1",
            correlation_id=self.request.request_id,
            source=WorkContextSource.CALLER,
            created_at=self.now.isoformat(),
        )
        with self.assertRaises(ProfileInUse):
            self.broker.open(
                self.request,
                replacement_context,
                worker_id=self.worker.descriptor.worker_id,
                operation_id="open-while-quarantined",
            )

    def test_durable_reservation_rejects_concurrent_navigation_before_dispatch(self):
        entered = threading.Event()
        release = threading.Event()

        class BlockingWorker(ScriptedBrowserWorker):
            def _navigate_serialized(self, session_id, url, command):
                entered.set()
                if not release.wait(timeout=5):
                    raise RuntimeError("test navigation was not released")
                return super()._navigate_serialized(session_id, url, command)

        worker = BlockingWorker()
        self.worker = worker
        self.broker = BrowserSessionBroker(
            [worker],
            store=self.store,
            capture_store=self.broker.capture_store,
            profiles=self.broker.profiles,
            profile_bindings=self.profile_bindings,
            clock=lambda: self.now,
            id_factory=Ids(),
            controller_ttl=timedelta(minutes=5),
        )
        session = self._open()
        outcome = []

        def navigate_first():
            try:
                outcome.append(
                    self.broker.navigate(
                        session.session_id,
                        self.context,
                        "http://127.0.0.1:8765/a",
                        expected_revision=session.revision,
                        expected_epoch=session.epoch,
                        operation_id="navigate-a",
                    )
                )
            except Exception as exc:  # pragma: no cover - assertion below reports it
                outcome.append(exc)

        thread = threading.Thread(target=navigate_first)
        thread.start()
        self.assertTrue(entered.wait(timeout=5))
        with self.assertRaises(ControllerConflict):
            self.broker.navigate(
                session.session_id,
                self.context,
                "http://127.0.0.1:8765/b",
                expected_revision=session.revision,
                expected_epoch=session.epoch,
                operation_id="navigate-b",
            )
        release.set()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(outcome), 1)
        self.assertFalse(isinstance(outcome[0], Exception))
        self.assertEqual(
            self.store.get_session(session.session_id).current_url,
            "http://127.0.0.1:8765/a",
        )
        self.assertEqual(worker.sessions[session.session_id]["url"], "http://127.0.0.1:8765/a")
        self.assertEqual(
            [call for call in worker.calls if call[0] == "navigate"],
            [("navigate", "navigate-a")],
        )


if __name__ == "__main__":
    unittest.main()
