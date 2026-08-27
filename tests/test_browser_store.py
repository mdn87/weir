import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from weir.actions import (
    ExecutionReceipt,
    ReceiptResult,
    Verification,
    VerificationConfidence,
)
from weir.browser.models import BrowserSession, ControllerKind, SessionState
from weir.browser.state import ALLOWED_TRANSITIONS, InvalidSessionTransition, require_transition
from weir.browser.store import (
    CommandAttemptSuperseded,
    CommandInDoubt,
    PreviousCommandFailed,
    SessionRevisionConflict,
    SQLiteSessionStore,
)
from weir.engines.base import (
    ControllerConflict,
    FailureClass,
    IdempotencyConflict,
    ProfileInUse,
)
from weir.models import DataClass


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += timedelta(seconds=seconds)


def _session(clock: Clock, session_id: str = "session-1") -> BrowserSession:
    now = clock().isoformat()
    return BrowserSession(
        session_id=session_id,
        owner_run_id="run-1",
        engine="playwright-observer",
        worker_id="worker-1",
        worker_session_id=f"pending-{session_id}",
        profile_id="profile-1",
        data_class=DataClass.BWA_INTERNAL,
        allowed_domains=["app.example.test"],
        state=SessionState.OPENING,
        revision=0,
        epoch=1,
        current_url=None,
        created_at=now,
        updated_at=now,
        expires_at=(clock() + timedelta(hours=1)).isoformat(),
    )


def _activate_session(
    store: SQLiteSessionStore,
    session_id: str = "session-1",
):
    command_id = f"open-{session_id}"
    start = store.begin_command(command_id, "open", f"sha256:{session_id}")
    lease = store.acquire_lease(
        session_id, "run-1", ControllerKind.AUTOMATION, ttl=timedelta(minutes=5)
    )
    store.reserve_worker_open(
        session_id,
        command_id=command_id,
        attempt_token=start.attempt_token or "",
        worker_instance_id="worker-instance-1",
        expected_revision=0,
        expected_epoch=1,
        required_lease=lease,
    )
    worker_session_id = f"worker-context-{session_id}"
    store.record_worker_context_created(
        session_id,
        worker_session_id=worker_session_id,
        worker_instance_id="worker-instance-1",
        command_id=command_id,
        attempt_token=start.attempt_token,
    )
    active = store.activate_opening_session(
        session_id,
        0,
        current_url="https://app.example.test/",
        worker_session_id=worker_session_id,
        worker_instance_id="worker-instance-1",
        event_type="web.browser.session.opened",
        complete_command_id=command_id,
        command_result={"session_id": session_id, "revision": 1},
        command_attempt_token=start.attempt_token or "",
        required_lease=lease,
    )
    return active, lease


class BrowserStateTests(unittest.TestCase):
    def test_transition_table_is_explicit_and_closed_is_terminal(self):
        for source in SessionState:
            for target in SessionState:
                if target in ALLOWED_TRANSITIONS[source]:
                    require_transition(source, target)
                else:
                    with self.assertRaises(InvalidSessionTransition):
                        require_transition(source, target)


class BrowserStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = Clock()
        self.temporary = tempfile.TemporaryDirectory()
        self.store = SQLiteSessionStore(
            Path(self.temporary.name) / "sessions.sqlite3", clock=self.clock
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def test_profile_reservation_is_unique_until_session_closes(self):
        first = self.store.create_session(_session(self.clock))
        with self.assertRaises(ProfileInUse):
            self.store.create_session(_session(self.clock, "session-2"))

        close_start = self.store.begin_command(
            "close-1", "close", "sha256:close-session-1"
        )
        reserved, cleanup = self.store.begin_close(
            first.session_id,
            "run-1",
            expected_revision=0,
            expected_epoch=1,
            command_id="close-1",
            command_attempt_token=close_start.attempt_token or "",
            ttl=timedelta(minutes=5),
        )
        self.store.close_with_lease(
            first.session_id,
            reserved.revision,
            cleanup,
            command_id="close-1",
            command_attempt_token=close_start.attempt_token or "",
            command_result={
                "session_id": first.session_id,
                "revision": reserved.revision + 1,
            },
        )
        second = self.store.create_session(_session(self.clock, "session-2"))
        self.assertEqual(second.session_id, "session-2")

    def test_compare_and_swap_rejects_stale_session_revision(self):
        self.store.create_session(_session(self.clock))
        active, lease = _activate_session(self.store)
        self.assertEqual(active.revision, 1)
        start = self.store.begin_command("cmd-stale", "navigate", "sha256:stale")
        with self.assertRaises(SessionRevisionConflict):
            self.store.reserve_automation_command(
                lease,
                expected_revision=0,
                expected_epoch=active.epoch,
                operation="navigate",
                command_id="cmd-stale",
                command_attempt_token=start.attempt_token or "",
                ttl=timedelta(minutes=5),
            )

    def test_opening_cannot_activate_after_its_controller_lease_expires(self):
        self.store.create_session(_session(self.clock))
        start = self.store.begin_command("open-expired", "open", "sha256:open")
        lease = self.store.acquire_lease(
            "session-1",
            "run-1",
            ControllerKind.AUTOMATION,
            ttl=timedelta(seconds=10),
        )
        self.store.reserve_worker_open(
            "session-1",
            command_id="open-expired",
            attempt_token=start.attempt_token or "",
            worker_instance_id="worker-instance-1",
            expected_revision=0,
            expected_epoch=1,
            required_lease=lease,
        )
        self.store.record_worker_context_created(
            "session-1",
            worker_session_id="worker-context-1",
            worker_instance_id="worker-instance-1",
            command_id="open-expired",
            attempt_token=start.attempt_token,
        )
        self.clock.advance(11)
        with self.assertRaisesRegex(ControllerConflict, "expired"):
            self.store.activate_opening_session(
                "session-1",
                0,
                current_url="https://app.example.test/",
                worker_session_id="worker-context-1",
                worker_instance_id="worker-instance-1",
                event_type="web.browser.session.opened",
                complete_command_id="open-expired",
                command_result={"session_id": "session-1", "revision": 1},
                command_attempt_token=start.attempt_token or "",
                required_lease=lease,
            )
        self.assertEqual(
            self.store.get_session("session-1").state, SessionState.OPENING
        )

    def test_stale_open_cannot_reserve_after_terminal_close_rotates_fence(self):
        open_start = self.store.begin_command("open-stale", "open", "sha256:open")
        session = self.store.create_session(_session(self.clock))
        stale_lease = self.store.acquire_lease(
            session.session_id,
            "run-1",
            ControllerKind.AUTOMATION,
            ttl=timedelta(minutes=5),
        )
        close_start = self.store.begin_command(
            "close-before-open", "close", "sha256:close"
        )
        closing, cleanup = self.store.begin_close(
            session.session_id,
            "run-1",
            expected_revision=session.revision,
            expected_epoch=session.epoch,
            command_id="close-before-open",
            command_attempt_token=close_start.attempt_token or "",
            ttl=timedelta(minutes=5),
        )
        closed = self.store.close_with_lease(
            session.session_id,
            closing.revision,
            cleanup,
            command_id="close-before-open",
            command_attempt_token=close_start.attempt_token or "",
            command_result={
                "session_id": session.session_id,
                "revision": closing.revision + 1,
            },
        )

        with self.assertRaises(ControllerConflict):
            self.store.reserve_worker_open(
                session.session_id,
                command_id="open-stale",
                attempt_token=open_start.attempt_token or "",
                worker_instance_id="worker-instance-1",
                expected_revision=session.revision,
                expected_epoch=session.epoch,
                required_lease=stale_lease,
            )

        self.assertEqual(closed.state, SessionState.CLOSED)
        self.assertFalse(
            any(
                event.event_type == "web.browser.worker.open.reserved"
                for event in self.store.events()
            )
        )

    def test_lease_expiry_and_reacquisition_rotate_the_fence(self):
        self.store.create_session(_session(self.clock))
        first = self.store.acquire_lease(
            "session-1", "run-1", ControllerKind.AUTOMATION, ttl=timedelta(seconds=10)
        )
        with self.assertRaises(ControllerConflict):
            self.store.acquire_lease(
                "session-1", "operator", ControllerKind.OPERATOR, ttl=timedelta(seconds=10)
            )

        self.clock.advance(11)
        self.assertIsNone(self.store.active_lease("session-1"))
        self.assertIsNone(self.store.get_session("session-1").controller_lease)
        second = self.store.acquire_lease(
            "session-1", "run-1", ControllerKind.AUTOMATION, ttl=timedelta(seconds=10)
        )
        self.assertGreater(second.generation, first.generation)
        self.assertNotEqual(second.fencing_token, first.fencing_token)
        self.assertFalse(self.store.valid_lease(first))
        with self.assertRaises(ControllerConflict):
            self.store.release_lease(first)

    def test_takeover_rotates_fence_and_pauses_atomically(self):
        self.store.create_session(_session(self.clock))
        active, lease = _activate_session(self.store)
        takeover_start = self.store.begin_command(
            "takeover-1", "takeover", "sha256:takeover"
        )
        paused, operator = self.store.transfer_lease_and_transition(
            lease,
            "operator-1",
            ControllerKind.OPERATOR,
            expected_revision=active.revision,
            target_state=SessionState.PAUSED,
            ttl=timedelta(minutes=5),
            authorization_ref="approval-1",
            command_id="takeover-1",
            command_attempt_token=takeover_start.attempt_token or "",
        )
        self.assertEqual(paused.state, SessionState.PAUSED)
        self.assertEqual(operator.generation, lease.generation + 1)
        self.assertEqual(paused.controller_lease.controller_id, "operator-1")
        self.assertFalse(self.store.valid_lease(lease))

        self.store.complete_command(
            "takeover-1",
            {"session_id": "session-1", "controller_generation": operator.generation},
            attempt_token=takeover_start.attempt_token,
        )
        return_start = self.store.begin_command(
            "return-1", "return_control", "sha256:return"
        )
        still_paused, automation = self.store.transfer_paused_controller(
            operator,
            "run-1",
            ControllerKind.AUTOMATION,
            expected_revision=paused.revision,
            ttl=timedelta(minutes=5),
            authorization_ref="return-1",
            command_id="return-1",
            command_attempt_token=return_start.attempt_token or "",
        )
        resumed = self.store.activate_after_fence(
            automation,
            expected_revision=still_paused.revision,
            authorization_ref="return-1",
            complete_command_id="return-1",
            command_result={
                "session_id": "session-1",
                "controller_generation": automation.generation,
            },
            command_attempt_token=return_start.attempt_token or "",
        )
        self.assertEqual(resumed.state, SessionState.ACTIVE)
        self.assertEqual(automation.generation, operator.generation + 1)

    def test_transfer_recovery_requires_the_exact_durable_event(self):
        self.store.create_session(_session(self.clock))
        active, lease = _activate_session(self.store)
        intended = self.store.begin_command(
            "takeover-intended", "takeover", "sha256:intended"
        )
        unrelated = self.store.begin_command(
            "takeover-unrelated", "takeover", "sha256:unrelated"
        )
        paused, operator = self.store.transfer_lease_and_transition(
            lease,
            "operator-1",
            ControllerKind.OPERATOR,
            expected_revision=active.revision,
            target_state=SessionState.PAUSED,
            ttl=timedelta(minutes=5),
            authorization_ref="approval-1",
            command_id="takeover-unrelated",
            command_attempt_token=unrelated.attempt_token or "",
        )

        with self.assertRaisesRegex(CommandInDoubt, "durable transfer record"):
            self.store.resume_transferred_controller(
                paused.session_id,
                command_id="takeover-intended",
                command_attempt_token=intended.attempt_token or "",
                expected_revision=paused.revision,
                expected_from_controller_id=active.owner_run_id,
                expected_from_kind=ControllerKind.AUTOMATION,
                expected_from_generation=lease.generation,
                expected_controller_id=operator.controller_id,
                expected_kind=ControllerKind.OPERATOR,
                authorization_ref="approval-1",
            )

    def test_transfer_recovery_accepts_the_exact_live_transfer_after_attempt_rotation(self):
        self.store.create_session(_session(self.clock))
        active, lease = _activate_session(self.store)
        first = self.store.begin_command(
            "takeover-recover", "takeover", "sha256:recover"
        )
        paused, operator = self.store.transfer_lease_and_transition(
            lease,
            "operator-1",
            ControllerKind.OPERATOR,
            expected_revision=active.revision,
            target_state=SessionState.PAUSED,
            ttl=timedelta(minutes=5),
            authorization_ref="approval-1",
            command_id="takeover-recover",
            command_attempt_token=first.attempt_token or "",
        )
        self.clock.advance(11)
        retry = self.store.begin_command(
            "takeover-recover",
            "takeover",
            "sha256:recover",
            resume_after=timedelta(seconds=10),
        )

        recovered, recovered_lease = self.store.resume_transferred_controller(
            paused.session_id,
            command_id="takeover-recover",
            command_attempt_token=retry.attempt_token or "",
            expected_revision=paused.revision,
            expected_from_controller_id=active.owner_run_id,
            expected_from_kind=ControllerKind.AUTOMATION,
            expected_from_generation=lease.generation,
            expected_controller_id=operator.controller_id,
            expected_kind=ControllerKind.OPERATOR,
            authorization_ref="approval-1",
        )
        self.assertEqual(recovered.state, SessionState.PAUSED)
        self.assertEqual(recovered_lease, operator)

    def test_reserved_command_rejects_valid_lease_from_another_session(self):
        self.store.create_session(_session(self.clock))
        active, lease = _activate_session(self.store)
        start = self.store.begin_command("observe-1", "observe", "sha256:observe")
        paused, _ = self.store.reserve_automation_command(
            lease,
            expected_revision=active.revision,
            expected_epoch=active.epoch,
            operation="observe",
            command_id="observe-1",
            command_attempt_token=start.attempt_token or "",
            ttl=timedelta(minutes=5),
        )
        other = _session(self.clock, "session-2")
        other.profile_id = "profile-2"
        self.store.create_session(other)
        other_lease = self.store.acquire_lease(
            other.session_id,
            other.owner_run_id,
            ControllerKind.AUTOMATION,
            ttl=timedelta(minutes=5),
        )

        with self.assertRaisesRegex(ControllerConflict, "another session"):
            self.store.complete_reserved_command(
                paused.session_id,
                paused.revision,
                other_lease,
                current_url="https://app.example.test/",
                command_id="observe-1",
                command_attempt_token=start.attempt_token or "",
                event_type="web.browser.observed",
            )
        self.assertEqual(
            self.store.get_session(paused.session_id).state, SessionState.PAUSED
        )

    def test_paused_command_rejects_generic_lease_reacquisition(self):
        self.store.create_session(_session(self.clock))
        active, lease = _activate_session(self.store)
        start = self.store.begin_command("navigate-1", "navigate", "sha256:navigate")
        paused, reserved_lease = self.store.reserve_automation_command(
            lease,
            expected_revision=active.revision,
            expected_epoch=active.epoch,
            operation="navigate",
            command_id="navigate-1",
            command_attempt_token=start.attempt_token or "",
            ttl=timedelta(seconds=10),
        )
        self.clock.advance(11)
        self.assertFalse(self.store.valid_lease(reserved_lease))
        with self.assertRaisesRegex(ControllerConflict, "command-bound transition"):
            self.store.acquire_lease(
                paused.session_id,
                paused.owner_run_id,
                ControllerKind.AUTOMATION,
                ttl=timedelta(minutes=5),
            )
        self.assertEqual(
            self.store.get_session(paused.session_id).state, SessionState.PAUSED
        )

    def test_reserved_command_cannot_be_activated_as_a_controller_return(self):
        self.store.create_session(_session(self.clock))
        active, lease = _activate_session(self.store)
        start = self.store.begin_command("navigate-1", "navigate", "sha256:navigate")
        paused, reserved_lease = self.store.reserve_automation_command(
            lease,
            expected_revision=active.revision,
            expected_epoch=active.epoch,
            operation="navigate",
            command_id="navigate-1",
            command_attempt_token=start.attempt_token or "",
            ttl=timedelta(minutes=5),
        )

        with self.assertRaisesRegex(CommandInDoubt, "durable return transfer"):
            self.store.activate_after_fence(
                reserved_lease,
                expected_revision=paused.revision,
                authorization_ref="approval-1",
                complete_command_id="navigate-1",
                command_result={"session_id": paused.session_id},
                command_attempt_token=start.attempt_token or "",
            )
        self.assertEqual(
            self.store.get_session(paused.session_id).state, SessionState.PAUSED
        )

    def test_only_original_owner_can_recover_lost_session(self):
        self.store.create_session(_session(self.clock))
        lost = self.store.mark_lost("session-1", 0)
        wrong_start = self.store.begin_command(
            "recover-wrong", "recover", "sha256:recover-wrong"
        )
        with self.assertRaisesRegex(ControllerConflict, "original run"):
            self.store.begin_recovery(
                "session-1",
                "another-run",
                lost.revision,
                worker_session_id="pending-recovery",
                command_id="recover-wrong",
                command_attempt_token=wrong_start.attempt_token or "",
            )
        right_start = self.store.begin_command(
            "recover-right", "recover", "sha256:recover-right"
        )
        opening = self.store.begin_recovery(
            "session-1",
            "run-1",
            lost.revision,
            worker_session_id="pending-recovery",
            command_id="recover-right",
            command_attempt_token=right_start.attempt_token or "",
        )
        self.assertEqual(opening.state, SessionState.OPENING)
        self.assertEqual(opening.epoch, 2)

    def test_command_ids_are_durably_bound_to_content(self):
        first = self.store.begin_command("cmd-1", "observe", "sha256:a")
        self.assertFalse(first.replay)
        with self.assertRaises(CommandInDoubt):
            self.store.begin_command("cmd-1", "observe", "sha256:a")
        self.store.complete_command("cmd-1", {"observation_id": "obs-1"})
        replay = self.store.begin_command("cmd-1", "observe", "sha256:a")
        self.assertTrue(replay.replay)
        self.assertEqual(replay.result["observation_id"], "obs-1")
        with self.assertRaises(IdempotencyConflict):
            self.store.begin_command("cmd-1", "observe", "sha256:b")

        self.store.begin_command("cmd-2", "navigate", "sha256:c")
        self.store.fail_command("cmd-2", "worker lost")
        with self.assertRaises(PreviousCommandFailed):
            self.store.begin_command("cmd-2", "navigate", "sha256:c")

    def test_superseded_close_attempt_cannot_commit_terminal_state(self):
        self.store.create_session(_session(self.clock))
        active, _ = _activate_session(self.store)
        self.store.record_worker_context_closed(
            "session-1",
            worker_session_id="worker-context-session-1",
            worker_instance_id="worker-instance-1",
            command_id="worker-close",
        )
        first = self.store.begin_command("close-stale", "close", "sha256:close")
        reserved, cleanup = self.store.begin_close(
            "session-1",
            "run-1",
            expected_revision=active.revision,
            expected_epoch=active.epoch,
            command_id="close-stale",
            command_attempt_token=first.attempt_token or "",
            ttl=timedelta(minutes=5),
        )
        self.clock.advance(11)
        retry = self.store.begin_command(
            "close-stale",
            "close",
            "sha256:close",
            resume_after=timedelta(seconds=10),
        )
        self.assertTrue(retry.resume)
        with self.assertRaises(CommandAttemptSuperseded):
            self.store.close_with_lease(
                "session-1",
                reserved.revision,
                cleanup,
                command_id="close-stale",
                command_result={"session_id": "session-1"},
                command_attempt_token=first.attempt_token,
            )
        self.assertEqual(
            self.store.get_session("session-1").state, SessionState.PAUSED
        )

    def test_operator_lease_cannot_bypass_close_reservation(self):
        self.store.create_session(_session(self.clock))
        active, automation = _activate_session(self.store)
        self.store.record_worker_context_closed(
            active.session_id,
            worker_session_id=active.worker_session_id,
            worker_instance_id="worker-instance-1",
            command_id="worker-close",
        )
        takeover_start = self.store.begin_command(
            "takeover-before-close", "takeover", "sha256:takeover-close"
        )
        paused, operator = self.store.transfer_lease_and_transition(
            automation,
            "operator-1",
            ControllerKind.OPERATOR,
            expected_revision=active.revision,
            target_state=SessionState.PAUSED,
            ttl=timedelta(minutes=5),
            authorization_ref="approval-1",
            command_id="takeover-before-close",
            command_attempt_token=takeover_start.attempt_token or "",
        )
        close_start = self.store.begin_command(
            "close-operator-bypass", "close", "sha256:operator-close"
        )

        with self.assertRaisesRegex(ControllerConflict, "automation cleanup lease"):
            self.store.close_with_lease(
                paused.session_id,
                paused.revision,
                operator,
                command_id="close-operator-bypass",
                command_attempt_token=close_start.attempt_token or "",
                command_result={"session_id": paused.session_id},
            )
        self.assertEqual(
            self.store.get_session(paused.session_id).state, SessionState.PAUSED
        )

    def test_paused_close_rejects_generic_lease_reacquisition(self):
        self.store.create_session(_session(self.clock))
        active, _ = _activate_session(self.store)
        self.store.record_worker_context_closed(
            active.session_id,
            worker_session_id=active.worker_session_id,
            worker_instance_id="worker-instance-1",
            command_id="worker-close",
        )
        close_start = self.store.begin_command(
            "close-old-fence", "close", "sha256:close-old-fence"
        )
        reserved, cleanup = self.store.begin_close(
            active.session_id,
            active.owner_run_id,
            expected_revision=active.revision,
            expected_epoch=active.epoch,
            command_id="close-old-fence",
            command_attempt_token=close_start.attempt_token or "",
            ttl=timedelta(seconds=10),
        )
        self.clock.advance(11)
        self.assertFalse(self.store.valid_lease(cleanup))
        with self.assertRaisesRegex(ControllerConflict, "command-bound transition"):
            self.store.acquire_lease(
                active.session_id,
                active.owner_run_id,
                ControllerKind.AUTOMATION,
                ttl=timedelta(minutes=5),
            )
        self.assertEqual(
            self.store.get_session(reserved.session_id).state, SessionState.PAUSED
        )

    def test_receipts_and_metadata_events_survive_store_reopen(self):
        self.store.create_session(_session(self.clock))
        receipt = ExecutionReceipt(
            receipt_id="receipt-1",
            action_id="action-1",
            proposal_hash="sha256:" + "1" * 64,
            session_id="session-1",
            session_epoch=1,
            lease_generation=1,
            executed_by="weir-default-deny",
            executed_at=self.clock().isoformat(),
            result=ReceiptResult.BLOCKED,
            approval_ref=None,
            capture_ids=(),
            failure_class=FailureClass.APPROVAL_REQUIRED,
            verification=Verification(
                None,
                VerificationConfidence.BLOCKED,
                (),
            ),
        )
        self.store.save_receipt(receipt)
        path = Path(self.temporary.name) / "sessions.sqlite3"
        self.store.close()
        self.store = SQLiteSessionStore(path, clock=self.clock)
        self.assertEqual(self.store.load_receipt("action-1")["result"], "blocked")
        events = self.store.events()
        self.assertEqual(events[0].event_type, "web.browser.session.created")
        self.assertNotIn("fencing_token", events[0].attributes)

    def test_receipt_store_rejects_unvalidated_mappings(self):
        with self.assertRaisesRegex(TypeError, "ExecutionReceipt"):
            self.store.save_receipt({"action_id": "action-1"})  # type: ignore[arg-type]

    def test_worker_close_attestation_must_match_created_context(self):
        self.store.create_session(_session(self.clock))
        self.store.record_worker_context_created(
            "session-1",
            worker_session_id="worker-context-1",
            worker_instance_id="worker-instance-1",
        )
        with self.assertRaisesRegex(ControllerConflict, "exact worker"):
            self.store.record_worker_context_closed(
                "session-1",
                worker_session_id="worker-context-1",
                worker_instance_id="worker-instance-2",
                command_id="close-wrong-instance",
            )
        with self.assertRaisesRegex(ControllerConflict, "exact worker"):
            self.store.record_worker_context_closed(
                "session-1",
                worker_session_id="worker-context-2",
                worker_instance_id="worker-instance-1",
                command_id="close-wrong-session",
            )
        self.assertTrue(
            self.store.worker_context_may_be_live(
                "session-1", worker_instance_id="worker-instance-1"
            )
        )
        self.store.record_worker_context_closed(
            "session-1",
            worker_session_id="worker-context-1",
            worker_instance_id="worker-instance-1",
            command_id="close-exact",
        )
        self.assertFalse(
            self.store.worker_context_may_be_live(
                "session-1", worker_instance_id="worker-instance-1"
            )
        )

    def test_unacknowledged_open_reservation_quarantines_until_worker_cleanup(self):
        start = self.store.begin_command("open-1", "open", "sha256:request")
        self.store.create_session(_session(self.clock))
        lease = self.store.acquire_lease(
            "session-1",
            "run-1",
            ControllerKind.AUTOMATION,
            ttl=timedelta(minutes=5),
        )
        self.store.reserve_worker_open(
            "session-1",
            command_id="open-1",
            attempt_token=start.attempt_token or "",
            worker_instance_id="worker-instance-1",
            expected_revision=0,
            expected_epoch=1,
            required_lease=lease,
        )
        self.assertTrue(
            self.store.worker_context_may_be_live(
                "session-1", worker_instance_id="worker-instance-1"
            )
        )
        self.store.record_worker_cleanup_attested(
            "session-1",
            worker_session_id="pending-session-1",
            worker_instance_id="worker-instance-1",
            command_id="close-reserved",
        )
        self.assertFalse(
            self.store.worker_context_may_be_live(
                "session-1", worker_instance_id="worker-instance-1"
            )
        )


if __name__ == "__main__":
    unittest.main()
