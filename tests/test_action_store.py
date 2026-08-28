import copy
import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from weir.actions import (
    ActionProposal,
    ExecutionPermit,
    ExecutionReceipt,
    QuarantineRecord,
    ReceiptResult,
    Verification,
    VerificationConfidence,
)
from weir.browser.models import BrowserSession, ControllerKind, SessionState
from weir.browser.store import SQLiteSessionStore
from weir.contract import canonical_digest
from weir.engines.base import ControllerConflict, FailureClass, IdempotencyConflict
from weir.models import DataClass
from weir.work_context import WorkContext

_FIXTURES = (
    Path(__file__).resolve().parents[1] / "contracts" / "fixtures" / "batch-0-v1.json"
)


def _documents() -> dict[str, dict]:
    manifest = json.loads(_FIXTURES.read_text(encoding="utf-8"))
    return {item["name"]: item["document"] for item in manifest["positive"]}


class ActionStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 8, 27, 12, 0, 20, tzinfo=timezone.utc)
        self.temporary = tempfile.TemporaryDirectory()
        self.store_path = Path(self.temporary.name) / "browser.sqlite3"
        self.store = SQLiteSessionStore(
            self.store_path,
            clock=lambda: self.now,
        )
        documents = _documents()
        self.context = WorkContext.from_dict(
            copy.deepcopy(documents["work_context.empty_fixed_inputs"])
        )
        self.proposal = ActionProposal.from_dict(
            copy.deepcopy(documents["action_proposal.full_authority"])
        )
        self.permit = ExecutionPermit.from_dict(
            copy.deepcopy(documents["execution_permit.one_use"])
        )
        session = BrowserSession(
            session_id=self.proposal.session_id,
            owner_run_id=self.proposal.owner_run_id,
            engine="playwright-observer",
            worker_id="worker-action-1",
            worker_session_id="worker-context-action-1",
            profile_id="profile-action-1",
            data_class=DataClass.BWA_INTERNAL,
            allowed_domains=["app.example.test"],
            state=SessionState.ACTIVE,
            revision=self.proposal.session_revision,
            epoch=self.proposal.session_epoch,
            current_url="https://app.example.test/form",
            created_at="2026-08-27T12:00:00+00:00",
            updated_at="2026-08-27T12:00:05+00:00",
            expires_at="2026-08-27T13:00:00+00:00",
        )
        self.store.create_session(
            session,
            work_context=self.context,
            site_profile_id="action-fixture",
            credential_scope="read_only",
            profile_policy_digest="sha256:" + "a" * 64,
            credential_binding_id="credential-binding-action-1",
            worker_instance_id="worker-instance-action-1",
        )
        self.lease = self.store.acquire_lease(
            session.session_id,
            session.owner_run_id,
            ControllerKind.AUTOMATION,
            ttl=timedelta(minutes=2),
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def _reserve(self, *, request_digest: str | None = None):
        return self.store.reserve_action_execution(
            self.permit,
            self.proposal,
            request_digest=request_digest or canonical_digest({"effect": "fixture"}),
            command_id="command-action-1",
            worker_id="worker-action-1",
            worker_instance_id="worker-instance-action-1",
            required_lease=self.lease,
        )

    def _receipt(
        self,
        reservation_ref: str,
        *,
        result: ReceiptResult = ReceiptResult.COMPLETED,
        quarantine_ref: str | None = None,
    ) -> ExecutionReceipt:
        unknown = result is ReceiptResult.OUTCOME_UNKNOWN
        reservation = self.store.action_reservation(self.permit.permit_id)
        return ExecutionReceipt.create(
            receipt_id="receipt-action-1",
            action_id=self.proposal.action_id,
            proposal_hash=self.proposal.proposal_hash,
            permit_id=self.permit.permit_id,
            work_context_hash=self.proposal.work_context_hash,
            command_id="command-action-1",
            reservation_ref=reservation_ref,
            session_id=self.proposal.session_id,
            session_epoch=self.proposal.session_epoch,
            lease_generation=(
                self.lease.generation
                if reservation is None
                else reservation.controller_generation
            ),
            executed_by="weir-worker-action-1",
            executed_at=self.now.isoformat(),
            result=result,
            approval_ref=self.permit.approval_ref,
            capture_ids=("webcap-before",) if unknown else ("webcap-before", "webcap-after"),
            failure_class=FailureClass.OUTCOME_UNKNOWN if unknown else None,
            verification=(
                Verification(None, VerificationConfidence.UNCERTAIN, ())
                if unknown
                else Verification(
                    "semantic_postcondition",
                    VerificationConfidence.VERIFIED,
                    ("webcap-after",),
                    1,
                )
            ),
            quarantine_ref=quarantine_ref,
        )

    def test_exact_permit_reservation_replays_without_new_dispatch_authority(self):
        first = self._reserve()
        self.store.close()
        self.now = datetime(2026, 8, 27, 12, 2, 0, tzinfo=timezone.utc)
        self.store = SQLiteSessionStore(self.store_path, clock=lambda: self.now)
        second = self._reserve()
        self.assertFalse(first.replay)
        self.assertTrue(second.replay)
        self.assertEqual(
            first.reservation.reservation_ref,
            second.reservation.reservation_ref,
        )
        with self.assertRaisesRegex(IdempotencyConflict, "different action request"):
            self._reserve(request_digest="sha256:" + "f" * 64)

    def test_open_action_holds_exclusive_session_and_blocks_release_paths(self):
        start = self._reserve()
        session = self.store.get_session(self.proposal.session_id)
        self.assertEqual(session.state, SessionState.PAUSED)
        self.assertIsNotNone(start.lease)
        self.assertEqual(
            start.lease.generation,
            start.reservation.controller_generation,
        )
        self.assertGreater(start.lease.generation, self.lease.generation)

        with self.assertRaisesRegex(ControllerConflict, "nonterminal"):
            self.store.release_lease(start.lease)
        with self.assertRaisesRegex(ControllerConflict, "nonterminal"):
            self.store.mark_lost(
                session.session_id,
                session.revision,
            )
        close = self.store.begin_command(
            "command-close-during-action",
            "close",
            canonical_digest({"close": session.session_id}),
        )
        with self.assertRaisesRegex(ControllerConflict, "nonterminal"):
            self.store.begin_close(
                session.session_id,
                session.owner_run_id,
                expected_revision=session.revision,
                expected_epoch=session.epoch,
                command_id="command-close-during-action",
                command_attempt_token=close.attempt_token,
                ttl=timedelta(seconds=30),
            )
        self.assertEqual(
            self.store.profile_reservation(session.session_id).state,
            "active",
        )

    def test_reservation_insert_failure_rolls_back_event_and_authority(self):
        self.store.database.execute(
            """CREATE TRIGGER reject_action_reservation
               BEFORE INSERT ON action_execution_reservations
               BEGIN SELECT RAISE(ABORT, 'injected reservation failure'); END"""
        )
        with self.assertRaisesRegex(IdempotencyConflict, "already reserved"):
            self._reserve()
        self.assertIsNone(self.store.action_reservation(self.permit.permit_id))
        event_count = self.store.database.execute(
            """SELECT COUNT(*) FROM browser_events
               WHERE event_type = 'web.action.execution.reserved'"""
        ).fetchone()[0]
        self.assertEqual(event_count, 0)

    def test_action_and_proposal_cannot_be_reserved_under_a_second_permit(self):
        first = self._reserve().reservation
        alternate = ExecutionPermit.create(
            permit_id="permit-action-alternate",
            proposal_hash=self.permit.proposal_hash,
            work_context_hash=self.permit.work_context_hash,
            owner_run_id=self.permit.owner_run_id,
            session_id=self.permit.session_id,
            session_epoch=self.permit.session_epoch,
            action_type=self.permit.action_type,
            risk=self.permit.risk,
            approval_ref="approval-action-alternate",
            issuer_id=self.permit.issuer_id,
            issued_at=self.permit.issued_at,
            expires_at=self.permit.expires_at,
        )
        with self.assertRaisesRegex(IdempotencyConflict, "already reserved"):
            self.store.reserve_action_execution(
                alternate,
                self.proposal,
                request_digest=canonical_digest({"effect": "fixture-alternate"}),
                command_id="command-action-alternate",
                worker_id="worker-action-1",
                worker_instance_id="worker-instance-action-1",
                required_lease=self.lease,
            )
        self.assertEqual(
            self.store.action_reservation(self.permit.permit_id).reservation_ref,
            first.reservation_ref,
        )
        self.assertIsNone(self.store.action_reservation(alternate.permit_id))

    def test_terminal_receipt_prevents_a_later_action_reservation(self):
        receipt = self._receipt("reservation-before-ledger")
        self.store.save_receipt(receipt)
        with self.assertRaisesRegex(IdempotencyConflict, "terminal execution receipt"):
            self._reserve()
        self.assertIsNone(self.store.action_reservation(self.permit.permit_id))

    def test_completed_receipt_commits_against_exact_reservation(self):
        reservation = self._reserve().reservation
        receipt = self._receipt(reservation.reservation_ref)
        with self.assertRaisesRegex(ValueError, "finalize_action_execution"):
            self.store.save_receipt(receipt)
        self.store.finalize_action_execution(receipt)
        self.store.finalize_action_execution(receipt)
        status = self.store.action_reservation(self.permit.permit_id)
        self.assertIsNotNone(status)
        self.assertEqual(status.status, "completed")
        self.assertEqual(status.receipt_id, receipt.receipt_id)
        self.assertEqual(
            self.store.load_receipt(receipt.action_id)["receipt_hash"],
            receipt.receipt_hash,
        )

    def test_unknown_outcome_atomically_quarantines_session_and_credential(self):
        reservation = self._reserve().reservation
        quarantine = QuarantineRecord.create_active(
            quarantine_id="quarantine-action-1",
            session_id=self.proposal.session_id,
            session_epoch=self.proposal.session_epoch,
            work_context_hash=self.proposal.work_context_hash,
            permit_id=self.permit.permit_id,
            command_id="command-action-1",
            receipt_id="receipt-action-1",
            recorded_at=(self.now + timedelta(seconds=1)).isoformat(),
        )
        receipt = self._receipt(
            reservation.reservation_ref,
            result=ReceiptResult.OUTCOME_UNKNOWN,
            quarantine_ref="weir-quarantine:quarantine-action-1",
        )
        self.store.finalize_action_execution(receipt, quarantine=quarantine)

        self.assertEqual(
            self.store.action_reservation(self.permit.permit_id).status,
            "outcome_unknown",
        )
        self.assertEqual(
            self.store.get_session(self.proposal.session_id).state,
            SessionState.LOST,
        )
        self.assertEqual(
            self.store.profile_reservation(self.proposal.session_id).state,
            "quarantined",
        )

        successor = quarantine.clear(
            disposition_actor_id="operator-action-1",
            disposition_ref="disposition-action-1",
            recorded_at=(self.now + timedelta(minutes=1)).isoformat(),
        )
        self.store.clear_action_quarantine(successor)
        self.store.clear_action_quarantine(successor)
        competing_successor = quarantine.clear(
            disposition_actor_id="operator-action-1",
            disposition_ref="disposition-action-competing",
            recorded_at=(self.now + timedelta(minutes=2)).isoformat(),
        )
        with self.assertRaisesRegex(IdempotencyConflict, "different successor"):
            self.store.clear_action_quarantine(competing_successor)
        rows = self.store.database.execute(
            """SELECT state FROM action_quarantine_records
               WHERE quarantine_id = ? ORDER BY recorded_at""",
            (quarantine.quarantine_id,),
        ).fetchall()
        self.assertEqual([row["state"] for row in rows], ["active", "cleared"])

        self.store.close()
        self.store = SQLiteSessionStore(self.store_path, clock=lambda: self.now)
        self.assertEqual(
            self.store.action_reservation(self.permit.permit_id).status,
            "outcome_unknown",
        )
        self.assertEqual(
            self.store.profile_reservation(self.proposal.session_id).state,
            "quarantined",
        )

    def test_unknown_outcome_failure_rolls_back_receipt_and_quarantine(self):
        reservation = self._reserve().reservation
        quarantine = QuarantineRecord.create_active(
            quarantine_id="quarantine-action-failure",
            session_id=self.proposal.session_id,
            session_epoch=self.proposal.session_epoch,
            work_context_hash=self.proposal.work_context_hash,
            permit_id=self.permit.permit_id,
            command_id="command-action-1",
            receipt_id="receipt-action-1",
            recorded_at=(self.now + timedelta(seconds=1)).isoformat(),
        )
        receipt = self._receipt(
            reservation.reservation_ref,
            result=ReceiptResult.OUTCOME_UNKNOWN,
            quarantine_ref="weir-quarantine:quarantine-action-failure",
        )
        self.store.database.execute(
            """CREATE TRIGGER reject_action_quarantine
               BEFORE INSERT ON action_quarantine_records
               BEGIN SELECT RAISE(ABORT, 'injected quarantine failure'); END"""
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.finalize_action_execution(receipt, quarantine=quarantine)
        self.assertIsNone(self.store.load_receipt(receipt.action_id))
        self.assertEqual(
            self.store.action_reservation(self.permit.permit_id).status,
            "reserved",
        )
        self.assertEqual(
            self.store.get_session(self.proposal.session_id).state,
            SessionState.PAUSED,
        )
        self.assertEqual(
            self.store.profile_reservation(self.proposal.session_id).state,
            "active",
        )


if __name__ == "__main__":
    unittest.main()
