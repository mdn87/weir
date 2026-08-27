import json
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from jsonschema import FormatChecker
from jsonschema.validators import Draft202012Validator
from weir.browser.protocol import (
    CommandExpired,
    IdempotentWorkerGuard,
    StaleWorkerCommand,
    WorkerCommand,
    WorkerIdempotencyConflict,
    WorkerProtocolError,
    WorkerResultEnvelope,
    WorkerResultStatus,
)
from weir.engines.base import FailureClass

CONTRACTS = Path(__file__).resolve().parents[1] / "contracts"
NOW = datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc)


def _command(
    *,
    command_id: str = "cmd-1",
    revision: int = 2,
    epoch: int = 1,
    fence: int = 3,
    payload=None,
) -> WorkerCommand:
    actual_payload = {"session_id": "session-1"} if payload is None else payload
    return WorkerCommand.build(
        command_id=command_id,
        operation="observe",
        session_id="session-1",
        worker_session_id="worker-session-1",
        owner_run_id="run-1",
        expected_revision=revision,
        session_epoch=epoch,
        lease_fence=fence,
        deadline_at=NOW + timedelta(minutes=1),
        payload=actual_payload,
    )


def _validator(name: str) -> Draft202012Validator:
    schema = json.loads((CONTRACTS / name).read_text(encoding="utf-8"))
    return Draft202012Validator(schema, format_checker=FormatChecker())


class BrowserProtocolTests(unittest.TestCase):
    def test_command_validates_payload_and_matches_contract(self):
        command = _command()
        command.validate_for("observe", {"session_id": "session-1"}, now=NOW)
        _validator("browser-worker-command.schema.json").validate(command.to_dict())
        with self.assertRaises(WorkerIdempotencyConflict):
            command.validate_for("observe", {"session_id": "different"}, now=NOW)
        with self.assertRaises(WorkerProtocolError):
            command.validate_for("navigate", {"session_id": "session-1"}, now=NOW)

    def test_expired_command_is_rejected(self):
        with self.assertRaises(CommandExpired):
            _command().validate(now=NOW + timedelta(minutes=2))

    def test_command_runtime_rejects_types_the_schema_rejects(self):
        command = _command()
        invalid_commands = (
            replace(command, expected_revision=True),
            replace(command, session_epoch="1"),
            replace(command, lease_fence=1.5),
            replace(command, operation=1),
            replace(command, deadline_at=1),
            replace(command, request_digest=7),
        )
        for invalid in invalid_commands:
            with self.subTest(command=invalid):
                with self.assertRaises(WorkerProtocolError):
                    invalid.validate(now=NOW)

    def test_protocol_failures_have_stable_durable_failure_classes(self):
        self.assertEqual(
            CommandExpired("expired").failure_class, FailureClass.COMMAND_EXPIRED
        )
        self.assertEqual(
            StaleWorkerCommand("stale").failure_class,
            FailureClass.STALE_REFERENCE,
        )
        self.assertEqual(
            WorkerIdempotencyConflict("reused").failure_class,
            FailureClass.IDEMPOTENCY_CONFLICT,
        )

    def test_replay_is_bound_to_revision_and_fence_not_only_payload(self):
        guard = IdempotentWorkerGuard()
        command = _command()
        self.assertEqual(guard.begin_worker_command(command), (False, None))
        guard.remember_worker_result(command, "result")
        self.assertEqual(guard.begin_worker_command(command), (True, "result"))

        reused = _command(revision=3)
        with self.assertRaises(WorkerIdempotencyConflict):
            guard.begin_worker_command(reused)

        extended = replace(
            command, deadline_at=(NOW + timedelta(minutes=2)).isoformat()
        )
        with self.assertRaises(WorkerIdempotencyConflict):
            guard.begin_worker_command(extended)

    def test_stale_epoch_or_fence_is_rejected(self):
        guard = IdempotentWorkerGuard()
        guard.begin_worker_command(_command(command_id="new", epoch=2, fence=5))
        for command in (
            _command(command_id="old-epoch", epoch=1, fence=99),
            _command(command_id="old-fence", epoch=2, fence=4),
        ):
            with self.subTest(command=command.command_id):
                with self.assertRaises(StaleWorkerCommand):
                    guard.begin_worker_command(command)

    def test_evicted_result_keeps_a_fail_closed_command_tombstone(self):
        guard = IdempotentWorkerGuard(max_cached_results=1, max_seen_commands=4)
        first = _command(command_id="first")
        second = _command(command_id="second")
        guard.begin_worker_command(first)
        guard.remember_worker_result(first, "one")
        guard.begin_worker_command(second)
        guard.remember_worker_result(second, "two")

        with self.assertRaisesRegex(WorkerProtocolError, "will not be replayed"):
            guard.begin_worker_command(first)
        with self.assertRaises(WorkerIdempotencyConflict):
            guard.begin_worker_command(_command(command_id="first", revision=9))

    def test_exact_session_cleanup_retires_uncertain_commands(self):
        guard = IdempotentWorkerGuard()
        uncertain = _command(command_id="uncertain")
        guard.begin_worker_command(uncertain)
        guard.forget_worker_session("session-1")

        with self.assertRaisesRegex(WorkerProtocolError, "will not be replayed"):
            guard.begin_worker_command(uncertain)

    def test_result_envelope_is_hashed_and_matches_contract(self):
        result = WorkerResultEnvelope.create(
            command=_command(),
            status=WorkerResultStatus.FAILED,
            completed_at=NOW,
            metadata={"retryable": False},
            failure_class=FailureClass.SESSION_LOST,
            detail="worker context disappeared",
        )
        _validator("browser-worker-result.schema.json").validate(result.to_dict())

    def test_result_runtime_rejects_types_the_schema_rejects(self):
        result = WorkerResultEnvelope.create(
            command=_command(),
            status=WorkerResultStatus.COMPLETED,
            completed_at=NOW,
            metadata={},
        )
        invalid_results = (
            replace(result, status="completed"),
            replace(result, completed_at=7),
            replace(result, result_digest=7),
            replace(result, metadata=[]),
            replace(result, metadata={1: "not-an-object-key"}),
            replace(result, failure_class="session_lost"),
            replace(result, detail=7),
        )
        for invalid in invalid_results:
            with self.subTest(result=invalid):
                with self.assertRaises(WorkerProtocolError):
                    invalid.validate()


if __name__ == "__main__":
    unittest.main()
