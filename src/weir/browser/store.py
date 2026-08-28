from __future__ import annotations

import json
import secrets
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from weir.actions import (
        ActionProposal,
        ExecutionPermit,
        ExecutionReceipt,
        QuarantineRecord,
    )
    from weir.browser.process_worker import WorkerDeathAttestation

from weir.browser.models import (
    BrowserSession,
    ControllerKind,
    ControllerLease,
    SessionState,
)
from weir.browser.state import require_transition
from weir.contract import (
    ContractViolation,
    is_sha256,
    parse_timestamp,
    validate_identifier,
)
from weir.engines.base import ControllerConflict, IdempotencyConflict, ProfileInUse
from weir.models import DataClass
from weir.work_context import WorkContext

STORE_SCHEMA_VERSION = 2
DEAD_WORKER_RETIREMENT_DISPOSITION = "release_after_confirmed_worker_death"
ACTIVE_STATES = (
    SessionState.OPENING.value,
    SessionState.ACTIVE.value,
    SessionState.PAUSED.value,
    SessionState.LOST.value,
)


class SessionNotFound(KeyError):
    pass


class SessionRevisionConflict(RuntimeError):
    pass


class CommandInDoubt(RuntimeError):
    pass


class CommandAttemptSuperseded(RuntimeError):
    pass


class PreviousCommandFailed(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class CommandStart:
    replay: bool
    result: dict[str, Any] | None = None
    resume: bool = False
    attempt_token: str | None = None


@dataclass(frozen=True, slots=True)
class CommandStatus:
    command_id: str
    operation: str
    request_digest: str
    status: str
    result: dict[str, Any] | None
    error_present: bool
    created_at: str
    updated_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "command_id": self.command_id,
            "operation": self.operation,
            "request_digest": self.request_digest,
            "status": self.status,
            "result": self.result,
            "error_present": self.error_present,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> CommandStatus:
        required = {
            "command_id",
            "operation",
            "request_digest",
            "status",
            "result",
            "error_present",
            "created_at",
            "updated_at",
        }
        if not isinstance(value, dict) or set(value) != required:
            raise ValueError("command status has missing or unknown fields")
        status = cls(**value)
        status.validate()
        return status

    def validate(self) -> None:
        for name in ("command_id", "operation", "request_digest"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value or len(value) > 256:
                raise ValueError(f"command status {name} is invalid")
        if self.status not in {"started", "completed", "failed"}:
            raise ValueError("command status value is invalid")
        if self.result is not None and not isinstance(self.result, dict):
            raise ValueError("command status result must be an object or null")
        if self.status == "completed" and self.result is None:
            raise ValueError("completed command status requires a result")
        if self.status != "completed" and self.result is not None:
            raise ValueError("only completed command status may carry a result")
        if type(self.error_present) is not bool or self.error_present != (
            self.status == "failed"
        ):
            raise ValueError("command status error marker is invalid")
        _parse(self.created_at)
        _parse(self.updated_at)


@dataclass(frozen=True, slots=True)
class SessionEvent:
    sequence: int
    occurred_at: str
    event_type: str
    session_id: str | None
    owner_run_id: str | None
    attributes: dict[str, Any]


@dataclass(frozen=True, slots=True)
class SessionProfileBinding:
    site_profile_id: str
    credential_scope: str
    policy_digest: str
    credential_binding_id: str


@dataclass(frozen=True, slots=True)
class ProfileReservation:
    reservation_id: str
    credential_binding_id: str
    session_id: str
    worker_id: str
    worker_instance_id: str
    state: str
    created_at: str
    updated_at: str
    release_kind: str | None
    release_actor_id: str | None
    release_ref: str | None


@dataclass(frozen=True, slots=True)
class ActionExecutionReservation:
    reservation_ref: str
    permit_id: str
    permit_hash: str
    action_id: str
    request_digest: str
    proposal_hash: str
    work_context_hash: str
    command_id: str
    session_id: str
    session_epoch: int
    controller_generation: int
    status: str
    receipt_id: str | None
    created_at: str
    updated_at: str


@dataclass(frozen=True, slots=True)
class ActionReservationStart:
    reservation: ActionExecutionReservation
    replay: bool
    lease: ControllerLease | None = None


@dataclass(frozen=True, slots=True)
class ActionDispatchMarker:
    reservation_ref: str
    before_capture_id: str
    approval_ref: str
    worker_id: str
    worker_instance_id: str
    controller_generation: int


class SQLiteSessionStore:
    """Transactional session state, fenced leases, and append-only metadata journal."""

    def __init__(
        self,
        database: str | Path = ":memory:",
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.database = sqlite3.connect(str(database), check_same_thread=False)
        self.database.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self.database.execute("PRAGMA foreign_keys = ON")
        self.database.execute("PRAGMA busy_timeout = 5000")
        try:
            self._initialize()
        except Exception:
            self.database.close()
            raise

    def close(self) -> None:
        self.database.close()

    def __enter__(self) -> SQLiteSessionStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _initialize(self) -> None:
        version = int(self.database.execute("PRAGMA user_version").fetchone()[0])
        if version == 1:
            raise RuntimeError(
                "WEIR browser-store schema 1 requires the offline v1-to-v2 migration"
            )
        if version not in {0, STORE_SCHEMA_VERSION}:
            raise RuntimeError(
                f"unsupported WEIR browser-store schema {version}; expected {STORE_SCHEMA_VERSION}"
            )
        if version == STORE_SCHEMA_VERSION:
            return
        with self.database:
            self.database.executescript(
                """
                CREATE TABLE browser_sessions (
                    session_id TEXT PRIMARY KEY,
                    owner_run_id TEXT NOT NULL,
                    engine TEXT NOT NULL,
                    worker_id TEXT NOT NULL,
                    worker_session_id TEXT NOT NULL,
                    profile_id TEXT NOT NULL,
                    data_class TEXT NOT NULL,
                    allowed_domains_json TEXT NOT NULL,
                    state TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    epoch INTEGER NOT NULL,
                    current_url TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX one_live_browser_profile
                    ON browser_sessions(worker_id, profile_id)
                    WHERE state != 'closed';

                CREATE TABLE browser_profile_reservations (
                    reservation_id TEXT PRIMARY KEY,
                    credential_binding_id TEXT NOT NULL,
                    session_id TEXT NOT NULL UNIQUE REFERENCES browser_sessions(session_id),
                    worker_id TEXT NOT NULL,
                    worker_instance_id TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('active', 'quarantined', 'released')),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    release_kind TEXT,
                    release_actor_id TEXT,
                    release_ref TEXT
                );
                CREATE UNIQUE INDEX one_reserved_credential_binding
                    ON browser_profile_reservations(credential_binding_id)
                    WHERE state IN ('active', 'quarantined');

                CREATE TABLE browser_worker_death_attestations (
                    attestation_hash TEXT PRIMARY KEY,
                    worker_id TEXT NOT NULL,
                    worker_instance_id TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    attestation_json TEXT NOT NULL,
                    recorded_at TEXT NOT NULL
                );

                CREATE TABLE browser_profile_retirements (
                    retirement_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL REFERENCES browser_sessions(session_id),
                    session_epoch INTEGER NOT NULL,
                    credential_binding_id TEXT NOT NULL,
                    worker_id TEXT NOT NULL,
                    worker_instance_id TEXT NOT NULL,
                    attestation_hash TEXT NOT NULL REFERENCES
                        browser_worker_death_attestations(attestation_hash),
                    disposition TEXT NOT NULL,
                    disposition_actor_id TEXT NOT NULL,
                    disposition_ref TEXT NOT NULL,
                    recorded_at TEXT NOT NULL
                );

                CREATE TABLE controller_leases (
                    session_id TEXT PRIMARY KEY REFERENCES browser_sessions(session_id),
                    active INTEGER NOT NULL,
                    lease_id TEXT,
                    controller_id TEXT,
                    controller_kind TEXT,
                    fencing_token TEXT,
                    generation INTEGER NOT NULL,
                    expires_at TEXT,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE browser_work_contexts (
                    session_id TEXT PRIMARY KEY REFERENCES browser_sessions(session_id),
                    context_hash TEXT NOT NULL,
                    context_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE browser_commands (
                    command_id TEXT PRIMARY KEY,
                    operation TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    status TEXT NOT NULL,
                    result_json TEXT,
                    error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE browser_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    occurred_at TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    session_id TEXT,
                    owner_run_id TEXT,
                    attributes_json TEXT NOT NULL
                );

                CREATE TABLE execution_receipts (
                    action_id TEXT PRIMARY KEY,
                    proposal_hash TEXT NOT NULL,
                    receipt_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE action_execution_reservations (
                    reservation_ref TEXT PRIMARY KEY,
                    permit_id TEXT NOT NULL UNIQUE,
                    permit_hash TEXT NOT NULL,
                    action_id TEXT NOT NULL UNIQUE,
                    request_digest TEXT NOT NULL,
                    proposal_hash TEXT NOT NULL UNIQUE,
                    work_context_hash TEXT NOT NULL,
                    command_id TEXT NOT NULL UNIQUE,
                    session_id TEXT NOT NULL REFERENCES browser_sessions(session_id),
                    session_epoch INTEGER NOT NULL,
                    controller_generation INTEGER NOT NULL,
                    status TEXT NOT NULL CHECK(
                        status IN ('reserved', 'completed', 'outcome_unknown')
                    ),
                    receipt_id TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE action_quarantine_records (
                    record_hash TEXT PRIMARY KEY,
                    quarantine_id TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('active', 'cleared')),
                    supersedes_hash TEXT,
                    record_json TEXT NOT NULL,
                    recorded_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX one_active_action_quarantine
                    ON action_quarantine_records(quarantine_id)
                    WHERE state = 'active';
                CREATE UNIQUE INDEX one_action_quarantine_successor
                    ON action_quarantine_records(supersedes_hash)
                    WHERE supersedes_hash IS NOT NULL;
                """
            )
            self.database.execute(f"PRAGMA user_version = {STORE_SCHEMA_VERSION}")

    def create_session(
        self,
        session: BrowserSession,
        *,
        work_context: WorkContext | None = None,
        site_profile_id: str | None = None,
        credential_scope: str | None = None,
        profile_policy_digest: str | None = None,
        credential_binding_id: str | None = None,
        worker_instance_id: str | None = None,
        opening_operation_id: str | None = None,
    ) -> BrowserSession:
        session.validate()
        binding_values = (
            site_profile_id,
            credential_scope,
            profile_policy_digest,
            credential_binding_id,
            worker_instance_id,
        )
        if not all(isinstance(value, str) and value for value in binding_values):
            raise ValueError(
                "session profile and credential binding must be complete and non-empty"
            )
        validate_identifier(credential_binding_id, "credential_binding_id")
        validate_identifier(worker_instance_id, "worker_instance_id")
        if opening_operation_id is not None and not opening_operation_id:
            raise ValueError("opening_operation_id cannot be empty")
        if work_context is not None:
            work_context.validate()
            if work_context.run_id != session.owner_run_id:
                raise ValueError("work context run_id must match session owner_run_id")
        with self._lock, self.database:
            try:
                self.database.execute(
                    """INSERT INTO browser_sessions
                       (session_id, owner_run_id, engine, worker_id, worker_session_id,
                        profile_id, data_class, allowed_domains_json, state, revision,
                        epoch, current_url, created_at, updated_at, expires_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        session.session_id,
                        session.owner_run_id,
                        session.engine,
                        session.worker_id,
                        session.worker_session_id,
                        session.profile_id,
                        session.data_class.value,
                        _json(list(session.allowed_domains)),
                        session.state.value,
                        session.revision,
                        session.epoch,
                        session.current_url,
                        session.created_at,
                        session.updated_at,
                        session.expires_at,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                if (
                    "browser_sessions.worker_id, browser_sessions.profile_id" in str(exc)
                    or "one_live_browser_profile" in str(exc)
                ):
                    raise ProfileInUse(
                        f"profile {session.profile_id!r} already has a live session on "
                        f"worker {session.worker_id!r}"
                    ) from exc
                raise
            try:
                now = _utc(self.clock())
                self.database.execute(
                    """INSERT INTO browser_profile_reservations
                       (reservation_id, credential_binding_id, session_id, worker_id,
                        worker_instance_id, state, created_at, updated_at,
                        release_kind, release_actor_id, release_ref)
                       VALUES (?, ?, ?, ?, ?, 'active', ?, ?, NULL, NULL, NULL)""",
                    (
                        f"profile-reservation-{uuid.uuid4().hex}",
                        credential_binding_id,
                        session.session_id,
                        session.worker_id,
                        worker_instance_id,
                        now,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                if (
                    "browser_profile_reservations.credential_binding_id" in str(exc)
                    or "one_reserved_credential_binding" in str(exc)
                ):
                    raise ProfileInUse(
                        "credential binding already has an active or quarantined session"
                    ) from exc
                raise
            if work_context is not None:
                self.database.execute(
                    """INSERT INTO browser_work_contexts
                       (session_id, context_hash, context_json, created_at)
                       VALUES (?, ?, ?, ?)""",
                    (
                        session.session_id,
                        work_context.context_hash,
                        _json(work_context.to_dict()),
                        _utc(self.clock()),
                    ),
                )
            self._insert_event(
                "web.browser.session.created",
                session.session_id,
                session.owner_run_id,
                {
                    "engine": session.engine,
                    "worker_id": session.worker_id,
                    "profile_id": session.profile_id,
                    "state": session.state.value,
                    "context_id": (
                        None if work_context is None else work_context.context_id
                    ),
                    "context_hash": (
                        None if work_context is None else work_context.context_hash
                    ),
                    "site_profile_id": site_profile_id,
                    "credential_scope": credential_scope,
                    "profile_policy_digest": profile_policy_digest,
                    "opening_operation_id": opening_operation_id,
                },
            )
        return self.get_session(session.session_id)

    def session_for_open_command(self, command_id: str) -> BrowserSession:
        """Recover the generated session identity for an in-doubt open command."""

        with self._lock:
            rows = self.database.execute(
                """SELECT session_id, attributes_json FROM browser_events
                   WHERE event_type = 'web.browser.session.created'
                   ORDER BY sequence DESC"""
            ).fetchall()
        for row in rows:
            attributes = json.loads(row["attributes_json"])
            if attributes.get("opening_operation_id") == command_id:
                return self.get_session(row["session_id"])
        raise SessionNotFound(f"open command {command_id!r} has no created session")

    def profile_binding(self, session_id: str) -> SessionProfileBinding:
        """Load the immutable site/credential policy selected when a session opened."""

        with self._lock:
            row = self.database.execute(
                """SELECT e.attributes_json, r.credential_binding_id
                   FROM browser_events AS e
                   JOIN browser_profile_reservations AS r
                     ON r.session_id = e.session_id
                   WHERE e.session_id = ?
                     AND e.event_type = 'web.browser.session.created'
                   ORDER BY e.sequence LIMIT 1""",
                (session_id,),
            ).fetchone()
        if row is None:
            raise SessionNotFound(f"session {session_id!r} has no creation event")
        attributes = json.loads(row["attributes_json"])
        values = (
            attributes.get("site_profile_id"),
            attributes.get("credential_scope"),
            attributes.get("profile_policy_digest"),
            row["credential_binding_id"],
        )
        if not all(isinstance(value, str) and value for value in values):
            raise ControllerConflict(
                f"session {session_id!r} has no durable site-profile policy binding"
            )
        return SessionProfileBinding(*values)

    def profile_reservation(self, session_id: str) -> ProfileReservation:
        with self._lock:
            row = self.database.execute(
                "SELECT * FROM browser_profile_reservations WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        if row is None:
            raise SessionNotFound(
                f"session {session_id!r} has no credential reservation"
            )
        return _profile_reservation_from_row(row)

    def assert_live_profile_reservation_holder(
        self,
        session_id: str,
        *,
        worker_id: str,
        worker_instance_id: str,
    ) -> None:
        """Require the exact live worker that owns a credential reservation."""

        validate_identifier(worker_id, "worker_id")
        validate_identifier(worker_instance_id, "worker_instance_id")
        with self._lock:
            reservation = self._required_profile_reservation_row(session_id)
            if (
                reservation["worker_id"] != worker_id
                or reservation["worker_instance_id"] != worker_instance_id
                or reservation["state"] not in {"active", "quarantined"}
            ):
                raise ControllerConflict(
                    "browser worker does not hold the credential reservation"
                )
            death = self.database.execute(
                """SELECT 1 FROM browser_worker_death_attestations
                   WHERE worker_id = ? AND worker_instance_id = ? LIMIT 1""",
                (worker_id, worker_instance_id),
            ).fetchone()
            if death is not None:
                raise ControllerConflict(
                    "a dead worker instance cannot reuse its credential reservation"
                )

    def work_context(self, session_id: str) -> WorkContext:
        with self._lock:
            row = self.database.execute(
                "SELECT context_json FROM browser_work_contexts WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        if row is None:
            raise SessionNotFound(f"session {session_id!r} has no work-context binding")
        value = json.loads(row["context_json"])
        return WorkContext.from_dict(value)

    def record_worker_context_created(
        self,
        session_id: str,
        *,
        worker_session_id: str,
        worker_instance_id: str,
        command_id: str | None = None,
        attempt_token: str | None = None,
    ) -> BrowserSession:
        """Persist the cleanup target immediately after a worker creates it."""

        if not worker_session_id or not worker_instance_id:
            raise ValueError("worker context identifiers cannot be empty")
        if (command_id is None) != (attempt_token is None):
            raise ValueError("worker context command ID and attempt token must be paired")
        with self._lock:
            self.database.execute("BEGIN IMMEDIATE")
            try:
                row = self._required_session_row(session_id)
                self._require_no_open_action(session_id, "worker context creation")
                if SessionState(row["state"]) is SessionState.CLOSED:
                    raise ControllerConflict(
                        "worker context identity cannot be recorded after close"
                    )
                if command_id is not None and attempt_token is not None:
                    self._require_current_command_attempt(command_id, attempt_token)
                    reservation = self._worker_open_reservation(command_id)
                    if reservation != (session_id, worker_instance_id, attempt_token):
                        raise CommandAttemptSuperseded(
                            "worker context does not match the current open reservation"
                        )
                identity = (worker_instance_id, worker_session_id)
                open_contexts = self._open_worker_contexts(session_id)
                if identity in open_contexts:
                    self.database.commit()
                    return self.get_session(session_id)
                if open_contexts:
                    raise ControllerConflict(
                        "cannot record a second worker context while another is unclosed"
                    )
                cursor = self.database.execute(
                    """UPDATE browser_sessions SET worker_session_id = ?, updated_at = ?
                       WHERE session_id = ? AND state != 'closed'""",
                    (worker_session_id, _utc(self.clock()), session_id),
                )
                if cursor.rowcount != 1:
                    raise ControllerConflict("browser session closed before context recording")
                self._insert_event(
                    "web.browser.worker.context.created",
                    session_id,
                    row["owner_run_id"],
                    {
                        "worker_session_id": worker_session_id,
                        "worker_instance_id": worker_instance_id,
                        "command_id": command_id,
                        "attempt_token": attempt_token,
                    },
                )
                self.database.commit()
            except Exception:
                self.database.rollback()
                raise
        return self.get_session(session_id)

    def record_worker_context_closed(
        self,
        session_id: str,
        *,
        worker_instance_id: str,
        worker_session_id: str,
        command_id: str,
    ) -> None:
        if not worker_instance_id or not worker_session_id:
            raise ValueError("worker context identifiers cannot be empty")
        with self._lock:
            self.database.execute("BEGIN IMMEDIATE")
            try:
                session = self._required_session_row(session_id)
                self._require_no_open_action(session_id, "worker context closure")
                identity = (worker_instance_id, worker_session_id)
                open_contexts = self._open_worker_contexts(session_id)
                if identity not in open_contexts:
                    closed = self._closed_worker_contexts(session_id)
                    if identity in closed:
                        self.database.commit()
                        return
                    raise ControllerConflict(
                        "only the exact worker context can attest closure"
                    )
                self._insert_event(
                    "web.browser.worker.context.closed",
                    session_id,
                    session["owner_run_id"],
                    {
                        "worker_instance_id": worker_instance_id,
                        "worker_session_id": worker_session_id,
                        "command_id": command_id,
                    },
                )
                self.database.commit()
            except Exception:
                self.database.rollback()
                raise

    def record_worker_cleanup_attested(
        self,
        session_id: str,
        *,
        worker_instance_id: str,
        worker_session_id: str,
        worker_id: str,
        credential_binding_id: str,
        command_id: str,
    ) -> None:
        """Record an exact close and retire this worker's unacknowledged opens.

        A worker can create a context after the durable open reservation but before
        WEIR receives its context identifier. A successful close from that same
        worker instance is therefore also an attestation that those unresolved open
        dispatches no longer retain authority.
        """

        if not all(
            (
                worker_id,
                worker_instance_id,
                worker_session_id,
                credential_binding_id,
                command_id,
            )
        ):
            raise ValueError("worker cleanup attestation fields cannot be empty")
        with self._lock:
            self.database.execute("BEGIN IMMEDIATE")
            try:
                session = self._required_session_row(session_id)
                self._require_no_open_action(session_id, "worker cleanup")
                reservation = self._required_profile_reservation_row(session_id)
                if (
                    reservation["worker_id"] != worker_id
                    or reservation["worker_instance_id"] != worker_instance_id
                    or reservation["credential_binding_id"] != credential_binding_id
                    or reservation["state"] not in {"active", "quarantined"}
                ):
                    raise ControllerConflict(
                        "worker cleanup does not match the held credential reservation"
                    )
                death = self.database.execute(
                    """SELECT 1 FROM browser_worker_death_attestations
                       WHERE worker_id = ? AND worker_instance_id = ? LIMIT 1""",
                    (worker_id, worker_instance_id),
                ).fetchone()
                if death is not None:
                    raise ControllerConflict(
                        "a dead worker instance cannot attest live cleanup"
                    )
                identity = (worker_instance_id, worker_session_id)
                open_contexts = self._open_worker_contexts(session_id)
                closed_contexts = self._closed_worker_contexts(session_id)
                reservations = {
                    reservation
                    for reservation in self._unresolved_worker_open_reservations(
                        session_id
                    )
                    if reservation[1] == worker_instance_id
                }
                if (
                    identity not in open_contexts
                    and identity not in closed_contexts
                    and not reservations
                ):
                    raise ControllerConflict(
                        "cleanup was not attested by the worker instance that may own the context"
                    )
                if identity in open_contexts:
                    self._insert_event(
                        "web.browser.worker.context.closed",
                        session_id,
                        session["owner_run_id"],
                        {
                            "worker_instance_id": worker_instance_id,
                            "worker_session_id": worker_session_id,
                            "command_id": command_id,
                        },
                    )
                for reserved_command_id, _ in sorted(reservations):
                    self._insert_event(
                        "web.browser.worker.open.retired",
                        session_id,
                        session["owner_run_id"],
                        {
                            "reserved_command_id": reserved_command_id,
                            "worker_instance_id": worker_instance_id,
                            "close_command_id": command_id,
                        },
                    )
                self._insert_event(
                    "web.browser.worker.cleanup.attested",
                    session_id,
                    session["owner_run_id"],
                    {
                        "worker_id": worker_id,
                        "worker_instance_id": worker_instance_id,
                        "worker_session_id": worker_session_id,
                        "command_id": command_id,
                    },
                )
                self.database.commit()
            except Exception:
                self.database.rollback()
                raise

    def worker_context_may_be_live(
        self, session_id: str, *, worker_instance_id: str
    ) -> bool:
        """Return whether a context or unacknowledged OPEN dispatch may be live."""

        if not worker_instance_id:
            raise ValueError("worker_instance_id cannot be empty")

        with self._lock:
            # An instance-ID mismatch is not proof that the old process is dead;
            # any unmatched identity or dispatch keeps the profile quarantined.
            return bool(
                self._open_worker_contexts(session_id)
                or self._unresolved_worker_open_reservations(session_id)
            )

    def record_worker_death_attestation(
        self, attestation: WorkerDeathAttestation
    ) -> None:
        """Persist process-tree death evidence without releasing any reservation."""

        from weir.browser.process_worker import WorkerDeathAttestation

        if not isinstance(attestation, WorkerDeathAttestation):
            raise TypeError("attestation must be a WorkerDeathAttestation")
        attestation.validate()
        serialized = _json(attestation.to_dict())
        with self._lock, self.database:
            existing = self.database.execute(
                """SELECT attestation_json FROM browser_worker_death_attestations
                   WHERE attestation_hash = ?""",
                (attestation.attestation_hash,),
            ).fetchone()
            if existing is not None:
                if existing["attestation_json"] != serialized:
                    raise IdempotencyConflict(
                        "worker death attestation hash has different content"
                    )
                return
            self.database.execute(
                """INSERT INTO browser_worker_death_attestations
                   (attestation_hash, worker_id, worker_instance_id, observed_at,
                    attestation_json, recorded_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    attestation.attestation_hash,
                    attestation.worker_id,
                    attestation.worker_instance_id,
                    attestation.observed_at,
                    serialized,
                    _utc(self.clock()),
                ),
            )

    def retire_dead_worker_reservation(
        self,
        session_id: str,
        *,
        retirement_id: str,
        expected_session_epoch: int,
        expected_worker_id: str,
        expected_worker_instance_id: str,
        expected_credential_binding_id: str,
        attestation_hash: str,
        disposition: str,
        disposition_actor_id: str,
        disposition_ref: str,
    ) -> BrowserSession:
        """Close one lost session after an authenticated operator disposition.

        Authentication belongs to the service boundary. This transaction rechecks the
        exact reservation and independently persisted process-tree death evidence.
        """

        for name, value in (
            ("retirement_id", retirement_id),
            ("expected_worker_id", expected_worker_id),
            ("expected_worker_instance_id", expected_worker_instance_id),
            (
                "expected_credential_binding_id",
                expected_credential_binding_id,
            ),
            ("attestation_hash", attestation_hash),
            ("disposition_actor_id", disposition_actor_id),
            ("disposition_ref", disposition_ref),
        ):
            validate_identifier(value, name)
        if type(expected_session_epoch) is not int or expected_session_epoch < 1:
            raise ValueError("expected_session_epoch must be a positive integer")
        if not is_sha256(attestation_hash):
            raise ValueError("attestation_hash must be a sha256 digest")
        if disposition != DEAD_WORKER_RETIREMENT_DISPOSITION:
            raise ValueError("dead-worker retirement disposition is not recognized")
        with self._lock:
            self.database.execute("BEGIN IMMEDIATE")
            try:
                session = self._required_session_row(session_id)
                reservation = self._required_profile_reservation_row(session_id)
                self._require_no_open_action(session_id, "operator retirement")
                existing = self.database.execute(
                    """SELECT session_id, session_epoch, credential_binding_id,
                              worker_id, worker_instance_id, attestation_hash,
                              disposition, disposition_actor_id, disposition_ref
                       FROM browser_profile_retirements WHERE retirement_id = ?""",
                    (retirement_id,),
                ).fetchone()
                if existing is not None:
                    expected = (
                        session_id,
                        expected_session_epoch,
                        expected_credential_binding_id,
                        expected_worker_id,
                        expected_worker_instance_id,
                        attestation_hash,
                        disposition,
                        disposition_actor_id,
                        disposition_ref,
                    )
                    if tuple(existing) != expected:
                        raise IdempotencyConflict(
                            "retirement ID is bound to a different disposition"
                        )
                    self.database.commit()
                    return self.get_session(session_id)
                if int(session["epoch"]) != expected_session_epoch:
                    raise ControllerConflict(
                        "operator retirement belongs to a stale browser-session epoch"
                    )
                if (
                    reservation["worker_id"] != expected_worker_id
                    or reservation["worker_instance_id"]
                    != expected_worker_instance_id
                    or reservation["credential_binding_id"]
                    != expected_credential_binding_id
                ):
                    raise ControllerConflict(
                        "operator retirement does not match the held credential reservation"
                    )
                if SessionState(session["state"]) is not SessionState.LOST:
                    raise ControllerConflict(
                        "operator retirement requires a lost browser session"
                    )
                if reservation["state"] != "quarantined":
                    raise ControllerConflict(
                        "operator retirement requires a quarantined credential reservation"
                    )
                death = self.database.execute(
                    """SELECT * FROM browser_worker_death_attestations
                       WHERE attestation_hash = ?""",
                    (attestation_hash,),
                ).fetchone()
                if death is None:
                    raise ControllerConflict(
                        "operator retirement requires persisted worker-death evidence"
                    )
                attestation_value = json.loads(death["attestation_json"])
                if (
                    death["worker_id"] != reservation["worker_id"]
                    or death["worker_instance_id"]
                    != reservation["worker_instance_id"]
                    or attestation_value.get("process_tree_confirmed_dead") is not True
                ):
                    raise ControllerConflict(
                        "worker-death evidence does not match the held reservation"
                    )
                if _parse(death["observed_at"]) < _parse(reservation["created_at"]):
                    raise ControllerConflict(
                        "worker-death evidence predates the held credential reservation"
                    )
                now = _utc(self.clock())
                self.database.execute(
                    """INSERT INTO browser_profile_retirements
                       (retirement_id, session_id, session_epoch,
                        credential_binding_id, worker_id, worker_instance_id,
                        attestation_hash, disposition, disposition_actor_id,
                        disposition_ref, recorded_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        retirement_id,
                        session_id,
                        expected_session_epoch,
                        reservation["credential_binding_id"],
                        reservation["worker_id"],
                        reservation["worker_instance_id"],
                        attestation_hash,
                        disposition,
                        disposition_actor_id,
                        disposition_ref,
                        now,
                    ),
                )
                self.database.execute(
                    """UPDATE browser_sessions
                       SET state = 'closed', revision = revision + 1, updated_at = ?
                       WHERE session_id = ? AND state = 'lost'""",
                    (now, session_id),
                )
                self.database.execute(
                    """UPDATE controller_leases
                       SET active = 0, lease_id = NULL, controller_id = NULL,
                           controller_kind = NULL, fencing_token = NULL,
                           expires_at = NULL, updated_at = ?
                       WHERE session_id = ?""",
                    (now, session_id),
                )
                self.database.execute(
                    """UPDATE browser_profile_reservations
                       SET state = 'released', updated_at = ?,
                           release_kind = 'operator_dead_worker_retirement',
                           release_actor_id = ?, release_ref = ?
                       WHERE session_id = ? AND state = 'quarantined'""",
                    (now, disposition_actor_id, disposition_ref, session_id),
                )
                self._insert_event(
                    "web.browser.profile.reservation.retired",
                    session_id,
                    session["owner_run_id"],
                    {
                        "retirement_id": retirement_id,
                        "attestation_hash": attestation_hash,
                        "disposition": disposition,
                        "disposition_actor_id": disposition_actor_id,
                        "disposition_ref": disposition_ref,
                    },
                )
                self.database.commit()
            except Exception:
                self.database.rollback()
                raise
        return self.get_session(session_id)

    def reserve_worker_open(
        self,
        session_id: str,
        *,
        command_id: str,
        attempt_token: str,
        worker_instance_id: str,
        expected_revision: int,
        expected_epoch: int,
        required_lease: ControllerLease,
    ) -> None:
        """Fence one OPEN dispatch against the exact durable session generation."""

        if not command_id or not attempt_token or not worker_instance_id:
            raise ValueError("worker open reservation fields cannot be empty")
        with self._lock:
            self.database.execute("BEGIN IMMEDIATE")
            try:
                session = self._required_session_row(session_id)
                self.assert_live_profile_reservation_holder(
                    session_id,
                    worker_id=session["worker_id"],
                    worker_instance_id=worker_instance_id,
                )
                self._require_current_command_attempt(command_id, attempt_token)
                if SessionState(session["state"]) is not SessionState.OPENING:
                    raise ControllerConflict(
                        "worker OPEN requires a session in the opening state"
                    )
                if int(session["revision"]) != expected_revision:
                    raise SessionRevisionConflict(
                        f"session {session_id!r} revision changed before worker OPEN"
                    )
                if int(session["epoch"]) != expected_epoch:
                    raise SessionRevisionConflict(
                        f"session {session_id!r} epoch changed before worker OPEN"
                    )
                if required_lease.session_id != session_id:
                    raise ControllerConflict("worker OPEN lease belongs to another session")
                self._require_valid_lease(required_lease, self.clock())
                if (
                    required_lease.kind is not ControllerKind.AUTOMATION
                    or required_lease.controller_id != session["owner_run_id"]
                ):
                    raise ControllerConflict(
                        "worker OPEN requires the owning automation lease"
                    )
                existing = self._worker_open_reservation(command_id)
                if existing is not None:
                    existing_session, existing_instance, existing_token = existing
                    if existing_session != session_id or existing_instance != worker_instance_id:
                        raise ControllerConflict(
                            "open command is reserved by another worker instance"
                        )
                    if existing_token == attempt_token:
                        self.database.commit()
                        return
                self._insert_event(
                    "web.browser.worker.open.reserved",
                    session_id,
                    session["owner_run_id"],
                    {
                        "command_id": command_id,
                        "attempt_token": attempt_token,
                        "worker_instance_id": worker_instance_id,
                        "revision": expected_revision,
                        "epoch": expected_epoch,
                        "controller_generation": required_lease.generation,
                    },
                )
                self.database.commit()
            except Exception:
                self.database.rollback()
                raise

    def started_open_worker_instance(self, command_id: str) -> str | None:
        """Return the reserved process only while an open command is STARTED."""

        with self._lock:
            row = self.database.execute(
                "SELECT status FROM browser_commands WHERE command_id = ?",
                (command_id,),
            ).fetchone()
            if row is None or row["status"] != "started":
                return None
            reservation = self._worker_open_reservation(command_id)
        return None if reservation is None else reservation[1]

    def get_session(self, session_id: str) -> BrowserSession:
        with self._lock:
            row = self.database.execute(
                "SELECT * FROM browser_sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
            if row is None:
                raise SessionNotFound(session_id)
            lease = self._lease_from_row(self._lease_row(session_id))
            return self._session_from_row(row, lease)

    def sessions(self, *, include_closed: bool = False) -> list[BrowserSession]:
        query = "SELECT session_id FROM browser_sessions"
        parameters: tuple[Any, ...] = ()
        if not include_closed:
            query += " WHERE state != ?"
            parameters = (SessionState.CLOSED.value,)
        query += " ORDER BY updated_at DESC, session_id"
        with self._lock:
            ids = [row[0] for row in self.database.execute(query, parameters)]
        return [self.get_session(session_id) for session_id in ids]

    def activate_opening_session(
        self,
        session_id: str,
        expected_revision: int,
        *,
        current_url: str,
        worker_session_id: str,
        worker_instance_id: str,
        event_type: str,
        attributes: dict[str, Any] | None = None,
        complete_command_id: str,
        command_result: dict[str, Any],
        command_attempt_token: str,
        required_lease: ControllerLease,
    ) -> BrowserSession:
        """Activate OPENING only with a live context, lease, and command attempt."""

        if not all(
            (
                current_url,
                worker_session_id,
                worker_instance_id,
                event_type,
                complete_command_id,
                command_attempt_token,
            )
        ):
            raise ValueError("opening activation proof fields cannot be empty")
        with self._lock:
            self.database.execute("BEGIN IMMEDIATE")
            try:
                row = self._required_session_row(session_id)
                self.assert_live_profile_reservation_holder(
                    session_id,
                    worker_id=row["worker_id"],
                    worker_instance_id=worker_instance_id,
                )
                if required_lease.session_id != session_id:
                    raise ControllerConflict(
                        "required controller lease belongs to another session"
                    )
                now = self.clock()
                self._require_valid_lease(required_lease, now)
                if (
                    required_lease.kind is not ControllerKind.AUTOMATION
                    or required_lease.controller_id != row["owner_run_id"]
                ):
                    raise ControllerConflict(
                        "opening activation requires the owning automation lease"
                    )
                if int(row["revision"]) != expected_revision:
                    raise SessionRevisionConflict(
                        f"session {session_id!r} revision is {row['revision']}, "
                        f"not expected {expected_revision}"
                    )
                current = SessionState(row["state"])
                if current is not SessionState.OPENING:
                    raise ControllerConflict("only an opening session can be activated")
                if (worker_instance_id, worker_session_id) not in self._open_worker_contexts(
                    session_id
                ):
                    raise ControllerConflict(
                        "opening activation requires an exact live worker context"
                    )
                if not self._worker_context_is_activation_eligible(
                    session_id,
                    worker_instance_id=worker_instance_id,
                    worker_session_id=worker_session_id,
                ):
                    raise ControllerConflict(
                        "opening activation requires a command-bound context acknowledgement"
                    )
                if self._unresolved_worker_open_reservations(session_id):
                    raise ControllerConflict(
                        "opening activation has an unresolved worker OPEN dispatch"
                    )
                self._require_current_command_attempt(
                    complete_command_id, command_attempt_token
                )
                require_transition(current, SessionState.ACTIVE)
                updated_at = _utc(now)
                revision = expected_revision + 1
                epoch = int(row["epoch"])
                cursor = self.database.execute(
                    """UPDATE browser_sessions
                       SET state = ?, revision = ?, epoch = ?, current_url = ?,
                           worker_session_id = ?, updated_at = ?
                       WHERE session_id = ? AND revision = ? AND state = 'opening'""",
                    (
                        SessionState.ACTIVE.value,
                        revision,
                        epoch,
                        current_url,
                        worker_session_id,
                        updated_at,
                        session_id,
                        expected_revision,
                    ),
                )
                if cursor.rowcount != 1:
                    raise SessionRevisionConflict(
                        f"session {session_id!r} changed before opening activation"
                    )
                self.database.execute(
                    """UPDATE browser_profile_reservations
                       SET state = 'active', updated_at = ?
                       WHERE session_id = ? AND state IN ('active', 'quarantined')""",
                    (updated_at, session_id),
                )
                event_attributes = {
                    "from_state": current.value,
                    "to_state": SessionState.ACTIVE.value,
                    "revision": revision,
                    "epoch": epoch,
                    **(attributes or {}),
                }
                self._insert_event(
                    event_type,
                    session_id,
                    row["owner_run_id"],
                    event_attributes,
                )
                self._complete_command_in_transaction(
                    complete_command_id,
                    command_result,
                    updated_at,
                    attempt_token=command_attempt_token,
                )
                self.database.commit()
            except Exception:
                self.database.rollback()
                raise
        return self.get_session(session_id)

    def mark_lost(
        self,
        session_id: str,
        expected_revision: int,
        *,
        event_type: str = "web.browser.session.lost",
        attributes: dict[str, Any] | None = None,
    ) -> BrowserSession:
        """Fail closed and invalidate the active controller lease."""

        with self._lock:
            self.database.execute("BEGIN IMMEDIATE")
            try:
                row = self._required_session_row(session_id)
                self._require_no_open_action(session_id, "session loss")
                if int(row["revision"]) != expected_revision:
                    raise SessionRevisionConflict(
                        f"session {session_id!r} revision changed before loss"
                    )
                current = SessionState(row["state"])
                if current not in {
                    SessionState.OPENING,
                    SessionState.ACTIVE,
                    SessionState.PAUSED,
                }:
                    raise ControllerConflict(
                        f"session state {current.value!r} cannot be marked lost"
                    )
                require_transition(current, SessionState.LOST)
                now = _utc(self.clock())
                revision = expected_revision + 1
                cursor = self.database.execute(
                    """UPDATE browser_sessions SET state = 'lost', revision = ?, updated_at = ?
                       WHERE session_id = ? AND revision = ?""",
                    (revision, now, session_id, expected_revision),
                )
                if cursor.rowcount != 1:
                    raise SessionRevisionConflict(
                        f"session {session_id!r} changed before loss"
                    )
                self.database.execute(
                    """UPDATE controller_leases
                       SET active = 0, lease_id = NULL, controller_id = NULL,
                           controller_kind = NULL, fencing_token = NULL,
                           expires_at = NULL, updated_at = ?
                       WHERE session_id = ?""",
                    (now, session_id),
                )
                self.database.execute(
                    """UPDATE browser_profile_reservations
                       SET state = 'quarantined', updated_at = ?
                       WHERE session_id = ? AND state = 'active'""",
                    (now, session_id),
                )
                self._insert_event(
                    event_type,
                    session_id,
                    row["owner_run_id"],
                    {
                        "from_state": current.value,
                        "to_state": SessionState.LOST.value,
                        "revision": revision,
                        **(attributes or {}),
                    },
                )
                self.database.commit()
            except Exception:
                self.database.rollback()
                raise
        return self.get_session(session_id)

    def acquire_lease(
        self,
        session_id: str,
        controller_id: str,
        kind: ControllerKind,
        *,
        ttl: timedelta,
    ) -> ControllerLease:
        if ttl.total_seconds() <= 0:
            raise ValueError("controller lease TTL must be positive")
        with self._lock:
            self.database.execute("BEGIN IMMEDIATE")
            try:
                session = self._required_session_row(session_id)
                state = SessionState(session["state"])
                if kind is not ControllerKind.AUTOMATION:
                    raise ControllerConflict(
                        "operator leases require an atomic command-bound controller transfer"
                    )
                if controller_id != session["owner_run_id"]:
                    raise ControllerConflict(
                        "automation leases belong only to the session owner"
                    )
                if state not in {SessionState.OPENING, SessionState.ACTIVE}:
                    raise ControllerConflict(
                        f"session state {state.value!r} requires a command-bound transition"
                    )
                now = self.clock()
                row = self._lease_row(session_id)
                if row is not None and row["active"] and now < _parse(row["expires_at"]):
                    raise ControllerConflict(
                        f"session {session_id!r} already has controller {row['controller_id']!r}"
                    )
                generation = int(row["generation"]) + 1 if row is not None else 1
                lease = self._new_lease(session, controller_id, kind, generation, ttl, now)
                self._write_lease(lease, active=True, now=now)
                self._insert_event(
                    "web.controller.acquired",
                    session_id,
                    session["owner_run_id"],
                    {
                        "controller_id": controller_id,
                        "controller_kind": kind.value,
                        "generation": generation,
                    },
                )
                self.database.commit()
            except Exception:
                self.database.rollback()
                raise
        return lease

    def renew_lease(self, lease: ControllerLease, *, ttl: timedelta) -> ControllerLease:
        if ttl.total_seconds() <= 0:
            raise ValueError("controller lease TTL must be positive")
        with self._lock, self.database:
            session = self._required_session_row(lease.session_id)
            now = self.clock()
            current = self._require_valid_lease(lease, now)
            expires_at = min(now + ttl, _parse(session["expires_at"]))
            renewed = ControllerLease(
                session_id=lease.session_id,
                lease_id=lease.lease_id,
                controller_id=lease.controller_id,
                kind=lease.kind,
                fencing_token=lease.fencing_token,
                generation=lease.generation,
                expires_at=_utc(expires_at),
            )
            self.database.execute(
                """UPDATE controller_leases SET expires_at = ?, updated_at = ?
                   WHERE session_id = ? AND active = 1 AND generation = ?""",
                (
                    renewed.expires_at,
                    _utc(now),
                    lease.session_id,
                    current["generation"],
                ),
            )
            self._insert_event(
                "web.controller.renewed",
                lease.session_id,
                session["owner_run_id"],
                {"controller_id": lease.controller_id, "generation": lease.generation},
            )
        return renewed

    def transfer_lease_and_transition(
        self,
        lease: ControllerLease,
        new_controller_id: str,
        new_kind: ControllerKind,
        *,
        expected_revision: int,
        target_state: SessionState,
        ttl: timedelta,
        authorization_ref: str,
        command_id: str,
        command_attempt_token: str,
    ) -> tuple[BrowserSession, ControllerLease]:
        """Atomically rotate the controller fence and pause/resume a session."""

        if not authorization_ref or not command_id or not command_attempt_token:
            raise ValueError("controller transfer requires authorization and a command attempt")
        with self._lock:
            self.database.execute("BEGIN IMMEDIATE")
            try:
                session = self._required_session_row(lease.session_id)
                self._require_current_command_attempt(
                    command_id, command_attempt_token
                )
                if int(session["revision"]) != expected_revision:
                    raise SessionRevisionConflict(
                        f"session {lease.session_id!r} revision changed before transfer"
                    )
                current_state = SessionState(session["state"])
                if (
                    current_state is not SessionState.ACTIVE
                    or target_state is not SessionState.PAUSED
                    or lease.kind is not ControllerKind.AUTOMATION
                    or lease.controller_id != session["owner_run_id"]
                    or new_kind is not ControllerKind.OPERATOR
                ):
                    raise ControllerConflict(
                        "this transition only supports fenced automation-to-operator takeover"
                    )
                require_transition(current_state, target_state)
                now = self.clock()
                current = self._require_valid_lease(lease, now)
                transferred = self._new_lease(
                    session,
                    new_controller_id,
                    new_kind,
                    int(current["generation"]) + 1,
                    ttl,
                    now,
                )
                self._write_lease(transferred, active=True, now=now)
                revision = expected_revision + 1
                self.database.execute(
                    """UPDATE browser_sessions SET state = ?, revision = ?, updated_at = ?
                       WHERE session_id = ? AND revision = ?""",
                    (
                        target_state.value,
                        revision,
                        _utc(now),
                        lease.session_id,
                        expected_revision,
                    ),
                )
                attributes = {
                    "from_controller_id": lease.controller_id,
                    "from_controller_kind": lease.kind.value,
                    "from_generation": lease.generation,
                    "to_controller_id": new_controller_id,
                    "controller_kind": new_kind.value,
                    "generation": transferred.generation,
                    "authorization_ref": authorization_ref,
                    "from_state": current_state.value,
                    "to_state": target_state.value,
                    "revision": revision,
                    "command_id": command_id,
                }
                self._insert_event(
                    "web.controller.transferred",
                    lease.session_id,
                    session["owner_run_id"],
                    attributes,
                )
                self.database.commit()
            except Exception:
                self.database.rollback()
                raise
        return self.get_session(lease.session_id), transferred

    def transfer_paused_controller(
        self,
        lease: ControllerLease,
        new_controller_id: str,
        new_kind: ControllerKind,
        *,
        expected_revision: int,
        ttl: timedelta,
        authorization_ref: str,
        command_id: str,
        command_attempt_token: str,
    ) -> tuple[BrowserSession, ControllerLease]:
        """Rotate control while the session remains non-dispatchable."""

        if not authorization_ref or not command_id or not command_attempt_token:
            raise ValueError("controller transfer requires authorization and a command attempt")
        with self._lock:
            self.database.execute("BEGIN IMMEDIATE")
            try:
                session = self._required_session_row(lease.session_id)
                self._require_no_open_action(
                    lease.session_id, "paused controller transfer"
                )
                self._require_current_command_attempt(
                    command_id, command_attempt_token
                )
                if int(session["revision"]) != expected_revision:
                    raise SessionRevisionConflict(
                        f"session {lease.session_id!r} revision changed before transfer"
                    )
                if SessionState(session["state"]) is not SessionState.PAUSED:
                    raise ControllerConflict(
                        "controller can transfer safely only while the session is paused"
                    )
                if (
                    lease.kind is not ControllerKind.OPERATOR
                    or new_kind is not ControllerKind.AUTOMATION
                    or new_controller_id != session["owner_run_id"]
                ):
                    raise ControllerConflict(
                        "paused control can return only from an operator to the owning run"
                    )
                now = self.clock()
                current = self._require_valid_lease(lease, now)
                transferred = self._new_lease(
                    session,
                    new_controller_id,
                    new_kind,
                    int(current["generation"]) + 1,
                    ttl,
                    now,
                )
                self._write_lease(transferred, active=True, now=now)
                self._insert_event(
                    "web.controller.transferred",
                    lease.session_id,
                    session["owner_run_id"],
                    {
                        "from_controller_id": lease.controller_id,
                        "from_controller_kind": lease.kind.value,
                        "from_generation": lease.generation,
                        "to_controller_id": new_controller_id,
                        "controller_kind": new_kind.value,
                        "generation": transferred.generation,
                        "authorization_ref": authorization_ref,
                        "state": SessionState.PAUSED.value,
                        "revision": expected_revision,
                        "command_id": command_id,
                    },
                )
                self.database.commit()
            except Exception:
                self.database.rollback()
                raise
        return self.get_session(lease.session_id), transferred

    def resume_transferred_controller(
        self,
        session_id: str,
        *,
        command_id: str,
        command_attempt_token: str,
        expected_revision: int,
        expected_from_controller_id: str,
        expected_from_kind: ControllerKind,
        expected_from_generation: int | None,
        expected_controller_id: str,
        expected_kind: ControllerKind,
        authorization_ref: str,
    ) -> tuple[BrowserSession, ControllerLease]:
        """Recover only the controller transfer made by this exact command."""

        if not command_id or not command_attempt_token or not authorization_ref:
            raise ValueError("transfer recovery requires authorization and a command attempt")
        with self._lock:
            self.database.execute("BEGIN IMMEDIATE")
            try:
                session = self._required_session_row(session_id)
                self._require_no_open_action(
                    session_id, "controller transfer recovery"
                )
                self._require_current_command_attempt(
                    command_id, command_attempt_token
                )
                if (
                    SessionState(session["state"]) is not SessionState.PAUSED
                    or int(session["revision"]) != expected_revision
                ):
                    raise CommandInDoubt(
                        "controller transfer recovery does not match the paused session revision"
                    )
                lease = self._lease_from_row(self._lease_row(session_id))
                if lease is None:
                    raise CommandInDoubt(
                        "transferred controller lease expired or is no longer active"
                    )
                if (
                    lease.controller_id != expected_controller_id
                    or lease.kind is not expected_kind
                ):
                    raise CommandInDoubt(
                        "active controller does not match the command's transferred controller"
                    )
                if not self._controller_transfer_matches(
                    session_id,
                    command_id,
                    revision=expected_revision,
                    from_controller_id=expected_from_controller_id,
                    from_controller_kind=expected_from_kind,
                    from_generation=expected_from_generation,
                    to_controller_id=expected_controller_id,
                    to_controller_kind=expected_kind,
                    to_generation=lease.generation,
                    authorization_ref=authorization_ref,
                ):
                    raise CommandInDoubt(
                        "active controller has no matching durable transfer record"
                    )
                recovered = self._session_from_row(session, lease)
                self.database.commit()
            except Exception:
                self.database.rollback()
                raise
        return recovered, lease

    def activate_after_fence(
        self,
        lease: ControllerLease,
        *,
        expected_revision: int,
        authorization_ref: str,
        complete_command_id: str,
        command_result: dict[str, Any],
        command_attempt_token: str,
    ) -> BrowserSession:
        """Expose an automation controller only after its worker fence is acknowledged."""

        if not authorization_ref or not complete_command_id or not command_attempt_token:
            raise ValueError("activation requires authorization and a command attempt")
        with self._lock:
            self.database.execute("BEGIN IMMEDIATE")
            try:
                session = self._required_session_row(lease.session_id)
                self._require_no_open_action(
                    lease.session_id, "controller activation"
                )
                self._require_current_command_attempt(
                    complete_command_id, command_attempt_token
                )
                if int(session["revision"]) != expected_revision:
                    raise SessionRevisionConflict(
                        f"session {lease.session_id!r} revision changed before activation"
                    )
                current = SessionState(session["state"])
                if current is not SessionState.PAUSED:
                    raise ControllerConflict("only a paused session can be activated")
                if (
                    lease.kind is not ControllerKind.AUTOMATION
                    or lease.controller_id != session["owner_run_id"]
                ):
                    raise ControllerConflict("activation requires the owning automation lease")
                now = self.clock()
                self._require_valid_lease(lease, now)
                if not self._controller_transfer_matches(
                    lease.session_id,
                    complete_command_id,
                    revision=expected_revision,
                    from_controller_id=None,
                    from_controller_kind=ControllerKind.OPERATOR,
                    from_generation=None,
                    to_controller_id=lease.controller_id,
                    to_controller_kind=ControllerKind.AUTOMATION,
                    to_generation=lease.generation,
                    authorization_ref=authorization_ref,
                ):
                    raise CommandInDoubt(
                        "automation activation has no matching durable return transfer"
                    )
                require_transition(current, SessionState.ACTIVE)
                revision = expected_revision + 1
                cursor = self.database.execute(
                    """UPDATE browser_sessions SET state = 'active', revision = ?, updated_at = ?
                       WHERE session_id = ? AND revision = ? AND state = 'paused'""",
                    (revision, _utc(now), lease.session_id, expected_revision),
                )
                if cursor.rowcount != 1:
                    raise SessionRevisionConflict(
                        f"session {lease.session_id!r} changed before activation"
                    )
                self._insert_event(
                    "web.controller.activated",
                    lease.session_id,
                    session["owner_run_id"],
                    {
                        "authorization_ref": authorization_ref,
                        "controller_generation": lease.generation,
                        "revision": revision,
                    },
                )
                self._complete_command_in_transaction(
                    complete_command_id,
                    command_result,
                    _utc(now),
                    attempt_token=command_attempt_token,
                )
                self.database.commit()
            except Exception:
                self.database.rollback()
                raise
        return self.get_session(lease.session_id)

    def reserve_automation_command(
        self,
        lease: ControllerLease,
        *,
        expected_revision: int,
        expected_epoch: int,
        operation: str,
        command_id: str,
        command_attempt_token: str,
        ttl: timedelta,
    ) -> tuple[BrowserSession, ControllerLease]:
        """Claim one session revision before dispatching a worker operation.

        The temporary PAUSED state is a durable in-flight marker. It prevents a
        second broker process from dispatching against the same browser state;
        completion returns the session to ACTIVE in a separate transaction.
        """

        if not operation or not command_id or not command_attempt_token:
            raise ValueError("reserved browser commands require operation and command IDs")
        with self._lock:
            self.database.execute("BEGIN IMMEDIATE")
            try:
                session = self._required_session_row(lease.session_id)
                self._require_current_command_attempt(
                    command_id, command_attempt_token
                )
                if int(session["revision"]) != expected_revision:
                    raise SessionRevisionConflict(
                        f"session {lease.session_id!r} revision changed before reservation"
                    )
                if int(session["epoch"]) != expected_epoch:
                    raise SessionRevisionConflict(
                        f"session {lease.session_id!r} epoch changed before reservation"
                    )
                current_state = SessionState(session["state"])
                if current_state is not SessionState.ACTIVE:
                    raise ControllerConflict("only active sessions can reserve a command")
                now = self.clock()
                current = self._require_valid_lease(lease, now)
                if (
                    lease.kind is not ControllerKind.AUTOMATION
                    or lease.controller_id != session["owner_run_id"]
                ):
                    raise ControllerConflict(
                        "only the owning automation controller can reserve a command"
                    )
                require_transition(current_state, SessionState.PAUSED)
                reserved_lease = self._new_lease(
                    session,
                    lease.controller_id,
                    ControllerKind.AUTOMATION,
                    int(current["generation"]) + 1,
                    ttl,
                    now,
                )
                self._write_lease(reserved_lease, active=True, now=now)
                revision = expected_revision + 1
                cursor = self.database.execute(
                    """UPDATE browser_sessions
                       SET state = 'paused', revision = ?, updated_at = ?
                       WHERE session_id = ? AND revision = ? AND state = 'active'""",
                    (revision, _utc(now), lease.session_id, expected_revision),
                )
                if cursor.rowcount != 1:
                    raise SessionRevisionConflict(
                        f"session {lease.session_id!r} changed before reservation"
                    )
                self._insert_event(
                    "web.browser.command.reserved",
                    lease.session_id,
                    session["owner_run_id"],
                    {
                        "operation": operation,
                        "command_id": command_id,
                        "revision": revision,
                        "controller_generation": reserved_lease.generation,
                    },
                )
                self.database.commit()
            except Exception:
                self.database.rollback()
                raise
        return self.get_session(lease.session_id), reserved_lease

    def complete_reserved_command(
        self,
        session_id: str,
        expected_revision: int,
        lease: ControllerLease,
        *,
        current_url: str,
        command_id: str,
        command_attempt_token: str,
        event_type: str,
        attributes: dict[str, Any] | None = None,
        command_result: dict[str, Any] | None = None,
    ) -> BrowserSession:
        """Commit a reserved worker result and make the session active again."""

        with self._lock:
            self.database.execute("BEGIN IMMEDIATE")
            try:
                row = self._required_session_row(session_id)
                self._require_no_open_action(
                    session_id, "reserved browser command completion"
                )
                self._require_current_command_attempt(
                    command_id, command_attempt_token
                )
                if int(row["revision"]) != expected_revision:
                    raise SessionRevisionConflict(
                        f"session {session_id!r} revision changed before command commit"
                    )
                current = SessionState(row["state"])
                if current is not SessionState.PAUSED:
                    raise ControllerConflict("reserved browser command is no longer in flight")
                if lease.session_id != session_id:
                    raise ControllerConflict(
                        "reserved command lease belongs to another session"
                    )
                if (
                    lease.kind is not ControllerKind.AUTOMATION
                    or lease.controller_id != row["owner_run_id"]
                ):
                    raise ControllerConflict(
                        "reserved command completion requires the owning automation lease"
                    )
                now = self.clock()
                self._require_valid_lease(lease, now)
                reserved_fence = self._reserved_command_fence(session_id, command_id)
                if reserved_fence != (expected_revision, lease.generation):
                    raise ControllerConflict(
                        "command completion does not match its reserved revision and fence"
                    )
                require_transition(current, SessionState.ACTIVE)
                revision = expected_revision + 1
                cursor = self.database.execute(
                    """UPDATE browser_sessions
                       SET state = 'active', revision = ?, current_url = ?, updated_at = ?
                       WHERE session_id = ? AND revision = ? AND state = 'paused'""",
                    (revision, current_url, _utc(now), session_id, expected_revision),
                )
                if cursor.rowcount != 1:
                    raise SessionRevisionConflict(
                        f"session {session_id!r} changed before command commit"
                    )
                self._insert_event(
                    event_type,
                    session_id,
                    row["owner_run_id"],
                    {
                        "revision": revision,
                        "command_id": command_id,
                        "controller_generation": lease.generation,
                        **(attributes or {}),
                    },
                )
                if command_result is not None:
                    self._complete_command_in_transaction(
                        command_id,
                        command_result,
                        _utc(now),
                        attempt_token=command_attempt_token,
                    )
                self.database.commit()
            except Exception:
                self.database.rollback()
                raise
        return self.get_session(session_id)

    def begin_close(
        self,
        session_id: str,
        owner_run_id: str,
        *,
        expected_revision: int,
        expected_epoch: int,
        command_id: str,
        command_attempt_token: str,
        ttl: timedelta,
    ) -> tuple[BrowserSession, ControllerLease]:
        """Reserve terminal cleanup, including for expired or failed sessions."""

        if ttl.total_seconds() <= 0:
            raise ValueError("cleanup lease TTL must be positive")
        if not command_id or not command_attempt_token:
            raise ValueError("close reservation requires a command attempt")
        with self._lock:
            self.database.execute("BEGIN IMMEDIATE")
            try:
                session = self._required_session_row(session_id)
                self._require_no_open_action(session_id, "session close")
                self._require_current_command_attempt(
                    command_id, command_attempt_token
                )
                if session["owner_run_id"] != owner_run_id:
                    raise ControllerConflict("only the original run may close a session")
                if int(session["revision"]) != expected_revision:
                    raise SessionRevisionConflict(
                        f"session {session_id!r} revision changed before close"
                    )
                if int(session["epoch"]) != expected_epoch:
                    raise SessionRevisionConflict(
                        f"session {session_id!r} epoch changed before close"
                    )
                current_state = SessionState(session["state"])
                if current_state is SessionState.CLOSED:
                    raise ControllerConflict("closed sessions do not need cleanup")

                now = self.clock()
                lease_row = self._lease_row(session_id)
                live_lease = bool(
                    lease_row is not None
                    and lease_row["active"]
                    and now < _parse(lease_row["expires_at"])
                )
                if live_lease:
                    live_kind = ControllerKind(lease_row["controller_kind"])
                    if live_kind is ControllerKind.OPERATOR:
                        raise ControllerConflict(
                            "cannot close while an operator controller lease is active"
                        )
                    if lease_row["controller_id"] != owner_run_id:
                        raise ControllerConflict(
                            "cannot close while another automation controller is active"
                        )
                    if current_state is SessionState.PAUSED:
                        raise ControllerConflict(
                            "cannot close while an automation command is in flight"
                        )

                generation = int(lease_row["generation"]) + 1 if lease_row else 1
                cleanup_expires_at = now + ttl
                cleanup = ControllerLease(
                    session_id=session_id,
                    lease_id=f"lease-{uuid.uuid4().hex}",
                    controller_id=owner_run_id,
                    kind=ControllerKind.AUTOMATION,
                    fencing_token=secrets.token_hex(24),
                    generation=generation,
                    # Cleanup remains possible after the ordinary session TTL.
                    expires_at=_utc(cleanup_expires_at),
                )
                self._write_lease(cleanup, active=True, now=now)
                target_state = (
                    SessionState.PAUSED
                    if current_state is SessionState.ACTIVE
                    else current_state
                )
                if current_state is SessionState.ACTIVE:
                    require_transition(current_state, target_state)
                revision = expected_revision + 1
                cursor = self.database.execute(
                    """UPDATE browser_sessions
                       SET state = ?, revision = ?, updated_at = ?, expires_at = ?
                       WHERE session_id = ? AND revision = ?""",
                    (
                        target_state.value,
                        revision,
                        _utc(now),
                        _utc(max(_parse(session["expires_at"]), cleanup_expires_at)),
                        session_id,
                        expected_revision,
                    ),
                )
                if cursor.rowcount != 1:
                    raise SessionRevisionConflict(
                        f"session {session_id!r} changed before close reservation"
                    )
                self._insert_event(
                    "web.browser.close.reserved",
                    session_id,
                    owner_run_id,
                    {
                        "from_state": current_state.value,
                        "reserved_state": target_state.value,
                        "revision": revision,
                        "command_id": command_id,
                        "controller_generation": cleanup.generation,
                    },
                )
                self.database.commit()
            except Exception:
                self.database.rollback()
                raise
        return self.get_session(session_id), cleanup

    def begin_recovery(
        self,
        session_id: str,
        owner_run_id: str,
        expected_revision: int,
        *,
        worker_session_id: str,
        command_id: str,
        command_attempt_token: str,
    ) -> BrowserSession:
        """Reopen a lost session for the same owner and invalidate every old fence."""

        with self._lock:
            self.database.execute("BEGIN IMMEDIATE")
            try:
                row = self._required_session_row(session_id)
                self._require_current_command_attempt(
                    command_id, command_attempt_token
                )
                if row["owner_run_id"] != owner_run_id:
                    raise ControllerConflict("only the original run may recover a session")
                if int(row["revision"]) != expected_revision:
                    raise SessionRevisionConflict(
                        f"session {session_id!r} revision changed before recovery"
                    )
                current = SessionState(row["state"])
                require_transition(current, SessionState.OPENING)
                now = self.clock()
                revision = expected_revision + 1
                epoch = int(row["epoch"]) + 1
                self.database.execute(
                    """UPDATE browser_sessions
                       SET state = 'opening', revision = ?, epoch = ?,
                           worker_session_id = ?, updated_at = ?
                       WHERE session_id = ? AND revision = ?""",
                    (
                        revision,
                        epoch,
                        worker_session_id,
                        _utc(now),
                        session_id,
                        expected_revision,
                    ),
                )
                self.database.execute(
                    """UPDATE controller_leases
                       SET active = 0, lease_id = NULL, controller_id = NULL,
                           controller_kind = NULL, fencing_token = NULL,
                           expires_at = NULL, updated_at = ?
                       WHERE session_id = ?""",
                    (_utc(now), session_id),
                )
                self._insert_event(
                    "web.browser.session.recovery_started",
                    session_id,
                    owner_run_id,
                    {"revision": revision, "epoch": epoch},
                )
                self.database.commit()
            except Exception:
                self.database.rollback()
                raise
        return self.get_session(session_id)

    def release_lease(self, lease: ControllerLease) -> None:
        with self._lock, self.database:
            session = self._required_session_row(lease.session_id)
            self._require_no_open_action(lease.session_id, "controller release")
            self._require_valid_lease(lease, self.clock(), allow_expired=True)
            cursor = self.database.execute(
                """UPDATE controller_leases
                   SET active = 0, lease_id = NULL, controller_id = NULL,
                       controller_kind = NULL, fencing_token = NULL,
                       expires_at = NULL, updated_at = ?
                   WHERE session_id = ? AND active = 1 AND lease_id = ?
                     AND fencing_token = ? AND generation = ?""",
                (
                    _utc(self.clock()),
                    lease.session_id,
                    lease.lease_id,
                    lease.fencing_token,
                    lease.generation,
                ),
            )
            if cursor.rowcount != 1:
                raise ControllerConflict("stale controller lease cannot release a newer lease")
            self._insert_event(
                "web.controller.released",
                lease.session_id,
                session["owner_run_id"],
                {"controller_id": lease.controller_id, "generation": lease.generation},
            )

    def close_with_lease(
        self,
        session_id: str,
        expected_revision: int,
        lease: ControllerLease,
        *,
        command_id: str,
        command_attempt_token: str,
        command_result: dict[str, Any],
        worker_cleanup: bool = True,
        cleanup_failure_class: str | None = None,
    ) -> BrowserSession:
        """Commit terminal state and invalidate the controller in one transaction."""

        if not command_id or not command_attempt_token:
            raise ValueError("terminal close requires a current command attempt")
        with self._lock:
            self.database.execute("BEGIN IMMEDIATE")
            try:
                row = self._required_session_row(session_id)
                self._require_no_open_action(session_id, "terminal session close")
                self._require_current_command_attempt(
                    command_id, command_attempt_token
                )
                if int(row["revision"]) != expected_revision:
                    raise SessionRevisionConflict(
                        f"session {session_id!r} revision changed before close"
                    )
                current = SessionState(row["state"])
                require_transition(current, SessionState.CLOSED)
                if lease.session_id != session_id:
                    raise ControllerConflict("cleanup lease belongs to another session")
                if (
                    lease.kind is not ControllerKind.AUTOMATION
                    or lease.controller_id != row["owner_run_id"]
                ):
                    raise ControllerConflict(
                        "terminal close requires the owning automation cleanup lease"
                    )
                now = self.clock()
                self._require_valid_lease(lease, now)
                close_fence = self._reservation_fence(
                    session_id,
                    command_id,
                    event_type="web.browser.close.reserved",
                )
                if close_fence != (expected_revision, lease.generation):
                    raise ControllerConflict(
                        "terminal close does not match its reserved revision and fence"
                    )
                if (
                    self._open_worker_contexts(session_id)
                    or self._unresolved_worker_open_reservations(session_id)
                ):
                    raise ControllerConflict(
                        "worker cleanup is not durably attested; profile remains quarantined"
                    )
                reservation = self._required_profile_reservation_row(session_id)
                if reservation["state"] not in {"active", "quarantined"}:
                    raise ControllerConflict(
                        "credential reservation is not held by the closing session"
                    )
                worker_was_dispatched = self.database.execute(
                    """SELECT 1 FROM browser_events
                       WHERE session_id = ?
                         AND event_type = 'web.browser.worker.open.reserved'
                       LIMIT 1""",
                    (session_id,),
                ).fetchone()
                if worker_was_dispatched is not None and not self._cleanup_matches(
                    session_id,
                    command_id=command_id,
                    worker_id=reservation["worker_id"],
                    worker_instance_id=reservation["worker_instance_id"],
                ):
                    raise ControllerConflict(
                        "terminal close requires cleanup attested by the reservation holder"
                    )
                revision = expected_revision + 1
                self.database.execute(
                    """UPDATE browser_sessions SET state = 'closed', revision = ?, updated_at = ?
                       WHERE session_id = ? AND revision = ?""",
                    (revision, _utc(now), session_id, expected_revision),
                )
                self.database.execute(
                    """UPDATE controller_leases
                       SET active = 0, lease_id = NULL, controller_id = NULL,
                           controller_kind = NULL, fencing_token = NULL,
                           expires_at = NULL, updated_at = ?
                       WHERE session_id = ? AND active = 1 AND generation = ?""",
                    (_utc(now), session_id, lease.generation),
                )
                release_kind = (
                    "live_worker_cleanup"
                    if worker_was_dispatched is not None
                    else "never_dispatched"
                )
                self.database.execute(
                    """UPDATE browser_profile_reservations
                       SET state = 'released', updated_at = ?, release_kind = ?,
                           release_actor_id = ?, release_ref = ?
                       WHERE session_id = ? AND state IN ('active', 'quarantined')""",
                    (
                        _utc(now),
                        release_kind,
                        reservation["worker_instance_id"],
                        command_id,
                        session_id,
                    ),
                )
                self._insert_event(
                    "web.browser.session.closed",
                    session_id,
                    row["owner_run_id"],
                    {
                        "from_state": current.value,
                        "revision": revision,
                        "command_id": command_id,
                        "controller_generation": lease.generation,
                        "worker_cleanup": worker_cleanup,
                        "cleanup_failure_class": cleanup_failure_class,
                    },
                )
                self._complete_command_in_transaction(
                    command_id,
                    command_result,
                    _utc(now),
                    attempt_token=command_attempt_token,
                )
                self.database.commit()
            except Exception:
                self.database.rollback()
                raise
        return self.get_session(session_id)

    def valid_lease(self, lease: ControllerLease) -> bool:
        with self._lock:
            try:
                self._require_valid_lease(lease, self.clock())
            except ControllerConflict:
                return False
            return True

    def active_lease(self, session_id: str) -> ControllerLease | None:
        with self._lock:
            return self._lease_from_row(self._lease_row(session_id))

    def begin_command(
        self,
        command_id: str,
        operation: str,
        request_digest: str,
        *,
        resume_after: timedelta | None = None,
    ) -> CommandStart:
        if resume_after is not None and resume_after.total_seconds() <= 0:
            raise ValueError("command resume delay must be positive")
        now_value = self.clock()
        now = _utc(now_value)
        with self._lock:
            self.database.execute("BEGIN IMMEDIATE")
            try:
                row = self.database.execute(
                    "SELECT * FROM browser_commands WHERE command_id = ?", (command_id,)
                ).fetchone()
                if row is not None:
                    if row["request_digest"] != request_digest or row["operation"] != operation:
                        raise IdempotencyConflict(
                            f"command id {command_id!r} was reused with different content"
                        )
                    if row["status"] == "completed":
                        result = json.loads(row["result_json"] or "{}")
                        self.database.commit()
                        return CommandStart(True, result)
                    if row["status"] == "failed":
                        raise PreviousCommandFailed(row["error"] or "previous command failed")
                    if resume_after is not None and now_value >= (
                        _parse(row["updated_at"]) + resume_after
                    ):
                        cursor = self.database.execute(
                            """UPDATE browser_commands SET updated_at = ?
                               WHERE command_id = ? AND status = 'started'
                                 AND updated_at = ?""",
                            (now, command_id, row["updated_at"]),
                        )
                        if cursor.rowcount != 1:
                            raise CommandInDoubt(
                                f"command {command_id!r} recovery was claimed concurrently"
                            )
                        self.database.commit()
                        return CommandStart(
                            False, resume=True, attempt_token=now
                        )
                    raise CommandInDoubt(
                        f"command {command_id!r} started but has no durable completion receipt"
                    )
                self.database.execute(
                    """INSERT INTO browser_commands
                       (command_id, operation, request_digest, status, created_at, updated_at)
                       VALUES (?, ?, ?, 'started', ?, ?)""",
                    (command_id, operation, request_digest, now, now),
                )
                self.database.commit()
                return CommandStart(False, attempt_token=now)
            except Exception:
                self.database.rollback()
                raise

    def command_status(self, command_id: str) -> CommandStatus | None:
        if not isinstance(command_id, str) or not command_id or len(command_id) > 128:
            raise ValueError("command_id must be a non-empty string up to 128 characters")
        with self._lock:
            row = self.database.execute(
                "SELECT * FROM browser_commands WHERE command_id = ?", (command_id,)
            ).fetchone()
        if row is None:
            return None
        result = json.loads(row["result_json"]) if row["result_json"] is not None else None
        status = CommandStatus(
            command_id=row["command_id"],
            operation=row["operation"],
            request_digest=row["request_digest"],
            status=row["status"],
            result=result,
            error_present=row["error"] is not None,
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
        status.validate()
        return status

    def complete_command(
        self,
        command_id: str,
        result: dict[str, Any],
        *,
        attempt_token: str | None = None,
    ) -> None:
        with self._lock, self.database:
            self._complete_command_in_transaction(
                command_id,
                result,
                _utc(self.clock()),
                attempt_token=attempt_token,
            )

    def complete_command_with_event(
        self,
        command_id: str,
        result: dict[str, Any],
        *,
        session_id: str,
        owner_run_id: str,
        event_type: str,
        attributes: dict[str, Any] | None = None,
        attempt_token: str | None = None,
        required_lease: ControllerLease | None = None,
    ) -> None:
        """Atomically journal a post-worker acknowledgement and command receipt."""

        with self._lock:
            self.database.execute("BEGIN IMMEDIATE")
            try:
                now = _utc(self.clock())
                if required_lease is not None:
                    if required_lease.session_id != session_id:
                        raise ControllerConflict(
                            "required controller lease belongs to another session"
                        )
                    self._require_valid_lease(required_lease, self.clock())
                self._insert_event(
                    event_type,
                    session_id,
                    owner_run_id,
                    {"command_id": command_id, **(attributes or {})},
                )
                self._complete_command_in_transaction(
                    command_id, result, now, attempt_token=attempt_token
                )
                self.database.commit()
            except Exception:
                self.database.rollback()
                raise

    def fail_command(
        self,
        command_id: str,
        error: str,
        *,
        attempt_token: str | None = None,
    ) -> bool:
        with self._lock, self.database:
            query = (
                """UPDATE browser_commands
                   SET status = 'failed', error = ?, updated_at = ?
                   WHERE command_id = ? AND status = 'started'"""
            )
            parameters: tuple[Any, ...] = (
                error[:1000],
                _utc(self.clock()),
                command_id,
            )
            if attempt_token is not None:
                query += " AND updated_at = ?"
                parameters = (*parameters, attempt_token)
            cursor = self.database.execute(query, parameters)
            return cursor.rowcount == 1

    def _complete_command_in_transaction(
        self,
        command_id: str,
        result: dict[str, Any],
        updated_at: str,
        *,
        attempt_token: str | None = None,
    ) -> None:
        query = (
            """UPDATE browser_commands
               SET status = 'completed', result_json = ?, updated_at = ?
               WHERE command_id = ? AND status = 'started'"""
        )
        parameters: tuple[Any, ...] = (_json(result), updated_at, command_id)
        if attempt_token is not None:
            query += " AND updated_at = ?"
            parameters = (*parameters, attempt_token)
        cursor = self.database.execute(query, parameters)
        if cursor.rowcount != 1:
            current = self.database.execute(
                "SELECT status, updated_at FROM browser_commands WHERE command_id = ?",
                (command_id,),
            ).fetchone()
            if (
                attempt_token is not None
                and current is not None
                and current["status"] == "started"
                and current["updated_at"] != attempt_token
            ):
                raise CommandAttemptSuperseded(
                    f"command {command_id!r} attempt was superseded"
                )
            raise RuntimeError(f"command {command_id!r} is not pending completion")

    def append_event(
        self,
        event_type: str,
        *,
        session_id: str | None = None,
        owner_run_id: str | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> SessionEvent:
        with self._lock, self.database:
            sequence = self._insert_event(
                event_type,
                session_id,
                owner_run_id,
                attributes or {},
            )
        return self.events(after_sequence=sequence - 1)[0]

    def events(self, *, after_sequence: int = 0, limit: int = 1000) -> list[SessionEvent]:
        if limit < 1 or limit > 10_000:
            raise ValueError("event limit must be between 1 and 10000")
        with self._lock:
            rows = self.database.execute(
                """SELECT * FROM browser_events WHERE sequence > ?
                   ORDER BY sequence LIMIT ?""",
                (after_sequence, limit),
            ).fetchall()
        return [
            SessionEvent(
                sequence=int(row["sequence"]),
                occurred_at=row["occurred_at"],
                event_type=row["event_type"],
                session_id=row["session_id"],
                owner_run_id=row["owner_run_id"],
                attributes=json.loads(row["attributes_json"]),
            )
            for row in rows
        ]

    def reserve_action_execution(
        self,
        permit: ExecutionPermit,
        proposal: ActionProposal,
        *,
        request_digest: str,
        command_id: str,
        worker_id: str,
        worker_instance_id: str,
        required_lease: ControllerLease,
    ) -> ActionReservationStart:
        """Reserve one exact permit and pause the session before any browser effect."""

        from weir.actions import ActionProposal, ExecutionPermit

        if not isinstance(permit, ExecutionPermit):
            raise TypeError("permit must be an ExecutionPermit")
        if not isinstance(proposal, ActionProposal):
            raise TypeError("proposal must be an ActionProposal")
        permit.validate()
        proposal.validate()
        permit_bindings = {
            "proposal_hash": proposal.proposal_hash,
            "work_context_hash": proposal.work_context_hash,
            "owner_run_id": proposal.owner_run_id,
            "session_id": proposal.session_id,
            "session_epoch": proposal.session_epoch,
            "action_type": proposal.action_type,
            "risk": proposal.risk,
        }
        if any(
            getattr(permit, name) != expected
            for name, expected in permit_bindings.items()
        ):
            raise ControllerConflict(
                "execution permit does not match the action proposal"
            )
        if not is_sha256(request_digest):
            raise ValueError("action request_digest must be a sha256 digest")
        validate_identifier(command_id, "command_id")
        validate_identifier(worker_id, "worker_id")
        validate_identifier(worker_instance_id, "worker_instance_id")
        with self._lock:
            self.database.execute("BEGIN IMMEDIATE")
            try:
                existing = self.database.execute(
                    """SELECT * FROM action_execution_reservations
                       WHERE permit_id = ?""",
                    (permit.permit_id,),
                ).fetchone()
                expected = {
                    "permit_hash": permit.permit_hash,
                    "action_id": proposal.action_id,
                    "request_digest": request_digest,
                    "proposal_hash": proposal.proposal_hash,
                    "work_context_hash": proposal.work_context_hash,
                    "command_id": command_id,
                    "session_id": proposal.session_id,
                    "session_epoch": proposal.session_epoch,
                }
                if existing is not None:
                    if any(existing[key] != value for key, value in expected.items()):
                        raise IdempotencyConflict(
                            "execution permit is bound to a different action request"
                        )
                    reservation = _action_reservation_from_row(existing)
                    self.database.commit()
                    return ActionReservationStart(reservation, replay=True)

                conflicting = self.database.execute(
                    """SELECT 1 FROM action_execution_reservations
                       WHERE action_id = ? OR proposal_hash = ? OR command_id = ?
                       LIMIT 1""",
                    (proposal.action_id, proposal.proposal_hash, command_id),
                ).fetchone()
                if conflicting is not None:
                    raise IdempotencyConflict(
                        "action, proposal, or command is already reserved"
                    )

                now_value = self.clock()
                permit.validate_for(proposal, now_value)
                if parse_timestamp(proposal.expires_at, "expires_at") <= now_value:
                    raise ContractViolation(
                        "proposal_expired",
                        "action proposal expired before reservation",
                    )
                existing_receipt = self.database.execute(
                    "SELECT 1 FROM execution_receipts WHERE action_id = ?",
                    (proposal.action_id,),
                ).fetchone()
                if existing_receipt is not None:
                    raise IdempotencyConflict(
                        "action already has a terminal execution receipt"
                    )
                session = self._required_session_row(proposal.session_id)
                if SessionState(session["state"]) is not SessionState.ACTIVE:
                    raise ControllerConflict(
                        "action execution requires an active browser session"
                    )
                if int(session["epoch"]) != proposal.session_epoch:
                    raise SessionRevisionConflict(
                        "action proposal belongs to a stale browser-session epoch"
                    )
                if int(session["revision"]) != proposal.session_revision:
                    raise SessionRevisionConflict(
                        "action proposal belongs to a stale browser-session revision"
                    )
                context = self.work_context(proposal.session_id)
                if context.context_hash != proposal.work_context_hash:
                    raise ControllerConflict(
                        "action proposal belongs to a different work context"
                    )
                if required_lease.session_id != proposal.session_id:
                    raise ControllerConflict("action lease belongs to another session")
                current_lease = self._require_valid_lease(required_lease, now_value)
                if (
                    required_lease.kind is not ControllerKind.AUTOMATION
                    or required_lease.controller_id != proposal.owner_run_id
                ):
                    raise ControllerConflict(
                        "action execution requires the owning automation lease"
                    )
                profile = self._required_profile_reservation_row(proposal.session_id)
                if (
                    session["worker_id"] != worker_id
                    or profile["worker_id"] != worker_id
                    or profile["worker_instance_id"] != worker_instance_id
                    or profile["state"] != "active"
                ):
                    raise ControllerConflict(
                        "action worker does not hold the active credential reservation"
                    )
                death = self.database.execute(
                    """SELECT 1 FROM browser_worker_death_attestations
                       WHERE worker_id = ? AND worker_instance_id = ? LIMIT 1""",
                    (worker_id, worker_instance_id),
                ).fetchone()
                if death is not None:
                    raise ControllerConflict("a dead worker instance cannot reserve an action")
                reserved_lease = self._new_lease(
                    session,
                    required_lease.controller_id,
                    ControllerKind.AUTOMATION,
                    int(current_lease["generation"]) + 1,
                    _parse(current_lease["expires_at"]) - now_value,
                    now_value,
                )
                self._write_lease(reserved_lease, active=True, now=now_value)
                require_transition(SessionState.ACTIVE, SessionState.PAUSED)
                reserved_revision = proposal.session_revision + 1
                cursor = self.database.execute(
                    """UPDATE browser_sessions
                       SET state = 'paused', revision = ?, updated_at = ?
                       WHERE session_id = ? AND revision = ? AND state = 'active'""",
                    (
                        reserved_revision,
                        _utc(now_value),
                        proposal.session_id,
                        proposal.session_revision,
                    ),
                )
                if cursor.rowcount != 1:
                    raise SessionRevisionConflict(
                        "action session changed before exclusive reservation"
                    )
                now = _utc(now_value)
                reservation_ref = f"reservation-{uuid.uuid4().hex}"
                self.database.execute(
                    """INSERT INTO action_execution_reservations
                       (reservation_ref, permit_id, permit_hash, action_id,
                        request_digest, proposal_hash, work_context_hash, command_id,
                        session_id, session_epoch, controller_generation, status,
                        receipt_id, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'reserved', NULL, ?, ?)""",
                    (
                        reservation_ref,
                        permit.permit_id,
                        permit.permit_hash,
                        proposal.action_id,
                        request_digest,
                        proposal.proposal_hash,
                        proposal.work_context_hash,
                        command_id,
                        proposal.session_id,
                        proposal.session_epoch,
                        reserved_lease.generation,
                        now,
                        now,
                    ),
                )
                self._insert_event(
                    "web.action.execution.reserved",
                    proposal.session_id,
                    proposal.owner_run_id,
                    {
                        "reservation_ref": reservation_ref,
                        "permit_id": permit.permit_id,
                        "proposal_hash": proposal.proposal_hash,
                        "command_id": command_id,
                        "session_epoch": proposal.session_epoch,
                        "session_revision": reserved_revision,
                        "controller_generation": reserved_lease.generation,
                        "worker_id": worker_id,
                        "worker_instance_id": worker_instance_id,
                    },
                )
                row = self.database.execute(
                    """SELECT * FROM action_execution_reservations
                       WHERE reservation_ref = ?""",
                    (reservation_ref,),
                ).fetchone()
                self.database.commit()
            except sqlite3.IntegrityError as exc:
                self.database.rollback()
                raise IdempotencyConflict(
                    "permit, action, proposal, or command is already reserved"
                ) from exc
            except Exception:
                self.database.rollback()
                raise
        assert row is not None
        return ActionReservationStart(
            _action_reservation_from_row(row),
            replay=False,
            lease=reserved_lease,
        )

    def action_reservation(self, permit_id: str) -> ActionExecutionReservation | None:
        validate_identifier(permit_id, "permit_id")
        with self._lock:
            row = self.database.execute(
                """SELECT * FROM action_execution_reservations
                   WHERE permit_id = ?""",
                (permit_id,),
            ).fetchone()
        return None if row is None else _action_reservation_from_row(row)

    def action_reservation_by_command(
        self, command_id: str
    ) -> ActionExecutionReservation | None:
        """Load the exact Fade command binding without exposing action parameters."""

        validate_identifier(command_id, "command_id")
        with self._lock:
            row = self.database.execute(
                """SELECT * FROM action_execution_reservations
                   WHERE command_id = ?""",
                (command_id,),
            ).fetchone()
        return None if row is None else _action_reservation_from_row(row)

    def mark_action_dispatching(
        self,
        reservation_ref: str,
        *,
        before_capture_id: str,
        approval_ref: str,
        worker_id: str,
        worker_instance_id: str,
        permit: ExecutionPermit,
        proposal: ActionProposal,
        expected_session_revision: int,
        required_lease: ControllerLease,
    ) -> None:
        """Durably mark the point after which an effect cannot be disproved."""

        validate_identifier(reservation_ref, "reservation_ref")
        validate_identifier(before_capture_id, "before_capture_id")
        validate_identifier(approval_ref, "approval_ref")
        validate_identifier(worker_id, "worker_id")
        validate_identifier(worker_instance_id, "worker_instance_id")
        from weir.actions import ActionProposal, ExecutionPermit

        if not isinstance(permit, ExecutionPermit):
            raise TypeError("permit must be an ExecutionPermit")
        if not isinstance(proposal, ActionProposal):
            raise TypeError("proposal must be an ActionProposal")
        if (
            type(expected_session_revision) is not int
            or expected_session_revision < 0
        ):
            raise ValueError("expected_session_revision must be non-negative")
        if not isinstance(required_lease, ControllerLease):
            raise TypeError("required_lease must be a ControllerLease")
        with self._lock:
            self.database.execute("BEGIN IMMEDIATE")
            try:
                reservation = self.database.execute(
                    """SELECT * FROM action_execution_reservations
                       WHERE reservation_ref = ?""",
                    (reservation_ref,),
                ).fetchone()
                if reservation is None:
                    raise ControllerConflict(
                        "action dispatch has no durable execution reservation"
                    )
                existing_marker = self._action_dispatch_marker(reservation_ref)
                if existing_marker is not None:
                    if (
                        existing_marker.before_capture_id != before_capture_id
                        or existing_marker.approval_ref != approval_ref
                        or existing_marker.worker_id != worker_id
                        or existing_marker.worker_instance_id != worker_instance_id
                        or existing_marker.controller_generation
                        != required_lease.generation
                    ):
                        raise IdempotencyConflict(
                            "action reservation is already dispatching from different evidence"
                        )
                    self.database.commit()
                    return
                if reservation["status"] != "reserved":
                    raise IdempotencyConflict(
                        "action reservation became terminal before worker dispatch"
                    )
                if (
                    required_lease.session_id != reservation["session_id"]
                    or required_lease.generation
                    != reservation["controller_generation"]
                ):
                    raise ControllerConflict(
                        "action dispatch lease does not match its durable reservation"
                    )
                now_value = self.clock()
                permit.validate_for(proposal, now_value)
                if parse_timestamp(proposal.expires_at, "expires_at") <= now_value:
                    raise ContractViolation(
                        "proposal_expired",
                        "action proposal expired before dispatch",
                    )
                if (
                    reservation["permit_id"] != permit.permit_id
                    or reservation["permit_hash"] != permit.permit_hash
                    or reservation["action_id"] != proposal.action_id
                    or reservation["proposal_hash"] != proposal.proposal_hash
                    or reservation["work_context_hash"] != proposal.work_context_hash
                ):
                    raise ControllerConflict(
                        "action dispatch authority differs from its durable reservation"
                    )
                self._require_valid_lease(required_lease, now_value)
                context = self.work_context(reservation["session_id"])
                if (
                    required_lease.kind is not ControllerKind.AUTOMATION
                    or required_lease.controller_id != context.run_id
                ):
                    raise ControllerConflict(
                        "action dispatch requires the owning automation lease"
                    )
                session = self._required_session_row(reservation["session_id"])
                if (
                    SessionState(session["state"]) is not SessionState.PAUSED
                    or int(session["epoch"]) != reservation["session_epoch"]
                    or int(session["revision"]) != expected_session_revision
                ):
                    raise ControllerConflict(
                        "action dispatch pre-state is no longer the exclusive paused state"
                    )
                profile = self._required_profile_reservation_row(
                    reservation["session_id"]
                )
                if (
                    session["worker_id"] != worker_id
                    or profile["worker_id"] != worker_id
                    or profile["worker_instance_id"] != worker_instance_id
                    or profile["state"] != "active"
                ):
                    raise ControllerConflict(
                        "action dispatch worker does not hold the credential reservation"
                    )
                death = self.database.execute(
                    """SELECT 1 FROM browser_worker_death_attestations
                       WHERE worker_id = ? AND worker_instance_id = ? LIMIT 1""",
                    (worker_id, worker_instance_id),
                ).fetchone()
                if death is not None:
                    raise ControllerConflict("a dead worker instance cannot dispatch an action")
                receipt = self.database.execute(
                    "SELECT 1 FROM execution_receipts WHERE action_id = ?",
                    (reservation["action_id"],),
                ).fetchone()
                if receipt is not None:
                    raise IdempotencyConflict(
                        "action became terminal before worker dispatch"
                    )
                now = _utc(now_value)
                self._insert_event(
                    "web.action.execution.dispatching",
                    reservation["session_id"],
                    context.run_id,
                    {
                        "reservation_ref": reservation_ref,
                        "permit_id": reservation["permit_id"],
                        "command_id": reservation["command_id"],
                        "before_capture_id": before_capture_id,
                        "approval_ref": approval_ref,
                        "worker_id": worker_id,
                        "worker_instance_id": worker_instance_id,
                        "session_revision": expected_session_revision,
                        "controller_generation": required_lease.generation,
                    },
                )
                self.database.execute(
                    """UPDATE action_execution_reservations SET updated_at = ?
                       WHERE reservation_ref = ? AND status = 'reserved'""",
                    (now, reservation_ref),
                )
                self.database.commit()
            except Exception:
                self.database.rollback()
                raise

    def action_dispatch_capture(self, reservation_ref: str) -> str | None:
        marker = self.action_dispatch_marker(reservation_ref)
        return None if marker is None else marker.before_capture_id

    def action_dispatch_marker(
        self, reservation_ref: str
    ) -> ActionDispatchMarker | None:
        validate_identifier(reservation_ref, "reservation_ref")
        with self._lock:
            return self._action_dispatch_marker(reservation_ref)

    def finalize_action_execution(
        self,
        receipt: ExecutionReceipt,
        *,
        quarantine: QuarantineRecord | None = None,
    ) -> None:
        """Commit a terminal receipt and any unknown-outcome quarantine atomically."""

        from weir.actions import (
            ExecutionReceipt,
            QuarantineRecord,
            QuarantineState,
            ReceiptResult,
        )

        if not isinstance(receipt, ExecutionReceipt):
            raise TypeError("receipt must be an ExecutionReceipt")
        receipt.validate()
        if quarantine is not None:
            if not isinstance(quarantine, QuarantineRecord):
                raise TypeError("quarantine must be a QuarantineRecord or null")
            quarantine.validate()
        if receipt.result is ReceiptResult.OUTCOME_UNKNOWN:
            if quarantine is None or quarantine.state is not QuarantineState.ACTIVE:
                raise ValueError("outcome_unknown requires an active quarantine record")
            if (
                receipt.quarantine_ref
                != f"weir-quarantine:{quarantine.quarantine_id}"
                or quarantine.session_id != receipt.session_id
                or quarantine.session_epoch != receipt.session_epoch
                or quarantine.work_context_hash != receipt.work_context_hash
                or quarantine.permit_id != receipt.permit_id
                or quarantine.command_id != receipt.command_id
                or quarantine.receipt_id != receipt.receipt_id
            ):
                raise ValueError("receipt and quarantine bindings do not match")
        elif quarantine is not None:
            raise ValueError("only outcome_unknown may create a quarantine record")

        serialized_receipt = _json(receipt.to_dict())
        with self._lock:
            self.database.execute("BEGIN IMMEDIATE")
            try:
                reservation = self.database.execute(
                    """SELECT * FROM action_execution_reservations
                       WHERE reservation_ref = ?""",
                    (receipt.reservation_ref,),
                ).fetchone()
                if reservation is None:
                    raise ControllerConflict(
                        "execution receipt has no durable action reservation"
                    )
                expected = {
                    "permit_id": receipt.permit_id,
                    "proposal_hash": receipt.proposal_hash,
                    "work_context_hash": receipt.work_context_hash,
                    "command_id": receipt.command_id,
                    "session_id": receipt.session_id,
                    "session_epoch": receipt.session_epoch,
                    "controller_generation": receipt.lease_generation,
                }
                if any(reservation[key] != value for key, value in expected.items()):
                    raise ControllerConflict(
                        "execution receipt does not match its durable reservation"
                    )
                existing = self.database.execute(
                    """SELECT receipt_json FROM execution_receipts
                       WHERE action_id = ?""",
                    (receipt.action_id,),
                ).fetchone()
                if existing is not None:
                    if existing["receipt_json"] != serialized_receipt:
                        raise IdempotencyConflict(
                            "action already has a different execution receipt"
                        )
                    self.database.commit()
                    return
                if reservation["status"] != "reserved":
                    raise IdempotencyConflict(
                        "action reservation is already terminal without this receipt"
                    )
                session = self._required_session_row(receipt.session_id)
                current = SessionState(session["state"])
                lease_row = self._lease_row(receipt.session_id)
                if receipt.result is ReceiptResult.OUTCOME_UNKNOWN:
                    if current not in {SessionState.PAUSED, SessionState.LOST}:
                        raise ControllerConflict(
                            "unknown action outcome requires the exclusive or lost session"
                        )
                else:
                    if current is not SessionState.PAUSED:
                        raise ControllerConflict(
                            "definite action outcome requires the exclusive paused session"
                        )
                    if (
                        lease_row is None
                        or not lease_row["active"]
                        or int(lease_row["generation"])
                        != reservation["controller_generation"]
                        or lease_row["controller_kind"]
                        != ControllerKind.AUTOMATION.value
                        or lease_row["controller_id"] != session["owner_run_id"]
                    ):
                        raise ControllerConflict(
                            "definite action outcome lost its exclusive controller fence"
                        )
                    profile = self._required_profile_reservation_row(receipt.session_id)
                    if profile["state"] != "active":
                        raise ControllerConflict(
                            "definite action outcome lost its credential reservation"
                        )
                now_value = self.clock()
                now = _utc(now_value)
                self.database.execute(
                    """INSERT INTO execution_receipts
                       (action_id, proposal_hash, receipt_json, created_at)
                       VALUES (?, ?, ?, ?)""",
                    (
                        receipt.action_id,
                        receipt.proposal_hash,
                        serialized_receipt,
                        now,
                    ),
                )
                status = "completed"
                if receipt.result is ReceiptResult.OUTCOME_UNKNOWN:
                    assert quarantine is not None
                    self.database.execute(
                        """INSERT INTO action_quarantine_records
                           (record_hash, quarantine_id, state, supersedes_hash,
                            record_json, recorded_at)
                           VALUES (?, ?, 'active', NULL, ?, ?)""",
                        (
                            quarantine.record_hash,
                            quarantine.quarantine_id,
                            _json(quarantine.to_dict()),
                            quarantine.recorded_at,
                        ),
                    )
                    if current is SessionState.CLOSED:
                        raise ControllerConflict(
                            "a closed session cannot acquire an action quarantine"
                        )
                    if current is not SessionState.LOST:
                        require_transition(current, SessionState.LOST)
                        self.database.execute(
                            """UPDATE browser_sessions
                               SET state = 'lost', revision = revision + 1,
                                   updated_at = ? WHERE session_id = ?""",
                            (now, receipt.session_id),
                        )
                    self.database.execute(
                        """UPDATE controller_leases
                           SET active = 0, lease_id = NULL, controller_id = NULL,
                               controller_kind = NULL, fencing_token = NULL,
                               expires_at = NULL, updated_at = ?
                           WHERE session_id = ?""",
                        (now, receipt.session_id),
                    )
                    profile_reservation = self._required_profile_reservation_row(
                        receipt.session_id
                    )
                    if profile_reservation["state"] == "released":
                        raise ControllerConflict(
                            "an unknown outcome cannot quarantine a released credential"
                        )
                    self.database.execute(
                        """UPDATE browser_profile_reservations
                           SET state = 'quarantined', updated_at = ?
                           WHERE session_id = ? AND state = 'active'""",
                        (now, receipt.session_id),
                    )
                    status = "outcome_unknown"
                else:
                    require_transition(current, SessionState.ACTIVE)
                    cursor = self.database.execute(
                        """UPDATE browser_sessions
                           SET state = 'active', revision = revision + 1, updated_at = ?
                           WHERE session_id = ? AND state = 'paused'""",
                        (now, receipt.session_id),
                    )
                    if cursor.rowcount != 1:
                        raise SessionRevisionConflict(
                            "action session changed before terminal activation"
                        )
                self.database.execute(
                    """UPDATE action_execution_reservations
                       SET status = ?, receipt_id = ?, updated_at = ?
                       WHERE reservation_ref = ? AND status = 'reserved'""",
                    (
                        status,
                        receipt.receipt_id,
                        now,
                        receipt.reservation_ref,
                    ),
                )
                self._insert_event(
                    "web.action.execution.recorded",
                    receipt.session_id,
                    self.work_context(receipt.session_id).run_id,
                    {
                        "reservation_ref": receipt.reservation_ref,
                        "permit_id": receipt.permit_id,
                        "proposal_hash": receipt.proposal_hash,
                        "command_id": receipt.command_id,
                        "receipt_id": receipt.receipt_id,
                        "result": receipt.result.value,
                        "quarantine_ref": receipt.quarantine_ref,
                    },
                )
                self.database.commit()
            except Exception:
                self.database.rollback()
                raise

    def clear_action_quarantine(self, successor: QuarantineRecord) -> None:
        """Append an operator-authored successor; never rewrite the active record."""

        from weir.actions import QuarantineRecord, QuarantineState

        if not isinstance(successor, QuarantineRecord):
            raise TypeError("successor must be a QuarantineRecord")
        successor.validate()
        if successor.state is not QuarantineState.CLEARED:
            raise ValueError("quarantine successor must have state=cleared")
        with self._lock:
            self.database.execute("BEGIN IMMEDIATE")
            try:
                prior = self.database.execute(
                    """SELECT record_json FROM action_quarantine_records
                       WHERE record_hash = ? AND quarantine_id = ? AND state = 'active'""",
                    (successor.supersedes_hash, successor.quarantine_id),
                ).fetchone()
                if prior is None:
                    raise ControllerConflict(
                        "quarantine successor does not reference an active record"
                    )
                serialized = _json(successor.to_dict())
                prior_successor = self.database.execute(
                    """SELECT record_json FROM action_quarantine_records
                       WHERE supersedes_hash = ?""",
                    (successor.supersedes_hash,),
                ).fetchone()
                if prior_successor is not None:
                    if prior_successor["record_json"] != serialized:
                        raise IdempotencyConflict(
                            "active quarantine already has a different successor"
                        )
                    self.database.commit()
                    return
                existing = self.database.execute(
                    """SELECT record_json FROM action_quarantine_records
                       WHERE record_hash = ?""",
                    (successor.record_hash,),
                ).fetchone()
                if existing is not None:
                    if existing["record_json"] != serialized:
                        raise IdempotencyConflict(
                            "quarantine record hash has different content"
                        )
                    self.database.commit()
                    return
                self.database.execute(
                    """INSERT INTO action_quarantine_records
                       (record_hash, quarantine_id, state, supersedes_hash,
                        record_json, recorded_at)
                       VALUES (?, ?, 'cleared', ?, ?, ?)""",
                    (
                        successor.record_hash,
                        successor.quarantine_id,
                        successor.supersedes_hash,
                        serialized,
                        successor.recorded_at,
                    ),
                )
                self.database.commit()
            except Exception:
                self.database.rollback()
                raise

    def save_receipt(
        self,
        receipt: ExecutionReceipt,
    ) -> None:
        from weir.actions import ExecutionReceipt, ReceiptResult

        if not isinstance(receipt, ExecutionReceipt):
            raise TypeError("receipt must be an ExecutionReceipt")
        receipt.validate()
        if receipt.result is ReceiptResult.OUTCOME_UNKNOWN:
            raise ValueError(
                "outcome_unknown must use finalize_action_execution with quarantine"
            )
        action_id = receipt.action_id
        proposal_hash = receipt.proposal_hash
        serialized = _json(receipt.to_dict())
        with self._lock, self.database:
            existing = self.database.execute(
                "SELECT proposal_hash, receipt_json FROM execution_receipts WHERE action_id = ?",
                (action_id,),
            ).fetchone()
            if existing is not None:
                if (
                    existing["proposal_hash"] != proposal_hash
                    or existing["receipt_json"] != serialized
                ):
                    raise IdempotencyConflict(
                        f"action id {action_id!r} already has a different receipt"
                    )
                return
            reservation = self.database.execute(
                """SELECT 1 FROM action_execution_reservations
                   WHERE proposal_hash = ? LIMIT 1""",
                (proposal_hash,),
            ).fetchone()
            if reservation is not None:
                raise ValueError(
                    "permit-reserved actions must use finalize_action_execution"
                )
            self.database.execute(
                """INSERT INTO execution_receipts
                   (action_id, proposal_hash, receipt_json, created_at)
                   VALUES (?, ?, ?, ?)""",
                (action_id, proposal_hash, serialized, _utc(self.clock())),
            )

    def load_receipt(self, action_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self.database.execute(
                "SELECT receipt_json FROM execution_receipts WHERE action_id = ?",
                (action_id,),
            ).fetchone()
        return json.loads(row[0]) if row is not None else None

    def _action_dispatch_marker(
        self, reservation_ref: str
    ) -> ActionDispatchMarker | None:
        rows = self.database.execute(
            """SELECT attributes_json FROM browser_events
               WHERE event_type = 'web.action.execution.dispatching'
               ORDER BY sequence DESC"""
        ).fetchall()
        for row in rows:
            attributes = json.loads(row["attributes_json"])
            if attributes.get("reservation_ref") != reservation_ref:
                continue
            capture_id = attributes.get("before_capture_id")
            approval_ref = attributes.get("approval_ref")
            worker_id = attributes.get("worker_id")
            worker_instance_id = attributes.get("worker_instance_id")
            generation = attributes.get("controller_generation")
            if (
                not isinstance(capture_id, str)
                or not capture_id
                or not isinstance(approval_ref, str)
                or not approval_ref
                or not isinstance(worker_id, str)
                or not worker_id
                or not isinstance(worker_instance_id, str)
                or not worker_instance_id
                or type(generation) is not int
                or generation < 1
            ):
                raise ControllerConflict(
                    "action dispatch marker has invalid before-state evidence"
                )
            return ActionDispatchMarker(
                reservation_ref=reservation_ref,
                before_capture_id=capture_id,
                approval_ref=approval_ref,
                worker_id=worker_id,
                worker_instance_id=worker_instance_id,
                controller_generation=generation,
            )
        return None

    def _require_no_open_action(self, session_id: str, operation: str) -> None:
        row = self.database.execute(
            """SELECT reservation_ref FROM action_execution_reservations
               WHERE session_id = ? AND status = 'reserved' LIMIT 1""",
            (session_id,),
        ).fetchone()
        if row is not None:
            raise ControllerConflict(
                f"{operation} is denied while an action execution is nonterminal"
            )

    def _required_session_row(self, session_id: str) -> sqlite3.Row:
        row = self.database.execute(
            "SELECT * FROM browser_sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
        if row is None:
            raise SessionNotFound(session_id)
        return row

    def _required_profile_reservation_row(self, session_id: str) -> sqlite3.Row:
        row = self.database.execute(
            "SELECT * FROM browser_profile_reservations WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        if row is None:
            raise SessionNotFound(
                f"session {session_id!r} has no credential reservation"
            )
        return row

    def _cleanup_matches(
        self,
        session_id: str,
        *,
        command_id: str,
        worker_id: str,
        worker_instance_id: str,
    ) -> bool:
        rows = self.database.execute(
            """SELECT attributes_json FROM browser_events
               WHERE session_id = ?
                 AND event_type = 'web.browser.worker.cleanup.attested'
               ORDER BY sequence DESC""",
            (session_id,),
        ).fetchall()
        for row in rows:
            attributes = json.loads(row["attributes_json"])
            if attributes.get("command_id") != command_id:
                continue
            return bool(
                attributes.get("worker_id") == worker_id
                and attributes.get("worker_instance_id") == worker_instance_id
            )
        return False

    def _worker_context_sets(
        self, session_id: str
    ) -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
        rows = self.database.execute(
            """SELECT event_type, attributes_json FROM browser_events
               WHERE session_id = ? AND event_type IN (
                   'web.browser.worker.context.created',
                   'web.browser.worker.context.closed'
               )
               ORDER BY sequence""",
            (session_id,),
        ).fetchall()
        open_contexts: set[tuple[str, str]] = set()
        closed_contexts: set[tuple[str, str]] = set()
        for row in rows:
            attributes = json.loads(row["attributes_json"])
            instance_id = attributes.get("worker_instance_id")
            worker_session_id = attributes.get("worker_session_id")
            if not isinstance(instance_id, str) or not isinstance(
                worker_session_id, str
            ):
                continue
            identity = (instance_id, worker_session_id)
            if row["event_type"] == "web.browser.worker.context.created":
                open_contexts.add(identity)
                closed_contexts.discard(identity)
            else:
                open_contexts.discard(identity)
                closed_contexts.add(identity)
        return open_contexts, closed_contexts

    def _open_worker_contexts(self, session_id: str) -> set[tuple[str, str]]:
        return self._worker_context_sets(session_id)[0]

    def _closed_worker_contexts(self, session_id: str) -> set[tuple[str, str]]:
        return self._worker_context_sets(session_id)[1]

    def _worker_context_is_activation_eligible(
        self,
        session_id: str,
        *,
        worker_instance_id: str,
        worker_session_id: str,
    ) -> bool:
        rows = self.database.execute(
            """SELECT attributes_json FROM browser_events
               WHERE session_id = ?
                 AND event_type = 'web.browser.worker.context.created'
               ORDER BY sequence DESC""",
            (session_id,),
        ).fetchall()
        for row in rows:
            attributes = json.loads(row["attributes_json"])
            if (
                attributes.get("worker_instance_id") == worker_instance_id
                and attributes.get("worker_session_id") == worker_session_id
            ):
                return bool(
                    isinstance(attributes.get("command_id"), str)
                    and attributes["command_id"]
                    and isinstance(attributes.get("attempt_token"), str)
                    and attributes["attempt_token"]
                )
        return False

    def _unresolved_worker_open_reservations(
        self, session_id: str
    ) -> set[tuple[str, str]]:
        rows = self.database.execute(
            """SELECT event_type, attributes_json FROM browser_events
               WHERE session_id = ? AND event_type IN (
                   'web.browser.worker.open.reserved',
                   'web.browser.worker.context.created',
                   'web.browser.worker.open.retired'
               )
               ORDER BY sequence""",
            (session_id,),
        ).fetchall()
        unresolved: set[tuple[str, str]] = set()
        for row in rows:
            attributes = json.loads(row["attributes_json"])
            instance_id = attributes.get("worker_instance_id")
            if not isinstance(instance_id, str) or not instance_id:
                continue
            if row["event_type"] == "web.browser.worker.open.reserved":
                command_id = attributes.get("command_id")
                if isinstance(command_id, str) and command_id:
                    unresolved.add((command_id, instance_id))
            elif row["event_type"] == "web.browser.worker.context.created":
                command_id = attributes.get("command_id")
                if isinstance(command_id, str) and command_id:
                    unresolved.discard((command_id, instance_id))
            else:
                command_id = attributes.get("reserved_command_id")
                if isinstance(command_id, str) and command_id:
                    unresolved.discard((command_id, instance_id))
        return unresolved

    def _worker_open_reservation(
        self, command_id: str
    ) -> tuple[str, str, str] | None:
        rows = self.database.execute(
            """SELECT session_id, attributes_json FROM browser_events
               WHERE event_type = 'web.browser.worker.open.reserved'
               ORDER BY sequence DESC"""
        ).fetchall()
        for row in rows:
            attributes = json.loads(row["attributes_json"])
            if attributes.get("command_id") != command_id:
                continue
            instance_id = attributes.get("worker_instance_id")
            attempt_token = attributes.get("attempt_token")
            if isinstance(instance_id, str) and isinstance(attempt_token, str):
                return row["session_id"], instance_id, attempt_token
        return None

    def _reserved_command_fence(
        self, session_id: str, command_id: str
    ) -> tuple[int, int] | None:
        return self._reservation_fence(
            session_id,
            command_id,
            event_type="web.browser.command.reserved",
        )

    def _reservation_fence(
        self,
        session_id: str,
        command_id: str,
        *,
        event_type: str,
    ) -> tuple[int, int] | None:
        rows = self.database.execute(
            """SELECT attributes_json FROM browser_events
               WHERE session_id = ? AND event_type = ?
               ORDER BY sequence DESC""",
            (session_id, event_type),
        ).fetchall()
        for row in rows:
            attributes = json.loads(row["attributes_json"])
            if attributes.get("command_id") != command_id:
                continue
            revision = attributes.get("revision")
            generation = attributes.get("controller_generation")
            if (
                isinstance(revision, int)
                and not isinstance(revision, bool)
                and isinstance(generation, int)
                and not isinstance(generation, bool)
            ):
                return revision, generation
        return None

    def _controller_transfer_matches(
        self,
        session_id: str,
        command_id: str,
        *,
        revision: int,
        from_controller_id: str | None,
        from_controller_kind: ControllerKind,
        from_generation: int | None,
        to_controller_id: str,
        to_controller_kind: ControllerKind,
        to_generation: int,
        authorization_ref: str,
    ) -> bool:
        rows = self.database.execute(
            """SELECT attributes_json FROM browser_events
               WHERE session_id = ? AND event_type = 'web.controller.transferred'
               ORDER BY sequence DESC""",
            (session_id,),
        ).fetchall()
        for row in rows:
            attributes = json.loads(row["attributes_json"])
            if attributes.get("command_id") != command_id:
                continue
            if (
                attributes.get("revision") != revision
                or attributes.get("from_controller_kind")
                != from_controller_kind.value
                or attributes.get("to_controller_id") != to_controller_id
                or attributes.get("controller_kind") != to_controller_kind.value
                or attributes.get("generation") != to_generation
                or attributes.get("authorization_ref") != authorization_ref
            ):
                continue
            if (
                from_controller_id is not None
                and attributes.get("from_controller_id") != from_controller_id
            ):
                continue
            if (
                from_generation is not None
                and attributes.get("from_generation") != from_generation
            ):
                continue
            return True
        return False

    def _require_current_command_attempt(
        self, command_id: str, attempt_token: str
    ) -> None:
        row = self.database.execute(
            """SELECT status, updated_at FROM browser_commands
               WHERE command_id = ?""",
            (command_id,),
        ).fetchone()
        if (
            row is None
            or row["status"] != "started"
            or row["updated_at"] != attempt_token
        ):
            raise CommandAttemptSuperseded(
                f"command {command_id!r} attempt is no longer current"
            )

    def _lease_row(self, session_id: str) -> sqlite3.Row | None:
        return self.database.execute(
            "SELECT * FROM controller_leases WHERE session_id = ?", (session_id,)
        ).fetchone()

    def _new_lease(
        self,
        session: sqlite3.Row,
        controller_id: str,
        kind: ControllerKind,
        generation: int,
        ttl: timedelta,
        now: datetime,
    ) -> ControllerLease:
        if not controller_id:
            raise ValueError("controller_id cannot be empty")
        expires_at = min(now + ttl, _parse(session["expires_at"]))
        if expires_at <= now:
            raise ControllerConflict("browser session has expired")
        return ControllerLease(
            session_id=session["session_id"],
            lease_id=f"lease-{uuid.uuid4().hex}",
            controller_id=controller_id,
            kind=kind,
            fencing_token=secrets.token_hex(24),
            generation=generation,
            expires_at=_utc(expires_at),
        )

    def _write_lease(self, lease: ControllerLease, *, active: bool, now: datetime) -> None:
        self.database.execute(
            """INSERT INTO controller_leases
               (session_id, active, lease_id, controller_id, controller_kind,
                fencing_token, generation, expires_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(session_id) DO UPDATE SET
                 active=excluded.active,
                 lease_id=excluded.lease_id,
                 controller_id=excluded.controller_id,
                 controller_kind=excluded.controller_kind,
                 fencing_token=excluded.fencing_token,
                 generation=excluded.generation,
                 expires_at=excluded.expires_at,
                 updated_at=excluded.updated_at""",
            (
                lease.session_id,
                int(active),
                lease.lease_id,
                lease.controller_id,
                lease.kind.value,
                lease.fencing_token,
                lease.generation,
                lease.expires_at,
                _utc(now),
            ),
        )

    def _require_valid_lease(
        self,
        lease: ControllerLease,
        now: datetime,
        *,
        allow_expired: bool = False,
    ) -> sqlite3.Row:
        row = self._lease_row(lease.session_id)
        if (
            row is None
            or not row["active"]
            or row["lease_id"] != lease.lease_id
            or row["controller_id"] != lease.controller_id
            or row["fencing_token"] != lease.fencing_token
            or int(row["generation"]) != lease.generation
            or (not allow_expired and now >= _parse(row["expires_at"]))
        ):
            raise ControllerConflict("controller lease is stale, expired, or no longer active")
        return row

    def _lease_from_row(self, row: sqlite3.Row | None) -> ControllerLease | None:
        if (
            row is None
            or not row["active"]
            or self.clock() >= _parse(row["expires_at"])
        ):
            return None
        return ControllerLease(
            session_id=row["session_id"],
            lease_id=row["lease_id"],
            controller_id=row["controller_id"],
            kind=ControllerKind(row["controller_kind"]),
            fencing_token=row["fencing_token"],
            generation=int(row["generation"]),
            expires_at=row["expires_at"],
        )

    def _session_from_row(
        self, row: sqlite3.Row, lease: ControllerLease | None
    ) -> BrowserSession:
        return BrowserSession(
            session_id=row["session_id"],
            owner_run_id=row["owner_run_id"],
            engine=row["engine"],
            worker_id=row["worker_id"],
            worker_session_id=row["worker_session_id"],
            profile_id=row["profile_id"],
            data_class=DataClass(row["data_class"]),
            allowed_domains=list(json.loads(row["allowed_domains_json"])),
            state=SessionState(row["state"]),
            revision=int(row["revision"]),
            epoch=int(row["epoch"]),
            current_url=row["current_url"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            expires_at=row["expires_at"],
            controller_lease=lease.public_view() if lease is not None else None,
        )

    def _insert_event(
        self,
        event_type: str,
        session_id: str | None,
        owner_run_id: str | None,
        attributes: dict[str, Any],
    ) -> int:
        cursor = self.database.execute(
            """INSERT INTO browser_events
               (occurred_at, event_type, session_id, owner_run_id, attributes_json)
               VALUES (?, ?, ?, ?, ?)""",
            (
                _utc(self.clock()),
                event_type,
                session_id,
                owner_run_id,
                _json(attributes),
            ),
        )
        return int(cursor.lastrowid)


def _json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _utc(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("browser-store timestamps must include a timezone")
    return value.astimezone(timezone.utc).isoformat()


def _parse(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("stored timestamp has no timezone")
    return parsed.astimezone(timezone.utc)


def _profile_reservation_from_row(row: sqlite3.Row) -> ProfileReservation:
    return ProfileReservation(
        reservation_id=row["reservation_id"],
        credential_binding_id=row["credential_binding_id"],
        session_id=row["session_id"],
        worker_id=row["worker_id"],
        worker_instance_id=row["worker_instance_id"],
        state=row["state"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        release_kind=row["release_kind"],
        release_actor_id=row["release_actor_id"],
        release_ref=row["release_ref"],
    )


def _action_reservation_from_row(row: sqlite3.Row) -> ActionExecutionReservation:
    return ActionExecutionReservation(
        reservation_ref=row["reservation_ref"],
        permit_id=row["permit_id"],
        permit_hash=row["permit_hash"],
        action_id=row["action_id"],
        request_digest=row["request_digest"],
        proposal_hash=row["proposal_hash"],
        work_context_hash=row["work_context_hash"],
        command_id=row["command_id"],
        session_id=row["session_id"],
        session_epoch=int(row["session_epoch"]),
        controller_generation=int(row["controller_generation"]),
        status=row["status"],
        receipt_id=row["receipt_id"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )
