from __future__ import annotations

import argparse
import json
import sqlite3
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Mapping

from weir.browser.store import STORE_SCHEMA_VERSION
from weir.contract import validate_identifier

V1_SCHEMA_VERSION = 1
MIGRATION_BINDINGS_VERSION = "0.1"
_V1_TABLES = frozenset(
    {
        "browser_sessions",
        "controller_leases",
        "browser_work_contexts",
        "browser_commands",
        "browser_events",
        "execution_receipts",
    }
)
_V2_TABLES = _V1_TABLES | frozenset(
    {
        "browser_profile_reservations",
        "browser_worker_death_attestations",
        "browser_profile_retirements",
        "action_execution_reservations",
        "action_quarantine_records",
    }
)

_V2_ADDITION_STATEMENTS = (
    """CREATE TABLE browser_profile_reservations (
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
       )""",
    """CREATE UNIQUE INDEX one_reserved_credential_binding
           ON browser_profile_reservations(credential_binding_id)
           WHERE state IN ('active', 'quarantined')""",
    """CREATE TABLE browser_worker_death_attestations (
           attestation_hash TEXT PRIMARY KEY,
           worker_id TEXT NOT NULL,
           worker_instance_id TEXT NOT NULL,
           observed_at TEXT NOT NULL,
           attestation_json TEXT NOT NULL,
           recorded_at TEXT NOT NULL
       )""",
    """CREATE TABLE browser_profile_retirements (
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
       )""",
    """CREATE TABLE action_execution_reservations (
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
           status TEXT NOT NULL CHECK(status IN ('reserved', 'completed', 'outcome_unknown')),
           receipt_id TEXT,
           created_at TEXT NOT NULL,
           updated_at TEXT NOT NULL
       )""",
    """CREATE TABLE action_quarantine_records (
           record_hash TEXT PRIMARY KEY,
           quarantine_id TEXT NOT NULL,
           state TEXT NOT NULL CHECK(state IN ('active', 'cleared')),
           supersedes_hash TEXT,
           record_json TEXT NOT NULL,
           recorded_at TEXT NOT NULL
       )""",
    """CREATE UNIQUE INDEX one_active_action_quarantine
           ON action_quarantine_records(quarantine_id)
           WHERE state = 'active'""",
    """CREATE UNIQUE INDEX one_action_quarantine_successor
           ON action_quarantine_records(supersedes_hash)
           WHERE supersedes_hash IS NOT NULL""",
)


@dataclass(frozen=True, slots=True)
class MigrationBinding:
    credential_binding_id: str
    worker_instance_id: str

    def validate(self) -> None:
        validate_identifier(self.credential_binding_id, "credential_binding_id")
        validate_identifier(self.worker_instance_id, "worker_instance_id")


@dataclass(frozen=True, slots=True)
class MigrationReport:
    database: str
    from_version: int
    to_version: int
    nonclosed_sessions: int
    migrated_reservations: int
    mode: str
    dry_run: bool
    backup: str | None


def load_migration_bindings(path: str | Path) -> dict[str, MigrationBinding]:
    source = Path(path)
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("migration binding file is unreadable or invalid JSON") from exc
    if not isinstance(value, dict) or set(value) != {"contract_version", "sessions"}:
        raise ValueError("migration binding file has missing or unknown fields")
    if value["contract_version"] != MIGRATION_BINDINGS_VERSION:
        raise ValueError("unsupported migration binding contract version")
    sessions = value["sessions"]
    if not isinstance(sessions, dict):
        raise ValueError("migration binding sessions must be an object")
    result: dict[str, MigrationBinding] = {}
    for session_id, item in sessions.items():
        validate_identifier(session_id, "session_id")
        if not isinstance(item, dict) or set(item) != {
            "credential_binding_id",
            "worker_instance_id",
        }:
            raise ValueError("migration session binding has missing or unknown fields")
        binding = MigrationBinding(
            credential_binding_id=item["credential_binding_id"],
            worker_instance_id=item["worker_instance_id"],
        )
        binding.validate()
        result[session_id] = binding
    return result


def migrate_v1_to_v2(
    database: str | Path,
    bindings: Mapping[str, MigrationBinding],
    *,
    backup: str | Path | None = None,
    dry_run: bool = False,
) -> MigrationReport:
    """Validate or migrate one stopped v1 store; never auto-runs at startup."""

    database_path = Path(database).resolve(strict=True)
    if not database_path.is_file():
        raise ValueError("browser store path must be a regular file")
    normalized = dict(bindings)
    for session_id, binding in normalized.items():
        validate_identifier(session_id, "session_id")
        if not isinstance(binding, MigrationBinding):
            raise TypeError("migration bindings must contain MigrationBinding values")
        binding.validate()

    backup_path: Path | None = None
    if not dry_run:
        if backup is None:
            raise ValueError("an explicit backup path is required for migration")
        backup_path = Path(backup).resolve()
        if backup_path == database_path:
            raise ValueError("backup path must differ from the browser store")
        if backup_path.exists():
            raise FileExistsError("migration backup path already exists")
        backup_path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(str(database_path), timeout=0)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        _require_v1_store(connection)
        rows = _nonclosed_session_rows(connection)
        _validate_bindings(rows, normalized)
        if dry_run:
            return MigrationReport(
                database=str(database_path),
                from_version=V1_SCHEMA_VERSION,
                to_version=STORE_SCHEMA_VERSION,
                nonclosed_sessions=len(rows),
                migrated_reservations=len(rows),
                mode="dry_run",
                dry_run=True,
                backup=None,
            )

        assert backup_path is not None
        source_data_version = int(
            connection.execute("PRAGMA data_version").fetchone()[0]
        )
        backup_connection = sqlite3.connect(str(backup_path))
        try:
            connection.backup(backup_connection)
        finally:
            backup_connection.close()
        backup_check = sqlite3.connect(str(backup_path))
        try:
            _require_v1_store(backup_check)
        finally:
            backup_check.close()

        connection.execute("BEGIN EXCLUSIVE")
        try:
            _require_v1_store(connection)
            if int(connection.execute("PRAGMA data_version").fetchone()[0]) != (
                source_data_version
            ):
                raise RuntimeError(
                    "browser store changed while its migration backup was created"
                )
            rows = _nonclosed_session_rows(connection)
            _validate_bindings(rows, normalized)
            for statement in _V2_ADDITION_STATEMENTS:
                connection.execute(statement)
            for row in rows:
                binding = normalized[row["session_id"]]
                connection.execute(
                    """INSERT INTO browser_profile_reservations
                       (reservation_id, credential_binding_id, session_id, worker_id,
                        worker_instance_id, state, created_at, updated_at,
                        release_kind, release_actor_id, release_ref)
                       VALUES (?, ?, ?, ?, ?, 'quarantined', ?, ?, NULL, NULL, NULL)""",
                    (
                        f"migrated-profile-reservation-{row['session_id']}",
                        binding.credential_binding_id,
                        row["session_id"],
                        row["worker_id"],
                        binding.worker_instance_id,
                        row["created_at"],
                        row["updated_at"],
                    ),
                )
            connection.execute(f"PRAGMA user_version = {STORE_SCHEMA_VERSION}")
            _require_integrity(connection)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
    finally:
        connection.close()

    return MigrationReport(
        database=str(database_path),
        from_version=V1_SCHEMA_VERSION,
        to_version=STORE_SCHEMA_VERSION,
        nonclosed_sessions=len(rows),
        migrated_reservations=len(rows),
        mode="migrate",
        dry_run=False,
        backup=str(backup_path),
    )


def read_v2_migration(
    database: str | Path,
    bindings: Mapping[str, MigrationBinding],
    *,
    backup: str | Path,
) -> MigrationReport:
    """Read back a completed migration without changing either database."""

    database_path = Path(database).resolve(strict=True)
    backup_path = Path(backup).resolve(strict=True)
    if not database_path.is_file() or not backup_path.is_file():
        raise ValueError("migration database and backup must be regular files")
    normalized = dict(bindings)
    for session_id, binding in normalized.items():
        validate_identifier(session_id, "session_id")
        if not isinstance(binding, MigrationBinding):
            raise TypeError("migration bindings must contain MigrationBinding values")
        binding.validate()

    current = sqlite3.connect(str(database_path), timeout=0)
    original = sqlite3.connect(str(backup_path), timeout=0)
    current.row_factory = sqlite3.Row
    original.row_factory = sqlite3.Row
    try:
        _require_v2_store(current)
        _require_v1_store(original)
        for table in sorted(_V1_TABLES):
            if _table_rows(current, table) != _table_rows(original, table):
                raise ValueError(
                    f"v2 readback found changed v1 table content: {table}"
                )
        rows = current.execute(
            """SELECT reservation_id, credential_binding_id, session_id,
                      worker_instance_id, state
               FROM browser_profile_reservations
               WHERE reservation_id LIKE 'migrated-profile-reservation-%'
               ORDER BY session_id"""
        ).fetchall()
        if {row["session_id"] for row in rows} != set(normalized):
            raise ValueError(
                "v2 readback reservations do not match the migration binding set"
            )
        for row in rows:
            binding = normalized[row["session_id"]]
            if (
                row["credential_binding_id"] != binding.credential_binding_id
                or row["worker_instance_id"] != binding.worker_instance_id
                or row["state"] != "quarantined"
            ):
                raise ValueError(
                    "v2 readback found a changed migrated credential reservation"
                )
    finally:
        current.close()
        original.close()

    return MigrationReport(
        database=str(database_path),
        from_version=V1_SCHEMA_VERSION,
        to_version=STORE_SCHEMA_VERSION,
        nonclosed_sessions=len(normalized),
        migrated_reservations=len(normalized),
        mode="readback",
        dry_run=False,
        backup=str(backup_path),
    )


def _nonclosed_session_rows(connection: sqlite3.Connection) -> list[sqlite3.Row]:
    return connection.execute(
        """SELECT session_id, worker_id, state, created_at, updated_at
           FROM browser_sessions WHERE state != 'closed'
           ORDER BY session_id"""
    ).fetchall()


def _validate_bindings(
    rows: list[sqlite3.Row], bindings: Mapping[str, MigrationBinding]
) -> None:
    expected_sessions = {row["session_id"] for row in rows}
    if set(bindings) != expected_sessions:
        missing = sorted(expected_sessions - set(bindings))
        extra = sorted(set(bindings) - expected_sessions)
        raise ValueError(
            "migration bindings must exactly cover non-closed sessions; "
            f"missing={missing!r} extra={extra!r}"
        )
    binding_ids = [item.credential_binding_id for item in bindings.values()]
    if len(set(binding_ids)) != len(binding_ids):
        raise ValueError(
            "non-closed sessions cannot share one credential binding during migration"
        )


def _require_v1_store(connection: sqlite3.Connection) -> None:
    version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    if version != V1_SCHEMA_VERSION:
        raise ValueError(
            f"offline migration requires schema {V1_SCHEMA_VERSION}, found {version}"
        )
    _require_integrity(connection)
    tables = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    }
    missing = sorted(_V1_TABLES - tables)
    if missing:
        raise ValueError(f"browser store is missing v1 tables: {missing!r}")


def _require_v2_store(connection: sqlite3.Connection) -> None:
    version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    if version != STORE_SCHEMA_VERSION:
        raise ValueError(
            f"migration readback requires schema {STORE_SCHEMA_VERSION}, found {version}"
        )
    _require_integrity(connection)
    tables = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    }
    missing = sorted(_V2_TABLES - tables)
    if missing:
        raise ValueError(f"browser store is missing v2 tables: {missing!r}")


def _table_rows(connection: sqlite3.Connection, table: str) -> tuple[tuple, ...]:
    if table not in _V1_TABLES:  # pragma: no cover - internal misuse guard
        raise ValueError("readback table is not part of the v1 contract")
    return tuple(
        tuple(row)
        for row in connection.execute(
            f'SELECT * FROM "{table}" ORDER BY rowid'
        ).fetchall()
    )


def _require_integrity(connection: sqlite3.Connection) -> None:
    result = connection.execute("PRAGMA integrity_check").fetchone()
    if result is None or result[0] != "ok":
        raise ValueError("browser store failed SQLite integrity_check")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Offline WEIR browser-store v1-to-v2 migration"
    )
    parser.add_argument("--database", required=True)
    parser.add_argument("--bindings", required=True)
    parser.add_argument("--backup")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--readback", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        bindings = load_migration_bindings(args.bindings)
        if args.readback:
            if args.backup is None:
                raise ValueError("migration readback requires --backup")
            report = read_v2_migration(
                args.database,
                bindings,
                backup=args.backup,
            )
        else:
            report = migrate_v1_to_v2(
                args.database,
                bindings,
                backup=args.backup,
                dry_run=args.dry_run,
            )
    except (OSError, sqlite3.Error, RuntimeError, TypeError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 2
    print(json.dumps({"ok": True, **asdict(report)}, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    raise SystemExit(main())


__all__ = [
    "MIGRATION_BINDINGS_VERSION",
    "MigrationBinding",
    "MigrationReport",
    "load_migration_bindings",
    "main",
    "migrate_v1_to_v2",
    "read_v2_migration",
]
