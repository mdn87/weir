import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import weir.browser.store_migration as migration_module
from weir.browser.store import STORE_SCHEMA_VERSION, SQLiteSessionStore
from weir.browser.store_migration import (
    MigrationBinding,
    load_migration_bindings,
    migrate_v1_to_v2,
    read_v2_migration,
)

_V1_SCHEMA = """
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
    ON browser_sessions(worker_id, profile_id) WHERE state != 'closed';
CREATE TABLE controller_leases (
    session_id TEXT PRIMARY KEY REFERENCES browser_sessions(session_id),
    active INTEGER NOT NULL, lease_id TEXT, controller_id TEXT,
    controller_kind TEXT, fencing_token TEXT, generation INTEGER NOT NULL,
    expires_at TEXT, updated_at TEXT NOT NULL
);
CREATE TABLE browser_work_contexts (
    session_id TEXT PRIMARY KEY REFERENCES browser_sessions(session_id),
    context_hash TEXT NOT NULL, context_json TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE browser_commands (
    command_id TEXT PRIMARY KEY, operation TEXT NOT NULL,
    request_digest TEXT NOT NULL, status TEXT NOT NULL, result_json TEXT,
    error TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE browser_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT, occurred_at TEXT NOT NULL,
    event_type TEXT NOT NULL, session_id TEXT, owner_run_id TEXT,
    attributes_json TEXT NOT NULL
);
CREATE TABLE execution_receipts (
    action_id TEXT PRIMARY KEY, proposal_hash TEXT NOT NULL,
    receipt_json TEXT NOT NULL, created_at TEXT NOT NULL
);
PRAGMA user_version = 1;
"""


def _create_v1(path: Path, *, sessions: tuple[str, ...] = ("session-1",)) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.executescript(_V1_SCHEMA)
        for session_id in sessions:
            connection.execute(
                """INSERT INTO browser_sessions
                   (session_id, owner_run_id, engine, worker_id, worker_session_id,
                    profile_id, data_class, allowed_domains_json, state, revision,
                    epoch, current_url, created_at, updated_at, expires_at)
                   VALUES (?, 'run-1', 'playwright-observer', ?, 'pending', ?,
                           'bwa_internal', '["app.example.test"]', 'lost', 1, 1,
                           NULL, '2026-08-28T00:00:00+00:00',
                           '2026-08-28T00:01:00+00:00',
                           '2026-08-28T01:00:00+00:00')""",
                (session_id, f"worker-{session_id}", f"profile-{session_id}"),
            )
        connection.execute(
            """INSERT INTO execution_receipts
               (action_id, proposal_hash, receipt_json, created_at)
               VALUES ('action-existing', 'sha256:existing', '{"receipt":true}',
                       '2026-08-28T00:02:00+00:00')"""
        )
        connection.commit()
    finally:
        connection.close()


class BrowserStoreMigrationTests(unittest.TestCase):
    def test_fresh_database_is_created_directly_at_v2(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "fresh.sqlite3"
            with SQLiteSessionStore(path) as store:
                version = int(store.database.execute("PRAGMA user_version").fetchone()[0])
                tables = {
                    row[0]
                    for row in store.database.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
            self.assertEqual(version, STORE_SCHEMA_VERSION)
            self.assertIn("browser_profile_reservations", tables)
            self.assertIn("action_execution_reservations", tables)

    def test_store_refuses_v1_and_unknown_versions(self):
        with tempfile.TemporaryDirectory() as temp:
            v1 = Path(temp) / "v1.sqlite3"
            _create_v1(v1)
            with self.assertRaisesRegex(RuntimeError, "offline v1-to-v2 migration"):
                SQLiteSessionStore(v1)

            unknown = Path(temp) / "unknown.sqlite3"
            connection = sqlite3.connect(unknown)
            try:
                connection.execute("PRAGMA user_version = 99")
                connection.commit()
            finally:
                connection.close()
            with self.assertRaisesRegex(RuntimeError, "unsupported"):
                SQLiteSessionStore(unknown)

    def test_dry_run_requires_exact_nonclosed_mapping_without_writing(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "v1.sqlite3"
            _create_v1(path)
            with self.assertRaisesRegex(ValueError, "exactly cover"):
                migrate_v1_to_v2(path, {}, dry_run=True)
            report = migrate_v1_to_v2(
                path,
                {
                    "session-1": MigrationBinding(
                        "credential-binding-1", "worker-instance-1"
                    )
                },
                dry_run=True,
            )
            self.assertTrue(report.dry_run)
            self.assertEqual(report.mode, "dry_run")
            connection = sqlite3.connect(path)
            try:
                self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)
            finally:
                connection.close()

    def test_migration_preserves_v1_backup_and_quarantines_reservation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "v1.sqlite3"
            backup = root / "v1.backup.sqlite3"
            _create_v1(path)
            report = migrate_v1_to_v2(
                path,
                {
                    "session-1": MigrationBinding(
                        "credential-binding-1", "worker-instance-1"
                    )
                },
                backup=backup,
            )
            self.assertFalse(report.dry_run)
            self.assertEqual(report.mode, "migrate")
            self.assertEqual(report.migrated_reservations, 1)
            connection = sqlite3.connect(backup)
            try:
                self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)
            finally:
                connection.close()
            with SQLiteSessionStore(path) as store:
                reservation = store.profile_reservation("session-1")
                self.assertEqual(reservation.state, "quarantined")
                self.assertEqual(
                    reservation.credential_binding_id, "credential-binding-1"
                )
            first = read_v2_migration(
                path,
                {
                    "session-1": MigrationBinding(
                        "credential-binding-1", "worker-instance-1"
                    )
                },
                backup=backup,
            )
            second = read_v2_migration(
                path,
                {
                    "session-1": MigrationBinding(
                        "credential-binding-1", "worker-instance-1"
                    )
                },
                backup=backup,
            )
            self.assertEqual(first, second)
            self.assertEqual(first.mode, "readback")

    def test_migration_rejects_duplicate_active_credential_bindings(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "v1.sqlite3"
            _create_v1(path, sessions=("session-1", "session-2"))
            bindings = {
                session_id: MigrationBinding("same-binding", f"instance-{session_id}")
                for session_id in ("session-1", "session-2")
            }
            with self.assertRaisesRegex(ValueError, "cannot share"):
                migrate_v1_to_v2(path, bindings, dry_run=True)

    def test_binding_file_is_strict(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bindings.json"
            path.write_text(
                json.dumps(
                    {
                        "contract_version": "0.1",
                        "sessions": {
                            "session-1": {
                                "credential_binding_id": "credential-binding-1",
                                "worker_instance_id": "worker-instance-1",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            bindings = load_migration_bindings(path)
            self.assertEqual(
                bindings["session-1"].credential_binding_id,
                "credential-binding-1",
            )

    def test_failed_schema_transaction_leaves_v1_store_unchanged(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "v1.sqlite3"
            backup = root / "v1.backup.sqlite3"
            _create_v1(path)
            statements = migration_module._V2_ADDITION_STATEMENTS + (
                "CREATE TABLE invalid SQL",
            )
            with mock.patch.object(
                migration_module,
                "_V2_ADDITION_STATEMENTS",
                statements,
            ):
                with self.assertRaises(sqlite3.OperationalError):
                    migrate_v1_to_v2(
                        path,
                        {
                            "session-1": MigrationBinding(
                                "credential-binding-1", "worker-instance-1"
                            )
                        },
                        backup=backup,
                    )
            connection = sqlite3.connect(path)
            try:
                version = connection.execute("PRAGMA user_version").fetchone()[0]
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
            finally:
                connection.close()
            self.assertEqual(version, 1)
            self.assertNotIn("browser_profile_reservations", tables)
            self.assertTrue(backup.is_file())

    def test_readback_detects_changed_v1_content(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "v1.sqlite3"
            backup = root / "v1.backup.sqlite3"
            _create_v1(path)
            bindings = {
                "session-1": MigrationBinding(
                    "credential-binding-1", "worker-instance-1"
                )
            }
            migrate_v1_to_v2(path, bindings, backup=backup)
            connection = sqlite3.connect(path)
            try:
                connection.execute(
                    "UPDATE execution_receipts SET receipt_json = ?",
                    ('{"changed":true}',),
                )
                connection.commit()
            finally:
                connection.close()
            with self.assertRaisesRegex(ValueError, "execution_receipts"):
                read_v2_migration(path, bindings, backup=backup)


if __name__ == "__main__":
    unittest.main()
