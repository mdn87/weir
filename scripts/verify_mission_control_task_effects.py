"""Characterize saved task edits in a disposable, loopback-only Mission Control instance."""

import argparse
import contextlib
import http.cookiejar
import json
import os
import secrets
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


class Seat:
    def __init__(self, origin):
        self.origin = origin
        self.client = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
        )

    def call(self, method, path, payload=None, *, expected=200):
        req = urllib.request.Request(
            self.origin + path,
            method=method,
            data=json.dumps(payload).encode() if payload is not None else None,
            headers={"Content-Type": "application/json", "Origin": self.origin},
        )
        try:
            response = self.client.open(req, timeout=12)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            check(response.status == expected, f"{method} {path} returned {response.status}")
            return json.load(response)

    def login(self, username, password):
        self.call("POST", "/api/auth/login", {"username": username, "password": password})


@contextlib.contextmanager
def server(app, node, root, port, credentials):
    origin = f"http://127.0.0.1:{port}"
    env = {
        "HOME": str(root),
        "PATH": str(node.parent) + os.pathsep + "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "NODE_ENV": "production",
        "HOSTNAME": "127.0.0.1",
        "PORT": str(port),
        "MC_ALLOWED_HOSTS": "127.0.0.1,localhost",
        "NEXT_TELEMETRY_DISABLED": "1",
        "MISSION_CONTROL_TEST_MODE": "1",
        "MISSION_CONTROL_DATA_DIR": str(root / "state"),
        "MISSION_CONTROL_DB_PATH": str(root / "state" / "fixture.db"),
        **credentials,
    }
    with (root / "fixture.log").open("ab") as log:
        child = subprocess.Popen(
            [node, app / "server.js"],
            cwd=app,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=log,
        )
        try:
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                check(child.poll() is None, "private fixture did not start")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=1):
                        break
                except OSError:
                    time.sleep(0.2)
            else:
                raise RuntimeError("private fixture startup timed out")
            yield origin
        finally:
            child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)


def witness(database, workspace_id, task_id):
    """Read the fixture with a separate read-only connection on every observation."""
    with contextlib.closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA query_only = ON")
        row = db.execute(
            "SELECT * FROM tasks WHERE workspace_id=? AND id=?", (workspace_id, task_id)
        ).fetchone()
        check(row is not None, "task not found by independent witness")
        updates = db.execute(
            """SELECT actor FROM activities WHERE workspace_id=? AND entity_type='task'
               AND entity_id=? AND type='task_updated' ORDER BY id""",
            (workspace_id, task_id),
        ).fetchall()
        notifications = db.execute(
            """SELECT count(*) FROM notifications WHERE workspace_id=? AND source_type='task'
               AND source_id=?""",
            (workspace_id, task_id),
        ).fetchone()[0]
        return dict(row), [r["actor"] for r in updates], notifications


def run(app, node):
    check(
        sys.platform == "linux" and {name for _, name in socket.if_nameindex()} == {"lo"},
        "run inside a private Linux network namespace with only loopback",
    )
    check(
        (app / "server.js").is_file() and node.is_file(),
        "expected a standalone build and Node executable",
    )
    check(
        not any(
            (app / name).exists()
            for name in (".env", ".env.local", ".env.production", ".env.production.local")
        ),
        "standalone fixture must have no environment files",
    )
    with tempfile.TemporaryDirectory(prefix="weir-saved-policy-") as temporary:
        root = Path(temporary)
        (root / "state").mkdir(mode=0o700)
        database = root / "state" / "fixture.db"
        with socket.socket() as available:
            available.bind(("127.0.0.1", 0))
            port = available.getsockname()[1]
        credentials = {
            "AUTH_USER": "fixture-admin",
            "AUTH_PASS": secrets.token_urlsafe(32),
            "AUTH_SECRET": secrets.token_urlsafe(40),
            "API_KEY": secrets.token_urlsafe(40),
        }
        owner_name = "fixture-owner"
        owner_password, viewer_password = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        cases = [
            ("title", "Initial title", "Edited title", "inbox"),
            ("status", "in_progress", "review", "in_progress"),
        ]
        observations = []
        with server(app, node, root, port, credentials) as origin:
            admin, owner, viewer = Seat(origin), Seat(origin), Seat(origin)
            admin.login(credentials["AUTH_USER"], credentials["AUTH_PASS"])
            for name, password, role in [
                (owner_name, owner_password, "operator"),
                ("fixture-viewer", viewer_password, "viewer"),
            ]:
                admin.call(
                    "POST",
                    "/api/auth/users",
                    {"username": name, "password": password, "role": role},
                    expected=201,
                )
            owner.login(owner_name, owner_password)
            viewer.login("fixture-viewer", viewer_password)
            for field, before, after, initial_status in cases:
                row = owner.call(
                    "POST",
                    "/api/tasks",
                    {"title": "Initial title", "status": initial_status},
                    expected=201,
                )["task"]
                ws, task_id = row["workspace_id"], row["id"]
                snapshot, events, notes = witness(database, ws, task_id)
                check(
                    snapshot[field] == before and snapshot["created_by"] == owner_name,
                    "wrong fixture task",
                )
                path = f"/api/tasks/{task_id}"
                viewer.call("PUT", path, {field: after}, expected=403)
                check(
                    witness(database, ws, task_id) == (snapshot, events, notes),
                    "viewer changed the fixture",
                )
                owner.call("PUT", path, {field: after})
                saved, updates, messages = witness(database, ws, task_id)
                changed = {k for k in saved if saved[k] != snapshot[k]}
                check(
                    saved[field] == after and changed <= {field, "updated_at"},
                    "unexpected task row changes",
                )
                check(
                    updates == events + [owner_name] and messages == notes,
                    "unexpected fixture activity",
                )
                observations.append((ws, task_id, field, before, after, snapshot, events, notes))
        results = []
        with server(app, node, root, port, credentials) as origin:
            owner = Seat(origin)
            owner.login(owner_name, owner_password)
            for ws, task_id, field, before, after, initial, events, notes in observations:
                saved, updates, _ = witness(database, ws, task_id)
                check(
                    saved[field] == after and updates == events + [owner_name],
                    "saved state lost after restart",
                )
                owner.call("PUT", f"/api/tasks/{task_id}", {field: before})
                restored, updated, messages = witness(database, ws, task_id)
                check(
                    all(restored[k] == v for k, v in initial.items() if k != "updated_at"),
                    "compensation changed other task fields",
                )
                check(
                    updated == events + [owner_name] * 2 and messages == notes,
                    "restoration audit mismatch",
                )
                results.append(
                    {
                        "field": field,
                        "before": before,
                        "after": after,
                        "viewer_status": 403,
                        "saved_after_restart": True,
                        "original_value_restored": True,
                        "task_update_activity_records": 2,
                        "new_task_notifications": messages - notes,
                    }
                )
        return {
            "site": "disposable Mission Control",
            "platform": "Linux",
            "network_interfaces": ["lo"],
            "path_under_test": "ordinary task route",
            "verification": "fresh read-only SQLite connection",
            "weir_permits_exercised": 0,
            "live_site_used": False,
            "cases": results,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, required=True, help="trusted standalone fixture build")
    parser.add_argument("--node", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.app.resolve(), args.node.resolve()), indent=2))
