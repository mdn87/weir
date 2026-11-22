"""Exercise the installed private saved-task workflow with Chromium's test authenticator."""

import argparse
import base64
import contextlib
import hashlib
import http.client
import json
import os
import socket
import socketserver
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from playwright.sync_api import expect, sync_playwright

HOST = "saved-task.test"


@contextlib.contextmanager
def intercept_effect(root, withdraw=None):
    """Hold a signed request at the writer to exercise response loss or owner withdrawal."""
    public, actual = root / "effect.sock", root / "effect-test.sock"
    os.rename(public, actual)
    errors, results = [], {}

    def rpc(path, request):
        with socket.socket(socket.AF_UNIX) as s:
            s.settimeout(10)
            s.connect(str(path))
            s.sendall(json.dumps(request).encode())
            s.shutdown(socket.SHUT_WR)
            with s.makefile("rb") as stream:
                return json.loads(stream.read(32_769))

    class Probe(socketserver.StreamRequestHandler):
        def handle(self):
            try:
                request = json.loads(self.rfile.read(32_769))
                lookup = {"command_id": request["command_id"]}
                if withdraw:
                    withdraw(request["command_id"], request["capsule"]["proposal_hash"])
                    assert rpc(actual, request)["result"]["state"] == "withdrawn"
                    item = rpc(root / "reader.sock", lookup)["result"]
                    assert item["receipt"] is None and item["task"]["revision"] == 3
                    results["withdrawal_fenced_delayed_commit"] = True
                    return
                for part in ("capsule", "permit"):
                    bad = {**request, part: {**request[part], "signature": "A" * 86}}
                    assert rpc(actual, bad)["ok"] is False
                before = rpc(root / "reader.sock", lookup)["result"]
                assert before["receipt"] is None and before["task"]["revision"] == 1
                concurrent = rpc(root / "weir.sock", {"operation": "execute", **lookup})
                assert concurrent["result"]["state"] == "outcome_unknown"
                assert rpc(actual, request)["result"]["state"] == "committed"
                assert rpc(actual, request)["result"]["state"] == "committed"
                after = rpc(root / "reader.sock", lookup)["result"]
                assert after["task"]["revision"] == 2 and after["receipt"]["revision"] == 2
                results.update(
                    tampered_signatures_refused=True,
                    concurrent_dispatch_fenced=True,
                    lost_effect_response_reconciled=True,
                )
                # The destination committed. Close the original connection without replying.
            except Exception as error:
                errors.append(error)

    try:
        with socketserver.UnixStreamServer(str(public), Probe) as proxy:
            thread = threading.Thread(target=proxy.serve_forever, daemon=True)
            thread.start()
            try:
                yield results
            finally:
                proxy.shutdown()
                thread.join()
    finally:
        public.unlink(missing_ok=True)
        os.rename(actual, public)
    if errors:
        raise RuntimeError("Private writer fault checks failed.") from errors[0]


def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextlib.contextmanager
def https_proxy(root, app_port):
    """Terminate private TLS and preserve the exact WebAuthn origin at the application."""

    class Handler(BaseHTTPRequestHandler):
        def forward(self):
            if (
                self.headers.get("Host") != HOST
                or not self.path.startswith("/")
                or self.path.startswith("//")
            ):
                self.send_error(400)
                return
            drop = {
                "host",
                "connection",
                "transfer-encoding",
                "content-length",
                "accept-encoding",
                "x-forwarded-host",
                "x-forwarded-for",
                "x-forwarded-proto",
            }
            data = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            headers = {k: v for k, v in self.headers.items() if k.lower() not in drop}
            headers.update(
                {
                    "Host": HOST,
                    "X-Forwarded-Host": HOST,
                    "X-Forwarded-Proto": "https",
                    "Accept-Encoding": "identity",
                    "Connection": "close",
                }
            )
            with contextlib.closing(
                http.client.HTTPConnection("127.0.0.1", app_port, timeout=30)
            ) as conn:
                try:
                    conn.request(self.command, self.path, data or None, headers)
                    res = conn.getresponse()
                    if self.path in {"/login", "/api/auth/login"}:
                        with (root / "proxy-status.log").open("a", encoding="ascii") as status_log:
                            status_log.write(
                                f"{self.command} {self.path} {res.status} {res.length}\n"
                            )
                    self.send_response(res.status)
                    for name, value in res.getheaders():
                        if name.lower() not in {
                            "transfer-encoding",
                            "connection",
                            "content-length",
                        }:
                            self.send_header(name, value)
                    self.end_headers()
                    if self.command != "HEAD":
                        while chunk := res.read1(65_536):
                            self.wfile.write(chunk)
                except (TimeoutError, ConnectionError, http.client.IncompleteRead):
                    pass

        do_GET = do_HEAD = do_POST = forward

        def log_message(self, *args):
            pass

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=2))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), False)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = root / "fixture.crt", root / "fixture.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    with os.fdopen(os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as out:
        out.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert_path, key_path)
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.server_port, base64.b64encode(hashlib.sha256(spki).digest()).decode()
        finally:
            server.shutdown()
            thread.join()


@contextlib.contextmanager
def running(args, app_port):
    command = [
        sys.executable,
        str(Path(__file__).with_name("saved_task_rehearsal.py")),
        "serve",
        str(args.directory),
        "--mission-control",
        str(args.mission_control),
        "--node",
        str(args.node),
        "--port",
        str(app_port),
    ]
    proc = subprocess.Popen(command, stdin=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 70
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError("Private site stopped. Check the private web log.")
            try:
                with socket.create_connection(("127.0.0.1", app_port), timeout=1):
                    break
            except OSError:
                time.sleep(0.3)
        else:
            raise RuntimeError("Private site did not start.")
        yield
    finally:
        proc.terminate()
        proc.wait(timeout=24)


def verify(args):
    if sys.platform != "linux" or {n for _, n in socket.if_nameindex()} != {"lo"}:
        raise RuntimeError(
            "Run the browser check in a private Linux network namespace with only loopback."
        )
    root = args.directory.absolute()
    if root.exists():
        raise ValueError("Verification starts with a new private directory.")
    subprocess.run(
        [
            sys.executable,
            str(Path(__file__).with_name("saved_task_rehearsal.py")),
            "init",
            str(root),
            "--mission-control",
            str(args.mission_control),
            "--node",
            str(args.node),
        ],
        check=True,
    )
    app_port = port()
    with https_proxy(root, app_port) as (tls_port, pin), sync_playwright() as p:
        browser = p.chromium.launch(
            executable_path=str(args.chromium),
            chromium_sandbox=True,
            args=[
                f"--host-resolver-rules=MAP {HOST} 127.0.0.1:{tls_port}, MAP * ~NOTFOUND",
                "--no-proxy-server",
                "--ignore-certificate-errors-spki-list=" + pin,
            ],
        )
        try:
            ctx = browser.new_context(service_workers="block")
            page = ctx.new_page()
            page.set_default_timeout(25_000)
            cdp = ctx.new_cdp_session(page)
            cdp.send("WebAuthn.enable")
            cdp.send(
                "WebAuthn.addVirtualAuthenticator",
                {
                    "options": {
                        "protocol": "ctap2",
                        "transport": "internal",
                        "hasResidentKey": True,
                        "hasUserVerification": True,
                        "isUserVerified": True,
                        "automaticPresenceSimulation": True,
                    }
                },
            )

            def api(path, body=None):
                return page.evaluate(
                    """async ([path,body])=>{const r=await fetch(path,{method:body?'POST':'GET',
                  headers:{'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});
                  const text=await r.text(); let bodyOut={}; try {bodyOut=JSON.parse(text)}
                  catch {bodyOut={error:'Non-JSON response at '+new URL(r.url).pathname}}
                  return {status:r.status,body:bodyOut}}""",
                    [path, body],
                )

            def accepted(path, body=None, status=200):
                r = api(path, body)
                if r["status"] != status:
                    raise RuntimeError(
                        f"{path} returned {r['status']}: {str(r['body'].get('error', ''))[:100]}"
                    )
                return r["body"]

            def open_panel(job_id=None):
                address = "https://" + HOST + "/lugos" + ("?savedTask=" + job_id if job_id else "")
                page.goto(address, wait_until="domcontentloaded")
                panel = page.get_by_role("region", name="Private task rehearsal")
                full = page.get_by_role("button", name="Switch to Full", exact=False)
                skip = page.get_by_role("button", name="Skip setup", exact=True)
                try:
                    expect(panel.or_(full).or_(skip).first).to_be_visible(timeout=35_000)
                    if skip.is_visible():
                        skip.click()
                        expect(skip).to_be_hidden()
                        if page.url != address:
                            page.goto(address, wait_until="domcontentloaded")
                    expect(panel.or_(full).first).to_be_visible(timeout=35_000)
                    if full.is_visible():
                        full.click()
                    expect(panel).to_be_visible(timeout=25_000)
                except AssertionError:
                    page.screenshot(path=str(root / "private-screen.png"))
                    state = api("/api/lugos/saved-task")
                    print(
                        "Private panel check:",
                        state["status"],
                        state["body"].get("error"),
                        page.locator("h1,h2,h3").all_text_contents()[:12],
                        file=sys.stderr,
                    )
                    raise
                return panel

            route = "/api/lugos/saved-task"
            with running(args, app_port):
                page.goto("https://" + HOST + "/login", wait_until="domcontentloaded")
                password = (root / "login").read_text()
                accepted("/api/auth/login", {"username": "fixture-owner", "password": password})
                accepted("/api/onboarding", {"action": "skip"})
                panel = open_panel()
                panel.get_by_label("Current rehearsal password").fill(password)
                enroll = panel.get_by_role("button", name="Set up rehearsal passkey")
                enroll.click()
                expect(enroll).to_be_hidden(timeout=15_000)
                sibling = accepted(
                    route, {"operation": "prepare", "after": "Earlier proposal"}, 201
                )
                panel.get_by_label("New title").fill("Reviewed café title")
                panel.get_by_role("button", name="Review change").click()
                expect(panel.get_by_text("Waiting for your decision.")).to_be_visible()
                job = panel.get_by_label("Saved jobs").input_value()
                with intercept_effect(root) as fault_checks:
                    panel.get_by_role("button", name="Approve with passkey").click()
                    expect(
                        panel.get_by_text("WEIR verified the saved title", exact=False)
                    ).to_be_visible(timeout=35_000)
                assert fault_checks.get("lost_effect_response_reconciled")
                initial = accepted(route + "?job=" + job)["evidence"]
                assert (
                    initial["state"] == "verified"
                    and initial["receipt"]["after"] == "Reviewed café title"
                )
                assert initial["receipt"]["revision"] == 2
                assert (
                    accepted(route + "?job=" + sibling["command_id"])["evidence"]["state"]
                    == "stale"
                )
                assert api(route, {"operation": "options", **sibling})["status"] == 409
            with running(args, app_port):
                panel = open_panel(job)
                expect(
                    panel.get_by_text("WEIR verified the saved title", exact=False)
                ).to_be_visible()
                expect(panel.get_by_role("link", name="Link to this job")).to_have_attribute(
                    "href", "/lugos?savedTask=" + job
                )
                reopened = accepted(route + "?job=" + job)
                assert reopened["evidence"] == initial
                replay = accepted(
                    route,
                    {
                        "operation": "resume",
                        "command_id": job,
                        "proposal_hash": reopened["review"]["proposal_hash"],
                    },
                )
                assert replay == initial
                panel.get_by_role("button", name="Review undo").click()
                expect(panel.get_by_text("Waiting for your decision.")).to_be_visible()
                undo = panel.get_by_label("Saved jobs").input_value()
                assert undo != job
                panel.get_by_role("button", name="Approve with passkey").click()
                expect(
                    panel.get_by_text("WEIR verified the saved title", exact=False)
                ).to_be_visible()
                restored = accepted(route + "?job=" + undo)["evidence"]
                assert (
                    restored["receipt"]["after"] == "Initial title"
                    and restored["receipt"]["revision"] == 3
                )
                assert accepted(route + "?job=" + job)["evidence"]["current"] is False
                old_undo = accepted(route, {"operation": "undo", "command_id": job}, 201)
                assert (
                    accepted(route + "?job=" + old_undo["command_id"])["evidence"]["state"]
                    == "stale"
                )
                panel.get_by_label("New title").fill("Declined title")
                panel.get_by_role("button", name="Review change").click()
                panel.get_by_role("button", name="Decline", exact=True).click()
                expect(panel.get_by_text("You declined this change.")).to_be_visible()
                assert accepted(route)["task"]["title"] == "Initial title"
                cookie = "; ".join(
                    c["name"] + "=" + c["value"] for c in ctx.cookies("https://" + HOST)
                )

                def withdraw(command, digest):
                    with contextlib.closing(
                        http.client.HTTPConnection("127.0.0.1", app_port, timeout=8)
                    ) as conn:
                        conn.request(
                            "POST",
                            route,
                            json.dumps(
                                {
                                    "operation": "decline",
                                    "command_id": command,
                                    "proposal_hash": digest,
                                }
                            ),
                            {
                                "Content-Type": "application/json",
                                "Origin": "https://" + HOST,
                                "Host": HOST,
                                "X-Forwarded-Proto": "https",
                                "Cookie": cookie,
                            },
                        )
                        response = conn.getresponse()
                        assert (
                            response.status == 200 and json.load(response)["state"] == "withdrawn"
                        )

                panel.get_by_label("New title").fill("Withdrawn title")
                panel.get_by_role("button", name="Review change").click()
                expect(panel.get_by_text("Waiting for your decision.")).to_be_visible()
                with intercept_effect(root, withdraw) as withdrawal_check:
                    panel.get_by_role("button", name="Approve with passkey").click()
                    expect(panel.get_by_text("You withdrew this approval.")).to_be_visible(
                        timeout=35_000
                    )
                assert withdrawal_check.get("withdrawal_fenced_delayed_commit")
                # Signed-in viewers and unauthenticated callers cannot reopen protected evidence.
                viewer_password = os.urandom(24).hex()
                accepted(
                    "/api/auth/users",
                    {"username": "fixture-viewer", "password": viewer_password, "role": "viewer"},
                    201,
                )
                ctx.clear_cookies()
                assert api(route + "?job=" + job)["status"] in (401, 403)
                accepted(
                    "/api/auth/login", {"username": "fixture-viewer", "password": viewer_password}
                )
                assert api(route + "?job=" + job)["status"] == 403
        finally:
            browser.close()
    with contextlib.closing(
        sqlite3.connect((root / "site.db").as_uri() + "?mode=ro", uri=True)
    ) as db:
        receipts = db.execute(
            "SELECT count(*) FROM weir_saved_reviews WHERE receipt IS NOT NULL"
        ).fetchone()[0]
        assertions = db.execute(
            "SELECT count(DISTINCT step_up_ref) FROM weir_saved_reviews"
        ).fetchone()[0]
        assert receipts == 2 and assertions == 3
        for table in ("tasks", "activities", "notifications"):
            assert db.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0
    return {
        "private_network_interfaces": ["lo"],
        "production_website_actions": 0,
        "browser": "Chromium virtual authenticator",
        "passkey_enrolled_in_owner_panel": True,
        "original_job_link_reopened": True,
        "verified_after_server_restart": True,
        "separately_approved_undo": True,
        "replay_returned_original_receipt": True,
        "decline_preserved_title": True,
        "viewer_denied_history": True,
        "verified_receipts": receipts,
        "distinct_passkey_decisions": assertions,
        "final_title": "Initial title",
        "final_revision": 3,
        "stale_proposal_and_undo_refused": True,
        "workspace_tasks_activities_notifications": [0, 0, 0],
        **fault_checks,
        **withdrawal_check,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ("directory", "--mission-control", "--node", "--chromium"):
        parser.add_argument(arg, type=Path, **({"required": True} if arg.startswith("--") else {}))
    print(json.dumps(verify(parser.parse_args()), indent=2))
