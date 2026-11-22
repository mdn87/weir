"""Opt-in acceptance using real Chromium, local Aire OCR and a loopback dashboard."""

import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import nullcontext
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont
from tests.test_playwright_observer import _ProfileStates
from weir.browser.broker import BrowserSessionBroker
from weir.browser.playwright_observer import PlaywrightObserverWorker
from weir.browser.store import SQLiteSessionStore
from weir.models import DataClass, RequestMode, WebRequest
from weir.persistence import CaptureStore
from weir.visual import Region, ValueQuery, png_bytes
from weir.visual_evidence import observe_value
from weir.work_context import WorkContext, WorkContextSource

from weir.profiles import SiteProfileRegistry


@unittest.skipUnless(
    os.environ.get("WEIR_VISUAL_SMOKE") == "1", "requires Chromium and the local Aire OCR runtime"
)
class VisualDashboardSmoke(unittest.TestCase):
    def test_installed_operator_reads_and_reopens_private_dashboard(self):
        tile = Image.new("RGB", (480, 96), "white")
        for family in ("arial.ttf", "DejaVuSans.ttf"):
            try:
                font = ImageFont.truetype(family, 40)
                break
            except OSError:
                continue
        else:
            font = ImageFont.load_default(size=40)
        ImageDraw.Draw(tile).text((14, 18), "In review: 23", font=font, fill="black")
        encoded = png_bytes(tile)
        state_tile = Image.new("RGB", tile.size, "white")
        ImageDraw.Draw(state_tile).text((14, 18), "Build: Passing", font=font, fill="black")
        state_png = png_bytes(state_tile)
        page = b"""<!doctype html><title>Private dashboard</title>
        <img alt="" src="/tile.png" style="position:absolute;left:32px;top:32px">
        <img alt="" src="/state.png" style="position:absolute;left:32px;top:144px">
        <main style="margin-top:270px"><button>Queued: 0</button>
        <button>Teams: 2</button><button>Teams: 2</button></main>"""
        methods = []

        class Dashboard(BaseHTTPRequestHandler):
            def do_GET(self):
                methods.append(self.command)
                if "session=valid" not in self.headers.get("Cookie", ""):
                    self.send_error(401)
                    return
                data, kind = {
                    "/tile.png": (encoded, "image/png"),
                    "/state.png": (state_png, "image/png"),
                }.get(self.path, (page, "text/html"))
                self.send_response(200)
                self.send_header("Content-Type", kind)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Dashboard)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        url = f"http://127.0.0.1:{server.server_port}/"
        archive = os.environ.get("WEIR_VISUAL_ARTIFACTS")
        workspace = (
            nullcontext(tempfile.mkdtemp(prefix="dashboard-", dir=archive))
            if archive
            else tempfile.TemporaryDirectory()
        )
        with workspace as directory:
            root = Path(directory)
            profile = {
                "contract_version": "0.1",
                "id": "authenticated-fixture",
                "domains": ["127.0.0.1"],
                "preferred_engines": ["playwright-observer"],
                "auth_mode": "dedicated_profile",
                "allowed_modes": ["observe"],
                "retention": {"screenshots": "full_evidence"},
                "browser_observation": {
                    "javascript": "disabled",
                    "network_methods": "get_head_only",
                    "credential_scope": "read_only",
                },
            }
            (root / "dashboard.yaml").write_text(json.dumps(profile), encoding="utf-8")
            profiles = SiteProfileRegistry.from_directory(root)
            store, database = root / "evidence", root / "sessions.sqlite3"
            rect = Region(32, 32, 480, 96)
            results = {}
            worker = PlaywrightObserverWorker(profile_states=_ProfileStates())
            try:
                with SQLiteSessionStore(database) as ledger:
                    broker = BrowserSessionBroker(
                        [worker],
                        store=ledger,
                        capture_store=CaptureStore(store),
                        profiles=profiles,
                        profile_bindings=_ProfileStates(),
                    )
                    request = WebRequest(
                        "dashboard-open",
                        "visual-smoke",
                        RequestMode.OBSERVE,
                        DataClass.BWA_INTERNAL,
                        auth_context="browser",
                        url=url,
                        profile_id="fixture-profile",
                        allowed_domains=["127.0.0.1"],
                        capture_policy="full_evidence",
                    )
                    context = WorkContext.create(
                        context_id="visual-context",
                        run_id=request.run_id,
                        correlation_id=request.request_id,
                        source=WorkContextSource.CALLER,
                        created_at=datetime.now(timezone.utc).isoformat(),
                    )
                    session = broker.open(
                        request,
                        context,
                        worker_id=worker.descriptor.worker_id,
                        operation_id="dashboard-open",
                    )
                    for label in ("Queued", "Teams", "In review"):
                        session = ledger.get_session(session.session_id)
                        result = observe_value(
                            broker,
                            session.session_id,
                            context,
                            ValueQuery(label),
                            region=rect,
                            expected_revision=session.revision,
                            expected_epoch=session.epoch,
                            operation_id="dashboard-" + label.replace(" ", "-"),
                        )
                        results[label] = result
                    queued_obs = broker.capture_store.load_capture(
                        results["Queued"]["source"]["capture_id"]
                    ).content["observation"]
                    self.assertEqual(
                        (results["Queued"]["value"], results["Queued"]["crop_ref"]),
                        (0, None),
                        queued_obs["accessibility_snapshot"],
                    )
                    self.assertEqual(
                        (results["Teams"]["status"], results["Teams"]["value"]), ("ambiguous", None)
                    )
                    visual = results["In review"]
                    self.assertEqual(
                        (visual["method"], visual["value"]), ("screenshot", 23), visual
                    )
                    self.assertEqual(len(visual["readings"]), 2)
                    session = ledger.get_session(session.session_id)
                    broker.close(
                        session.session_id,
                        context,
                        expected_revision=session.revision,
                        expected_epoch=session.epoch,
                        operation_id="dashboard-close",
                    )
            finally:
                worker.shutdown()

            def cli(*args, expected=0):
                executable = Path(sys.executable).with_name(
                    "weir.exe" if os.name == "nt" else "weir"
                )
                entry = (
                    [str(executable)]
                    if executable.is_file()
                    else [sys.executable, "-m", "weir.cli"]
                )
                proc = subprocess.run(
                    [*entry, "visual", *args, "--sessions", str(database), "--store", str(store)],
                    env={**os.environ, "WEIR_PROFILE_DIR": directory},
                    cwd=root,
                    capture_output=True,
                    text=True,
                    timeout=75,
                )
                self.assertEqual(proc.returncode, expected, proc.stderr + proc.stdout)
                return json.loads(proc.stdout) if proc.stdout else None

            reopened = cli(
                "show", "--reading", visual["reading_id"], "--export-crop", str(root / "export.png")
            )
            self.assertEqual(visual, reopened)
            with Image.open(root / "export.png") as exported:
                self.assertEqual(exported.tobytes(), tile.tobytes())
            repeated = cli(
                "read",
                "--label",
                "In review",
                "--capture",
                visual["source"]["capture_id"],
                "--region",
                "32",
                "32",
                "480",
                "96",
            )
            self.assertEqual(visual, repeated)
            state = cli(
                "read",
                "--label",
                "Build",
                "--choice",
                "Passing",
                "--choice",
                "Failed",
                "--capture",
                visual["source"]["capture_id"],
                "--region",
                "32",
                "144",
                "480",
                "96",
            )
            self.assertEqual((state["method"], state["value"]), ("screenshot", "Passing"))
            uncertain = cli(
                "read",
                "--label",
                "In review",
                "--capture",
                visual["source"]["capture_id"],
                "--region",
                "600",
                "200",
                "120",
                "60",
                expected=3,
            )
            self.assertEqual((uncertain["status"], uncertain["value"]), ("unreadable", None))
            cli(
                "show",
                "--reading",
                visual["reading_id"],
                "--export-crop",
                str(root / "export.png"),
                expected=2,
            )
            self.assertEqual(set(methods), {"GET"})
            if archive:
                (root / "reading.json").write_text(
                    json.dumps(reopened, indent=2) + "\n", encoding="utf-8"
                )
            if output := os.environ.get("WEIR_VISUAL_RECEIPT"):
                receipt = {
                    "tested_at": datetime.now(timezone.utc).isoformat(),
                    "source": "authenticated loopback dashboard",
                    "requests": sorted(set(methods)),
                    "reading_id": visual["reading_id"],
                    "crop": visual["crop_ref"],
                    "readers": visual["readings"],
                    "visual_count": visual["value"],
                    "visual_state": state["value"],
                    "structured_count": 0,
                    "duplicate_labels": results["Teams"]["status"],
                    "blank_region": uncertain["status"],
                    "exact_crop_after_close": True,
                    "repeat_read_identical": True,
                }
                Path(output).write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
