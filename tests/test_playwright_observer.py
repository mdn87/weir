import os
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from weir.browser.broker import BrowserSessionBroker
from weir.browser.playwright_observer import (
    PlaywrightObserverWorker,
    VerifiedProfileState,
    _ContainmentState,
    _LiveSession,
)
from weir.browser.protocol import SessionSpec, StaleWorkerCommand, WorkerCommand
from weir.browser.store import SQLiteSessionStore
from weir.engines.base import EngineFailure, EnginePolicyBlocked
from weir.models import DataClass, RequestMode, WebRequest
from weir.persistence import CaptureStore
from weir.work_context import WorkContext, WorkContextSource

from weir.profiles import SiteProfile, SiteProfileRegistry


class _AuthenticatedHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if "session=valid" not in self.headers.get("Cookie", ""):
            self.send_response(401)
            self.end_headers()
            return
        body = (
            b"<!doctype html><title>Authenticated fixture</title>"
            b'<main><button data-testid="save">Save</button></main>'
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        return


class _ProfileStates:
    def state_for(self, profile_id):
        if profile_id != "fixture-profile":
            raise KeyError(profile_id)
        return VerifiedProfileState(
            profile_id="fixture-profile",
            site_profile_id="authenticated-fixture",
            credential_scope="read_only",
            storage_state={
                "cookies": [
                    {
                        "name": "session",
                        "value": "valid",
                        "domain": "127.0.0.1",
                        "path": "/",
                        "expires": -1,
                        "httpOnly": True,
                        "secure": False,
                        "sameSite": "Lax",
                    }
                ],
                "origins": [],
            },
        )


class _Ids:
    def __init__(self):
        self.value = 0

    def __call__(self, prefix):
        self.value += 1
        return f"{prefix}-smoke-{self.value}"


class PlaywrightContainmentTests(unittest.TestCase):
    def test_all_playwright_calls_run_on_one_dedicated_thread(self):
        worker = PlaywrightObserverWorker()
        caller_threads = []
        worker_threads = []

        def invoke():
            caller_threads.append(threading.get_ident())
            worker_threads.append(
                worker._on_worker_thread(  # noqa: SLF001 - thread-affinity fixture
                    "thread-test", threading.get_ident
                )
            )

        callers = [threading.Thread(target=invoke) for _ in range(3)]
        try:
            for caller in callers:
                caller.start()
            for caller in callers:
                caller.join(timeout=5)
        finally:
            worker.shutdown()

        self.assertTrue(all(not caller.is_alive() for caller in callers))
        self.assertEqual(len(set(worker_threads)), 1)
        self.assertTrue(set(worker_threads).isdisjoint(caller_threads))

    def test_profile_state_metadata_must_match_session_policy(self):
        spec = SessionSpec(
            session_id="session-1",
            worker_session_id="pending-1",
            owner_run_id="run-1",
            profile_id="profile-1",
            site_profile_id="portal",
            credential_scope="read_only",
            data_class=DataClass.BWA_INTERNAL,
            allowed_domains=("portal.example.test",),
            initial_url="https://portal.example.test/",
        )
        state = VerifiedProfileState(
            profile_id="profile-1",
            site_profile_id="portal",
            credential_scope="admin",
            storage_state={"cookies": [{}], "origins": []},
        )
        with self.assertRaisesRegex(EnginePolicyBlocked, "read-only"):
            state.validate_for(spec)

    def test_probe_reports_unlaunchable_chromium_as_unavailable(self):
        worker = PlaywrightObserverWorker()
        try:
            with (
                mock.patch(
                    "weir.browser.playwright_observer._playwright_installed",
                    return_value=True,
                ),
                mock.patch.object(
                    worker,
                    "_probe_chromium_serialized",
                    side_effect=RuntimeError("executable missing"),
                ),
            ):
                probe = worker.probe()
        finally:
            worker.shutdown()
        self.assertFalse(probe.available)
        self.assertIn("executable missing", probe.detail or "")

    def test_observation_mode_blocks_page_driven_unsafe_http_methods(self):
        class Context:
            callback = None

            def route(self, _pattern, callback):
                self.callback = callback

            def route_web_socket(self, _pattern, _callback):
                return None

        class Request:
            url = "https://portal.example.test/mutate"
            method = "POST"

        class Route:
            request = Request()
            continued = False
            aborted = False

            def continue_(self):
                self.continued = True

            def abort(self, _reason):
                self.aborted = True

        context = Context()
        containment = _ContainmentState()
        worker = PlaywrightObserverWorker()
        spec = SessionSpec(
            session_id="session-1",
            worker_session_id="pending-1",
            owner_run_id="run-1",
            profile_id="profile-1",
            site_profile_id="portal",
            credential_scope="read_only",
            data_class=DataClass.BWA_INTERNAL,
            allowed_domains=("portal.example.test",),
            initial_url="https://portal.example.test/",
        )
        worker._install_containment(context, spec, containment)  # noqa: SLF001
        route = Route()
        context.callback(route)
        self.assertTrue(route.aborted)
        self.assertFalse(route.continued)
        self.assertIn("http_method_post_blocked", containment.last_blocked_reason)

    def test_request_budget_is_bounded_and_redacts_page_urls(self):
        class Context:
            callback = None

            def route(self, _pattern, callback):
                self.callback = callback

            def route_web_socket(self, _pattern, _callback):
                return None

        class Request:
            url = "about:blank?token=do-not-persist#private"
            method = "GET"

        class Route:
            request = Request()
            aborted = False

            def continue_(self):
                return None

            def abort(self, _reason):
                self.aborted = True

        worker = PlaywrightObserverWorker(max_requests_per_session=1)
        context = Context()
        containment = _ContainmentState()
        spec = SessionSpec(
            session_id="session-1",
            worker_session_id="pending-1",
            owner_run_id="run-1",
            profile_id="profile-1",
            site_profile_id="portal",
            credential_scope="read_only",
            data_class=DataClass.BWA_INTERNAL,
            allowed_domains=("portal.example.test",),
            initial_url="https://portal.example.test/",
        )
        worker._install_containment(context, spec, containment)  # noqa: SLF001
        context.callback(Route())
        second = Route()
        context.callback(second)
        self.assertTrue(second.aborted)
        self.assertTrue(containment.budget_exceeded)
        self.assertEqual(containment.request_count, 2)
        self.assertNotIn("do-not-persist", containment.last_blocked_reason)
        self.assertNotIn("private", containment.last_blocked_reason)

    def test_declared_response_budget_closes_context_before_body_finishes(self):
        class Context:
            response_callback = None
            closed = False

            def route(self, _pattern, _callback):
                return None

            def route_web_socket(self, _pattern, _callback):
                return None

            def on(self, event, callback):
                if event == "response":
                    self.response_callback = callback

            def close(self):
                self.closed = True

        class Request:
            method = "GET"

        class Response:
            url = "https://portal.example.test/private?token=do-not-persist"
            request = Request()

            def header_value(self, name):
                return "101" if name == "content-length" else None

        context = Context()
        containment = _ContainmentState()
        worker = PlaywrightObserverWorker(
            max_declared_response_bytes=100,
            max_declared_bytes_per_session=200,
        )
        spec = SessionSpec(
            session_id="session-1",
            worker_session_id="pending-1",
            owner_run_id="run-1",
            profile_id="profile-1",
            site_profile_id="portal",
            credential_scope="read_only",
            data_class=DataClass.BWA_INTERNAL,
            allowed_domains=("portal.example.test",),
            initial_url="https://portal.example.test/",
        )
        try:
            worker._install_containment(context, spec, containment)  # noqa: SLF001
            context.response_callback(Response())
        finally:
            worker.shutdown()

        self.assertTrue(context.closed)
        self.assertTrue(containment.budget_exceeded)
        self.assertEqual(containment.declared_response_bytes, 101)
        self.assertIn("response_byte_budget_exceeded", containment.last_blocked_reason)
        self.assertNotIn("do-not-persist", containment.last_blocked_reason)

    def test_observation_rejects_navigation_during_atomic_screenshot(self):
        containment = _ContainmentState(document_generation=1)

        class EmptyLocator:
            def count(self):
                return 0

        class BodyLocator:
            def aria_snapshot(self, **_kwargs):
                return '- button "Save"'

        class Page:
            url = "http://127.0.0.1/"

            def locator(self, _selector):
                return BodyLocator()

            def get_by_role(self, _role):
                return EmptyLocator()

            def title(self):
                return "Before navigation"

            def screenshot(self, **_kwargs):
                containment.document_generation += 1
                return b"png"

        spec = SessionSpec(
            session_id="session-1",
            worker_session_id="worker-context-1",
            owner_run_id="run-1",
            profile_id="profile-1",
            site_profile_id="portal",
            credential_scope="read_only",
            data_class=DataClass.BWA_INTERNAL,
            allowed_domains=("127.0.0.1",),
            initial_url="http://127.0.0.1/",
        )
        payload = {"session_id": "session-1", "include_screenshot": True}
        command = WorkerCommand.build(
            command_id="observe-1",
            operation="observe",
            session_id="session-1",
            worker_session_id="worker-context-1",
            owner_run_id="run-1",
            expected_revision=1,
            session_epoch=1,
            lease_fence=1,
            deadline_at=datetime.now(timezone.utc).replace(microsecond=0)
            + timedelta(minutes=1),
            payload=payload,
        )
        worker = PlaywrightObserverWorker()
        worker._sessions["session-1"] = _LiveSession(  # noqa: SLF001
            "worker-context-1", spec, None, None, Page(), containment
        )
        try:
            with self.assertRaises(StaleWorkerCommand):
                worker._observe_serialized(  # noqa: SLF001
                    "session-1", command, include_screenshot=True
                )
        finally:
            worker._sessions.clear()  # noqa: SLF001
            worker.shutdown()

    def test_failed_browser_close_keeps_session_available_for_retry(self):
        class Context:
            close_count = 0

            def close(self):
                self.close_count += 1

        class Browser:
            close_count = 0
            fail = True

            def close(self):
                self.close_count += 1
                if self.fail:
                    raise RuntimeError("browser process still running")

        spec = SessionSpec(
            session_id="session-1",
            worker_session_id="worker-context-1",
            owner_run_id="run-1",
            profile_id="profile-1",
            site_profile_id="portal",
            credential_scope="read_only",
            data_class=DataClass.BWA_INTERNAL,
            allowed_domains=("127.0.0.1",),
            initial_url="http://127.0.0.1/",
        )
        context = Context()
        browser = Browser()
        worker = PlaywrightObserverWorker()
        worker._sessions[spec.session_id] = _LiveSession(  # noqa: SLF001
            spec.worker_session_id,
            spec,
            browser,
            context,
            object(),
            _ContainmentState(),
        )

        def close_command(command_id):
            payload = {"session_id": spec.session_id}
            return WorkerCommand.build(
                command_id=command_id,
                operation="close",
                session_id=spec.session_id,
                worker_session_id=spec.worker_session_id,
                owner_run_id=spec.owner_run_id,
                expected_revision=1,
                session_epoch=1,
                lease_fence=1,
                deadline_at=datetime.now(timezone.utc) + timedelta(minutes=1),
                payload=payload,
            )

        try:
            with self.assertRaisesRegex(EngineFailure, "could not be confirmed"):
                worker._close_session_serialized(  # noqa: SLF001
                    spec.session_id, close_command("close-first")
                )
            self.assertIn(spec.session_id, worker._sessions)  # noqa: SLF001

            browser.fail = False
            worker._close_session_serialized(  # noqa: SLF001
                spec.session_id, close_command("close-retry")
            )
            self.assertNotIn(spec.session_id, worker._sessions)  # noqa: SLF001
            self.assertEqual(context.close_count, 2)
            self.assertEqual(browser.close_count, 2)
        finally:
            worker._sessions.clear()  # noqa: SLF001
            worker.shutdown()


@unittest.skipUnless(
    os.environ.get("WEIR_PLAYWRIGHT_SMOKE") == "1",
    "set WEIR_PLAYWRIGHT_SMOKE=1 for the local Chromium integration test",
)
class PlaywrightObserverSmokeTests(unittest.TestCase):
    def test_authenticated_broker_observation_and_screenshot(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), _AuthenticatedHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        worker = PlaywrightObserverWorker(profile_states=_ProfileStates())
        temporary = tempfile.TemporaryDirectory()
        store = SQLiteSessionStore(Path(temporary.name) / "browser.sqlite3")
        try:
            url = f"http://127.0.0.1:{server.server_port}/"
            profile = SiteProfile.from_dict(
                {
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
            )
            broker = BrowserSessionBroker(
                [worker],
                store=store,
                capture_store=CaptureStore(Path(temporary.name) / "evidence"),
                profiles=SiteProfileRegistry([profile]),
                id_factory=_Ids(),
            )
            request = WebRequest(
                request_id="smoke-request",
                run_id="smoke-run",
                mode=RequestMode.OBSERVE,
                data_class=DataClass.BWA_INTERNAL,
                auth_context="browser",
                intent="observe authenticated fixture",
                url=url,
                profile_id="fixture-profile",
                allowed_domains=["127.0.0.1"],
                capture_policy="full_evidence",
            )
            context = WorkContext.create(
                context_id="smoke-context",
                run_id="smoke-run",
                correlation_id="smoke-request",
                source=WorkContextSource.CALLER,
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            session = broker.open(
                request,
                context,
                worker_id=worker.descriptor.worker_id,
                operation_id="smoke-open",
            )
            result = broker.observe(
                session.session_id,
                context,
                expected_revision=session.revision,
                expected_epoch=session.epoch,
                operation_id="smoke-observe",
                include_screenshot=True,
            )
            self.assertEqual(result.observation.title, "Authenticated fixture")
            self.assertTrue(
                any(element.name == "Save" for element in result.observation.elements)
            )
            screenshot = broker.capture_store.load_blob(
                result.observation.artifact_refs[0]
            )
            self.assertTrue(screenshot.startswith(b"\x89PNG"))
            self.assertTrue(result.persistence.stored)
            broker.close(
                session.session_id,
                context,
                expected_revision=result.session.revision,
                expected_epoch=result.session.epoch,
                operation_id="smoke-close",
            )
        finally:
            worker.shutdown()
            store.close()
            temporary.cleanup()
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
