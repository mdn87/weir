from __future__ import annotations

import functools
import gc
import math
import multiprocessing
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import weakref
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import weir.browser.process_worker as process_worker_module
from tests.browser_fakes import ScriptedBrowserWorker
from weir.browser.admission import WorkerContainmentEvidence, WorkerResourceLimits
from weir.browser.broker import BrowserSessionBroker
from weir.browser.models import SessionState
from weir.browser.process_worker import (
    ProcessBrowserWorker,
    WorkerProcessRequestError,
    WorkerProcessStartupError,
    WorkerProcessTimeout,
    WorkerRemoteError,
)
from weir.browser.profile_registry import (
    StaticProfileStateRegistry,
    VerifiedProfileState,
)
from weir.browser.protocol import SessionSpec, WorkerCommand
from weir.browser.store import SQLiteSessionStore
from weir.models import DataClass, RequestMode, WebRequest
from weir.persistence import CaptureStore
from weir.work_context import WorkContext, WorkContextSource

from weir.profiles import SiteProfile, SiteProfileRegistry


class FailingWorker(ScriptedBrowserWorker):
    def open_session(self, spec: SessionSpec, command: WorkerCommand) -> str:
        raise RuntimeError("secret child failure detail")


class ProcessTreeWorker(ScriptedBrowserWorker):
    def __init__(self, marker: str) -> None:
        super().__init__()
        self.marker = Path(marker)

    def observe(
        self,
        session_id: str,
        command: WorkerCommand,
        *,
        include_screenshot: bool = False,
    ):
        creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            creationflags=creation_flags,
        )
        self.marker.write_text(str(child.pid), encoding="ascii")
        time.sleep(30)
        return super().observe(
            session_id,
            command,
            include_screenshot=include_screenshot,
        )


class ShutdownCountingWorker(ScriptedBrowserWorker):
    def __init__(self, marker: str) -> None:
        super().__init__()
        self.marker = Path(marker)

    def shutdown(self) -> None:
        count = int(self.marker.read_text(encoding="ascii"))
        self.marker.write_text(str(count + 1), encoding="ascii")


class SlowObservationWorker(ScriptedBrowserWorker):
    def __init__(self, started_marker: str, navigation_marker: str) -> None:
        super().__init__()
        self.started_marker = Path(started_marker)
        self.navigation_marker = Path(navigation_marker)

    def observe(
        self,
        session_id: str,
        command: WorkerCommand,
        *,
        include_screenshot: bool = False,
    ):
        self.started_marker.write_text("started", encoding="ascii")
        time.sleep(0.75)
        return super().observe(
            session_id,
            command,
            include_screenshot=include_screenshot,
        )

    def navigate(self, session_id: str, url: str, command: WorkerCommand) -> str:
        self.navigation_marker.write_text("dispatched", encoding="ascii")
        return super().navigate(session_id, url, command)


class HugeScreenshotWorker(ScriptedBrowserWorker):
    def screenshot(self, session_id: str, command: WorkerCommand) -> bytes:
        return b"x" * 4096


class SelfTerminatingWorker(ScriptedBrowserWorker):
    def __init__(self) -> None:
        super().__init__()
        threading.Thread(target=self._terminate, daemon=True).start()

    @staticmethod
    def _terminate() -> None:
        time.sleep(0.5)
        os._exit(17)


def scripted_factory() -> ScriptedBrowserWorker:
    return ScriptedBrowserWorker()


def failing_factory() -> FailingWorker:
    return FailingWorker()


def broken_factory():
    raise RuntimeError("secret startup failure")


def _parent_death_host(worker_marker: str, descendant_marker: str) -> None:
    worker = ProcessBrowserWorker(
        functools.partial(ProcessTreeWorker, descendant_marker),
        call_timeout_seconds=30,
        shutdown_timeout_seconds=2,
    )
    Path(worker_marker).write_text(str(worker.process_id), encoding="ascii")
    worker.observe(
        "session-process-1",
        _command("observe", {"session_id": "session-process-1"}, seconds=30),
    )


def _spec() -> SessionSpec:
    return SessionSpec(
        session_id="session-process-1",
        worker_session_id="pending-session-process-1",
        owner_run_id="run-process-1",
        profile_id="ephemeral:process-1",
        credential_binding_id="credential-binding-process-1",
        site_profile_id="site-process-1",
        credential_scope="read-only",
        data_class=DataClass.PUBLIC,
        allowed_domains=("example.test",),
        initial_url="https://example.test/start",
    )


def _command(
    operation: str,
    payload,
    *,
    worker_session_id: str = "pending-session-process-1",
    seconds: float = 5,
) -> WorkerCommand:
    return WorkerCommand.build(
        command_id=f"command-{operation}-{time.monotonic_ns()}",
        operation=operation,
        session_id="session-process-1",
        worker_session_id=worker_session_id,
        owner_run_id="run-process-1",
        expected_revision=1,
        session_epoch=1,
        lease_fence=1,
        deadline_at=datetime.now(timezone.utc) + timedelta(seconds=seconds),
        payload=payload,
    )


class ProcessBrowserWorkerTests(unittest.TestCase):
    def test_timeouts_must_be_finite_and_platform_representable(self):
        values = (math.nan, math.inf, -math.inf, threading.TIMEOUT_MAX * 2, 10**1000)
        for value in values:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    ProcessBrowserWorker(
                        scripted_factory,
                        call_timeout_seconds=value,
                    )

    def test_explicit_resource_limits_are_attested_before_worker_start(self):
        limits = WorkerResourceLimits(512 * 1024 * 1024, 8)

        def prepared_containment(
            process_id: int,
            requested: WorkerResourceLimits,
            base: WorkerContainmentEvidence,
        ) -> WorkerContainmentEvidence:
            self.assertEqual(requested, limits)
            self.assertEqual(process_id, base.process_id)
            return replace(
                base,
                resource_limits=requested,
                resource_limits_enforced=True,
            )

        with ProcessBrowserWorker(
            scripted_factory,
            resource_limits=limits,
            containment_verifier=prepared_containment,
        ) as worker:
            evidence = worker.containment_evidence
            self.assertTrue(worker.production_process_transport)
            self.assertEqual(evidence.process_id, worker.process_id)
            self.assertEqual(evidence.resource_limits, limits)
            self.assertTrue(evidence.resource_limits_enforced)
            self.assertTrue(evidence.process_tree_enforced)
            self.assertTrue(evidence.kill_on_supervisor_exit)

    def test_resource_limits_without_platform_enforcement_fail_closed(self):
        limits = WorkerResourceLimits(512 * 1024 * 1024, 8)
        if os.name == "nt":
            with ProcessBrowserWorker(
                scripted_factory,
                resource_limits=limits,
            ) as worker:
                self.assertEqual(worker.containment_evidence.resource_limits, limits)
                self.assertTrue(
                    worker.containment_evidence.resource_limits_enforced
                )
            return

        with self.assertRaises(WorkerProcessStartupError):
            ProcessBrowserWorker(scripted_factory, resource_limits=limits)

    def test_containment_verifier_cannot_rebind_another_process(self):
        limits = WorkerResourceLimits(512 * 1024 * 1024, 8)

        def wrong_process(
            process_id: int,
            requested: WorkerResourceLimits,
            base: WorkerContainmentEvidence,
        ) -> WorkerContainmentEvidence:
            return replace(
                base,
                process_id=process_id + 1,
                resource_limits=requested,
                resource_limits_enforced=True,
            )

        with self.assertRaises(WorkerProcessStartupError):
            ProcessBrowserWorker(
                scripted_factory,
                resource_limits=limits,
                containment_verifier=wrong_process,
            )

    def test_protocol_round_trip_and_graceful_tree_attestation(self):
        worker = ProcessBrowserWorker(scripted_factory)
        with worker:
            self.assertNotEqual(worker.process_id, os.getpid())
            self.assertTrue(worker.probe().available)
            spec = _spec()
            worker_session_id = worker.open_session(
                spec,
                _command("open", {"spec": spec.to_dict()}),
            )
            attached_spec = replace(spec, worker_session_id=worker_session_id)
            self.assertTrue(
                worker.attach_session(
                    attached_spec,
                    _command(
                        "attach",
                        {"spec": attached_spec.to_dict()},
                        worker_session_id=worker_session_id,
                    ),
                )
            )
            final_url = "https://example.test/next"
            self.assertEqual(
                worker.navigate(
                    spec.session_id,
                    final_url,
                    _command(
                        "navigate",
                        {"session_id": spec.session_id, "url": final_url},
                        worker_session_id=worker_session_id,
                    ),
                ),
                final_url,
            )
            observation = worker.observe(
                spec.session_id,
                _command(
                    "observe",
                    {"session_id": spec.session_id, "include_screenshot": True},
                    worker_session_id=worker_session_id,
                ),
                include_screenshot=True,
            )
            self.assertEqual(observation.url, final_url)
            self.assertEqual(observation.screenshot, b"fake-png")
            self.assertEqual(
                worker.screenshot(
                    spec.session_id,
                    _command(
                        "screenshot",
                        {"session_id": spec.session_id},
                        worker_session_id=worker_session_id,
                    ),
                ),
                b"fake-png",
            )
            worker.fence_session(
                spec.session_id,
                _command(
                    "fence",
                    {"session_id": spec.session_id},
                    worker_session_id=worker_session_id,
                ),
            )
            worker.close_session(
                spec.session_id,
                _command(
                    "close",
                    {"session_id": spec.session_id},
                    worker_session_id=worker_session_id,
                ),
            )

        attestation = worker.death_attestation
        self.assertIsNotNone(attestation)
        self.assertTrue(attestation.worker_exited_gracefully)
        self.assertTrue(attestation.process_tree_confirmed_dead)
        self.assertFalse(worker.is_alive)
        self.assertIsNone(worker._process._popen)  # noqa: SLF001 - handle regression
        attestation.validate()

    def test_remote_exception_is_generic_and_does_not_kill_worker(self):
        with ProcessBrowserWorker(failing_factory) as worker:
            spec = _spec()
            with self.assertRaises(WorkerRemoteError) as raised:
                worker.open_session(
                    spec,
                    _command("open", {"spec": spec.to_dict()}),
                )
            self.assertNotIn("secret child failure", str(raised.exception))
            self.assertTrue(worker.is_alive)

    def test_deadline_kills_worker_and_descendant_process_tree(self):
        with tempfile.TemporaryDirectory() as temp:
            marker = Path(temp) / "grandchild.pid"
            worker = ProcessBrowserWorker(
                functools.partial(ProcessTreeWorker, str(marker)),
                call_timeout_seconds=0.5,
                shutdown_timeout_seconds=2,
            )
            command = _command(
                "observe",
                {"session_id": "session-process-1"},
                seconds=1,
            )
            started = time.monotonic()
            with self.assertRaises(WorkerProcessTimeout):
                worker.observe("session-process-1", command)
            self.assertLess(time.monotonic() - started, 4)
            self.assertTrue(marker.exists())
            grandchild_pid = int(marker.read_text(encoding="ascii"))
            try:
                deadline = time.monotonic() + 3
                while _pid_exists(grandchild_pid) and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertFalse(_pid_exists(grandchild_pid))
            finally:
                if _pid_exists(grandchild_pid):
                    os.kill(grandchild_pid, signal.SIGTERM)
            self.assertFalse(worker.is_alive)
            self.assertEqual(
                worker.death_attestation.reason,
                "deadline_exceeded",
            )
            self.assertTrue(worker.death_attestation.process_tree_confirmed_dead)

    def test_factory_failure_is_safe(self):
        with self.assertRaises(WorkerProcessStartupError) as raised:
            ProcessBrowserWorker(broken_factory, start_timeout_seconds=3)
        self.assertNotIn("secret startup failure", str(raised.exception))

    def test_expired_command_waiting_for_lock_is_never_dispatched(self):
        with tempfile.TemporaryDirectory() as temp:
            started_marker = Path(temp) / "observe-started"
            navigation_marker = Path(temp) / "navigate-dispatched"
            worker = ProcessBrowserWorker(
                functools.partial(
                    SlowObservationWorker,
                    str(started_marker),
                    str(navigation_marker),
                )
            )
            try:
                spec = _spec()
                worker_session_id = worker.open_session(
                    spec,
                    _command("open", {"spec": spec.to_dict()}),
                )
                outcome = []

                def observe() -> None:
                    outcome.append(
                        worker.observe(
                            spec.session_id,
                            _command(
                                "observe",
                                {"session_id": spec.session_id},
                                worker_session_id=worker_session_id,
                            ),
                        )
                    )

                thread = threading.Thread(target=observe)
                thread.start()
                self.assertTrue(_wait_for_path(started_marker))
                with self.assertRaises(WorkerProcessTimeout) as raised:
                    worker.navigate(
                        spec.session_id,
                        "https://example.test/late",
                        _command(
                            "navigate",
                            {
                                "session_id": spec.session_id,
                                "url": "https://example.test/late",
                            },
                            worker_session_id=worker_session_id,
                            seconds=0.1,
                        ),
                    )
                thread.join(timeout=3)
                self.assertFalse(thread.is_alive())
                self.assertEqual(raised.exception.failure_class.value, "command_expired")
                self.assertEqual(len(outcome), 1)
                self.assertFalse(navigation_marker.exists())
                self.assertTrue(worker.is_alive)
            finally:
                worker.shutdown()

    def test_ipc_size_limits_fail_closed_without_dispatch(self):
        worker = ProcessBrowserWorker(
            scripted_factory,
            max_request_bytes=2048,
        )
        try:
            with self.assertRaises(WorkerProcessRequestError):
                worker.navigate(
                    "session-process-1",
                    "https://example.test/" + ("x" * 4096),
                    _command(
                        "navigate",
                        {
                            "session_id": "session-process-1",
                            "url": "https://example.test/" + ("x" * 4096),
                        },
                    ),
                )
            self.assertTrue(worker.is_alive)
        finally:
            worker.shutdown()

        worker = ProcessBrowserWorker(
            HugeScreenshotWorker,
            max_response_bytes=2048,
        )
        try:
            with self.assertRaises(WorkerRemoteError):
                worker.screenshot(
                    "session-process-1",
                    _command("screenshot", {"session_id": "session-process-1"}),
                )
            self.assertTrue(worker.is_alive)
        finally:
            worker.shutdown()

    def test_parent_death_kills_worker_and_descendant_tree(self):
        with tempfile.TemporaryDirectory() as temp:
            worker_marker = Path(temp) / "worker.pid"
            descendant_marker = Path(temp) / "descendant.pid"
            context = multiprocessing.get_context("spawn")
            host = context.Process(
                target=_parent_death_host,
                args=(str(worker_marker), str(descendant_marker)),
            )
            host.start()
            worker_pid = None
            descendant_pid = None
            try:
                self.assertTrue(_wait_for_path(worker_marker, timeout=5))
                self.assertTrue(_wait_for_path(descendant_marker, timeout=5))
                worker_pid = int(worker_marker.read_text(encoding="ascii"))
                descendant_pid = int(descendant_marker.read_text(encoding="ascii"))
                host.terminate()
                host.join(timeout=5)
                self.assertFalse(host.is_alive())
                self.assertTrue(_wait_for_pid_exit(worker_pid, timeout=5))
                self.assertTrue(_wait_for_pid_exit(descendant_pid, timeout=5))
            finally:
                if host.is_alive():
                    host.terminate()
                    host.join(timeout=5)
                for process_id in (worker_pid, descendant_pid):
                    if process_id is not None and _pid_exists(process_id):
                        os.kill(process_id, signal.SIGTERM)
                if not host.is_alive():
                    host.close()

    def test_unexpected_worker_exit_is_reaped_without_an_api_call(self):
        worker = ProcessBrowserWorker(SelfTerminatingWorker)
        deadline = time.monotonic() + 4
        while worker.death_attestation is None and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertIsNotNone(worker.death_attestation)
        self.assertEqual(worker.death_attestation.reason, "worker_exited")
        self.assertFalse(worker.death_attestation.worker_exited_gracefully)
        self.assertTrue(worker.death_attestation.process_tree_confirmed_dead)
        self.assertFalse(worker.is_alive)

    def test_response_decoding_cannot_outlive_transport_deadline(self):
        worker = ProcessBrowserWorker(
            scripted_factory,
            call_timeout_seconds=0.2,
            shutdown_timeout_seconds=2,
        )
        original_decode = process_worker_module._decode_message

        def slow_decode(payload: bytes):
            time.sleep(1)
            return original_decode(payload)

        started = time.monotonic()
        with patch.object(process_worker_module, "_decode_message", new=slow_decode):
            with self.assertRaises(WorkerProcessTimeout):
                worker.probe()
        self.assertLess(time.monotonic() - started, 3)
        self.assertFalse(worker.is_alive)
        self.assertEqual(worker.death_attestation.reason, "deadline_exceeded")

    def test_ipc_codec_rejects_executable_and_ambiguous_payloads(self):
        with self.assertRaises(ValueError):
            process_worker_module._decode_message(b"\x80\x04N.")
        with self.assertRaises(ValueError):
            process_worker_module._decode_message(b'{"kind":"one","kind":"two"}')
        with self.assertRaises(ValueError):
            process_worker_module._decode_message(b'{"value":NaN}')
        invalid_error = process_worker_module._encode_message(
            {
                "kind": "error",
                "request_id": 1,
                "failure_class": "not-a-failure-class",
            },
            1024,
        )
        with self.assertRaises(ValueError):
            process_worker_module._decode_rpc_response(
                invalid_error,
                operation="probe",
                request_id=1,
            )

    def test_abandoned_wrapper_terminates_worker_process(self):
        worker = ProcessBrowserWorker(scripted_factory, shutdown_timeout_seconds=2)
        process = worker._process  # noqa: SLF001 - abandonment regression fixture
        process_id = worker.process_id
        reference = weakref.ref(worker)
        try:
            del worker
            deadline = time.monotonic() + 5
            while reference() is not None and time.monotonic() < deadline:
                gc.collect()
                time.sleep(0.02)
            self.assertIsNone(reference())
            self.assertTrue(_wait_for_pid_exit(process_id, timeout=5))
        finally:
            try:
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=2)
                if not process.is_alive():
                    process.close()
            except ValueError:
                pass

    def test_worker_shutdown_runs_once(self):
        with tempfile.TemporaryDirectory() as temp:
            marker = Path(temp) / "shutdown-count.txt"
            marker.write_text("0", encoding="ascii")
            with ProcessBrowserWorker(functools.partial(ShutdownCountingWorker, str(marker))):
                pass
            self.assertEqual(marker.read_text(encoding="ascii"), "1")

    def test_browser_broker_uses_process_worker_as_drop_in_transport(self):
        now = datetime.now(timezone.utc)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            store = SQLiteSessionStore(root / "browser.sqlite3", clock=lambda: now)
            worker = ProcessBrowserWorker(scripted_factory)
            try:
                profile = SiteProfile.from_dict(
                    {
                        "contract_version": "0.1",
                        "id": "test-portal",
                        "domains": ["127.0.0.1"],
                        "preferred_engines": ["fake-browser"],
                        "auth_mode": "dedicated_profile",
                        "allowed_modes": ["observe"],
                        "approval_risks": ["external_submit"],
                        "known_failures": {},
                        "retention": {"screenshots": "full_evidence"},
                        "browser_observation": {
                            "javascript": "disabled",
                            "network_methods": "get_head_only",
                            "credential_scope": "read_only",
                        },
                        "notes": ["Out-of-process broker integration fixture."],
                    }
                )
                broker = BrowserSessionBroker(
                    [worker],
                    store=store,
                    capture_store=CaptureStore(root / "evidence"),
                    profiles=SiteProfileRegistry([profile]),
                    profile_bindings=StaticProfileStateRegistry(
                        [
                            VerifiedProfileState(
                                profile_id="profile-process-broker",
                                credential_binding_id="credential-binding-process-broker",
                                site_profile_id="test-portal",
                                credential_scope="read_only",
                                storage_state={},
                            )
                        ]
                    ),
                    clock=lambda: now,
                )
                request = WebRequest(
                    request_id="request-process-broker",
                    run_id="run-process-broker",
                    mode=RequestMode.OBSERVE,
                    data_class=DataClass.BWA_INTERNAL,
                    auth_context="browser",
                    intent="exercise the process-backed browser broker",
                    url="http://127.0.0.1:8765/start",
                    profile_id="profile-process-broker",
                    allowed_domains=["127.0.0.1"],
                    capture_policy="full_evidence",
                )
                context = WorkContext.create(
                    context_id="context-process-broker",
                    objective_id="objective-process-broker",
                    run_id=request.run_id,
                    assignment_id="assignment-process-broker",
                    correlation_id=request.request_id,
                    source=WorkContextSource.OGMI,
                    created_at=now.isoformat(),
                )

                session = broker.open(
                    request,
                    context,
                    worker_id=worker.descriptor.worker_id,
                    operation_id="open-process-broker",
                )
                observed = broker.observe(
                    session.session_id,
                    context,
                    expected_revision=session.revision,
                    expected_epoch=session.epoch,
                    operation_id="observe-process-broker",
                    include_screenshot=True,
                )
                closed = broker.close(
                    session.session_id,
                    context,
                    expected_revision=observed.session.revision,
                    expected_epoch=observed.session.epoch,
                    operation_id="close-process-broker",
                )

                self.assertEqual(closed.state, SessionState.CLOSED)
                self.assertTrue(observed.persistence.stored)
                self.assertEqual(observed.capture.engine_version, "test")
            finally:
                worker.shutdown()
                store.close()


def _pid_exists(process_id: int) -> bool:
    if os.name != "nt":
        try:
            os.kill(process_id, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    open_process = kernel32.OpenProcess
    open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    open_process.restype = wintypes.HANDLE
    get_exit_code = kernel32.GetExitCodeProcess
    get_exit_code.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    get_exit_code.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    handle = open_process(0x1000, False, process_id)
    if not handle:
        return False
    try:
        exit_code = wintypes.DWORD()
        return bool(get_exit_code(handle, ctypes.byref(exit_code))) and (exit_code.value == 259)
    finally:
        close_handle(handle)


def _wait_for_path(path: Path, *, timeout: float = 3) -> bool:
    deadline = time.monotonic() + timeout
    while not path.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    return path.exists()


def _wait_for_pid_exit(process_id: int, *, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while _pid_exists(process_id) and time.monotonic() < deadline:
        time.sleep(0.05)
    return not _pid_exists(process_id)


if __name__ == "__main__":
    unittest.main()
