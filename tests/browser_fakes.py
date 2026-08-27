from __future__ import annotations

from weir.browser.models import ObservedElement
from weir.browser.protocol import (
    IdempotentWorkerGuard,
    SessionSpec,
    WorkerCapability,
    WorkerCommand,
    WorkerDescriptor,
    WorkerObservation,
)
from weir.engines.base import EngineProbe


class ScriptedBrowserWorker:
    def __init__(
        self,
        worker_id: str = "fake-worker-1",
        engine: str = "fake-browser",
    ) -> None:
        self._descriptor = WorkerDescriptor(
            worker_id=worker_id,
            engine=engine,
            capabilities=frozenset(WorkerCapability),
            version="test",
            instance_id="fake-instance-1",
        )
        self.guard = IdempotentWorkerGuard()
        self.sessions: dict[str, dict[str, str]] = {}
        self.calls: list[tuple[str, str]] = []
        self.attach_available = True
        self.fail_open = False
        self.fail_close = False

    @property
    def descriptor(self) -> WorkerDescriptor:
        return self._descriptor

    def probe(self) -> EngineProbe:
        return EngineProbe(self.descriptor.engine, True, version="test")

    def open_session(self, spec: SessionSpec, command: WorkerCommand) -> str:
        with self.guard.serialize_worker_session(spec.session_id):
            return self._open_session_serialized(spec, command)

    def _open_session_serialized(self, spec: SessionSpec, command: WorkerCommand) -> str:
        payload = {"spec": spec.to_dict()}
        command.validate_for("open", payload)
        replay, result = self.guard.begin_worker_command(command)
        if replay:
            return result
        self.calls.append(("open", command.command_id))
        if self.fail_open:
            raise RuntimeError("scripted open failure")
        worker_session_id = f"fake-context-{len(self.sessions) + 1}"
        self.sessions[spec.session_id] = {
            "worker_session_id": worker_session_id,
            "url": spec.initial_url,
            "owner_run_id": spec.owner_run_id,
        }
        return self.guard.remember_worker_result(command, worker_session_id)

    def attach_session(self, spec: SessionSpec, command: WorkerCommand) -> bool:
        with self.guard.serialize_worker_session(spec.session_id):
            return self._attach_session_serialized(spec, command)

    def _attach_session_serialized(self, spec: SessionSpec, command: WorkerCommand) -> bool:
        payload = {"spec": spec.to_dict()}
        command.validate_for("attach", payload)
        replay, result = self.guard.begin_worker_command(command)
        if replay:
            return result
        self.calls.append(("attach", command.command_id))
        live = self.sessions.get(spec.session_id)
        attached = bool(
            self.attach_available
            and live is not None
            and live["worker_session_id"] == spec.worker_session_id
            and live["owner_run_id"] == spec.owner_run_id
        )
        return self.guard.remember_worker_result(command, attached)

    def navigate(self, session_id: str, url: str, command: WorkerCommand) -> str:
        with self.guard.serialize_worker_session(session_id):
            return self._navigate_serialized(session_id, url, command)

    def _navigate_serialized(
        self, session_id: str, url: str, command: WorkerCommand
    ) -> str:
        payload = {"session_id": session_id, "url": url}
        command.validate_for("navigate", payload)
        replay, result = self.guard.begin_worker_command(command)
        if replay:
            return result
        self._assert_live(session_id, command)
        self.calls.append(("navigate", command.command_id))
        self.sessions[session_id]["url"] = url
        return self.guard.remember_worker_result(command, url)

    def observe(
        self,
        session_id: str,
        command: WorkerCommand,
        *,
        include_screenshot: bool = False,
    ) -> WorkerObservation:
        with self.guard.serialize_worker_session(session_id):
            return self._observe_serialized(
                session_id, command, include_screenshot=include_screenshot
            )

    def _observe_serialized(
        self,
        session_id: str,
        command: WorkerCommand,
        *,
        include_screenshot: bool = False,
    ) -> WorkerObservation:
        payload = {"session_id": session_id}
        if include_screenshot:
            payload["include_screenshot"] = True
        command.validate_for("observe", payload)
        replay, result = self.guard.begin_worker_command(command)
        if replay:
            return result
        self._assert_live(session_id, command)
        self.calls.append(("observe", command.command_id))
        result = WorkerObservation(
            url=self.sessions[session_id]["url"],
            title="Test portal",
            elements=(
                ObservedElement(
                    ref="fake-1",
                    role="button",
                    name="Save",
                    test_id="save",
                    state="enabled",
                ),
            ),
            accessibility_snapshot='- button "Save"',
            screenshot=b"fake-png" if include_screenshot else None,
        )
        return self.guard.remember_worker_result(command, result)

    def screenshot(self, session_id: str, command: WorkerCommand) -> bytes:
        with self.guard.serialize_worker_session(session_id):
            return self._screenshot_serialized(session_id, command)

    def _screenshot_serialized(self, session_id: str, command: WorkerCommand) -> bytes:
        payload = {"session_id": session_id}
        command.validate_for("screenshot", payload)
        replay, result = self.guard.begin_worker_command(command)
        if replay:
            return result
        self._assert_live(session_id, command)
        self.calls.append(("screenshot", command.command_id))
        return self.guard.remember_worker_result(command, b"fake-png")

    def fence_session(self, session_id: str, command: WorkerCommand) -> None:
        payload = {"session_id": session_id}
        with self.guard.serialize_worker_session(session_id):
            command.validate_for("fence", payload)
            replay, _ = self.guard.begin_worker_command(command)
            if replay:
                return
            self._assert_live(session_id, command)
            self.calls.append(("fence", command.command_id))
            self.guard.remember_worker_result(command, None)

    def close_session(self, session_id: str, command: WorkerCommand) -> None:
        with self.guard.serialize_worker_session(session_id):
            self._close_session_serialized(session_id, command)

    def _close_session_serialized(
        self, session_id: str, command: WorkerCommand
    ) -> None:
        payload = {"session_id": session_id}
        command.validate_for("close", payload)
        replay, _ = self.guard.begin_worker_command(command)
        if replay:
            return
        self.calls.append(("close", command.command_id))
        if self.fail_close:
            raise RuntimeError("scripted close failure")
        live = self.sessions.get(session_id)
        if live is not None and live["owner_run_id"] != command.owner_run_id:
            raise RuntimeError("fake owner mismatch")
        self.sessions.pop(session_id, None)
        self.guard.forget_worker_session(
            session_id, exclude_command_id=command.command_id
        )
        self.guard.remember_worker_result(command, None)

    def _assert_live(self, session_id: str, command: WorkerCommand) -> None:
        live = self.sessions.get(session_id)
        if live is None:
            raise RuntimeError("fake browser context is missing")
        if live["worker_session_id"] != command.worker_session_id:
            raise RuntimeError("fake worker_session_id mismatch")
        if live["owner_run_id"] != command.owner_run_id:
            raise RuntimeError("fake owner mismatch")
