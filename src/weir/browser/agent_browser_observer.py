from __future__ import annotations

import json
import math
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable

from weir.browser.models import ObservedElement
from weir.browser.policy import check_browser_target_policy
from weir.browser.protocol import (
    BrowserWorker,
    CommandExpired,
    IdempotentWorkerGuard,
    SessionSpec,
    WorkerCapability,
    WorkerCommand,
    WorkerDescriptor,
    WorkerObservation,
)
from weir.engines.agent_browser_reader import _run_detached_safe
from weir.engines.base import (
    EngineFailure,
    EnginePolicyBlocked,
    EngineProbe,
    EngineUnavailable,
)
from weir.engines.shims import safe_argv

Runner = Callable[[list[str], int], tuple[int, str, str]]


@dataclass(slots=True)
class _AgentBrowserSession:
    spec: SessionSpec
    cli_session: str
    current_url: str


class AgentBrowserObserverWorker(BrowserWorker):
    """Contained agent-browser adapter for ephemeral observation sessions.

    agent-browser rejects domain containment combined with Chrome profiles,
    storage-state replay, restore, CDP, and auto-connect. This adapter therefore
    accepts only logical profile IDs prefixed with ``ephemeral:`` and never adds
    any of those authority-expanding flags.
    """

    def __init__(
        self,
        *,
        binary: str = "agent-browser",
        worker_id: str = "agent-browser-observer-1",
        runner: Runner = _run_detached_safe,
        timeout_seconds: int = 60,
        max_output_chars: int = 200_000,
    ) -> None:
        self.binary = binary
        self.runner = runner
        self.timeout_seconds = timeout_seconds
        self.max_output_chars = max_output_chars
        self._guard = IdempotentWorkerGuard()
        self._sessions: dict[str, _AgentBrowserSession] = {}
        self._descriptor = WorkerDescriptor(
            worker_id=worker_id,
            engine="agent-browser",
            capabilities=frozenset(
                {
                    WorkerCapability.OPEN,
                    WorkerCapability.ATTACH,
                    WorkerCapability.NAVIGATE,
                    WorkerCapability.OBSERVE,
                    WorkerCapability.FENCE,
                    WorkerCapability.CLOSE,
                }
            ),
            instance_id=f"ab-worker-{uuid.uuid4().hex}",
        )

    @property
    def descriptor(self) -> WorkerDescriptor:
        return self._descriptor

    def probe(self) -> EngineProbe:
        path = shutil.which(self.binary)
        if path is None:
            return EngineProbe(
                self.descriptor.engine,
                False,
                detail=f"{self.binary} not found on PATH",
            )
        try:
            code, stdout, stderr = self.runner([path, "--version"], 15)
        except (OSError, subprocess.SubprocessError) as exc:
            return EngineProbe(self.descriptor.engine, False, detail=str(exc))
        reported = (stdout or stderr).strip() or None
        return EngineProbe(
            self.descriptor.engine,
            code == 0,
            version=reported,
            detail=path,
        )

    def open_session(self, spec: SessionSpec, command: WorkerCommand) -> str:
        with self._guard.serialize_worker_session(spec.session_id):
            return self._open_session_serialized(spec, command)

    def _open_session_serialized(self, spec: SessionSpec, command: WorkerCommand) -> str:
        payload = {"spec": spec.to_dict()}
        command.validate_for("open", payload)
        replay, result = self._guard.begin_worker_command(command)
        if replay:
            return str(result)
        if not spec.profile_id.startswith("ephemeral:"):
            raise EnginePolicyBlocked(
                "contained agent-browser sessions require an ephemeral: profile ID; "
                "persistent profiles and restored state are incompatible with its allowlist"
            )
        check_browser_target_policy(
            spec.initial_url, spec.allowed_domains, spec.data_class
        )
        cli_session = f"weir-{uuid.uuid4().hex}"
        created = False
        try:
            self._run_json(
                spec, cli_session, ["open", spec.initial_url], worker_command=command
            )
            created = True
            current_url = (
                self._get_value(spec, cli_session, "url", command) or spec.initial_url
            )
            check_browser_target_policy(
                current_url, spec.allowed_domains, spec.data_class
            )
        except Exception:
            if created:
                try:
                    self._run_json(
                        spec,
                        cli_session,
                        ["close"],
                        allow_empty=True,
                        worker_command=command,
                    )
                except Exception as cleanup_exc:
                    raise EngineFailure(
                        "agent-browser open failed and its ephemeral context could not be closed"
                    ) from cleanup_exc
            raise
        self._sessions[spec.session_id] = _AgentBrowserSession(
            spec, cli_session, current_url
        )
        return self._guard.remember_worker_result(command, cli_session)

    def attach_session(self, spec: SessionSpec, command: WorkerCommand) -> bool:
        with self._guard.serialize_worker_session(spec.session_id):
            return self._attach_session_serialized(spec, command)

    def _attach_session_serialized(self, spec: SessionSpec, command: WorkerCommand) -> bool:
        payload = {"spec": spec.to_dict()}
        command.validate_for("attach", payload)
        replay, result = self._guard.begin_worker_command(command)
        if replay:
            return bool(result)
        live = self._sessions.get(spec.session_id)
        attached = bool(
            live is not None
            and live.cli_session == spec.worker_session_id
            and live.spec.owner_run_id == spec.owner_run_id
            and live.spec.profile_id == spec.profile_id
            and live.spec.site_profile_id == spec.site_profile_id
            and live.spec.credential_scope == spec.credential_scope
            and live.spec.allowed_domains == spec.allowed_domains
            and live.spec.data_class is spec.data_class
        )
        return self._guard.remember_worker_result(command, attached)

    def navigate(self, session_id: str, url: str, command: WorkerCommand) -> str:
        with self._guard.serialize_worker_session(session_id):
            return self._navigate_serialized(session_id, url, command)

    def _navigate_serialized(
        self, session_id: str, url: str, command: WorkerCommand
    ) -> str:
        payload = {"session_id": session_id, "url": url}
        command.validate_for("navigate", payload)
        replay, result = self._guard.begin_worker_command(command)
        if replay:
            return str(result)
        live = self._required(session_id, command)
        check_browser_target_policy(url, live.spec.allowed_domains, live.spec.data_class)
        self._run_json(
            live.spec, live.cli_session, ["open", url], worker_command=command
        )
        final_url = self._get_value(
            live.spec, live.cli_session, "url", command
        ) or url
        check_browser_target_policy(
            final_url, live.spec.allowed_domains, live.spec.data_class
        )
        live.current_url = final_url
        return self._guard.remember_worker_result(command, final_url)

    def observe(
        self,
        session_id: str,
        command: WorkerCommand,
        *,
        include_screenshot: bool = False,
    ) -> WorkerObservation:
        if include_screenshot:
            raise EnginePolicyBlocked(
                "the contained agent-browser adapter has no coherent screenshot transport"
            )
        with self._guard.serialize_worker_session(session_id):
            return self._observe_serialized(session_id, command)

    def _observe_serialized(
        self, session_id: str, command: WorkerCommand
    ) -> WorkerObservation:
        payload = {"session_id": session_id}
        command.validate_for("observe", payload)
        replay, result = self._guard.begin_worker_command(command)
        if replay:
            return result
        live = self._required(session_id, command)
        response = self._run_json(
            live.spec,
            live.cli_session,
            ["snapshot", "-i"],
            worker_command=command,
        )
        data = response.get("data")
        if not isinstance(data, dict):
            raise EngineFailure("agent-browser snapshot returned no data object")
        snapshot = data.get("snapshot")
        refs = data.get("refs", {})
        if not isinstance(snapshot, str) or not isinstance(refs, dict):
            raise EngineFailure("agent-browser snapshot has an invalid shape")
        elements: list[ObservedElement] = []
        for ref, raw in refs.items():
            if not isinstance(ref, str) or not isinstance(raw, dict):
                continue
            role = raw.get("role")
            if not isinstance(role, str):
                continue
            name = raw.get("name") if isinstance(raw.get("name"), str) else None
            test_id = (
                raw.get("testId") if isinstance(raw.get("testId"), str) else None
            )
            state = _element_state(raw)
            elements.append(ObservedElement(ref, role.lower(), name, test_id, state))
        current_url = self._get_value(live.spec, live.cli_session, "url", command)
        title = self._get_value(live.spec, live.cli_session, "title", command)
        if current_url:
            check_browser_target_policy(
                current_url, live.spec.allowed_domains, live.spec.data_class
            )
            live.current_url = current_url
        boundary = response.get("_boundary")
        notes = ("agent-browser content boundary present",) if boundary else ()
        result = WorkerObservation(
            url=live.current_url,
            title=title,
            elements=tuple(elements),
            accessibility_snapshot=snapshot,
            notes=notes,
        )
        return self._guard.remember_worker_result(command, result)

    def screenshot(self, session_id: str, command: WorkerCommand) -> bytes:
        raise EnginePolicyBlocked(
            "the contained agent-browser adapter has no binary screenshot transport"
        )

    def fence_session(self, session_id: str, command: WorkerCommand) -> None:
        payload = {"session_id": session_id}
        with self._guard.serialize_worker_session(session_id):
            command.validate_for("fence", payload)
            replay, _ = self._guard.begin_worker_command(command)
            if replay:
                return
            self._required(session_id, command)
            self._guard.remember_worker_result(command, None)

    def close_session(self, session_id: str, command: WorkerCommand) -> None:
        with self._guard.serialize_worker_session(session_id):
            self._close_session_serialized(session_id, command)

    def _close_session_serialized(
        self, session_id: str, command: WorkerCommand
    ) -> None:
        payload = {"session_id": session_id}
        command.validate_for("close", payload)
        replay, _ = self._guard.begin_worker_command(command)
        if replay:
            return
        live = self._sessions.get(session_id)
        if live is None:
            self._guard.forget_worker_session(
                session_id, exclude_command_id=command.command_id
            )
            self._guard.remember_worker_result(command, None)
            return
        if command.owner_run_id != live.spec.owner_run_id:
            raise EngineFailure("agent-browser owner_run_id mismatch")
        self._run_json(
            live.spec,
            live.cli_session,
            ["close"],
            allow_empty=True,
            worker_command=command,
        )
        self._sessions.pop(session_id, None)
        self._guard.forget_worker_session(
            session_id, exclude_command_id=command.command_id
        )
        self._guard.remember_worker_result(command, None)

    def _required(
        self, session_id: str, command: WorkerCommand
    ) -> _AgentBrowserSession:
        live = self._sessions.get(session_id)
        if live is None:
            raise EngineFailure(f"agent-browser session {session_id!r} is not attached")
        if command.worker_session_id != live.cli_session:
            raise EngineFailure("agent-browser worker_session_id mismatch")
        if command.owner_run_id != live.spec.owner_run_id:
            raise EngineFailure("agent-browser owner_run_id mismatch")
        return live

    def _get_value(
        self,
        spec: SessionSpec,
        cli_session: str,
        name: str,
        worker_command: WorkerCommand,
    ) -> str | None:
        response = self._run_json(
            spec,
            cli_session,
            ["get", name],
            worker_command=worker_command,
        )
        data = response.get("data")
        if not isinstance(data, dict):
            return None
        for key in ("value", name, "text"):
            value = data.get(key)
            if isinstance(value, str):
                return value
        return None

    def _run_json(
        self,
        spec: SessionSpec,
        cli_session: str,
        command: list[str],
        *,
        allow_empty: bool = False,
        worker_command: WorkerCommand | None = None,
    ) -> dict[str, Any]:
        binary = shutil.which(self.binary)
        if binary is None and self.runner is _run_detached_safe:
            raise EngineUnavailable(f"{self.binary} not found on PATH")
        executable = binary or self.binary
        domains = []
        for domain in spec.allowed_domains:
            domains.extend((domain, f"*.{domain}"))
        argv = safe_argv(
            executable,
            [
                "--session",
                cli_session,
                "--allowed-domains",
                ",".join(domains),
                "--content-boundaries",
                "--max-output",
                str(self.max_output_chars),
                "--json",
                *command,
            ],
        )
        forbidden = {
            "--profile",
            "--state",
            "--restore",
            "--session-name",
            "--cdp",
            "--auto-connect",
            "--args",
        }
        if any(argument in forbidden for argument in argv):
            raise EnginePolicyBlocked("unsafe agent-browser startup option")
        timeout_seconds = self.timeout_seconds
        if worker_command is not None:
            deadline = worker_command.deadline_at.replace("Z", "+00:00")
            remaining = datetime.fromisoformat(deadline).timestamp() - time.time()
            if remaining <= 0:
                raise CommandExpired(
                    f"browser worker command {worker_command.command_id!r} expired"
                )
            timeout_seconds = max(1, min(timeout_seconds, math.ceil(remaining)))
        try:
            code, stdout, stderr = self.runner(argv, timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            raise EngineFailure(
                f"agent-browser timed out after {timeout_seconds} seconds"
            ) from exc
        if code != 0:
            raise EngineFailure(stderr.strip() or f"agent-browser exited {code}")
        text = stdout.strip()
        if not text and allow_empty:
            return {"success": True, "data": {}}
        if len(text) > self.max_output_chars + 20_000:
            raise EngineFailure("agent-browser output exceeded the broker envelope limit")
        try:
            value = json.loads(text)
        except json.JSONDecodeError as exc:
            raise EngineFailure("agent-browser returned invalid JSON") from exc
        if not isinstance(value, dict):
            raise EngineFailure("agent-browser returned a non-object response")
        if value.get("success") is False:
            raise EngineFailure(str(value.get("error") or "agent-browser failed"))
        return value


def _element_state(value: dict[str, Any]) -> str | None:
    for key, state in (
        ("disabled", "disabled"),
        ("checked", "checked"),
        ("selected", "selected"),
        ("expanded", "expanded"),
        ("pressed", "pressed"),
    ):
        if value.get(key) is True:
            return state
    state = value.get("state")
    return state.lower() if isinstance(state, str) and state else None


__all__ = ["AgentBrowserObserverWorker"]
