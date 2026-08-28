from __future__ import annotations

import importlib.util
import json
import re
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from importlib.metadata import PackageNotFoundError, version
from typing import Any
from urllib.parse import urlsplit

from weir.browser.models import ObservedElement
from weir.browser.policy import (
    check_browser_resource_policy,
    check_browser_target_policy,
    resolve_browser_host,
)
from weir.browser.profile_registry import (
    EmptyProfileStateProvider,
    ProfileStateProvider,
    StaticProfileStateRegistry,
    VerifiedProfileBinding,
    VerifiedProfileState,
)
from weir.browser.protocol import (
    BrowserWorker,
    CommandExpired,
    IdempotentWorkerGuard,
    SessionSpec,
    StaleWorkerCommand,
    WorkerCapability,
    WorkerCommand,
    WorkerDescriptor,
    WorkerObservation,
)
from weir.engines.base import (
    EngineFailure,
    EnginePolicyBlocked,
    EngineProbe,
    EngineUnavailable,
)


@dataclass(slots=True)
class _LiveSession:
    worker_session_id: str
    spec: SessionSpec
    browser: Any
    context: Any
    page: Any
    containment: _ContainmentState


@dataclass(slots=True)
class _ContainmentState:
    request_count: int = 0
    declared_response_bytes: int = 0
    blocked_count: int = 0
    last_blocked_reason: str | None = None
    budget_exceeded: bool = False
    document_generation: int = 0

    def block(self, url: str, exc: Exception, *, method: str) -> None:
        self.blocked_count += 1
        parsed = urlsplit(url)
        host = (parsed.hostname or "opaque").lower()
        scheme = parsed.scheme.lower() or "unknown"
        if "response byte budget exceeded" in str(exc):
            reason = "response_byte_budget_exceeded"
            self.budget_exceeded = True
        elif "request budget exceeded" in str(exc):
            reason = "request_budget_exceeded"
            self.budget_exceeded = True
        elif "HTTP method" in str(exc):
            reason = f"http_method_{method.lower()}_blocked"
        elif isinstance(exc, EnginePolicyBlocked):
            reason = "target_policy_blocked"
        else:
            reason = "resource_validation_failed"
        # Deliberately omit path, query, fragment, and exception text. Page URLs
        # can contain bearer tokens or personal data and errors enter the journal.
        self.last_blocked_reason = (
            f"browser resource blocked: scheme={scheme} host={host} reason={reason}"
        )


_SNAPSHOT_LINE = re.compile(
    r'^\s*-\s+([a-z][a-z0-9_-]*)(?:\s+"((?:[^"\\]|\\.)*)")?'
    r"(?:\s+\[([^\]]+)\])?"
)
_ROLES = (
    "button",
    "link",
    "textbox",
    "checkbox",
    "radio",
    "combobox",
    "option",
    "heading",
    "img",
    "listitem",
    "tab",
    "menuitem",
    "switch",
    "spinbutton",
    "slider",
)
_STATES = (
    "disabled",
    "checked",
    "unchecked",
    "expanded",
    "collapsed",
    "selected",
    "pressed",
    "readonly",
    "required",
)


class PlaywrightObserverWorker(BrowserWorker):
    """Isolated Playwright worker with navigation and observation capabilities only.

    It never launches a persistent browser profile, attaches over CDP, evaluates page
    JavaScript, or exposes click/fill/upload methods.
    """

    def __init__(
        self,
        *,
        worker_id: str = "playwright-observer-1",
        profile_states: ProfileStateProvider | None = None,
        headless: bool = True,
        max_elements: int = 200,
        max_snapshot_chars: int = 500_000,
        max_screenshot_bytes: int = 10 * 1024 * 1024,
        max_requests_per_session: int = 2_048,
        max_declared_response_bytes: int = 16 * 1024 * 1024,
        max_declared_bytes_per_session: int = 64 * 1024 * 1024,
    ) -> None:
        if min(
            max_elements,
            max_snapshot_chars,
            max_screenshot_bytes,
            max_requests_per_session,
            max_declared_response_bytes,
            max_declared_bytes_per_session,
        ) < 1:
            raise ValueError("Playwright observation limits must be positive")
        self._descriptor = WorkerDescriptor(
            worker_id=worker_id,
            engine="playwright-observer",
            capabilities=frozenset(
                {
                    WorkerCapability.OPEN,
                    WorkerCapability.ATTACH,
                    WorkerCapability.NAVIGATE,
                    WorkerCapability.OBSERVE,
                    WorkerCapability.SCREENSHOT,
                    WorkerCapability.FENCE,
                    WorkerCapability.CLOSE,
                }
            ),
            version=_playwright_version(),
            instance_id=f"pw-worker-{uuid.uuid4().hex}",
        )
        self.profile_states = profile_states or EmptyProfileStateProvider()
        self.headless = headless
        self.max_elements = max_elements
        self.max_snapshot_chars = max_snapshot_chars
        self.max_screenshot_bytes = max_screenshot_bytes
        self.max_requests_per_session = max_requests_per_session
        self.max_declared_response_bytes = max_declared_response_bytes
        self.max_declared_bytes_per_session = max_declared_bytes_per_session
        self._guard = IdempotentWorkerGuard()
        self._sessions: dict[str, _LiveSession] = {}
        self._playwright: Any = None
        self._executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix=f"weir-{worker_id}"
        )
        self._lifecycle_lock = threading.Lock()
        self._shutdown = False

    @property
    def descriptor(self) -> WorkerDescriptor:
        return self._descriptor

    def probe(self) -> EngineProbe:
        if not _playwright_installed():
            return EngineProbe(
                engine=self.descriptor.engine,
                available=False,
                version=_playwright_version(),
                detail="install the optional 'browser' dependency and Chromium",
            )
        try:
            self._on_worker_thread("__probe__", self._probe_chromium_serialized)
        except Exception as exc:
            detail = " ".join(str(exc).split())[:240]
            return EngineProbe(
                engine=self.descriptor.engine,
                available=False,
                version=_playwright_version(),
                detail=f"Chromium launch probe failed: {detail or type(exc).__name__}",
            )
        return EngineProbe(
            engine=self.descriptor.engine,
            available=True,
            version=_playwright_version(),
            detail="sandboxed isolated contexts; authenticated observation only",
        )

    def _probe_chromium_serialized(self) -> None:
        if self._playwright is None:
            from playwright.sync_api import sync_playwright

            self._playwright = sync_playwright().start()
        browser = self._playwright.chromium.launch(
            headless=True,
            chromium_sandbox=True,
            args=["--no-proxy-server"],
        )
        browser.close()

    def open_session(self, spec: SessionSpec, command: WorkerCommand) -> str:
        return self._on_worker_thread(
            spec.session_id, self._open_session_serialized, spec, command
        )

    def _open_session_serialized(self, spec: SessionSpec, command: WorkerCommand) -> str:
        payload = {"spec": spec.to_dict()}
        command.validate_for("open", payload)
        replay, result = self._guard.begin_worker_command(command)
        if replay:
            return str(result)
        if spec.session_id in self._sessions:
            raise EngineFailure(f"session {spec.session_id!r} is already open")
        initial_host = check_browser_target_policy(
            spec.initial_url, spec.allowed_domains, spec.data_class
        )
        if initial_host not in spec.allowed_domains:
            raise EnginePolicyBlocked(
                "Playwright sessions require each reachable hostname to be an exact "
                "allowed_domains entry so its network address can be pinned"
            )

        verified_state = self.profile_states.state_for(spec.profile_id)
        if verified_state is None:
            raise EnginePolicyBlocked(
                f"no private browser state is configured for profile {spec.profile_id!r}"
            )
        if not isinstance(verified_state, VerifiedProfileState):
            raise EnginePolicyBlocked(
                "profile provider did not return registry-attested credential metadata"
            )
        storage_state = verified_state.validate_for(spec)
        if not any(
            isinstance(storage_state.get(key), list) and storage_state[key]
            for key in ("cookies", "origins")
        ):
            raise EnginePolicyBlocked(
                f"profile {spec.profile_id!r} contains no authenticated browser state"
            )
        browser = self._launch_browser(spec)
        context: Any = None
        containment = _ContainmentState()
        try:
            context = browser.new_context(
                storage_state=storage_state,
                service_workers="block",
                accept_downloads=False,
                java_script_enabled=False,
            )
            self._install_containment(context, spec, containment)
            page = context.new_page()
            page.on("popup", lambda popup: popup.close())
            page.on(
                "framenavigated",
                lambda frame: _record_main_frame_navigation(
                    page, frame, containment
                ),
            )
            page.goto(
                spec.initial_url,
                wait_until="domcontentloaded",
                timeout=_remaining_milliseconds(command),
            )
            _require_exact_allowed_host(page.url, spec)
            if containment.budget_exceeded:
                raise EnginePolicyBlocked(
                    containment.last_blocked_reason or "browser request budget exceeded"
                )
        except Exception as exc:
            try:
                _close_browser_context(context, browser)
            except EngineFailure as cleanup_exc:
                raise EngineFailure(
                    "Playwright open failed and browser cleanup could not be confirmed"
                ) from cleanup_exc
            self._raise_contained_failure(containment, exc)
        worker_session_id = f"pw-context-{uuid.uuid4().hex}"
        live = _LiveSession(worker_session_id, spec, browser, context, page, containment)
        self._sessions[spec.session_id] = live
        return self._guard.remember_worker_result(command, worker_session_id)

    def attach_session(self, spec: SessionSpec, command: WorkerCommand) -> bool:
        return self._on_worker_thread(
            spec.session_id, self._attach_session_serialized, spec, command
        )

    def _attach_session_serialized(self, spec: SessionSpec, command: WorkerCommand) -> bool:
        payload = {"spec": spec.to_dict()}
        command.validate_for("attach", payload)
        replay, result = self._guard.begin_worker_command(command)
        if replay:
            return bool(result)
        live = self._sessions.get(spec.session_id)
        attached = bool(
            live is not None
            and live.worker_session_id == spec.worker_session_id
            and live.spec.profile_id == spec.profile_id
            and live.spec.site_profile_id == spec.site_profile_id
            and live.spec.credential_scope == spec.credential_scope
            and live.spec.owner_run_id == spec.owner_run_id
            and live.spec.allowed_domains == spec.allowed_domains
            and live.spec.data_class is spec.data_class
        )
        return self._guard.remember_worker_result(command, attached)

    def navigate(self, session_id: str, url: str, command: WorkerCommand) -> str:
        return self._on_worker_thread(
            session_id, self._navigate_serialized, session_id, url, command
        )

    def _navigate_serialized(
        self, session_id: str, url: str, command: WorkerCommand
    ) -> str:
        payload = {"session_id": session_id, "url": url}
        command.validate_for("navigate", payload)
        replay, result = self._guard.begin_worker_command(command)
        if replay:
            return str(result)
        live = self._required_session(session_id, command)
        _require_exact_allowed_host(url, live.spec)
        blocked_before = live.containment.blocked_count
        try:
            live.page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=_remaining_milliseconds(command),
            )
            _require_exact_allowed_host(live.page.url, live.spec)
            if live.containment.budget_exceeded:
                raise EnginePolicyBlocked(
                    live.containment.last_blocked_reason
                    or "browser request budget exceeded"
                )
        except Exception as exc:
            self._raise_contained_failure(
                live.containment, exc, blocked_before=blocked_before
            )
        return self._guard.remember_worker_result(command, live.page.url)

    def observe(
        self,
        session_id: str,
        command: WorkerCommand,
        *,
        include_screenshot: bool = False,
    ) -> WorkerObservation:
        return self._on_worker_thread(
            session_id,
            self._observe_serialized,
            session_id,
            command,
            include_screenshot,
        )

    def _observe_serialized(
        self,
        session_id: str,
        command: WorkerCommand,
        include_screenshot: bool = False,
    ) -> WorkerObservation:
        payload: dict[str, Any] = {"session_id": session_id}
        if include_screenshot:
            payload["include_screenshot"] = True
        command.validate_for("observe", payload)
        replay, result = self._guard.begin_worker_command(command)
        if replay:
            return result
        live = self._required_session(session_id, command)
        initial_url = live.page.url
        initial_generation = live.containment.document_generation
        _require_exact_allowed_host(initial_url, live.spec)
        snapshot = live.page.locator("body").aria_snapshot(
            timeout=_remaining_milliseconds(command)
        )
        if len(snapshot) > self.max_snapshot_chars:
            raise EngineFailure("Playwright accessibility snapshot exceeded its size limit")
        elements = self._observed_elements(live.page, command)
        title = live.page.title() or None
        screenshot: bytes | None = None
        if include_screenshot:
            payload_bytes = live.page.screenshot(
                type="png", full_page=False, timeout=_remaining_milliseconds(command)
            )
            if len(payload_bytes) > self.max_screenshot_bytes:
                raise EngineFailure("Playwright screenshot exceeded its size limit")
            screenshot = bytes(payload_bytes)
        final_url = live.page.url
        if (
            live.containment.document_generation != initial_generation
            or final_url != initial_url
        ):
            raise StaleWorkerCommand(
                "the main document navigated while browser evidence was captured"
            )
        notes = ()
        if live.containment.blocked_count:
            notes = (f"blocked_resources={live.containment.blocked_count}",)
        result = WorkerObservation(
            url=final_url,
            title=title,
            elements=tuple(elements),
            accessibility_snapshot=snapshot,
            notes=notes,
            screenshot=screenshot,
        )
        return self._guard.remember_worker_result(command, result)

    def screenshot(self, session_id: str, command: WorkerCommand) -> bytes:
        return self._on_worker_thread(
            session_id, self._screenshot_serialized, session_id, command
        )

    def _screenshot_serialized(self, session_id: str, command: WorkerCommand) -> bytes:
        payload: dict[str, Any] = {"session_id": session_id}
        command.validate_for("screenshot", payload)
        replay, result = self._guard.begin_worker_command(command)
        if replay:
            return result
        live = self._required_session(session_id, command)
        payload_bytes = live.page.screenshot(
            type="png", full_page=False, timeout=_remaining_milliseconds(command)
        )
        if len(payload_bytes) > self.max_screenshot_bytes:
            raise EngineFailure("Playwright screenshot exceeded its size limit")
        return self._guard.remember_worker_result(command, bytes(payload_bytes))

    def fence_session(self, session_id: str, command: WorkerCommand) -> None:
        self._on_worker_thread(
            session_id, self._fence_session_serialized, session_id, command
        )

    def _fence_session_serialized(
        self, session_id: str, command: WorkerCommand
    ) -> None:
        payload: dict[str, Any] = {"session_id": session_id}
        command.validate_for("fence", payload)
        replay, _ = self._guard.begin_worker_command(command)
        if replay:
            return
        self._required_session(session_id, command)
        self._guard.remember_worker_result(command, None)

    def close_session(self, session_id: str, command: WorkerCommand) -> None:
        self._on_worker_thread(
            session_id, self._close_session_serialized, session_id, command
        )

    def _close_session_serialized(
        self, session_id: str, command: WorkerCommand
    ) -> None:
        payload: dict[str, Any] = {"session_id": session_id}
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
            raise EngineFailure("owner_run_id does not match the live context")
        _close_browser_context(live.context, live.browser)
        self._sessions.pop(session_id, None)
        self._guard.forget_worker_session(
            session_id, exclude_command_id=command.command_id
        )
        self._guard.remember_worker_result(command, None)

    def shutdown(self) -> None:
        with self._lifecycle_lock:
            if self._shutdown:
                return
            self._shutdown = True
            future = self._executor.submit(self._shutdown_serialized)
        try:
            future.result()
        finally:
            self._executor.shutdown(wait=True)

    def _shutdown_serialized(self) -> None:
        cleanup_errors: list[Exception] = []
        for session_id, live in list(self._sessions.items()):
            try:
                _close_browser_context(live.context, live.browser)
            except EngineFailure as exc:
                cleanup_errors.append(exc)
            else:
                self._sessions.pop(session_id, None)
        if self._playwright is not None:
            try:
                self._playwright.stop()
            except Exception as exc:
                cleanup_errors.append(exc)
            else:
                self._playwright = None
                self._sessions.clear()
        if cleanup_errors:
            raise EngineFailure(
                "one or more Playwright browser contexts could not be closed"
            ) from cleanup_errors[-1]

    def _on_worker_thread(
        self, session_id: str, function: Any, *args: Any
    ) -> Any:
        with self._lifecycle_lock:
            if self._shutdown:
                raise EngineUnavailable("Playwright observer worker is shut down")
            future = self._executor.submit(
                self._run_serialized, session_id, function, args
            )
        return future.result()

    def _run_serialized(
        self, session_id: str, function: Any, args: tuple[Any, ...]
    ) -> Any:
        with self._guard.serialize_worker_session(session_id):
            return function(*args)

    def _launch_browser(self, spec: SessionSpec) -> Any:
        if not _playwright_installed():
            raise EngineUnavailable("Playwright is not installed")
        try:
            if self._playwright is None:
                from playwright.sync_api import sync_playwright

                self._playwright = sync_playwright().start()
            mappings = []
            for host in spec.allowed_domains:
                address = resolve_browser_host(host, spec.data_class)
                destination = f"[{address}]" if ":" in address else address
                mappings.append(f"MAP {host} {destination}")
            mappings.append("MAP * ~NOTFOUND")
            return self._playwright.chromium.launch(
                headless=self.headless,
                chromium_sandbox=True,
                args=[
                    f"--host-resolver-rules={','.join(mappings)}",
                    "--host-resolver-retry-attempts=0",
                    "--no-proxy-server",
                ],
            )
        except (EngineFailure, EnginePolicyBlocked):
            raise
        except Exception as exc:
            raise EngineUnavailable(f"cannot launch Playwright Chromium: {exc}") from exc

    def _install_containment(
        self, context: Any, spec: SessionSpec, containment: _ContainmentState
    ) -> None:
        def route_request(route: Any) -> None:
            containment.request_count += 1
            try:
                url = route.request.url
                if containment.request_count > self.max_requests_per_session:
                    raise EnginePolicyBlocked("browser resource request budget exceeded")
                if route.request.method.upper() not in {"GET", "HEAD"}:
                    raise EnginePolicyBlocked(
                        f"HTTP method {route.request.method!r} is blocked in observation mode"
                    )
                if urlsplit(url).scheme.lower() in {"about", "blob", "data"}:
                    route.continue_()
                    return
                host = check_browser_target_policy(
                    url,
                    spec.allowed_domains,
                    spec.data_class,
                    resolve=False,
                )
                if host not in spec.allowed_domains:
                    raise EnginePolicyBlocked(
                        f"host {host!r} has no exact pinned address"
                    )
                # Resolve every request. Caching a prior answer here allows DNS
                # rebinding to bypass the private-address policy on later fetches.
                check_browser_resource_policy(
                    url, spec.allowed_domains, spec.data_class, resolve=True
                )
                route.continue_()
            except Exception as exc:
                containment.block(
                    route.request.url,
                    exc,
                    method=route.request.method,
                )
                route.abort("blockedbyclient")

        context.route("**/*", route_request)
        if hasattr(context, "route_web_socket"):
            context.route_web_socket("**/*", lambda websocket: websocket.close())
        if hasattr(context, "on"):
            context.on(
                "response",
                lambda response: self._enforce_declared_response_budget(
                    context, response, containment
                ),
            )

    def _enforce_declared_response_budget(
        self,
        context: Any,
        response: Any,
        containment: _ContainmentState,
    ) -> None:
        """Interrupt responses whose declared wire size exceeds local budgets.

        Missing Content-Length and compressed expansion still require the planned
        process/OS resource boundary; this is an early fail-closed defense where
        Chromium exposes a trustworthy nonnegative declaration.
        """

        if containment.budget_exceeded:
            return
        raw_length = response.header_value("content-length")
        if raw_length is None:
            return
        normalized = raw_length.strip()
        if not normalized.isascii() or not normalized.isdecimal():
            return
        declared = int(normalized)
        containment.declared_response_bytes += declared
        if (
            declared <= self.max_declared_response_bytes
            and containment.declared_response_bytes
            <= self.max_declared_bytes_per_session
        ):
            return
        error = EnginePolicyBlocked("browser response byte budget exceeded")
        containment.block(
            response.url,
            error,
            method=response.request.method,
        )
        # Playwright emits `response` after headers and before `requestfinished`.
        # Closing the isolated context here interrupts body transfer where headers
        # make the over-budget response knowable before full materialization.
        context.close()

    def _required_session(
        self, session_id: str, command: WorkerCommand
    ) -> _LiveSession:
        live = self._sessions.get(session_id)
        if live is None:
            raise EngineFailure(f"browser session {session_id!r} is not attached")
        if command.worker_session_id != live.worker_session_id:
            # Opening uses a pending worker-session ID; every later command must
            # address the exact context returned by open_session.
            raise EngineFailure("worker_session_id does not match the live context")
        if command.owner_run_id != live.spec.owner_run_id:
            raise EngineFailure("owner_run_id does not match the live context")
        return live

    def _observed_elements(
        self, page: Any, command: WorkerCommand
    ) -> list[ObservedElement]:
        elements: list[ObservedElement] = []
        for role in _ROLES:
            locator = page.get_by_role(role)
            count = min(locator.count(), self.max_elements - len(elements))
            for index in range(count):
                item = locator.nth(index)
                lines = item.aria_snapshot(
                    timeout=_remaining_milliseconds(command)
                ).splitlines()
                line = lines[0] if lines else ""
                parsed_role, name, state = _parse_snapshot_line(line, role)
                test_id = item.get_attribute(
                    "data-testid", timeout=_remaining_milliseconds(command)
                )
                elements.append(
                    ObservedElement(
                        ref=f"pw-{len(elements) + 1}",
                        role=parsed_role,
                        name=name,
                        test_id=test_id or None,
                        state=state,
                    )
                )
                if len(elements) >= self.max_elements:
                    return elements
        return elements

    @staticmethod
    def _raise_contained_failure(
        containment: _ContainmentState,
        exc: Exception,
        *,
        blocked_before: int = 0,
    ) -> None:
        if containment.blocked_count > blocked_before:
            raise EnginePolicyBlocked(
                containment.last_blocked_reason or "browser resource blocked"
            ) from exc
        if isinstance(exc, (EngineFailure, EnginePolicyBlocked)):
            raise exc
        raise EngineFailure(f"Playwright observation failed: {exc}") from exc


def _require_exact_allowed_host(url: str, spec: SessionSpec) -> str:
    host = check_browser_target_policy(url, spec.allowed_domains, spec.data_class)
    if host not in spec.allowed_domains:
        raise EnginePolicyBlocked(f"host {host!r} has no exact pinned address")
    return host


def _record_main_frame_navigation(
    page: Any, frame: Any, containment: _ContainmentState
) -> None:
    if frame == page.main_frame:
        containment.document_generation += 1


def _remaining_milliseconds(command: WorkerCommand) -> float:
    deadline = datetime.fromisoformat(command.deadline_at.replace("Z", "+00:00"))
    remaining = (deadline.timestamp() - time.time()) * 1000
    if remaining <= 0:
        raise CommandExpired(f"browser worker command {command.command_id!r} expired")
    return min(remaining, 120_000)


def _close_browser_context(context: Any, browser: Any) -> None:
    """Close an isolated context and confirm its owning browser terminated."""

    if context is not None:
        try:
            context.close()
        except Exception:
            # Browser termination is the definitive containment boundary. A
            # context-close error must not prevent that stronger cleanup step.
            pass
    try:
        browser.close()
    except Exception as exc:
        raise EngineFailure("Playwright browser cleanup could not be confirmed") from exc


def _parse_snapshot_line(line: str, fallback_role: str) -> tuple[str, str | None, str | None]:
    match = _SNAPSHOT_LINE.match(line)
    if not match:
        return fallback_role, None, None
    role, raw_name, raw_flags = match.groups()
    name = None
    if raw_name:
        try:
            name = json.loads(f'"{raw_name}"')
        except json.JSONDecodeError:
            name = raw_name
    flags = (raw_flags or "").replace(",", " ").split()
    state = next((candidate for candidate in _STATES if candidate in flags), None)
    return role, name, state


def _playwright_version() -> str | None:
    try:
        return version("playwright")
    except PackageNotFoundError:
        return None


def _playwright_installed() -> bool:
    try:
        return importlib.util.find_spec("playwright") is not None
    except (ImportError, ModuleNotFoundError):
        return False


__all__ = [
    "EmptyProfileStateProvider",
    "PlaywrightObserverWorker",
    "ProfileStateProvider",
    "StaticProfileStateRegistry",
    "VerifiedProfileBinding",
    "VerifiedProfileState",
]
