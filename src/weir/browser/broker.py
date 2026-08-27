from __future__ import annotations

import json
import re
import urllib.parse
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Callable

from weir.browser.models import (
    BrowserSession,
    ControllerKind,
    ControllerLease,
    Observation,
    SessionState,
)
from weir.browser.policy import check_browser_target_policy, normalize_allowed_domains
from weir.browser.protocol import (
    BrowserWorker,
    SessionSpec,
    WorkerCapability,
    WorkerCommand,
    canonical_digest,
)
from weir.browser.store import (
    CommandAttemptSuperseded,
    CommandInDoubt,
    SessionRevisionConflict,
    SQLiteSessionStore,
)
from weir.engines.base import (
    ControllerConflict,
    EngineFailure,
    EnginePolicyBlocked,
    FailureClass,
    WeirEngineError,
)
from weir.models import DataClass, ReaderResult, RequestMode, WebCapture, WebRequest
from weir.persistence import CaptureStore, PersistenceInfo
from weir.profiles import SiteProfile, SiteProfileRegistry
from weir.work_context import WorkContext

MAX_BROWSER_CAPTURE_BYTES = 5 * 1024 * 1024
MAX_BROWSER_SCREENSHOT_BYTES = 10 * 1024 * 1024
_EXTERNAL_OPERATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class SessionOwnershipError(ControllerConflict):
    pass


@dataclass(frozen=True, slots=True)
class NavigationResult:
    session: BrowserSession
    final_url: str
    committed_revision: int
    command_id: str


@dataclass(frozen=True, slots=True)
class BrowserObservationResult:
    session: BrowserSession
    observation: Observation
    capture: WebCapture
    persistence: PersistenceInfo
    command_id: str


class BrowserSessionBroker:
    """Durable browser-session coordinator, intentionally separate from acquisition."""

    def __init__(
        self,
        workers: list[BrowserWorker],
        *,
        store: SQLiteSessionStore,
        capture_store: CaptureStore,
        profiles: SiteProfileRegistry,
        clock: Callable[[], datetime] | None = None,
        id_factory: Callable[[str], str] | None = None,
        session_ttl: timedelta = timedelta(hours=1),
        controller_ttl: timedelta = timedelta(minutes=2),
        command_timeout: timedelta = timedelta(seconds=30),
        command_resume_after: timedelta | None = None,
        max_capture_bytes: int = MAX_BROWSER_CAPTURE_BYTES,
        max_screenshot_bytes: int = MAX_BROWSER_SCREENSHOT_BYTES,
    ) -> None:
        self.workers = {worker.descriptor.worker_id: worker for worker in workers}
        if len(self.workers) != len(workers):
            raise ValueError("browser worker IDs must be unique")
        self.store = store
        self.capture_store = capture_store
        self.profiles = profiles
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.id_factory = id_factory or (lambda prefix: f"{prefix}-{uuid.uuid4().hex}")
        self.session_ttl = session_ttl
        self.controller_ttl = controller_ttl
        self.command_timeout = command_timeout
        self.command_resume_after = command_resume_after or (command_timeout * 2)
        self.max_capture_bytes = max_capture_bytes
        self.max_screenshot_bytes = max_screenshot_bytes
        if min(
            session_ttl.total_seconds(),
            controller_ttl.total_seconds(),
            command_timeout.total_seconds(),
            self.command_resume_after.total_seconds(),
        ) <= 0:
            raise ValueError("browser broker TTL and timeout values must be positive")
        if self.command_resume_after <= self.command_timeout:
            raise ValueError("command resume delay must exceed the worker command timeout")
        if max_capture_bytes < 256 or max_screenshot_bytes < 256:
            raise ValueError("browser evidence limits must be at least 256 bytes")

    def open(
        self,
        request: WebRequest,
        context: WorkContext,
        *,
        worker_id: str,
        operation_id: str,
    ) -> BrowserSession:
        _require_external_operation_id(operation_id)
        worker = self._worker(worker_id)
        profile = self._validate_open_request(request, context, worker)
        reserved_instance = self.store.started_open_worker_instance(operation_id)
        if reserved_instance is not None and (
            reserved_instance != worker.descriptor.instance_id
        ):
            raise CommandInDoubt(
                f"open command {operation_id!r} is reserved by another worker process"
            )
        request_basis = {
            "request": request.to_dict(),
            "work_context": context.to_dict(),
            "worker_id": worker_id,
            "site_profile": profile.id,
        }
        start = self.store.begin_command(
            operation_id,
            "open",
            canonical_digest(request_basis),
            resume_after=self.command_resume_after,
        )
        if start.replay:
            return self.store.get_session(_result_string(start.result, "session_id"))
        if start.resume:
            return self._resume_open(
                request,
                context,
                worker,
                profile,
                operation_id=operation_id,
                attempt_token=start.attempt_token or "",
            )

        session_id = self.id_factory("browser")
        pending_worker_session_id = self.id_factory("pending")
        now = _utc_now(self.clock)
        session = BrowserSession(
            session_id=session_id,
            owner_run_id=request.run_id,
            engine=worker.descriptor.engine,
            worker_id=worker.descriptor.worker_id,
            worker_session_id=pending_worker_session_id,
            profile_id=request.profile_id or "",
            data_class=request.data_class,
            allowed_domains=list(normalize_allowed_domains(request.allowed_domains)),
            state=SessionState.OPENING,
            revision=0,
            epoch=1,
            current_url=None,
            created_at=now.isoformat(),
            updated_at=now.isoformat(),
            expires_at=(now + self.session_ttl).isoformat(),
        )
        created = False
        lease: ControllerLease | None = None
        worker_context_created = False
        worker_context_recorded = False
        try:
            session = self.store.create_session(
                session,
                work_context=context,
                site_profile_id=profile.id,
                credential_scope=profile.browser_observation["credential_scope"],
                profile_policy_digest=_profile_policy_digest(profile),
                opening_operation_id=operation_id,
            )
            created = True
            lease = self.store.acquire_lease(
                session_id,
                request.run_id,
                ControllerKind.AUTOMATION,
                ttl=self.controller_ttl,
            )
            spec = self._spec(session, request.url or "", profile=profile)
            payload = {"spec": spec.to_dict()}
            command = self._command(operation_id, "open", session, lease, payload)
            self.store.reserve_worker_open(
                session_id,
                command_id=operation_id,
                attempt_token=start.attempt_token or "",
                worker_instance_id=worker.descriptor.instance_id or "",
                expected_revision=session.revision,
                expected_epoch=session.epoch,
                required_lease=lease,
            )
            worker_session_id = worker.open_session(spec, command)
            if not worker_session_id:
                raise RuntimeError("browser worker returned an empty worker_session_id")
            worker_context_created = True
            # Persist the cleanup target before any later database operation can
            # fail and strand an authenticated worker context.
            session.worker_session_id = worker_session_id
            session = self.store.record_worker_context_created(
                session_id,
                worker_session_id=worker_session_id,
                worker_instance_id=worker.descriptor.instance_id or "",
                command_id=operation_id,
                attempt_token=start.attempt_token,
            )
            worker_context_recorded = True
            result = {"session_id": session_id, "revision": session.revision + 1}
            session = self.store.activate_opening_session(
                session_id,
                session.revision,
                current_url=request.url,
                worker_session_id=worker_session_id,
                worker_instance_id=worker.descriptor.instance_id or "",
                event_type="web.browser.session.opened",
                attributes={
                    "command_id": operation_id,
                    "context_hash": context.context_hash,
                    "site_profile": profile.id,
                },
                complete_command_id=operation_id,
                command_result=result,
                command_attempt_token=start.attempt_token,
                required_lease=lease,
            )
            return session
        except CommandAttemptSuperseded:
            raise
        except Exception as exc:
            if not self.store.fail_command(
                operation_id,
                _safe_error(exc),
                attempt_token=start.attempt_token,
            ):
                raise CommandAttemptSuperseded(
                    f"open command {operation_id!r} attempt was superseded"
                ) from exc
            if worker_context_created and lease is not None:
                cleanup_succeeded = False
                try:
                    cleanup_payload = {"session_id": session_id}
                    cleanup_command = self._command(
                        f"{operation_id}:rollback-close",
                        "close",
                        session,
                        lease,
                        cleanup_payload,
                    )
                    worker.close_session(session_id, cleanup_command)
                    cleanup_succeeded = True
                    self.store.record_worker_cleanup_attested(
                        session_id,
                        worker_instance_id=worker.descriptor.instance_id or "",
                        worker_session_id=session.worker_session_id,
                        command_id=cleanup_command.command_id,
                    )
                except Exception:
                    if not cleanup_succeeded and not worker_context_recorded:
                        try:
                            self.store.record_worker_context_created(
                                session_id,
                                worker_session_id=session.worker_session_id,
                                worker_instance_id=worker.descriptor.instance_id or "",
                            )
                        except Exception:
                            pass
            if created:
                self._best_effort_lost(session_id, "open_failed", exc)
            if lease is not None and self.store.valid_lease(lease):
                self.store.release_lease(lease)
            raise

    def navigate(
        self,
        session_id: str,
        context: WorkContext,
        url: str,
        *,
        expected_revision: int,
        expected_epoch: int,
        operation_id: str,
    ) -> NavigationResult:
        _require_external_operation_id(operation_id)
        session = self._owned_session(session_id, context)
        worker = self._worker(session.worker_id)
        self._require_capabilities(worker, WorkerCapability.NAVIGATE)
        payload = {"session_id": session_id, "url": url}
        request_digest = canonical_digest(
            {
                "payload": payload,
                "expected_revision": expected_revision,
                "expected_epoch": expected_epoch,
                "context_hash": context.context_hash,
            }
        )
        start = self.store.begin_command(operation_id, "navigate", request_digest)
        if start.replay:
            return NavigationResult(
                session=self.store.get_session(session_id),
                final_url=_result_string(start.result, "final_url"),
                committed_revision=_result_int(start.result, "revision"),
                command_id=operation_id,
            )
        reserved: BrowserSession | None = None
        reserved_lease: ControllerLease | None = None
        try:
            self._require_fresh_active(session, expected_revision, expected_epoch)
            target_host = check_browser_target_policy(
                url, session.allowed_domains, session.data_class
            )
            if session.engine == "playwright-observer" and (
                target_host not in session.allowed_domains
            ):
                raise EnginePolicyBlocked(
                    "Playwright navigation requires an exact pinned allowed_domains host"
                )
            lease = self._automation_lease(session)
            reserved, reserved_lease = self.store.reserve_automation_command(
                lease,
                expected_revision=expected_revision,
                expected_epoch=expected_epoch,
                operation="navigate",
                command_id=operation_id,
                command_attempt_token=start.attempt_token or "",
                ttl=self.controller_ttl,
            )
            command = self._command(
                operation_id, "navigate", reserved, reserved_lease, payload
            )
            final_url = worker.navigate(session_id, url, command)
            check_browser_target_policy(
                final_url, session.allowed_domains, session.data_class
            )
            result = {
                "session_id": session_id,
                "final_url": final_url,
                "revision": reserved.revision + 1,
            }
            updated = self.store.complete_reserved_command(
                session_id,
                reserved.revision,
                reserved_lease,
                current_url=final_url,
                command_id=operation_id,
                command_attempt_token=start.attempt_token or "",
                event_type="web.browser.navigate",
                command_result=result,
            )
            return NavigationResult(updated, final_url, updated.revision, operation_id)
        except CommandAttemptSuperseded:
            raise
        except Exception as exc:
            if not self.store.fail_command(
                operation_id,
                _safe_error(exc),
                attempt_token=start.attempt_token,
            ):
                raise CommandAttemptSuperseded(
                    f"navigate command {operation_id!r} attempt was superseded"
                ) from exc
            if reserved is not None:
                self._best_effort_lost(session_id, "navigate_failed", exc)
            if reserved_lease is not None and self.store.valid_lease(reserved_lease):
                self.store.release_lease(reserved_lease)
            raise

    def observe(
        self,
        session_id: str,
        context: WorkContext,
        *,
        expected_revision: int,
        expected_epoch: int,
        operation_id: str,
        include_screenshot: bool = False,
    ) -> BrowserObservationResult:
        _require_external_operation_id(operation_id)
        session = self._owned_session(session_id, context)
        worker = self._worker(session.worker_id)
        capabilities = [WorkerCapability.OBSERVE]
        if include_screenshot:
            capabilities.append(WorkerCapability.SCREENSHOT)
        self._require_capabilities(worker, *capabilities)
        payload = {"session_id": session_id}
        if include_screenshot:
            payload["include_screenshot"] = True
        request_digest = canonical_digest(
            {
                "payload": payload,
                "expected_revision": expected_revision,
                "expected_epoch": expected_epoch,
                "include_screenshot": include_screenshot,
                "context_hash": context.context_hash,
            }
        )
        start = self.store.begin_command(operation_id, "observe", request_digest)
        if start.replay:
            capture = self.capture_store.load_capture(
                _result_string(start.result, "capture_id")
            )
            content = capture.content
            if not isinstance(content, dict) or not isinstance(
                content.get("observation"), dict
            ):
                raise ValueError("stored browser capture has no observation")
            return BrowserObservationResult(
                session=self.store.get_session(session_id),
                observation=Observation.from_dict(content["observation"]),
                capture=capture,
                persistence=_persistence_from_result(start.result),
                command_id=operation_id,
            )

        reserved: BrowserSession | None = None
        reserved_lease: ControllerLease | None = None
        try:
            self._require_fresh_active(session, expected_revision, expected_epoch)
            if include_screenshot:
                self._require_screenshot_retention(session)
            lease = self._automation_lease(session)
            reserved, reserved_lease = self.store.reserve_automation_command(
                lease,
                expected_revision=expected_revision,
                expected_epoch=expected_epoch,
                operation="observe",
                command_id=operation_id,
                command_attempt_token=start.attempt_token or "",
                ttl=self.controller_ttl,
            )
            command = self._command(
                operation_id, "observe", reserved, reserved_lease, payload
            )
            raw = worker.observe(
                session_id, command, include_screenshot=include_screenshot
            )
            check_browser_target_policy(
                raw.url, session.allowed_domains, session.data_class
            )
            evidence_request = self._evidence_request(
                operation_id, session, raw.url
            )
            artifact_refs: list[str] = []
            if include_screenshot:
                screenshot = raw.screenshot
                if screenshot is None:
                    raise EngineFailure(
                        "browser worker omitted the requested atomic screenshot",
                        FailureClass.CANNOT_READ,
                    )
                if len(screenshot) > self.max_screenshot_bytes:
                    raise EngineFailure(
                        "browser screenshot exceeded the evidence size limit",
                        FailureClass.CANNOT_READ,
                    )
                screenshot_ref = self.capture_store.persist_blob(
                    screenshot, evidence_request
                )
                if screenshot_ref is None:
                    raise EnginePolicyBlocked(
                        "browser screenshot retention requires full_evidence policy"
                    )
                artifact_refs.append(screenshot_ref)

            capture_id = self.id_factory("webcap")
            captured_at = _utc_now(self.clock).isoformat()
            observation = Observation.create(
                observation_id=self.id_factory("observation"),
                session_id=session_id,
                session_revision=reserved.revision + 1,
                session_epoch=expected_epoch,
                capture_id=capture_id,
                captured_at=captured_at,
                url=raw.url,
                title=raw.title,
                elements=list(raw.elements),
                accessibility_snapshot=raw.accessibility_snapshot,
                artifact_refs=artifact_refs,
            )
            capture_content = {
                "kind": "browser_observation",
                "observation": observation.to_dict(),
                "work_context": context.to_dict(),
                "worker_notes": list(raw.notes),
            }
            if _json_size(capture_content) > self.max_capture_bytes:
                raise EngineFailure(
                    "browser observation exceeded the evidence size limit",
                    FailureClass.CANNOT_READ,
                )
            capture = WebCapture.from_reader_result(
                ReaderResult(
                    engine=session.engine,
                    engine_version=worker.descriptor.version,
                    requested_url=session.current_url or raw.url,
                    final_url=raw.url,
                    title=raw.title,
                    auth_scope=f"profile:{session.profile_id}",
                    content=capture_content,
                ),
                evidence_request,
                capture_id=capture_id,
                captured_at=captured_at,
            )
            if artifact_refs:
                capture = replace(
                    capture, screenshot_artifact_ref=artifact_refs[0]
                )
            capture, persistence = self.capture_store.persist(
                capture, evidence_request
            )
            if not persistence.stored:
                raise EnginePolicyBlocked(
                    "browser observations require durable evidence retention"
                )
            result = {
                "session_id": session_id,
                "revision": reserved.revision + 1,
                "observation_id": observation.observation_id,
                "capture_id": capture.capture_id,
                "persistence": persistence.to_dict(),
            }
            updated = self.store.complete_reserved_command(
                session_id,
                reserved.revision,
                reserved_lease,
                current_url=raw.url,
                command_id=operation_id,
                command_attempt_token=start.attempt_token or "",
                event_type="web.browser.observe",
                attributes={
                    "observation_id": observation.observation_id,
                    "capture_id": capture.capture_id,
                },
                command_result=result,
            )
            return BrowserObservationResult(
                updated, observation, capture, persistence, operation_id
            )
        except CommandAttemptSuperseded:
            raise
        except Exception as exc:
            if not self.store.fail_command(
                operation_id,
                _safe_error(exc),
                attempt_token=start.attempt_token,
            ):
                raise CommandAttemptSuperseded(
                    f"observe command {operation_id!r} attempt was superseded"
                ) from exc
            if reserved is not None:
                self._best_effort_lost(session_id, "observation_failed", exc)
            if reserved_lease is not None and self.store.valid_lease(reserved_lease):
                self.store.release_lease(reserved_lease)
            raise

    def takeover(
        self,
        session_id: str,
        context: WorkContext,
        operator_id: str,
        authorization_ref: str,
        *,
        expected_revision: int,
        operation_id: str,
    ) -> tuple[BrowserSession, ControllerLease]:
        _require_external_operation_id(operation_id)
        session = self._owned_session(session_id, context)
        worker = self._worker(session.worker_id)
        self._require_capabilities(worker, WorkerCapability.FENCE)
        digest = canonical_digest(
            {
                "session_id": session_id,
                "expected_revision": expected_revision,
                "operator_id": operator_id,
                "authorization_ref": authorization_ref,
                "context_hash": context.context_hash,
            }
        )
        start = self.store.begin_command(
            operation_id,
            "takeover",
            digest,
            resume_after=self.command_resume_after,
        )
        if start.replay:
            active = self.store.active_lease(session_id)
            if active is None or active.generation != _result_int(
                start.result, "controller_generation"
            ):
                raise ControllerConflict("takeover receipt no longer names the active lease")
            return self.store.get_session(session_id), active
        operator: ControllerLease | None = None
        paused: BrowserSession | None = None
        try:
            if start.resume:
                paused, operator = self.store.resume_transferred_controller(
                    session_id,
                    command_id=operation_id,
                    command_attempt_token=start.attempt_token or "",
                    expected_revision=expected_revision + 1,
                    expected_from_controller_id=session.owner_run_id,
                    expected_from_kind=ControllerKind.AUTOMATION,
                    expected_from_generation=None,
                    expected_controller_id=operator_id,
                    expected_kind=ControllerKind.OPERATOR,
                    authorization_ref=authorization_ref,
                )
            else:
                lease = self._automation_lease(session)
                paused, operator = self.store.transfer_lease_and_transition(
                    lease,
                    operator_id,
                    ControllerKind.OPERATOR,
                    expected_revision=expected_revision,
                    target_state=SessionState.PAUSED,
                    ttl=self.controller_ttl,
                    authorization_ref=authorization_ref,
                    command_id=operation_id,
                    command_attempt_token=start.attempt_token or "",
                )
            self._fence_session(
                worker,
                paused,
                operator,
                command_id=_attempt_worker_command_id(
                    operation_id, "fence", start.attempt_token or ""
                ),
            )
            result = {
                "session_id": session_id,
                "revision": paused.revision,
                "controller_generation": operator.generation,
            }
            self.store.complete_command_with_event(
                operation_id,
                result,
                session_id=session_id,
                owner_run_id=session.owner_run_id,
                event_type="web.browser.takeover.fenced",
                attributes={"controller_generation": operator.generation},
                attempt_token=start.attempt_token,
                required_lease=operator,
            )
            return paused, operator
        except CommandAttemptSuperseded:
            raise
        except Exception as exc:
            if not self.store.fail_command(
                operation_id,
                _safe_error(exc),
                attempt_token=start.attempt_token,
            ):
                raise CommandAttemptSuperseded(
                    f"takeover command {operation_id!r} attempt was superseded"
                ) from exc
            if paused is not None:
                self._best_effort_lost(session_id, "takeover_fence_failed", exc)
            if operator is not None and self.store.valid_lease(operator):
                self.store.release_lease(operator)
            raise

    def return_control(
        self,
        context: WorkContext,
        operator_lease: ControllerLease,
        authorization_ref: str,
        *,
        expected_revision: int,
        operation_id: str,
    ) -> tuple[BrowserSession, ControllerLease]:
        _require_external_operation_id(operation_id)
        session = self._owned_session(operator_lease.session_id, context)
        if operator_lease.kind is not ControllerKind.OPERATOR:
            raise ControllerConflict("return_control requires an operator lease")
        worker = self._worker(session.worker_id)
        self._require_capabilities(worker, WorkerCapability.FENCE)
        digest = canonical_digest(
            {
                "session_id": session.session_id,
                "expected_revision": expected_revision,
                "controller_generation": operator_lease.generation,
                "authorization_ref": authorization_ref,
                "context_hash": context.context_hash,
            }
        )
        start = self.store.begin_command(
            operation_id,
            "return_control",
            digest,
            resume_after=self.command_resume_after,
        )
        if start.replay:
            active = self.store.active_lease(session.session_id)
            if active is None or active.generation != _result_int(
                start.result, "controller_generation"
            ):
                raise ControllerConflict("return receipt no longer names the active lease")
            return self.store.get_session(session.session_id), active
        automation: ControllerLease | None = None
        resumed: BrowserSession | None = None
        paused: BrowserSession | None = None
        try:
            if start.resume:
                paused, automation = self.store.resume_transferred_controller(
                    session.session_id,
                    command_id=operation_id,
                    command_attempt_token=start.attempt_token or "",
                    expected_revision=expected_revision,
                    expected_from_controller_id=operator_lease.controller_id,
                    expected_from_kind=ControllerKind.OPERATOR,
                    expected_from_generation=operator_lease.generation,
                    expected_controller_id=session.owner_run_id,
                    expected_kind=ControllerKind.AUTOMATION,
                    authorization_ref=authorization_ref,
                )
            else:
                paused, automation = self.store.transfer_paused_controller(
                    operator_lease,
                    session.owner_run_id,
                    ControllerKind.AUTOMATION,
                    expected_revision=expected_revision,
                    ttl=self.controller_ttl,
                    authorization_ref=authorization_ref,
                    command_id=operation_id,
                    command_attempt_token=start.attempt_token or "",
                )
            self._fence_session(
                worker,
                paused,
                automation,
                command_id=_attempt_worker_command_id(
                    operation_id, "fence", start.attempt_token or ""
                ),
            )
            result = {
                "session_id": session.session_id,
                "revision": paused.revision + 1,
                "controller_generation": automation.generation,
            }
            resumed = self.store.activate_after_fence(
                automation,
                expected_revision=paused.revision,
                authorization_ref=authorization_ref,
                complete_command_id=operation_id,
                command_result=result,
                command_attempt_token=start.attempt_token,
            )
            return resumed, automation
        except CommandAttemptSuperseded:
            raise
        except Exception as exc:
            if not self.store.fail_command(
                operation_id,
                _safe_error(exc),
                attempt_token=start.attempt_token,
            ):
                raise CommandAttemptSuperseded(
                    f"return command {operation_id!r} attempt was superseded"
                ) from exc
            if paused is not None:
                self._best_effort_lost(
                    session.session_id, "return_control_fence_failed", exc
                )
            if automation is not None and self.store.valid_lease(automation):
                self.store.release_lease(automation)
            raise

    def renew_controller(
        self, session_id: str, context: WorkContext
    ) -> ControllerLease:
        self._owned_session(session_id, context)
        lease = self.store.active_lease(session_id)
        if lease is None or lease.controller_id != context.run_id:
            raise ControllerConflict("the work context does not own the active controller")
        return self.store.renew_lease(lease, ttl=self.controller_ttl)

    def mark_lost(
        self,
        session_id: str,
        context: WorkContext,
        *,
        expected_revision: int,
        detail: str,
    ) -> BrowserSession:
        session = self._owned_session(session_id, context)
        if session.revision != expected_revision:
            raise SessionRevisionConflict("session revision changed before loss report")
        return self.store.mark_lost(
            session_id,
            expected_revision,
            event_type="web.browser.session.lost",
            attributes={"reason_code": _reason_code(detail)},
        )

    def recover(
        self,
        session_id: str,
        context: WorkContext,
        *,
        expected_revision: int,
        expected_epoch: int,
        operation_id: str,
    ) -> BrowserSession:
        _require_external_operation_id(operation_id)
        old = self._owned_session(session_id, context)
        digest = canonical_digest(
            {
                "session_id": session_id,
                "expected_revision": expected_revision,
                "expected_epoch": expected_epoch,
                "context_hash": context.context_hash,
            }
        )
        start = self.store.begin_command(operation_id, "recover", digest)
        if start.replay:
            return self.store.get_session(session_id)
        if old.state is not SessionState.LOST:
            if not self.store.fail_command(
                operation_id,
                f"{FailureClass.CONTROLLER_CONFLICT.value}: session is not lost",
                attempt_token=start.attempt_token,
            ):
                raise CommandAttemptSuperseded(
                    f"recovery command {operation_id!r} attempt was superseded"
                )
            raise ControllerConflict("only lost sessions can be recovered")
        if old.revision != expected_revision or old.epoch != expected_epoch:
            if not self.store.fail_command(
                operation_id,
                f"{FailureClass.STALE_REFERENCE.value}: revision or epoch changed",
                attempt_token=start.attempt_token,
            ):
                raise CommandAttemptSuperseded(
                    f"recovery command {operation_id!r} attempt was superseded"
                )
            raise SessionRevisionConflict(
                "browser session revision or epoch changed before recovery"
            )
        worker = self._worker(old.worker_id)
        pending_id = self.id_factory("pending")
        lease: ControllerLease | None = None
        opening: BrowserSession | None = None
        new_worker_context = False
        new_worker_context_recorded = False
        try:
            opening = self.store.begin_recovery(
                session_id,
                context.run_id,
                expected_revision,
                worker_session_id=pending_id,
                command_id=operation_id,
                command_attempt_token=start.attempt_token or "",
            )
            lease = self.store.acquire_lease(
                session_id,
                context.run_id,
                ControllerKind.AUTOMATION,
                ttl=self.controller_ttl,
            )
            initial_url = old.current_url or ""
            if not initial_url:
                raise ControllerConflict("lost session has no target URL to recover")
            attached = False
            if worker.descriptor.supports(WorkerCapability.ATTACH):
                attach_spec = self._spec(
                    opening,
                    initial_url,
                    worker_session_id=old.worker_session_id,
                )
                attach_payload = {"spec": attach_spec.to_dict()}
                attach_command = self._command(
                    f"{operation_id}:attach",
                    "attach",
                    opening,
                    lease,
                    attach_payload,
                    worker_session_id=old.worker_session_id,
                )
                attached = worker.attach_session(attach_spec, attach_command)
            worker_session_id = old.worker_session_id
            if not attached:
                if self.store.worker_context_may_be_live(
                    session_id,
                    worker_instance_id=worker.descriptor.instance_id or "",
                ):
                    prior_cleanup_payload = {"session_id": session_id}
                    prior_cleanup_command = self._command(
                        f"{operation_id}:prior-close",
                        "close",
                        opening,
                        lease,
                        prior_cleanup_payload,
                        worker_session_id=old.worker_session_id,
                    )
                    try:
                        worker.close_session(session_id, prior_cleanup_command)
                        self.store.record_worker_cleanup_attested(
                            session_id,
                            worker_instance_id=worker.descriptor.instance_id or "",
                            worker_session_id=old.worker_session_id,
                            command_id=prior_cleanup_command.command_id,
                        )
                    except Exception as cleanup_exc:
                        raise EngineFailure(
                            "cannot replace an unclosed prior browser context",
                            FailureClass.SESSION_LOST,
                        ) from cleanup_exc
                self._require_capabilities(worker, WorkerCapability.OPEN)
                open_spec = self._spec(opening, initial_url)
                open_payload = {"spec": open_spec.to_dict()}
                open_command = self._command(
                    f"{operation_id}:open", "open", opening, lease, open_payload
                )
                self.store.reserve_worker_open(
                    session_id,
                    command_id=operation_id,
                    attempt_token=start.attempt_token or "",
                    worker_instance_id=worker.descriptor.instance_id or "",
                    expected_revision=opening.revision,
                    expected_epoch=opening.epoch,
                    required_lease=lease,
                )
                worker_session_id = worker.open_session(open_spec, open_command)
                if not worker_session_id:
                    raise RuntimeError("browser worker returned an empty worker_session_id")
                new_worker_context = True
                opening.worker_session_id = worker_session_id
                opening = self.store.record_worker_context_created(
                    session_id,
                    worker_session_id=worker_session_id,
                    worker_instance_id=worker.descriptor.instance_id or "",
                    command_id=operation_id,
                    attempt_token=start.attempt_token,
                )
                new_worker_context_recorded = True
            result = {
                "session_id": session_id,
                "revision": opening.revision + 1,
                "epoch": opening.epoch,
                "attached": attached,
            }
            active = self.store.activate_opening_session(
                session_id,
                opening.revision,
                current_url=initial_url,
                worker_session_id=worker_session_id,
                worker_instance_id=worker.descriptor.instance_id or "",
                event_type="web.browser.session.recovered",
                attributes={"command_id": operation_id, "attached": attached},
                complete_command_id=operation_id,
                command_result=result,
                command_attempt_token=start.attempt_token or "",
                required_lease=lease,
            )
            return active
        except CommandAttemptSuperseded:
            raise
        except Exception as exc:
            if not self.store.fail_command(
                operation_id,
                _safe_error(exc),
                attempt_token=start.attempt_token,
            ):
                raise CommandAttemptSuperseded(
                    f"recovery command {operation_id!r} attempt was superseded"
                ) from exc
            if new_worker_context and opening is not None and lease is not None:
                cleanup_succeeded = False
                try:
                    cleanup_payload = {"session_id": session_id}
                    cleanup_command = self._command(
                        f"{operation_id}:rollback-close",
                        "close",
                        opening,
                        lease,
                        cleanup_payload,
                    )
                    worker.close_session(session_id, cleanup_command)
                    cleanup_succeeded = True
                    self.store.record_worker_cleanup_attested(
                        session_id,
                        worker_instance_id=worker.descriptor.instance_id or "",
                        worker_session_id=opening.worker_session_id,
                        command_id=cleanup_command.command_id,
                    )
                except Exception:
                    if not cleanup_succeeded and not new_worker_context_recorded:
                        try:
                            self.store.record_worker_context_created(
                                session_id,
                                worker_session_id=opening.worker_session_id,
                                worker_instance_id=worker.descriptor.instance_id or "",
                            )
                        except Exception:
                            pass
            self._best_effort_lost(session_id, "recovery_failed", exc)
            if lease is not None and self.store.valid_lease(lease):
                self.store.release_lease(lease)
            raise

    def close(
        self,
        session_id: str,
        context: WorkContext,
        *,
        expected_revision: int,
        expected_epoch: int,
        operation_id: str,
    ) -> BrowserSession:
        _require_external_operation_id(operation_id)
        session = self._owned_session(session_id, context)
        payload = {"session_id": session_id}
        request_digest = canonical_digest(
            {
                "payload": payload,
                "expected_revision": expected_revision,
                "expected_epoch": expected_epoch,
                "context_hash": context.context_hash,
            }
        )
        start = self.store.begin_command(operation_id, "close", request_digest)
        if start.replay:
            return self.store.get_session(session_id)
        if session.state is SessionState.CLOSED:
            self.store.complete_command(
                operation_id,
                {
                    "session_id": session_id,
                    "revision": session.revision,
                    "worker_fenced": True,
                    "worker_cleanup": True,
                },
                attempt_token=start.attempt_token,
            )
            return session

        worker = self._worker(session.worker_id)
        self._require_capabilities(
            worker, WorkerCapability.FENCE, WorkerCapability.CLOSE
        )
        worker_instance_id = worker.descriptor.instance_id or ""
        context_may_be_live = self.store.worker_context_may_be_live(
            session_id, worker_instance_id=worker_instance_id
        )
        reserved: BrowserSession | None = None
        cleanup_lease: ControllerLease | None = None
        try:
            reserved, cleanup_lease = self.store.begin_close(
                session_id,
                context.run_id,
                expected_revision=expected_revision,
                expected_epoch=expected_epoch,
                command_id=operation_id,
                command_attempt_token=start.attempt_token or "",
                ttl=self.controller_ttl,
            )
            worker_fenced = True
            worker_cleanup = True
            cleanup_failure_class: str | None = None
            try:
                self._fence_session(
                    worker,
                    reserved,
                    cleanup_lease,
                    command_id=f"{operation_id}:fence",
                )
            except Exception as exc:
                worker_fenced = False
                cleanup_failure_class = _failure_code(exc)

            command = self._command(
                operation_id, "close", reserved, cleanup_lease, payload
            )
            try:
                worker.close_session(session_id, command)
                self.store.record_worker_cleanup_attested(
                    session_id,
                    worker_instance_id=worker_instance_id,
                    worker_session_id=reserved.worker_session_id,
                    command_id=operation_id,
                )
            except Exception as exc:
                worker_cleanup = False
                cleanup_failure_class = cleanup_failure_class or _failure_code(exc)

            if not worker_cleanup and context_may_be_live:
                quarantine_error = EngineFailure(
                    "worker cleanup is unconfirmed; the authenticated profile remains quarantined",
                    FailureClass.SESSION_LOST,
                )
                self._best_effort_lost(
                    session_id, "worker_cleanup_unconfirmed", quarantine_error
                )
                raise quarantine_error

            result = {
                "session_id": session_id,
                "revision": reserved.revision + 1,
                "worker_fenced": worker_fenced,
                "worker_cleanup": worker_cleanup,
            }
            closed = self.store.close_with_lease(
                session_id,
                reserved.revision,
                cleanup_lease,
                command_id=operation_id,
                worker_cleanup=worker_cleanup,
                cleanup_failure_class=cleanup_failure_class,
                command_result=result,
                command_attempt_token=start.attempt_token,
            )
            return closed
        except CommandAttemptSuperseded:
            raise
        except Exception as exc:
            if not self.store.fail_command(
                operation_id,
                _safe_error(exc),
                attempt_token=start.attempt_token,
            ):
                raise CommandAttemptSuperseded(
                    f"close command {operation_id!r} attempt was superseded"
                ) from exc
            if cleanup_lease is not None and self.store.valid_lease(cleanup_lease):
                self.store.release_lease(cleanup_lease)
            raise

    def _resume_open(
        self,
        request: WebRequest,
        context: WorkContext,
        worker: BrowserWorker,
        profile: SiteProfile,
        *,
        operation_id: str,
        attempt_token: str,
    ) -> BrowserSession:
        if not attempt_token:
            raise CommandInDoubt("resumed open command has no attempt fence")
        session = self.store.session_for_open_command(operation_id)
        session = self._owned_session(session.session_id, context)
        if (
            session.worker_id != worker.descriptor.worker_id
            or session.profile_id != request.profile_id
            or session.data_class is not request.data_class
            or session.allowed_domains
            != list(normalize_allowed_domains(request.allowed_domains))
        ):
            raise CommandInDoubt(
                f"open command {operation_id!r} is bound to a different session policy"
            )
        if session.state is SessionState.ACTIVE:
            self.store.complete_command(
                operation_id,
                {"session_id": session.session_id, "revision": session.revision},
                attempt_token=attempt_token,
            )
            return session
        if session.state is not SessionState.OPENING:
            raise CommandInDoubt(
                f"open command {operation_id!r} left session {session.session_id!r} "
                f"in state {session.state.value!r}; close that session explicitly"
            )

        lease = self.store.active_lease(session.session_id)
        if lease is None:
            lease = self.store.acquire_lease(
                session.session_id,
                request.run_id,
                ControllerKind.AUTOMATION,
                ttl=self.controller_ttl,
            )
        elif (
            lease.kind is not ControllerKind.AUTOMATION
            or lease.controller_id != request.run_id
        ):
            raise CommandInDoubt(
                f"opening session {session.session_id!r} has a different controller"
            )

        spec = self._spec(session, request.url or "", profile=profile)
        context_may_be_live = self.store.worker_context_may_be_live(
            session.session_id,
            worker_instance_id=worker.descriptor.instance_id or "",
        )
        if context_may_be_live:
            if not worker.descriptor.supports(WorkerCapability.ATTACH):
                raise CommandInDoubt(
                    f"opening session {session.session_id!r} may have a live worker context"
                )
            attach_command = self._command(
                _attempt_worker_command_id(
                    operation_id, "resume-attach", attempt_token
                ),
                "attach",
                session,
                lease,
                {"spec": spec.to_dict()},
                worker_session_id=session.worker_session_id,
            )
            if not worker.attach_session(spec, attach_command):
                raise CommandInDoubt(
                    f"opening session {session.session_id!r} could not reattach its "
                    "recorded worker context"
                )
            worker_session_id = session.worker_session_id
        else:
            self.store.reserve_worker_open(
                session.session_id,
                command_id=operation_id,
                attempt_token=attempt_token,
                worker_instance_id=worker.descriptor.instance_id or "",
                expected_revision=session.revision,
                expected_epoch=session.epoch,
                required_lease=lease,
            )
            open_command = self._command(
                _attempt_worker_command_id(operation_id, "resume-open", attempt_token),
                "open",
                session,
                lease,
                {"spec": spec.to_dict()},
            )
            worker_session_id = worker.open_session(spec, open_command)
            if not worker_session_id:
                raise RuntimeError("browser worker returned an empty worker_session_id")
            session.worker_session_id = worker_session_id
            session = self.store.record_worker_context_created(
                session.session_id,
                worker_session_id=worker_session_id,
                worker_instance_id=worker.descriptor.instance_id or "",
                command_id=operation_id,
                attempt_token=attempt_token,
            )

        result = {"session_id": session.session_id, "revision": session.revision + 1}
        return self.store.activate_opening_session(
            session.session_id,
            session.revision,
            current_url=request.url,
            worker_session_id=worker_session_id,
            worker_instance_id=worker.descriptor.instance_id or "",
            event_type="web.browser.session.opened",
            attributes={
                "command_id": operation_id,
                "context_hash": context.context_hash,
                "site_profile": profile.id,
                "resumed": True,
            },
            complete_command_id=operation_id,
            command_result=result,
            command_attempt_token=attempt_token,
            required_lease=lease,
        )

    def _validate_open_request(
        self,
        request: WebRequest,
        context: WorkContext,
        worker: BrowserWorker,
    ) -> SiteProfile:
        request.validate()
        context.validate()
        if context.run_id != request.run_id:
            raise SessionOwnershipError("work context run_id must match WebRequest.run_id")
        if context.correlation_id != request.request_id:
            raise SessionOwnershipError(
                "work context correlation_id must match WebRequest.request_id"
            )
        if request.mode is not RequestMode.OBSERVE or request.side_effects_allowed:
            raise EnginePolicyBlocked(
                "the browser session broker currently accepts observation-only requests"
            )
        if not request.url:
            raise EnginePolicyBlocked("browser observation requires an initial URL")
        if request.auth_context == "none" or request.profile_id is None:
            raise EnginePolicyBlocked(
                "browser sessions require an explicit authenticated profile context"
            )
        if request.data_class is DataClass.RESTRICTED:
            raise EnginePolicyBlocked(
                "restricted browser placement is not implemented by the local broker"
            )
        if not worker.descriptor.instance_id:
            raise EnginePolicyBlocked(
                "browser workers require a stable process instance_id for cleanup auditing"
            )
        if request.capture_policy != "full_evidence":
            raise EnginePolicyBlocked(
                "browser observations require capture_policy=full_evidence"
            )
        if (
            request.preferred_engine is not None
            and request.preferred_engine != worker.descriptor.engine
        ):
            raise EnginePolicyBlocked(
                f"request prefers engine {request.preferred_engine!r}, not "
                f"{worker.descriptor.engine!r}"
            )
        domains = normalize_allowed_domains(request.allowed_domains)
        target_host = check_browser_target_policy(
            request.url, domains, request.data_class
        )
        if (
            worker.descriptor.engine == "playwright-observer"
            and target_host not in domains
        ):
            raise EnginePolicyBlocked(
                "Playwright requires the initial hostname as an exact allowed_domains entry"
            )
        _, profile = self.profiles.apply(
            request, [worker.descriptor.engine]
        )
        if profile is None:
            raise EnginePolicyBlocked("browser sessions require a matching site profile")
        # preferred_engines orders candidates; it is intentionally not an
        # engine allowlist. Worker-specific containment remains mandatory.
        if worker.descriptor.engine == "agent-browser":
            raise EnginePolicyBlocked(
                "contained agent-browser cannot attest the authenticated profile scope "
                "required by this broker"
            )
        required_observation_policy = {
            "javascript": "disabled",
            "network_methods": "get_head_only",
            "credential_scope": "read_only",
        }
        if profile.browser_observation != required_observation_policy:
            raise EnginePolicyBlocked(
                "authenticated browser observation requires a site profile that "
                "attests disabled JavaScript, GET/HEAD-only transport, and read-only "
                "credentials"
            )
        if any(
            not any(
                domain == profile_domain
                or domain.endswith("." + profile_domain)
                for profile_domain in profile.domains
            )
            for domain in domains
        ):
            raise EnginePolicyBlocked(
                f"request allowlist exceeds site profile {profile.id!r}"
            )
        self._require_capabilities(
            worker,
            WorkerCapability.OPEN,
            WorkerCapability.OBSERVE,
            WorkerCapability.FENCE,
            WorkerCapability.CLOSE,
        )
        return profile

    def _owned_session(
        self, session_id: str, context: WorkContext
    ) -> BrowserSession:
        context.validate()
        session = self.store.get_session(session_id)
        stored = self.store.work_context(session_id)
        if session.owner_run_id != context.run_id or stored.context_hash != context.context_hash:
            raise SessionOwnershipError(
                "browser session is bound to a different run or work context"
            )
        return session

    def _automation_lease(self, session: BrowserSession) -> ControllerLease:
        lease = self.store.active_lease(session.session_id)
        if (
            lease is None
            or lease.kind is not ControllerKind.AUTOMATION
            or lease.controller_id != session.owner_run_id
            or not self.store.valid_lease(lease)
        ):
            raise ControllerConflict(
                "browser session has no valid automation controller lease"
            )
        return lease

    @staticmethod
    def _require_fresh_active(
        session: BrowserSession, expected_revision: int, expected_epoch: int
    ) -> None:
        if session.state is not SessionState.ACTIVE:
            raise ControllerConflict("browser session is not active")
        if session.revision != expected_revision or session.epoch != expected_epoch:
            raise SessionRevisionConflict(
                "browser session revision or epoch changed before the command"
            )

    def _worker(self, worker_id: str) -> BrowserWorker:
        try:
            return self.workers[worker_id]
        except KeyError as exc:
            raise EnginePolicyBlocked(f"unknown browser worker {worker_id!r}") from exc

    @staticmethod
    def _require_capabilities(
        worker: BrowserWorker, *capabilities: WorkerCapability
    ) -> None:
        missing = [
            capability.value
            for capability in capabilities
            if not worker.descriptor.supports(capability)
        ]
        if missing:
            raise EnginePolicyBlocked(
                f"browser worker {worker.descriptor.worker_id!r} lacks capabilities {missing}"
            )

    def _spec(
        self,
        session: BrowserSession,
        initial_url: str,
        *,
        profile: SiteProfile | None = None,
        worker_session_id: str | None = None,
    ) -> SessionSpec:
        bound_profile, credential_scope = self._bound_profile(
            session, initial_url, expected_profile=profile
        )
        return SessionSpec(
            session_id=session.session_id,
            worker_session_id=worker_session_id or session.worker_session_id,
            owner_run_id=session.owner_run_id,
            profile_id=session.profile_id,
            site_profile_id=bound_profile.id,
            credential_scope=credential_scope,
            data_class=session.data_class,
            allowed_domains=tuple(session.allowed_domains),
            initial_url=initial_url,
        )

    def _fence_session(
        self,
        worker: BrowserWorker,
        session: BrowserSession,
        lease: ControllerLease,
        *,
        command_id: str,
    ) -> None:
        payload = {"session_id": session.session_id}
        command = self._command(
            command_id, "fence", session, lease, payload
        )
        worker.fence_session(session.session_id, command)

    def _require_screenshot_retention(self, session: BrowserSession) -> None:
        if not session.current_url:
            raise EnginePolicyBlocked(
                "browser screenshot retention requires a current session URL"
            )
        profile, _ = self._bound_profile(session, session.current_url)
        setting = profile.retention.get("screenshots")
        if setting != "full_evidence":
            raise EnginePolicyBlocked(
                "the matching site profile does not permit screenshot retention"
            )

    def _bound_profile(
        self,
        session: BrowserSession,
        url: str,
        *,
        expected_profile: SiteProfile | None = None,
    ) -> tuple[SiteProfile, str]:
        binding = self.store.profile_binding(session.session_id)
        profile = expected_profile or self.profiles.get(binding.site_profile_id)
        if profile is None:
            raise EnginePolicyBlocked(
                "browser session's bound site profile is no longer configured"
            )
        if profile.id != binding.site_profile_id or (
            _profile_policy_digest(profile) != binding.policy_digest
        ):
            raise EnginePolicyBlocked(
                "browser session's bound site-profile policy changed after open"
            )
        if not profile.matches_host(urllib.parse.urlsplit(url).hostname or ""):
            raise EnginePolicyBlocked(
                "browser session URL is outside its durably bound site profile"
            )
        credential_scope = profile.browser_observation.get("credential_scope")
        if credential_scope != binding.credential_scope or credential_scope != "read_only":
            raise EnginePolicyBlocked(
                "browser session credential scope changed after open"
            )
        return profile, credential_scope

    def _command(
        self,
        command_id: str,
        operation: str,
        session: BrowserSession,
        lease: ControllerLease,
        payload: object,
        *,
        expected_revision: int | None = None,
        expected_epoch: int | None = None,
        worker_session_id: str | None = None,
    ) -> WorkerCommand:
        now = _utc_now(self.clock)
        lease_expiry = datetime.fromisoformat(
            lease.expires_at.replace("Z", "+00:00")
        ).astimezone(timezone.utc)
        deadline = min(now + self.command_timeout, lease_expiry)
        if deadline <= now:
            raise ControllerConflict("controller lease expired before worker dispatch")
        return WorkerCommand.build(
            command_id=command_id,
            operation=operation,
            session_id=session.session_id,
            worker_session_id=worker_session_id or session.worker_session_id,
            owner_run_id=session.owner_run_id,
            expected_revision=(
                session.revision if expected_revision is None else expected_revision
            ),
            session_epoch=session.epoch if expected_epoch is None else expected_epoch,
            lease_fence=lease.generation,
            deadline_at=deadline,
            payload=payload,
        )

    @staticmethod
    def _evidence_request(
        operation_id: str, session: BrowserSession, url: str
    ) -> WebRequest:
        return WebRequest(
            request_id=operation_id,
            run_id=session.owner_run_id,
            mode=RequestMode.OBSERVE,
            data_class=session.data_class,
            auth_context="browser_profile",
            intent="retain browser observation evidence",
            url=url,
            profile_id=session.profile_id,
            allowed_domains=list(session.allowed_domains),
            preferred_engine=session.engine,
            evidence_required=True,
            side_effects_allowed=False,
            capture_policy="full_evidence",
        )

    def _best_effort_lost(
        self, session_id: str, reason: str, exc: Exception
    ) -> None:
        try:
            current = self.store.get_session(session_id)
            if current.state in {
                SessionState.OPENING,
                SessionState.ACTIVE,
                SessionState.PAUSED,
            }:
                self.store.mark_lost(
                    session_id,
                    current.revision,
                    event_type="web.browser.session.lost",
                    attributes={"reason": reason, "detail": _safe_error(exc)},
                )
        except Exception:
            return


def _utc_now(clock: Callable[[], datetime]) -> datetime:
    value = clock()
    if value.tzinfo is None:
        raise ValueError("browser broker clock must return timezone-aware datetimes")
    return value.astimezone(timezone.utc)


def _require_external_operation_id(operation_id: str) -> None:
    if not isinstance(operation_id, str) or not _EXTERNAL_OPERATION_ID.fullmatch(
        operation_id
    ):
        raise ValueError(
            "operation_id must be 1-128 ASCII letters, digits, '.', '_', or '-'; "
            "':' is reserved for broker-derived worker commands"
        )


def _attempt_worker_command_id(
    operation_id: str, phase: str, attempt_token: str
) -> str:
    if not attempt_token:
        raise CommandInDoubt(
            f"{phase} worker command has no durable broker-attempt fence"
        )
    suffix = canonical_digest({"attempt_token": attempt_token})[7:23]
    return f"{operation_id}:{phase}:{suffix}"


def _result_string(result: dict | None, key: str) -> str:
    value = None if result is None else result.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"durable command result has no {key!r}")
    return value


def _result_int(result: dict | None, key: str) -> int:
    value = None if result is None else result.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"durable command result has no integer {key!r}")
    return value


def _persistence_from_result(result: dict | None) -> PersistenceInfo:
    value = None if result is None else result.get("persistence")
    if not isinstance(value, dict):
        raise ValueError("durable observation result has no persistence metadata")
    return PersistenceInfo(
        stored=bool(value.get("stored")),
        manifest_ref=value.get("manifest_ref"),
        artifact_ref=value.get("artifact_ref"),
        reason=str(value.get("reason", "")),
    )


def _safe_error(exc: Exception) -> str:
    if isinstance(exc, WeirEngineError):
        return f"{exc.failure_class.value}: {type(exc).__name__}"
    return f"{FailureClass.UNKNOWN.value}: {type(exc).__name__}"


def _failure_code(exc: Exception) -> str:
    if isinstance(exc, WeirEngineError):
        return exc.failure_class.value
    return FailureClass.UNKNOWN.value


def _reason_code(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9_.-]+", "_", value.strip().lower()).strip("_")
    return (normalized or "unspecified")[:64]


def _json_size(value: object) -> int:
    return len(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    )


def _profile_policy_digest(profile: SiteProfile) -> str:
    return canonical_digest(
        {
            "site_profile_id": profile.id,
            "domains": list(profile.domains),
            "auth_mode": profile.auth_mode,
            "allowed_modes": sorted(mode.value for mode in profile.allowed_modes),
            "retention": profile.retention,
            "browser_observation": profile.browser_observation,
        }
    )


__all__ = [
    "BrowserObservationResult",
    "BrowserSessionBroker",
    "NavigationResult",
    "SessionOwnershipError",
]
