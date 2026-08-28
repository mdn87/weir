"""Run one real loopback Fade -> WEIR -> Playwright synthetic action canary.

The canary is deliberately narrow: one public textbox on an ephemeral HTTP loopback
origin, one fill effect, no production profile, and no external network request. Raw
stores stay beneath the requested run directory for restart and audit inspection.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any, Callable
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from playwright.sync_api import Route, sync_playwright
from weir.actions import (
    ActionCompiler,
    ActionCondition,
    ActionType,
    ConditionKind,
    Risk,
)
from weir.browser.effect_driver import (
    FADE_AUTHORITY_ID,
    BrowserActionDriver,
    EffectResult,
    PrivateEffectCommand,
    SyntheticFixtureEffectPolicy,
)
from weir.browser.locators import resolve_locator
from weir.browser.models import (
    BrowserSession,
    ControllerKind,
    Observation,
    ObservedElement,
    SemanticLocator,
    SessionState,
)
from weir.browser.store import SQLiteSessionStore
from weir.events import ActionEventState, CorrelationHeader, WeirActionEvent
from weir.models import DataClass, ReaderResult, RequestMode, WebCapture, WebRequest
from weir.persistence import CaptureStore
from weir.proposals import ActionProposalStore
from weir.service import (
    ACTION_EXECUTE_SCOPE,
    ACTION_STATUS_SCOPE,
    PROPOSAL_READ_FULL_SCOPE,
    ClientCredential,
    ClientRegistry,
    WeirService,
    WeirServiceApplication,
)
from weir.work_context import WorkContext, WorkContextSource

REPORT_SCHEMA = "weir-fade-local-action-canary/v1"
MARKER = "WEIR_LOCAL_CANARY_OK"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


class _FixtureHandler(BaseHTTPRequestHandler):
    body = b"""
<!doctype html>
<html><head><meta charset="utf-8"><title>WEIR local action canary</title></head>
<body>
  <main>
    <label for="fixture-value">Fixture value</label>
    <input id="fixture-value" data-testid="fixture-value" aria-label="Fixture value" value="">
    <output id="fixture-state">empty</output>
  </main>
  <script>
    window.weirEffectCount = 0;
    const input = document.getElementById('fixture-value');
    const state = document.getElementById('fixture-state');
    input.addEventListener('input', () => {
      window.weirEffectCount += 1;
      state.textContent = input.value.length === 0 ? 'empty' : 'filled';
    });
  </script>
</body></html>
""".strip()

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/fixture-form":
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


class FixturePage:
    def __init__(self) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
        self.thread = Thread(
            target=self.server.serve_forever,
            name="weir-canary-fixture",
            daemon=True,
        )

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    @property
    def url(self) -> str:
        return self.origin + "/fixture-form"

    def __enter__(self) -> FixturePage:
        self.thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def _persist_observation(
    capture_store: CaptureStore,
    context: WorkContext,
    session: BrowserSession,
    observation: Observation,
) -> None:
    request = WebRequest(
        request_id=f"observe-{observation.observation_id}",
        run_id=context.run_id,
        mode=RequestMode.OBSERVE,
        data_class=session.data_class,
        auth_context="browser_profile",
        intent="retain the local synthetic action canary observation",
        url=observation.url,
        profile_id=session.profile_id,
        allowed_domains=list(session.allowed_domains),
        preferred_engine=session.engine,
        evidence_required=True,
        side_effects_allowed=False,
        capture_policy="full_evidence",
    )
    capture = WebCapture.from_reader_result(
        ReaderResult(
            engine=session.engine,
            engine_version="playwright-canary-1",
            requested_url=observation.url,
            final_url=observation.url,
            title=observation.title,
            auth_scope=f"profile:{session.profile_id}",
            content={
                "kind": "browser_observation",
                "observation": observation.to_dict(),
                "work_context": context.to_dict(),
                "worker_notes": ["local_loopback_fixture"],
            },
        ),
        request,
        capture_id=observation.capture_id,
        captured_at=observation.captured_at,
    )
    stored, persistence = capture_store.persist(capture, request)
    if not persistence.stored or stored.capture_id != observation.capture_id:
        raise RuntimeError("canary observation was not retained")


class PlaywrightFixtureEffectWorker:
    worker_id = "playwright-synthetic-canary"

    def __init__(
        self,
        store: SQLiteSessionStore,
        capture_store: CaptureStore,
        context: WorkContext,
        url: str,
    ) -> None:
        self.store = store
        self.capture_store = capture_store
        self.context = context
        self.url = url
        self.origin = f"{urlsplit(url).scheme}://{urlsplit(url).netloc}"
        self.worker_instance_id = "worker-instance-" + secrets.token_hex(12)
        self.apply_calls = 0
        self._observations = 0
        self._executor = ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="weir-canary-playwright",
        )
        self._executor.submit(self._start).result(timeout=30)

    def _start(self) -> None:
        self._playwright = sync_playwright().start()
        self._browser = self._playwright.chromium.launch(headless=True)
        self._context = self._browser.new_context(
            accept_downloads=False,
            service_workers="block",
        )
        self._context.set_default_timeout(5_000)
        self._context.route("**/*", self._route)
        self._page = self._context.new_page()
        self._page.goto(self.url, wait_until="domcontentloaded")

    def _route(self, route: Route) -> None:
        request = route.request
        parsed = urlsplit(request.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin == self.origin and request.method in {"GET", "HEAD"}:
            route.continue_()
        else:
            route.abort("blockedbyclient")

    def observe(
        self,
        session_id: str,
        *,
        command_id: str,
        stage: str,
    ) -> Observation:
        return self._executor.submit(self._observe, session_id, command_id, stage).result(
            timeout=15
        )

    def _observe(
        self,
        session_id: str,
        command_id: str,
        stage: str,
    ) -> Observation:
        if stage not in {"approved", "before", "after"}:
            raise ValueError("invalid canary observation stage")
        session = self.store.get_session(session_id)
        revision = session.revision + 1
        self._observations += 1
        value = self._page.get_by_test_id("fixture-value").input_value()
        state = "empty" if value == "" else "filled"
        captured_at = _iso(_utc_now())
        observation = Observation.create(
            observation_id=f"observation-{stage}-{self._observations}",
            session_id=session_id,
            session_revision=revision,
            session_epoch=session.epoch,
            capture_id=f"webcap-{stage}-{self._observations}-{secrets.token_hex(6)}",
            captured_at=captured_at,
            url=self._page.url,
            title=self._page.title(),
            elements=[
                ObservedElement(
                    f"element-{stage}-{self._observations}",
                    "textbox",
                    "Fixture value",
                    "fixture-value",
                    state,
                )
            ],
            accessibility_snapshot={
                "stage": stage,
                "state": state,
                "command_id": command_id,
            },
        )
        with self.store._lock, self.store.database:  # trusted canary adapter seam
            self.store.database.execute(
                """UPDATE browser_sessions
                   SET revision = ?, current_url = ?, updated_at = ?
                   WHERE session_id = ?""",
                (revision, observation.url, captured_at, session_id),
            )
        _persist_observation(
            self.capture_store,
            self.context,
            self.store.get_session(session_id),
            observation,
        )
        return observation

    def apply(self, command: PrivateEffectCommand) -> EffectResult:
        return self._executor.submit(self._apply, command).result(timeout=15)

    def _apply(self, command: PrivateEffectCommand) -> EffectResult:
        command.validate()
        if (
            command.worker_id != self.worker_id
            or command.worker_instance_id != self.worker_instance_id
            or command.action_type is not ActionType.FILL
            or command.target.role != "textbox"
            or command.target.test_id != "fixture-value"
        ):
            raise ValueError("canary effect command is outside the fixed fixture")
        parameters = command.parameters()
        if set(parameters) != {"value"} or parameters["value"] != MARKER:
            raise ValueError("canary fill value is not the fixed marker")
        self.apply_calls += 1
        self._page.get_by_test_id("fixture-value").fill(MARKER)
        if self._page.get_by_test_id("fixture-value").input_value() != MARKER:
            raise RuntimeError("Playwright did not apply the fixture fill")
        return EffectResult(self.worker_id, self.worker_instance_id, True)

    def effect_count(self) -> int:
        return int(
            self._executor.submit(self._page.evaluate, "() => window.weirEffectCount").result(
                timeout=10
            )
        )

    def close(self) -> None:
        def shutdown() -> None:
            self._context.close()
            self._browser.close()
            self._playwright.stop()

        try:
            self._executor.submit(shutdown).result(timeout=15)
        finally:
            self._executor.shutdown(wait=True, cancel_futures=True)


class _UnusedBackend:
    def __getattr__(self, name: str) -> Callable[..., object]:
        raise RuntimeError(f"unexpected acquisition backend call: {name}")


class DropFirstExecuteResponseClient:
    """Call real WEIR once, then emulate loss of its successful HTTP response."""

    def __init__(self, inner: object, ambiguous_error: type[Exception]) -> None:
        self.inner = inner
        self.ambiguous_error = ambiguous_error
        self.execute_calls = 0
        self.dropped_responses = 0

    def get_proposal(self, proposal_hash: str) -> object:
        return self.inner.get_proposal(proposal_hash)

    def execute_action(self, **kwargs: object) -> object:
        self.execute_calls += 1
        status = self.inner.execute_action(**kwargs)
        if self.dropped_responses == 0:
            self.dropped_responses += 1
            raise self.ambiguous_error(
                "canary_response_lost",
                "the synthetic successful WEIR response was deliberately dropped",
                status=502,
            )
        return status

    def get_action_status(self, **kwargs: object) -> object:
        return self.inner.get_action_status(**kwargs)


def _json_request(
    url: str,
    *,
    method: str = "GET",
    body: dict[str, object] | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    payload = None if body is None else json.dumps(body).encode("utf-8")
    request = Request(
        url,
        data=payload,
        method=method,
        headers={
            "Accept": "application/json",
            **({"Content-Type": "application/json"} if payload is not None else {}),
            **(headers or {}),
        },
    )
    try:
        with urlopen(request, timeout=10) as response:  # noqa: S310 - loopback only
            return response.status, json.loads(response.read())
    except HTTPError as error:
        return error.code, json.loads(error.read())


def _write_report(path: Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(report, indent=2, sort_keys=True) + "\n"
    path.write_text(serialized, encoding="utf-8")


def run_canary(run_dir: Path, report_path: Path, fade_source: Path) -> dict[str, object]:
    if run_dir.exists():
        raise FileExistsError(f"canary run directory already exists: {run_dir}")
    run_dir.mkdir(parents=True)
    if not (fade_source / "fade" / "weir_authority.py").is_file():
        raise FileNotFoundError(f"Fade source tree is invalid: {fade_source}")
    sys.path.insert(0, str(fade_source))

    from fade.weir_authority import (  # noqa: PLC0415
        WEIR_AUTHORITY_SCOPES,
        AmbiguousWeirTransportError,
        AuthorityClientCredential,
        AuthorityClientRegistry,
        AuthorityRunStore,
        FadeWeirAuthorityServer,
        HttpWeirActionClient,
        WeirAuthorityCoordinator,
    )
    from fade.weir_contract import WeirApprovalCommand  # noqa: PLC0415

    started_at = _utc_now()
    run_token = secrets.token_hex(8)
    run_id = f"batch9-canary-{run_token}"
    command_id = f"fade-command-{run_token}"
    weir_credential = "weir-canary-" + secrets.token_urlsafe(36)
    operator_credential = "fade-canary-" + secrets.token_urlsafe(36)
    store = SQLiteSessionStore(run_dir / "browser.sqlite3")
    captures = CaptureStore(run_dir / "captures")
    worker: PlaywrightFixtureEffectWorker | None = None
    events: list[dict[str, object]] = []

    class EventSink:
        def post(self, event: dict[str, object]) -> None:
            events.append(json.loads(json.dumps(event)))

    try:
        with FixturePage() as fixture:
            context = WorkContext.create(
                context_id=f"context-{run_token}",
                run_id=run_id,
                correlation_id=f"correlation-{run_token}",
                assignment_id=f"assignment-{run_token}",
                source=WorkContextSource.AUTOWORK,
                evidence_refs=("weir-evidence:batch9-synthetic-input",),
                created_at=_iso(started_at),
            )
            worker = PlaywrightFixtureEffectWorker(
                store,
                captures,
                context,
                fixture.url,
            )
            session = BrowserSession(
                session_id=f"session-{run_token}",
                owner_run_id=run_id,
                engine=worker.worker_id,
                worker_id=worker.worker_id,
                worker_session_id=f"worker-session-{run_token}",
                profile_id=f"profile-{run_token}",
                data_class=DataClass.PUBLIC,
                allowed_domains=["127.0.0.1"],
                state=SessionState.ACTIVE,
                revision=0,
                epoch=1,
                current_url=fixture.url,
                created_at=_iso(started_at),
                updated_at=_iso(started_at),
                expires_at=_iso(started_at + timedelta(hours=1)),
            )
            store.create_session(
                session,
                work_context=context,
                site_profile_id="synthetic-action-fixture",
                credential_scope="fixture_only",
                profile_policy_digest="sha256:" + "a" * 64,
                credential_binding_id=f"credential-{run_token}",
                worker_instance_id=worker.worker_instance_id,
            )
            approved = worker.observe(
                session.session_id,
                command_id=f"observe-approved-{run_token}",
                stage="approved",
            )
            locator = SemanticLocator(
                role="textbox",
                name="Fixture value",
                test_id="fixture-value",
            )
            target = resolve_locator(locator, approved)
            proposal = ActionCompiler().propose(
                action_id=f"action-{run_token}",
                request_id=f"request-{run_token}",
                owner_run_id=run_id,
                work_context_hash=context.context_hash,
                correlation_id=context.correlation_id,
                assignment_id=context.assignment_id,
                observation=approved,
                locator=locator,
                action_type=ActionType.FILL,
                parameters={"value": MARKER},
                parameter_data_class=DataClass.PUBLIC,
                risk=Risk.UNKNOWN,
                expected_postconditions=[
                    ActionCondition(
                        ConditionKind.ELEMENT_STATE_EQUALS,
                        "filled",
                        locator=locator,
                        target=target,
                    )
                ],
                created_at=_iso(_utc_now()),
                expires_at=_iso(_utc_now() + timedelta(minutes=10)),
            )
            proposal.preconditions.append(
                ActionCondition(
                    ConditionKind.ELEMENT_STATE_EQUALS,
                    "empty",
                    locator=locator,
                    target=target,
                )
            )
            proposal.proposal_hash = proposal.compute_hash()
            proposal.validate()
            proposals = ActionProposalStore(
                run_dir / "proposals",
                captures,
                store,
            )
            proposals.register(proposal)
            store.acquire_lease(
                session.session_id,
                run_id,
                ControllerKind.AUTOMATION,
                ttl=timedelta(minutes=5),
            )
            driver = BrowserActionDriver(
                store,
                proposals,
                worker,
                SyntheticFixtureEffectPolicy(
                    "synthetic-action-fixture",
                    fixture.origin,
                ),
            )
            application = WeirServiceApplication(
                _UnusedBackend(),
                ClientRegistry(
                    [
                        ClientCredential(
                            FADE_AUTHORITY_ID,
                            weir_credential,
                            frozenset(
                                {
                                    PROPOSAL_READ_FULL_SCOPE,
                                    ACTION_EXECUTE_SCOPE,
                                    ACTION_STATUS_SCOPE,
                                }
                            ),
                            frozenset({DataClass.PUBLIC}),
                        )
                    ]
                ),
                proposal_store=proposals,
                session_store=store,
                action_driver=driver,
            )
            command = WeirApprovalCommand(
                command_id=command_id,
                proposal_hash=proposal.proposal_hash,
                action_id=proposal.action_id,
                work_context_hash=proposal.work_context_hash,
                decision="approved",
                reason="operator approved the local synthetic fixture canary",
            )
            fade_headers = {
                "Authorization": f"Bearer {operator_credential}",
                "X-Fade-Client-Id": "local-operator",
            }

            with WeirService(application) as weir_server:
                weir_url = f"http://{weir_server.address[0]}:{weir_server.address[1]}"
                real_client = HttpWeirActionClient(
                    weir_url,
                    credential=weir_credential,
                )
                dropping_client = DropFirstExecuteResponseClient(
                    real_client,
                    AmbiguousWeirTransportError,
                )
                coordinator = WeirAuthorityCoordinator(
                    AuthorityRunStore(run_dir / "fade-runs"),
                    dropping_client,
                    event_sink=EventSink(),
                    sleeper=lambda _seconds: None,
                )
                clients = AuthorityClientRegistry(
                    (
                        AuthorityClientCredential(
                            "local-operator",
                            operator_credential,
                            WEIR_AUTHORITY_SCOPES,
                        ),
                    )
                )
                with FadeWeirAuthorityServer(coordinator, clients) as fade_server:
                    fade_url = f"http://{fade_server.address[0]}:{fade_server.address[1]}"
                    first_status, first = _json_request(
                        fade_url + "/v1/weir/runs",
                        method="POST",
                        body=command.to_dict(),
                        headers=fade_headers,
                    )
                    replay_status, replay = _json_request(
                        fade_url + "/v1/weir/runs",
                        method="POST",
                        body=command.to_dict(),
                        headers=fade_headers,
                    )
                    conflict_command = {
                        **command.to_dict(),
                        "decision": "denied",
                        "reason": "conflicting replay must fail",
                    }
                    conflict_status, conflict = _json_request(
                        fade_url + "/v1/weir/runs",
                        method="POST",
                        body=conflict_command,
                        headers=fade_headers,
                    )

            if first_status != 200 or first.get("state") != "completed":
                raise RuntimeError(f"first canary action failed: {first_status} {first}")
            if replay_status != 200 or replay != first:
                raise RuntimeError("same-process replay did not return the same result")
            if conflict_status != 409:
                raise RuntimeError(
                    f"conflicting replay was not rejected: {conflict_status} {conflict}"
                )
            if worker.apply_calls != 1 or worker.effect_count() != 1:
                raise RuntimeError("ambiguous transport or replay duplicated the effect")

            with WeirService(application) as restarted_weir:
                restarted_client = HttpWeirActionClient(
                    f"http://{restarted_weir.address[0]}:{restarted_weir.address[1]}",
                    credential=weir_credential,
                )
                restarted_coordinator = WeirAuthorityCoordinator(
                    AuthorityRunStore(run_dir / "fade-runs"),
                    restarted_client,
                    event_sink=EventSink(),
                    sleeper=lambda _seconds: None,
                )
                restarted_clients = AuthorityClientRegistry(
                    (
                        AuthorityClientCredential(
                            "local-operator",
                            operator_credential,
                            WEIR_AUTHORITY_SCOPES,
                        ),
                    )
                )
                with FadeWeirAuthorityServer(
                    restarted_coordinator,
                    restarted_clients,
                ) as restarted_fade:
                    restarted_url = (
                        f"http://{restarted_fade.address[0]}:{restarted_fade.address[1]}"
                    )
                    restart_status, restart_replay = _json_request(
                        restarted_url + "/v1/weir/runs",
                        method="POST",
                        body=command.to_dict(),
                        headers=fade_headers,
                    )
                    status_code, status_body = _json_request(
                        restarted_url + f"/v1/weir/runs/{command_id}",
                        headers=fade_headers,
                    )

            if restart_status != 200 or restart_replay != first:
                raise RuntimeError("post-restart replay did not preserve the result")
            if status_code != 200 or status_body != first:
                raise RuntimeError("post-restart status did not preserve the result")
            if worker.apply_calls != 1 or worker.effect_count() != 1:
                raise RuntimeError("service restart duplicated the browser effect")
            final_session = store.get_session(session.session_id)
            if final_session.state is not SessionState.ACTIVE:
                raise RuntimeError("completed action did not restore the active session")
            if first["decision"]["actor_id"] != "local-operator":
                raise RuntimeError("Fade did not preserve the local operator identity")
            serialized_public = json.dumps(
                {"fade": first, "events": events},
                sort_keys=True,
            )
            if MARKER in serialized_public or '"parameters"' in serialized_public:
                raise RuntimeError("private action parameters leaked into public output")

            finished_at = _utc_now()
            public_action_event = WeirActionEvent(
                header=CorrelationHeader(
                    event_id=f"weir-action-completed-{run_token}",
                    occurred_at=_iso(finished_at),
                    producer="weir",
                    run_id=context.run_id,
                    assignment_id=context.assignment_id,
                    correlation_id=context.correlation_id,
                    work_context_hash=context.context_hash,
                ),
                event_type="weir.action.completed",
                state=ActionEventState.COMPLETED,
                action_id=proposal.action_id,
                session_id=proposal.session_id,
                action_type=proposal.action_type,
                risk=proposal.risk,
                proposal_hash=proposal.proposal_hash,
                permit_hash=first["permit_ref"]["permit_hash"],
                receipt_id=first["receipt"]["receipt_id"],
                evidence_ref_count=len(context.evidence_refs),
                parameter_data_class=proposal.parameter_data_class,
                reason_code=None,
            )
            public_action_event.validate()
            report: dict[str, object] = {
                "schema": REPORT_SCHEMA,
                "run_id": run_id,
                "started_at": _iso(started_at),
                "finished_at": _iso(finished_at),
                "result": "passed",
                "scope": {
                    "origin_class": "http_loopback_ip",
                    "data_class": "public",
                    "action_type": "fill",
                    "risk": "unknown",
                    "production_account": False,
                },
                "bindings": {
                    "work_context_hash": context.context_hash,
                    "proposal_hash": proposal.proposal_hash,
                    "command_id": command_id,
                    "receipt_id": first["receipt"]["receipt_id"],
                    "receipt_hash": first["receipt"]["receipt_hash"],
                },
                "work_context": context.to_dict(),
                "public_action_event": public_action_event.to_dict(),
                "assertions": {
                    "real_playwright_effect": True,
                    "fade_http_boundary": True,
                    "weir_http_boundary": True,
                    "transport_response_loss_reconciled": (dropping_client.dropped_responses == 1),
                    "same_process_replay_stable": replay == first,
                    "conflicting_replay_rejected": conflict_status == 409,
                    "post_restart_replay_stable": restart_replay == first,
                    "effect_count": worker.effect_count(),
                    "worker_apply_calls": worker.apply_calls,
                    "session_state": final_session.state.value,
                    "operator_actor": first["decision"]["actor_id"],
                    "public_parameter_leak": False,
                },
                "event_types": sorted({str(event.get("type")) for event in events}),
                "raw_artifacts": (
                    run_dir.relative_to(Path.cwd().resolve()).as_posix()
                    if run_dir.is_relative_to(Path.cwd().resolve())
                    else run_dir.name
                ),
            }
            report["report_sha256"] = (
                "sha256:"
                + hashlib.sha256(
                    json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
                ).hexdigest()
            )
            _write_report(report_path, report)
            return report
    finally:
        if worker is not None:
            worker.close()
        store.close()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument(
        "--fade-source",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "fade",
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    report = run_canary(
        args.run_dir.resolve(),
        args.report.resolve(),
        args.fade_source.resolve(),
    )
    print(
        json.dumps(
            {
                "result": report["result"],
                "run_id": report["run_id"],
                "report": str(args.report.resolve()),
                "report_sha256": report["report_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
