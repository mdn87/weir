"""Run the bounded Batch 8 Mission Control -> relay -> Fade -> WEIR canary.

The only effect is one fixed fill against an ephemeral loopback page containing
public synthetic data. Mission Control receives only the redacted WEIR proposal
event; the value to fill remains in the workstation-local proposal store.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from run_fade_weir_action_canary import (
    MARKER,
    FixturePage,
    PlaywrightFixtureEffectWorker,
    _UnusedBackend,
)
from weir.actions import (
    ActionCompiler,
    ActionCondition,
    ActionType,
    ConditionKind,
    Risk,
)
from weir.browser.admission import LocalSyntheticActionAdmission
from weir.browser.effect_driver import (
    FADE_AUTHORITY_ID,
    BrowserActionDriver,
    SyntheticFixtureEffectPolicy,
)
from weir.browser.locators import resolve_locator
from weir.browser.models import (
    BrowserSession,
    ControllerKind,
    SemanticLocator,
    SessionState,
)
from weir.browser.store import SQLiteSessionStore
from weir.events import ActionEventState, CorrelationHeader, WeirActionEvent
from weir.models import DataClass
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

REPORT_SCHEMA = "weir-fade-remote-relay-canary/v1"
ACKNOWLEDGEMENT = "ALLOW BATCH 8 SYNTHETIC REMOTE RELAY"
APU_WATCH_EXECUTABLE = Path(r"C:\Users\Matt\.local\bin\apu-watch.exe")
FINAL_AUTHORITY_STATES = frozenset(
    {
        "completed",
        "failed",
        "blocked",
        "denied",
        "expired",
        "conflict",
        "cancelled",
        "outcome_unknown",
    }
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _write_report(path: Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _apu_watch_payload(payload: object, *, now: datetime) -> dict[str, object]:
    try:
        if not isinstance(payload, dict) or set(payload) != {"watchers"}:
            raise TypeError
        watchers = payload["watchers"]
        if not isinstance(watchers, list):
            raise TypeError
        matches = [
            item
            for item in watchers
            if isinstance(item, dict)
            and item.get("watcher") == "primary-agent-autonomy-loss"
        ]
        if len(matches) != 1:
            raise ValueError
        selected = matches[0]
        heartbeat = datetime.fromisoformat(
            str(selected["service_heartbeat"]).replace("Z", "+00:00")
        ).astimezone(timezone.utc)
        attributed_at = datetime.fromisoformat(
            str(selected["last_successful_attribution"]).replace("Z", "+00:00")
        ).astimezone(timezone.utc)
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("apu-watch returned invalid health evidence") from exc
    heartbeat_age = (now - heartbeat).total_seconds()
    attribution_age = (now - attributed_at).total_seconds()
    if (
        selected.get("enabled") is not True
        or selected.get("provider") != "codex"
        or selected.get("selector_mode") != "strict"
        or type(selected.get("ambiguity_count")) is not int
        or selected["ambiguity_count"] != 0
        or selected.get("background_service") is not False
        or not isinstance(selected.get("package_version"), str)
        or not selected["package_version"]
        or not isinstance(selected.get("build_revision"), str)
        or len(selected["build_revision"]) != 71
        or not selected["build_revision"].startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in selected["build_revision"][7:])
        or not -5 <= heartbeat_age <= 300
        or not -5 <= attribution_age <= 300
    ):
        raise RuntimeError("apu-watch attribution evidence is unhealthy")
    return {
        "watcher": selected["watcher"],
        "enabled": True,
        "provider": selected["provider"],
        "selector_mode": selected["selector_mode"],
        "ambiguity_count": 0,
        "background_service": False,
        "package_version": selected.get("package_version"),
        "build_revision": selected.get("build_revision"),
        "last_successful_attribution": selected["last_successful_attribution"],
        "service_heartbeat": selected["service_heartbeat"],
    }


def _apu_watch_status(executable: Path) -> dict[str, object]:
    if not executable.is_file():
        raise RuntimeError("the configured apu-watch executable is unavailable")
    completed = subprocess.run(
        [str(executable), "--json"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("apu-watch returned invalid health evidence") from exc
    return _apu_watch_payload(payload, now=_utc_now())


def _event_ingest_url(value: str) -> str:
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("event ingest URL has an invalid port") from exc
    if (
        parsed.scheme != "http"
        or parsed.hostname != "10.0.1.33"
        or port != 8787
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("event ingest must be the reviewed LAN origin http://10.0.1.33:8787")
    return "http://10.0.1.33:8787"


def _action_event(
    *,
    event_id: str,
    context: WorkContext,
    proposal: Any,
    state: ActionEventState,
    permit_hash: str | None = None,
    receipt_id: str | None = None,
    reason_code: str | None = None,
) -> WeirActionEvent:
    event = WeirActionEvent(
        header=CorrelationHeader(
            event_id=event_id,
            occurred_at=_iso(_utc_now()),
            producer="weir",
            run_id=context.run_id,
            assignment_id=context.assignment_id,
            correlation_id=context.correlation_id,
            work_context_hash=context.context_hash,
        ),
        event_type=f"weir.action.{state.value}",
        state=state,
        action_id=proposal.action_id,
        session_id=proposal.session_id,
        action_type=proposal.action_type,
        risk=proposal.risk,
        proposal_hash=proposal.proposal_hash,
        permit_hash=permit_hash,
        receipt_id=receipt_id,
        evidence_ref_count=len(context.evidence_refs),
        parameter_data_class=proposal.parameter_data_class,
        reason_code=reason_code,
    )
    event.validate()
    return event


def _failure_event_state(
    worker: PlaywrightFixtureEffectWorker | None,
) -> ActionEventState:
    # apply_calls increments immediately before the browser mutation. Once that
    # boundary is crossed, a broken page cannot safely prove whether the fill
    # happened, so failure reporting must be conservative without querying it.
    if worker is not None and worker.apply_calls > 0:
        return ActionEventState.OUTCOME_UNKNOWN
    return ActionEventState.BLOCKED


def _authority_event_types(events: list[dict[str, object]]) -> list[str]:
    event_types = [event.get("type") for event in events]
    if any(
        not isinstance(event_type, str) or not event_type
        for event_type in event_types
    ):
        raise RuntimeError("remote canary captured an invalid Fade authority event")
    return sorted(set(event_types))


def run_remote_canary(
    run_dir: Path,
    report_path: Path,
    fade_source: Path,
    *,
    event_ingest_url: str,
    event_ingest_token: str,
    apu_watch: Path,
    timeout_seconds: int,
) -> dict[str, object]:
    if run_dir.exists():
        raise FileExistsError(f"canary run directory already exists: {run_dir}")
    run_dir.mkdir(parents=True)
    if not (fade_source / "fade" / "remote_relay_poller.py").is_file():
        raise FileNotFoundError(f"Fade source tree lacks the remote relay client: {fade_source}")
    if len(event_ingest_token) < 20:
        raise ValueError("LUGOS_EVENT_INGEST_TOKEN is unavailable")
    sys.path.insert(0, str(fade_source))

    from fade.events import EventIngestClient  # noqa: PLC0415
    from fade.remote_decision import RemoteDecisionAcknowledgement  # noqa: PLC0415
    from fade.remote_relay_poller import poller_from_environment  # noqa: PLC0415
    from fade.weir_authority import (  # noqa: PLC0415
        WEIR_AUTHORITY_SCOPES,
        AuthorityClientCredential,
        AuthorityClientRegistry,
        AuthorityRunStore,
        FadeWeirAuthorityServer,
        HttpWeirActionClient,
        WeirAuthorityCoordinator,
    )

    started_at = _utc_now()
    run_token = secrets.token_hex(8)
    run_id = f"batch8-remote-canary-{run_token}"
    weir_credential = "weir-remote-canary-" + secrets.token_urlsafe(36)
    operator_credential = "fade-remote-canary-" + secrets.token_urlsafe(36)
    apu_status = _apu_watch_status(apu_watch)
    ingest = EventIngestClient(event_ingest_url, token=event_ingest_token)
    store = SQLiteSessionStore(run_dir / "browser.sqlite3")
    captures = CaptureStore(run_dir / "captures")
    worker: PlaywrightFixtureEffectWorker | None = None
    proposal_publish_attempted = False
    proposal_published = False
    terminal_published = False
    remote_acknowledgement_confirmed = False
    context: WorkContext | None = None
    proposal: Any | None = None
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
                evidence_refs=("weir-evidence:batch8-synthetic-input",),
                created_at=_iso(started_at),
            )
            worker = PlaywrightFixtureEffectWorker(store, captures, context, fixture.url)
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
            observation = worker.observe(
                session.session_id,
                command_id=f"observe-approved-{run_token}",
                stage="approved",
            )
            locator = SemanticLocator(role="textbox", name="Fixture value", test_id="fixture-value")
            target = resolve_locator(locator, observation)
            proposal = ActionCompiler().propose(
                action_id=f"action-{run_token}",
                request_id=f"request-{run_token}",
                owner_run_id=run_id,
                work_context_hash=context.context_hash,
                correlation_id=context.correlation_id,
                assignment_id=context.assignment_id,
                observation=observation,
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
            proposals = ActionProposalStore(run_dir / "proposals", captures, store)
            proposals.register(proposal)
            store.acquire_lease(
                session.session_id,
                run_id,
                ControllerKind.AUTOMATION,
                ttl=timedelta(minutes=10),
            )
            driver = BrowserActionDriver(
                store,
                proposals,
                worker,
                SyntheticFixtureEffectPolicy("synthetic-action-fixture", fixture.origin),
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
                action_admission=LocalSyntheticActionAdmission("approved-batch8-remote-canary"),
            )
            command_id = "mc-remote-approve-" + proposal.proposal_hash.removeprefix("sha256:")[:32]
            run_store = AuthorityRunStore(run_dir / "fade-runs")
            clients = AuthorityClientRegistry(
                (
                    AuthorityClientCredential(
                        "local-operator",
                        operator_credential,
                        WEIR_AUTHORITY_SCOPES,
                    ),
                )
            )
            proposed_event = _action_event(
                event_id=f"weir-action-proposed-{run_token}",
                context=context,
                proposal=proposal,
                state=ActionEventState.PROPOSED,
            )

            with WeirService(application) as weir_server:
                weir_url = f"http://{weir_server.address[0]}:{weir_server.address[1]}"
                coordinator = WeirAuthorityCoordinator(
                    run_store,
                    HttpWeirActionClient(weir_url, credential=weir_credential),
                    event_sink=EventSink(),
                )
                with FadeWeirAuthorityServer(coordinator, clients):
                    poller = poller_from_environment(coordinator)
                    health = poller.consumer.client.health()
                    if health["device_id"] != poller.consumer.device_id:
                        raise RuntimeError("remote relay health named a different device")
                    proposal_publish_attempted = True
                    ingest.post(proposed_event.to_dict())
                    proposal_published = True
                    print(
                        json.dumps(
                            {
                                "event": "remote_canary_waiting_for_passkey_approval",
                                "command_id": command_id,
                                "proposal_hash": proposal.proposal_hash,
                                "operator_url": "https://knot.newman.foo",
                                "timeout_seconds": timeout_seconds,
                            },
                            sort_keys=True,
                        ),
                        flush=True,
                    )
                    poller.start()
                    try:
                        deadline = time.monotonic() + timeout_seconds
                        authority_record = None
                        relay_record = None
                        while time.monotonic() < deadline:
                            authority_record = run_store.load(command_id)
                            relay_record = poller.consumer.ledger.load(command_id)
                            if (
                                authority_record is not None
                                and authority_record["state"] in FINAL_AUTHORITY_STATES
                                and relay_record is not None
                                and relay_record["acknowledgement"] is not None
                            ):
                                break
                            time.sleep(0.25)
                        else:
                            raise TimeoutError(
                                "remote canary approval did not settle before timeout"
                            )
                    finally:
                        poller.close()

                    acknowledgement_record = RemoteDecisionAcknowledgement.from_dict(
                        relay_record["acknowledgement"]
                    )
                    # A local settled record proves replay safety, but not that an
                    # ambiguous HTTP response reached the host. Re-send the exact
                    # idempotent acknowledgement and require the relay's bound
                    # terminal response before calling the canary successful.
                    poller.consumer.client.acknowledge(acknowledgement_record)
                    remote_acknowledgement_confirmed = True
                    first = run_store.projection(authority_record)
                    # Restart the outbound poll loop against the settled ledgers. The
                    # terminal queue record must not become a second effect.
                    restarted_poller = poller_from_environment(coordinator)
                    restarted_poller.start()
                    time.sleep(2.0)
                    restarted_poller.close()

            if first["state"] != "completed":
                raise RuntimeError(f"remote authority ended in {first['state']}")
            if worker.apply_calls != 1 or worker.effect_count() != 1:
                raise RuntimeError("remote relay restart or replay duplicated the effect")
            final_session = store.get_session(session.session_id)
            if final_session.state is not SessionState.ACTIVE:
                raise RuntimeError("completed remote action did not restore the active session")
            acknowledgement = acknowledgement_record.to_dict()
            if (
                acknowledgement["outcome"] != "completed"
                or acknowledgement["command_id"] != command_id
                or acknowledgement["actor_id"] != first["decision"]["actor_id"]
                or acknowledgement["transport_principal"] != health["transport_principal"]
            ):
                raise RuntimeError("remote acknowledgement lost an authority binding")
            serialized_public = json.dumps(
                {"fade": first, "relay": relay_record, "events": events},
                sort_keys=True,
            )
            if MARKER in serialized_public or '"parameters"' in serialized_public:
                raise RuntimeError("private action parameters leaked into remote output")

            terminal_event = _action_event(
                event_id=f"weir-action-completed-{run_token}",
                context=context,
                proposal=proposal,
                state=ActionEventState.COMPLETED,
                permit_hash=first["permit_ref"]["permit_hash"],
                receipt_id=first["receipt"]["receipt_id"],
            )
            ingest.post(terminal_event.to_dict())
            terminal_published = True
            finished_at = _utc_now()
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
                    "target_device": health["device_id"],
                },
                "bindings": {
                    "work_context_hash": context.context_hash,
                    "proposal_hash": proposal.proposal_hash,
                    "command_id": command_id,
                    "capsule_id": relay_record["capsule_id"],
                    "receipt_id": first["receipt"]["receipt_id"],
                    "receipt_hash": first["receipt"]["receipt_hash"],
                    "acknowledgement_hash": acknowledgement["acknowledgement_hash"],
                    "transport_principal": acknowledgement["transport_principal"],
                    "operator_actor": acknowledgement["actor_id"],
                },
                "apu_watch": apu_status,
                "assertions": {
                    "real_playwright_effect": True,
                    "mission_control_projection_event": proposal_published,
                    "tls13_mtls_relay_health": True,
                    "signed_capsule_verified": True,
                    "fade_ledger_reserved_before_dispatch": True,
                    "final_revocation_check": True,
                    "terminal_acknowledgement": remote_acknowledgement_confirmed,
                    "poller_restart_replay_safe": worker.effect_count() == 1,
                    "effect_count": worker.effect_count(),
                    "worker_apply_calls": worker.apply_calls,
                    "session_state": final_session.state.value,
                    "public_parameter_leak": False,
                    "terminal_projection_event": terminal_published,
                },
                "event_types": _authority_event_types(events),
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
    except Exception:
        if (
            proposal_publish_attempted
            and not terminal_published
            and context is not None
            and proposal is not None
        ):
            state = _failure_event_state(worker)
            reason = (
                "remote_canary_unverified"
                if state is ActionEventState.OUTCOME_UNKNOWN
                else "remote_canary_failed"
            )
            try:
                ingest.post(
                    _action_event(
                        event_id=f"weir-action-{state.value}-{run_token}",
                        context=context,
                        proposal=proposal,
                        state=state,
                        reason_code=reason,
                    ).to_dict()
                )
            except Exception:
                pass
        raise
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
    parser.add_argument(
        "--event-ingest-url",
        default=os.environ.get("FADE_EVENT_INGEST_URL", "http://10.0.1.33:8787"),
    )
    parser.add_argument(
        "--apu-watch",
        type=Path,
        default=APU_WATCH_EXECUTABLE,
    )
    parser.add_argument("--timeout-seconds", type=int, default=420)
    parser.add_argument("--arm-remote-relay", action="store_true")
    parser.add_argument("--acknowledge-target", default="")
    return parser


def main() -> int:
    args = _parser().parse_args()
    if (
        not args.arm_remote_relay
        or args.acknowledge_target != ACKNOWLEDGEMENT
        or os.environ.get("FADE_REMOTE_RELAY_ENABLED") != "true"
        or os.environ.get("FADE_WEIR_RELAY_INGRESS_ENABLED") != "true"
    ):
        raise SystemExit(
            "remote canary requires both Fade flags, --arm-remote-relay, and "
            f'--acknowledge-target "{ACKNOWLEDGEMENT}"'
        )
    if not 30 <= args.timeout_seconds <= 480:
        raise SystemExit("--timeout-seconds must be between 30 and 480")
    if args.apu_watch.resolve() != APU_WATCH_EXECUTABLE.resolve():
        raise SystemExit(f"--apu-watch must resolve to {APU_WATCH_EXECUTABLE}")
    event_ingest_token = os.environ.get("LUGOS_EVENT_INGEST_TOKEN", "")
    report = run_remote_canary(
        args.run_dir.resolve(),
        args.report.resolve(),
        args.fade_source.resolve(),
        event_ingest_url=_event_ingest_url(args.event_ingest_url),
        event_ingest_token=event_ingest_token,
        apu_watch=args.apu_watch.resolve(),
        timeout_seconds=args.timeout_seconds,
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
