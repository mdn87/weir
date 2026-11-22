"""Prepare the fixed proposal and serve it through the existing authenticated WEIR routes."""

from datetime import datetime, timedelta, timezone
import secrets
from types import SimpleNamespace
from urllib.parse import urlsplit

from weir.actions import ActionCompiler, ActionCondition, ActionType, ConditionKind, Risk
from weir.browser.admission import ProductionAdmission
from weir.browser.enrolled_fill import EnrolledField, MARKER, require
from weir.browser.enrolled_worker import EnrolledFieldWorker
from weir.browser.linux_fill_driver import LinuxEnrolledFillDriver
from weir.browser.locators import resolve_locator
from weir.browser.models import BrowserSession, ControllerKind, SessionState
from weir.models import DataClass
from weir.service import WeirServiceApplication


def prepare_enrolled_fill(*, store, proposals, context, authority, clients, backend, open_controller):
    """Called by the host, after protected enrollment and before human approval of the proposal."""
    now = datetime.now(timezone.utc)
    with authority.lock() as ingress:
        with authority.journal() as (_, rows):
            spent = rows[1] if len(rows) > 1 else None
        previous = store.enrolled_grant_requests()
        if spent is not None:
            require(previous in ([], [spent["request_digest"]]), "Session ledger and spend witness disagree")
            field = EnrolledField(**spent["field"])
            closed = SimpleNamespace(worker_id="linux-enrolled-field", worker_instance_id=spent["worker"],
                                     production_binding=None)
            def unavailable():
                raise RuntimeError("The deployment's grant is spent")
            driver = LinuxEnrolledFillDriver(store, proposals, closed, field, authority,
                                             ProductionAdmission(unavailable, expected_platform="linux"))
            app = WeirServiceApplication(backend, clients, proposal_store=proposals, session_store=store,
                                         action_driver=driver, action_admission=driver)
            return app, None
        require(not previous, "The grant witness predates the session ledger's spend")
        field, enrollment = authority.enrollment(ingress, now)
    controller = open_controller(field)
    try:
        worker = EnrolledFieldWorker(store, proposals.capture_store, field, controller, enrollment.capsule_hash)
        host = ProductionAdmission(controller.evidence, expected_platform="linux")
        driver = LinuxEnrolledFillDriver(store, proposals, worker, field, authority, host)
        driver._current_host()
        tag = secrets.token_hex(12)
        session = BrowserSession(
            session_id="field-session-" + tag, owner_run_id=context.run_id, engine=worker.worker_id,
            worker_id=worker.worker_id, worker_session_id="field-browser-" + tag, profile_id=field.profile_id,
            data_class=DataClass.PUBLIC, allowed_domains=[urlsplit(field.url).hostname], state=SessionState.ACTIVE,
            revision=0, epoch=1, current_url=field.url, created_at=now.isoformat(), updated_at=now.isoformat(),
            expires_at=(now + timedelta(minutes=10)).isoformat())
        store.create_session(session, work_context=context, site_profile_id=field.profile_id,
                             credential_scope="anonymous-enrolled-field", profile_policy_digest=field.profile_digest,
                             credential_binding_id=field.credential_binding_id, worker_instance_id=worker.worker_instance_id)
        obs = worker.observe(session.session_id, command_id="field-observe-" + tag, stage="approved")
        locator = field.locator
        target = resolve_locator(locator, obs)
        proposal = ActionCompiler().propose(
            action_id="field-fill-" + tag, request_id="field-request-" + tag, owner_run_id=context.run_id,
            work_context_hash=context.context_hash, correlation_id=context.correlation_id, assignment_id=context.assignment_id,
            observation=obs, locator=locator, action_type=ActionType.FILL, parameters={"value": MARKER},
            parameter_data_class=DataClass.PUBLIC, risk=Risk.UNKNOWN,
            expected_postconditions=[ActionCondition(ConditionKind.ELEMENT_STATE_EQUALS, "filled", locator=locator, target=target)],
            created_at=now.isoformat(), expires_at=(now + timedelta(minutes=5)).isoformat())
        proposal.preconditions.append(ActionCondition(ConditionKind.ELEMENT_STATE_EQUALS, "empty", locator=locator, target=target))
        proposal.proposal_hash = proposal.compute_hash()
        proposals.register(proposal)
        store.acquire_lease(session.session_id, context.run_id, ControllerKind.AUTOMATION, ttl=timedelta(minutes=5))
        application = WeirServiceApplication(backend, clients, proposal_store=proposals, session_store=store,
                                             action_driver=driver, action_admission=driver)
        return application, proposal
    except BaseException:
        controller.contain()
        raise
