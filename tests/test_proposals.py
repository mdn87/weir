from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from weir.actions import ActionCompiler, ActionProposal, ActionType
from weir.broker import AcquisitionBroker
from weir.browser.models import (
    BrowserSession,
    Observation,
    ObservedElement,
    SemanticLocator,
    SessionState,
)
from weir.browser.store import SQLiteSessionStore
from weir.client import HttpWeirClient, InProcessWeirClient, WeirClientError
from weir.contract import ContractViolation
from weir.models import DataClass, ReaderResult, RequestMode, WebCapture, WebRequest
from weir.persistence import CaptureStore
from weir.proposals import ActionProposalStore, ProposalNotFound
from weir.router import EngineRegistry
from weir.service import (
    PROPOSAL_READ_FULL_SCOPE,
    PROPOSAL_READ_REDACTED_SCOPE,
    PROPOSAL_WRITE_SCOPE,
    ClientCredential,
    ClientRegistry,
    WeirService,
    WeirServiceApplication,
)
from weir.work_context import WorkContext, WorkContextSource

URL = "https://app.example.test/form"
WRITER_CREDENTIAL = "proposal-writer-" + "a" * 40
FADE_CREDENTIAL = "fade-proposal-" + "b" * 40
HUD_CREDENTIAL = "hud-projection-" + "c" * 40
LIMITED_CREDENTIAL = "limited-reader-" + "d" * 40


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 8, 27, 12, 0, 2, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now


def _fixture(
    root: Path,
) -> tuple[
    ActionProposal,
    ActionProposalStore,
    CaptureStore,
    SQLiteSessionStore,
    Clock,
]:
    clock = Clock()
    capture_store = CaptureStore(root / "captures")
    session_store = SQLiteSessionStore(root / "browser.sqlite3", clock=clock)
    context = WorkContext.create(
        context_id="context-proposal-1",
        run_id="run-proposal-1",
        correlation_id="correlation-proposal-1",
        assignment_id="assignment-proposal-1",
        source=WorkContextSource.AUTOWORK,
        created_at="2026-08-27T12:00:00+00:00",
    )
    session = BrowserSession(
        session_id="session-proposal-1",
        owner_run_id=context.run_id,
        engine="playwright-observer",
        worker_id="worker-proposal-1",
        worker_session_id="worker-session-proposal-1",
        profile_id="profile-proposal-1",
        data_class=DataClass.BWA_INTERNAL,
        allowed_domains=["app.example.test"],
        state=SessionState.ACTIVE,
        revision=2,
        epoch=1,
        current_url=URL,
        created_at="2026-08-27T12:00:00+00:00",
        updated_at="2026-08-27T12:00:01+00:00",
        expires_at="2026-08-27T13:00:00+00:00",
    )
    session_store.create_session(
        session,
        work_context=context,
        site_profile_id="site-profile-proposal",
        credential_scope="credential-scope-proposal",
        profile_policy_digest="sha256:" + "1" * 64,
    )
    observation = Observation.create(
        observation_id="observation-proposal-1",
        session_id=session.session_id,
        session_revision=session.revision,
        session_epoch=session.epoch,
        capture_id="webcap-proposal-1",
        captured_at="2026-08-27T12:00:01+00:00",
        url=URL,
        title="Private form",
        elements=[
            ObservedElement(
                "element-address",
                "textbox",
                "Shipping address",
                "shipping-address",
                "enabled",
            )
        ],
        accessibility_snapshot='- textbox "Shipping address"',
    )
    request = WebRequest(
        request_id="observe-proposal-1",
        run_id=context.run_id,
        mode=RequestMode.OBSERVE,
        data_class=session.data_class,
        auth_context="browser_profile",
        intent="retain browser observation evidence",
        url=URL,
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
            engine_version="test",
            requested_url=URL,
            final_url=URL,
            title="Private form",
            auth_scope=f"profile:{session.profile_id}",
            content={
                "kind": "browser_observation",
                "observation": observation.to_dict(),
                "work_context": context.to_dict(),
                "worker_notes": [],
            },
        ),
        request,
        capture_id=observation.capture_id,
        captured_at=observation.captured_at,
    )
    capture_store.persist(capture, request)
    proposal = ActionCompiler().propose(
        action_id="action-proposal-1",
        request_id="request-proposal-1",
        owner_run_id=context.run_id,
        work_context_hash=context.context_hash,
        correlation_id=context.correlation_id,
        assignment_id=context.assignment_id,
        observation=observation,
        locator=SemanticLocator(role="textbox", name="Shipping address"),
        action_type=ActionType.FILL,
        parameters={"value": "123 Private Street"},
        parameter_data_class=DataClass.PERSONAL,
        created_at="2026-08-27T12:00:01+00:00",
        expires_at="2026-08-27T12:05:01+00:00",
    )
    proposal_store = ActionProposalStore(
        root / "proposals",
        capture_store,
        session_store,
        clock=clock,
    )
    return proposal, proposal_store, capture_store, session_store, clock


def _registry() -> ClientRegistry:
    authority_classes = frozenset({DataClass.PERSONAL, DataClass.BWA_INTERNAL})
    return ClientRegistry(
        [
            ClientCredential(
                "proposal-writer",
                WRITER_CREDENTIAL,
                frozenset({PROPOSAL_WRITE_SCOPE}),
                authority_classes,
            ),
            ClientCredential(
                "fade-proposal",
                FADE_CREDENTIAL,
                frozenset({PROPOSAL_READ_FULL_SCOPE}),
                authority_classes,
            ),
            ClientCredential(
                "hud-projection",
                HUD_CREDENTIAL,
                frozenset({PROPOSAL_READ_REDACTED_SCOPE}),
                frozenset({DataClass.PUBLIC}),
            ),
            ClientCredential(
                "limited-reader",
                LIMITED_CREDENTIAL,
                frozenset({PROPOSAL_READ_FULL_SCOPE, PROPOSAL_WRITE_SCOPE}),
                frozenset({DataClass.PUBLIC}),
            ),
        ]
    )


def _http_client(
    service: WeirService, client_id: str, credential: str
) -> HttpWeirClient:
    host, port = service.address
    return HttpWeirClient(f"http://{host}:{port}", client_id, credential)


class ProposalStoreTests(unittest.TestCase):
    def test_registration_is_observation_bound_redacted_and_restart_safe(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            proposal, store, capture_store, session_store, clock = _fixture(root)
            registered = store.register(proposal)
            projection = store.load_projection(proposal.proposal_hash)

            self.assertEqual(registered, proposal)
            self.assertEqual(store.load_by_action(proposal.action_id), proposal)
            self.assertEqual(projection.proposal_hash, proposal.proposal_hash)
            serialized = json.dumps(projection.to_dict())
            self.assertNotIn("123 Private Street", serialized)
            self.assertNotIn('"parameters"', serialized)
            self.assertEqual(
                store.required_data_classes(proposal.proposal_hash),
                frozenset({DataClass.PERSONAL, DataClass.BWA_INTERNAL}),
            )
            session_store.close()

            reopened_sessions = SQLiteSessionStore(
                root / "browser.sqlite3", clock=clock
            )
            try:
                reopened = ActionProposalStore(
                    root / "proposals",
                    CaptureStore(capture_store.root),
                    reopened_sessions,
                    clock=clock,
                )
                self.assertEqual(reopened.load(proposal.proposal_hash), proposal)
                self.assertEqual(
                    reopened.load_projection(proposal.proposal_hash), projection
                )
            finally:
                reopened_sessions.close()

    def test_registration_rejects_missing_context_and_stale_observations(self):
        with tempfile.TemporaryDirectory() as temp:
            proposal, store, _, session_store, _ = _fixture(Path(temp))
            proposal.work_context_hash = "sha256:" + "f" * 64
            proposal.proposal_hash = proposal.compute_hash()
            with self.assertRaises(ContractViolation) as raised:
                store.register(proposal)
            self.assertEqual(raised.exception.reason_code, "proposal_context_mismatch")
            session_store.close()

        with tempfile.TemporaryDirectory() as temp:
            proposal, store, _, session_store, _ = _fixture(Path(temp))
            session_store.mark_lost(
                proposal.session_id,
                proposal.session_revision,
                event_type="web.browser.session.lost",
                attributes={"reason": "test"},
            )
            with self.assertRaises(ContractViolation) as raised:
                store.register(proposal)
            self.assertEqual(raised.exception.reason_code, "proposal_observation_stale")
            session_store.close()

    def test_action_id_conflict_never_publishes_the_losing_proposal(self):
        with tempfile.TemporaryDirectory() as temp:
            proposal, store, _, session_store, _ = _fixture(Path(temp))
            store.register(proposal)
            competing = ActionProposal.from_dict(proposal.to_dict())
            competing.parameters = {"value": "Different value"}
            competing.proposal_hash = competing.compute_hash()
            competing.validate()

            with self.assertRaises(ContractViolation) as raised:
                store.register(competing)
            self.assertEqual(raised.exception.reason_code, "proposal_action_conflict")
            with self.assertRaises(ProposalNotFound):
                store.load(competing.proposal_hash)
            self.assertEqual(store.load(proposal.proposal_hash), proposal)
            session_store.close()

    def test_projection_tampering_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            proposal, store, _, session_store, _ = _fixture(root)
            store.register(proposal)
            digest = proposal.proposal_hash.removeprefix("sha256:")
            projection_path = (
                root
                / "proposals"
                / "by-hash"
                / digest[:2]
                / f"{digest}.projection.json"
            )
            projection_path.write_bytes(b"{}\n")
            with self.assertRaises(ContractViolation) as raised:
                store.load_projection(proposal.proposal_hash)
            self.assertEqual(raised.exception.reason_code, "proposal_store_corrupt")
            session_store.close()


class ProposalServiceTests(unittest.TestCase):
    def test_clients_share_contract_with_prewrite_and_preread_authorization(self):
        with tempfile.TemporaryDirectory() as temp:
            proposal, proposal_store, capture_store, session_store, _ = _fixture(
                Path(temp)
            )
            backend = InProcessWeirClient(
                AcquisitionBroker(
                    registry=EngineRegistry([]),
                    store=capture_store,
                ),
                capture_store,
                proposal_store=proposal_store,
            )
            application = WeirServiceApplication(
                backend,
                _registry(),
                proposal_store=proposal_store,
            )
            with WeirService(application) as service:
                limited = _http_client(
                    service, "limited-reader", LIMITED_CREDENTIAL
                )
                with self.assertRaises(WeirClientError) as raised:
                    limited.register_proposal(proposal)
                self.assertEqual(raised.exception.reason_code, "data_class_denied")
                with self.assertRaises(ProposalNotFound):
                    proposal_store.load(proposal.proposal_hash)

                writer = _http_client(
                    service, "proposal-writer", WRITER_CREDENTIAL
                )
                self.assertEqual(writer.register_proposal(proposal), proposal)
                self.assertEqual(backend.get_proposal(proposal.proposal_hash), proposal)

                fade = _http_client(service, "fade-proposal", FADE_CREDENTIAL)
                self.assertEqual(fade.get_proposal(proposal.proposal_hash), proposal)

                with mock.patch.object(
                    proposal_store,
                    "load_record",
                    wraps=proposal_store.load_record,
                ) as full_load:
                    with self.assertRaises(WeirClientError) as raised:
                        limited.get_proposal(proposal.proposal_hash)
                    self.assertEqual(
                        raised.exception.reason_code, "data_class_denied"
                    )
                    full_load.assert_not_called()

                hud = _http_client(service, "hud-projection", HUD_CREDENTIAL)
                with mock.patch.object(
                    proposal_store,
                    "load_record",
                    side_effect=AssertionError("redacted reads must not load authority"),
                ):
                    projection = hud.get_proposal_projection(proposal.proposal_hash)
                self.assertEqual(
                    projection,
                    backend.get_proposal_projection(proposal.proposal_hash),
                )
                self.assertNotIn(
                    "123 Private Street", json.dumps(projection.to_dict())
                )
            session_store.close()


if __name__ == "__main__":
    unittest.main()
