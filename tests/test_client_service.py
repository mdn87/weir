from __future__ import annotations

import http.client
import itertools
import json
import tempfile
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from weir.broker import AcquisitionBroker
from weir.browser.models import BrowserSession, SessionState
from weir.browser.process_worker import WorkerDeathAttestation
from weir.browser.store import (
    DEAD_WORKER_RETIREMENT_DISPOSITION,
    SQLiteSessionStore,
)
from weir.client import HttpWeirClient, InProcessWeirClient, WeirClientError
from weir.engines.base import EngineProbe, ReaderEngine, SearchEngine
from weir.evidence import AcquisitionEnvelope
from weir.models import DataClass, ReaderResult, RequestMode, WebRequest
from weir.persistence import CaptureStore, FileCaptureCache
from weir.router import EngineRegistry
from weir.service import (
    ACQUISITION_READ_SCOPE,
    COMMAND_READ_SCOPE,
    EVIDENCE_READ_SCOPE,
    PROFILE_RETIRE_SCOPE,
    ClientCredential,
    ClientRegistry,
    ServiceRequestError,
    WeirService,
    WeirServiceApplication,
)
from weir.work_context import WorkContext, WorkContextSource

LUGOS_CREDENTIAL = "lugos-mcp-" + "a" * 40
FADE_CREDENTIAL = "fade-authority-" + "b" * 40
OPERATOR_CREDENTIAL = "weir-operator-" + "c" * 40


class StubReader(ReaderEngine):
    def __init__(self, engine_id: str, *, content_size: int = 8) -> None:
        self.id = engine_id
        self.content_size = content_size
        self.calls = 0

    def probe(self) -> EngineProbe:
        return EngineProbe(self.id, True, version="test")

    def read(self, request: WebRequest) -> ReaderResult:
        self.calls += 1
        return ReaderResult(
            engine=self.id,
            engine_version="test",
            requested_url=request.url or "",
            final_url=request.url or "",
            content={"text": "evidence" * self.content_size},
        )


class StubSearch(SearchEngine):
    id = "ebay"

    def __init__(self) -> None:
        self.calls = 0

    def probe(self) -> EngineProbe:
        return EngineProbe(self.id, True, version="test")

    def search(self, request: WebRequest) -> ReaderResult:
        self.calls += 1
        return ReaderResult(
            engine=self.id,
            engine_version="test",
            requested_url="https://api.ebay.test/search",
            final_url="https://api.ebay.test/search",
            content={"listings": [{"id": "listing-1", "title": "Keyboard"}]},
        )


def _read_request(
    request_id: str,
    *,
    data_class: DataClass = DataClass.PUBLIC,
) -> WebRequest:
    private = data_class is not DataClass.PUBLIC
    return WebRequest(
        request_id=request_id,
        run_id="run-service",
        mode=RequestMode.READ,
        data_class=data_class,
        auth_context="browser" if private else "none",
        profile_id="private-profile" if private else None,
        url="https://example.com/page",
        capture_policy="full_evidence" if private else "content",
    )


def _search_request(request_id: str) -> WebRequest:
    return WebRequest(
        request_id=request_id,
        run_id="run-service",
        mode=RequestMode.SEARCH,
        data_class=DataClass.PUBLIC,
        auth_context="none",
        query="keyboard",
        source="ebay",
        capture_policy="content",
    )


def _acquisition(request: WebRequest) -> AcquisitionEnvelope:
    context = WorkContext.create(
        context_id=f"context-{request.request_id}",
        run_id=request.run_id,
        correlation_id=request.request_id,
        source=WorkContextSource.CALLER,
        created_at="2026-08-27T12:00:00+00:00",
    )
    return AcquisitionEnvelope.create(work_context=context, request=request)


def _client_registry() -> ClientRegistry:
    return ClientRegistry(
        [
            ClientCredential(
                "lugos-mcp",
                LUGOS_CREDENTIAL,
                frozenset({ACQUISITION_READ_SCOPE, EVIDENCE_READ_SCOPE}),
                frozenset({DataClass.PUBLIC}),
            ),
            ClientCredential(
                "fade-weir",
                FADE_CREDENTIAL,
                frozenset({COMMAND_READ_SCOPE}),
                frozenset({DataClass.PUBLIC}),
            ),
            ClientCredential(
                "weir-operator",
                OPERATOR_CREDENTIAL,
                frozenset({PROFILE_RETIRE_SCOPE}),
                frozenset({DataClass.PUBLIC, DataClass.BWA_INTERNAL}),
            ),
        ]
    )


def _backend(
    root: Path,
    *,
    command_store: SQLiteSessionStore | None = None,
    content_size: int = 8,
    evidence_id: str | None = None,
) -> tuple[InProcessWeirClient, StubReader, StubSearch]:
    oc = StubReader("oc", content_size=content_size)
    agent = StubReader("agent-browser-read", content_size=content_size)
    search = StubSearch()
    store = CaptureStore(root)
    identifiers = itertools.count(1)
    broker = AcquisitionBroker(
        registry=EngineRegistry([oc, agent, search]),
        store=store,
        cache=FileCaptureCache(root / "cache"),
        evidence_id_factory=(
            (lambda: evidence_id)
            if evidence_id is not None
            else (lambda: f"evidence-service-{next(identifiers)}")
        ),
    )
    return (
        InProcessWeirClient(broker, store, command_store=command_store),
        oc,
        search,
    )


def _http_client(service: WeirService, *, fade: bool = False) -> HttpWeirClient:
    host, port = service.address
    return HttpWeirClient(
        f"http://{host}:{port}",
        "fade-weir" if fade else "lugos-mcp",
        FADE_CREDENTIAL if fade else LUGOS_CREDENTIAL,
    )


def _raw_request(
    base_url: str,
    path: str,
    *,
    client_id: str = "lugos-mcp",
    credential: str = LUGOS_CREDENTIAL,
    deadline: datetime | None = None,
    body: bytes | None = None,
) -> tuple[int, dict]:
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {credential}",
        "X-Weir-Client-Id": client_id,
        "X-Weir-Deadline": (
            deadline or datetime.now(timezone.utc) + timedelta(seconds=10)
        ).isoformat(),
    }
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        base_url + path,
        data=body,
        headers=headers,
        method="POST" if body is not None else "GET",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


class ClientContractTests(unittest.TestCase):
    def _exercise_client(self, client, suffix: str) -> None:
        read = client.read(_acquisition(_read_request(f"read-{suffix}")))
        search = client.search(_acquisition(_search_request(f"search-{suffix}")))
        enrich = client.enrich(_acquisition(_read_request(f"enrich-{suffix}")))

        for response in (read, search, enrich):
            response.validate()
            stored = client.get_evidence(response.evidence_reference_ref)
            self.assertEqual(stored, response.evidence_reference)
            materialized = client.materialize_evidence(stored.evidence_ref_id)
            self.assertEqual(materialized.reference, stored)
            self.assertEqual(materialized.content, response.capture.content)

        self.assertEqual(read.capture.engine, "oc")
        self.assertEqual(search.capture.engine, "ebay")
        self.assertEqual(enrich.evidence_reference.request_id, f"enrich-{suffix}")

    @mock.patch("weir.broker.check_target_policy")
    def test_in_process_and_http_clients_obey_one_contract(self, policy_check):
        with tempfile.TemporaryDirectory() as temp:
            backend, _, _ = _backend(Path(temp))
            self._exercise_client(backend, "in-process")
            application = WeirServiceApplication(backend, _client_registry())
            with WeirService(application) as service:
                self._exercise_client(_http_client(service), "http")


class ServiceBoundaryTests(unittest.TestCase):
    def test_profile_retirement_uses_authenticated_actor_and_exact_death_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            store = SQLiteSessionStore(root / "browser.sqlite3")
            now = datetime.now(timezone.utc)
            session = BrowserSession(
                session_id="session-retire-1",
                owner_run_id="run-retire-1",
                engine="playwright-observer",
                worker_id="worker-retire-1",
                worker_session_id="pending-retire-1",
                profile_id="profile-retire-1",
                data_class=DataClass.BWA_INTERNAL,
                allowed_domains=["app.example.test"],
                state=SessionState.OPENING,
                revision=0,
                epoch=1,
                current_url=None,
                created_at=now.isoformat(),
                updated_at=now.isoformat(),
                expires_at=(now + timedelta(hours=1)).isoformat(),
            )
            store.create_session(
                session,
                site_profile_id="site-retire-1",
                credential_scope="read_only",
                profile_policy_digest="sha256:" + "a" * 64,
                credential_binding_id="credential-binding-retire-1",
                worker_instance_id="worker-instance-retire-1",
            )
            store.mark_lost(session.session_id, session.revision)
            attestation = WorkerDeathAttestation.create(
                worker_id=session.worker_id,
                worker_instance_id="worker-instance-retire-1",
                process_id=4321,
                exit_code=1,
                reason="worker_exited",
                worker_exited_gracefully=False,
                process_tree_confirmed_dead=True,
            )
            store.record_worker_death_attestation(attestation)
            body = json.dumps(
                {
                    "session_id": session.session_id,
                    "retirement_id": "retirement-service-1",
                    "expected_session_epoch": session.epoch,
                    "expected_worker_id": session.worker_id,
                    "expected_worker_instance_id": "worker-instance-retire-1",
                    "expected_credential_binding_id": (
                        "credential-binding-retire-1"
                    ),
                    "attestation_hash": attestation.attestation_hash,
                    "disposition": DEAD_WORKER_RETIREMENT_DISPOSITION,
                    "disposition_ref": "operator-ticket-1",
                }
            ).encode("utf-8")
            backend, _, _ = _backend(root / "captures", command_store=store)
            application = WeirServiceApplication(
                backend,
                _client_registry(),
                session_store=store,
            )
            try:
                with WeirService(application) as service:
                    base_url = f"http://{service.address[0]}:{service.address[1]}"
                    denied, denied_body = _raw_request(
                        base_url,
                        "/v1/browser/profile-retirements",
                        client_id="fade-weir",
                        credential=FADE_CREDENTIAL,
                        body=body,
                    )
                    self.assertEqual(denied, 403)
                    self.assertEqual(
                        denied_body["error"]["reason_code"],
                        "scope_denied",
                    )

                    status, response = _raw_request(
                        base_url,
                        "/v1/browser/profile-retirements",
                        client_id="weir-operator",
                        credential=OPERATOR_CREDENTIAL,
                        body=body,
                    )
                    replay_status, replay = _raw_request(
                        base_url,
                        "/v1/browser/profile-retirements",
                        client_id="weir-operator",
                        credential=OPERATOR_CREDENTIAL,
                        body=body,
                    )
                self.assertEqual(status, 200)
                self.assertEqual(replay_status, 200)
                self.assertEqual(replay, response)
                self.assertEqual(response["session_state"], "closed")
                self.assertEqual(response["reservation_state"], "released")
                reservation = store.profile_reservation(session.session_id)
                self.assertEqual(reservation.release_actor_id, "weir-operator")
                self.assertEqual(reservation.release_ref, "operator-ticket-1")
            finally:
                store.close()

    def test_registry_rejects_shared_credentials(self):
        with self.assertRaisesRegex(ValueError, "may not share"):
            ClientRegistry(
                [
                    ClientCredential(
                        "first",
                        LUGOS_CREDENTIAL,
                        frozenset({ACQUISITION_READ_SCOPE}),
                    ),
                    ClientCredential(
                        "second",
                        LUGOS_CREDENTIAL,
                        frozenset({EVIDENCE_READ_SCOPE}),
                    ),
                ]
            )
        credential = ClientCredential(
            "safe-repr",
            LUGOS_CREDENTIAL,
            frozenset({ACQUISITION_READ_SCOPE}),
        )
        self.assertNotIn(LUGOS_CREDENTIAL, repr(credential))

    def test_server_and_client_reject_non_loopback_origins(self):
        with tempfile.TemporaryDirectory() as temp:
            backend, _, _ = _backend(Path(temp))
            application = WeirServiceApplication(backend, _client_registry())
            with self.assertRaisesRegex(ValueError, "loopback"):
                WeirService(application, host="0.0.0.0")
        with self.assertRaisesRegex(ValueError, "loopback"):
            HttpWeirClient(
                "http://192.0.2.1:8811", "lugos-mcp", LUGOS_CREDENTIAL
            )
        with self.assertRaisesRegex(ValueError, "invalid port"):
            HttpWeirClient(
                "http://127.0.0.1:not-a-port", "lugos-mcp", LUGOS_CREDENTIAL
            )

    @mock.patch("weir.broker.check_target_policy")
    def test_max_length_evidence_id_and_prefixed_handle_round_trip(self, policy_check):
        with tempfile.TemporaryDirectory() as temp:
            backend, _, _ = _backend(Path(temp), evidence_id="e" * 128)
            application = WeirServiceApplication(backend, _client_registry())
            with WeirService(application) as service:
                client = _http_client(service)
                response = client.read(
                    _acquisition(_read_request("max-evidence-id"))
                )
                loaded = client.get_evidence(response.evidence_reference_ref)
            self.assertEqual(loaded, response.evidence_reference)

    @mock.patch("weir.broker.check_target_policy")
    def test_named_identity_scope_and_data_class_fail_before_engine(self, policy_check):
        with tempfile.TemporaryDirectory() as temp:
            backend, reader, _ = _backend(Path(temp))
            application = WeirServiceApplication(backend, _client_registry())
            with WeirService(application) as service:
                wrong_secret = HttpWeirClient(
                    f"http://{service.address[0]}:{service.address[1]}",
                    "lugos-mcp",
                    "wrong-credential-" + "x" * 40,
                )
                with self.assertRaises(WeirClientError) as raised:
                    wrong_secret.read(_acquisition(_read_request("wrong-secret")))
                self.assertEqual(raised.exception.status, 401)

                with self.assertRaises(WeirClientError) as raised:
                    _http_client(service, fade=True).read(
                        _acquisition(_read_request("wrong-scope"))
                    )
                self.assertEqual(raised.exception.reason_code, "scope_denied")

                with self.assertRaises(WeirClientError) as raised:
                    _http_client(service).read(
                        _acquisition(
                            _read_request(
                                "private-data", data_class=DataClass.PERSONAL
                            )
                        )
                    )
                self.assertEqual(raised.exception.reason_code, "data_class_denied")

        self.assertEqual(reader.calls, 0)

    @mock.patch("weir.broker.check_target_policy")
    def test_evidence_data_class_is_checked_before_materialization(self, policy_check):
        with tempfile.TemporaryDirectory() as temp:
            backend, _, _ = _backend(Path(temp))
            acquired = backend.read(
                _acquisition(
                    _read_request("private-reference", data_class=DataClass.PERSONAL)
                )
            )
            application = WeirServiceApplication(backend, _client_registry())
            with mock.patch.object(
                backend, "materialize_evidence", wraps=backend.materialize_evidence
            ) as materialize:
                with WeirService(application) as service:
                    base_url = f"http://{service.address[0]}:{service.address[1]}"
                    status, value = _raw_request(
                        base_url,
                        (
                            "/v1/evidence/"
                            f"{acquired.evidence_reference.evidence_ref_id}/content"
                        ),
                    )
            self.assertEqual(status, 403)
            self.assertEqual(value["error"]["reason_code"], "data_class_denied")
            materialize.assert_not_called()

    def test_deadline_and_request_size_are_enforced(self):
        with tempfile.TemporaryDirectory() as temp:
            backend, _, _ = _backend(Path(temp))
            application = WeirServiceApplication(backend, _client_registry())
            with WeirService(application) as service:
                base_url = f"http://{service.address[0]}:{service.address[1]}"
                body = json.dumps(
                    _acquisition(_read_request("expired")).to_dict()
                ).encode()
                status, value = _raw_request(
                    base_url,
                    "/v1/acquisition/read",
                    deadline=datetime.now(timezone.utc) - timedelta(seconds=1),
                    body=body,
                )
                self.assertEqual(status, 408)
                self.assertEqual(value["error"]["reason_code"], "deadline_expired")

                connection = http.client.HTTPConnection(
                    service.address[0], service.address[1], timeout=5
                )
                try:
                    connection.putrequest("POST", "/v1/acquisition/read")
                    connection.putheader("Content-Type", "application/json")
                    connection.putheader("Content-Length", str(256 * 1024 + 1))
                    connection.putheader("Expect", "100-continue")
                    connection.endheaders()
                    response = connection.getresponse()
                    value = json.loads(response.read())
                    self.assertEqual(response.status, 413)
                    self.assertEqual(
                        value["error"]["reason_code"], "request_too_large"
                    )
                finally:
                    connection.close()

    @mock.patch("weir.broker.check_target_policy")
    def test_deadline_is_rechecked_after_dispatch(self, policy_check):
        with tempfile.TemporaryDirectory() as temp:
            backend, _, _ = _backend(Path(temp))
            started = datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc)
            ticks = iter((started, started + timedelta(seconds=2)))
            application = WeirServiceApplication(
                backend, _client_registry(), clock=lambda: next(ticks)
            )
            headers = {
                "Authorization": f"Bearer {LUGOS_CREDENTIAL}",
                "X-Weir-Client-Id": "lugos-mcp",
                "X-Weir-Deadline": (started + timedelta(seconds=1)).isoformat(),
            }
            body = json.dumps(
                _acquisition(_read_request("post-dispatch-deadline")).to_dict()
            ).encode()
            with self.assertRaises(ServiceRequestError) as raised:
                application.handle("POST", "/v1/acquisition/read", headers, body)
            self.assertEqual(raised.exception.status, 504)
            self.assertEqual(raised.exception.reason_code, "deadline_exceeded")

    @mock.patch("weir.broker.check_target_policy")
    def test_evidence_survives_backend_and_service_restart(self, policy_check):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            backend, _, _ = _backend(root)
            acquired = backend.read(_acquisition(_read_request("restart-evidence")))
            reference_id = acquired.evidence_reference.evidence_ref_id

            restarted_backend, _, _ = _backend(root)
            application = WeirServiceApplication(
                restarted_backend, _client_registry()
            )
            with WeirService(application) as service:
                client = _http_client(service)
                reference = client.get_evidence(reference_id)
                materialized = client.materialize_evidence(reference_id)

            self.assertEqual(reference, acquired.evidence_reference)
            self.assertEqual(materialized.reference, acquired.evidence_reference)
            self.assertEqual(materialized.content, acquired.capture.content)

    @mock.patch("weir.broker.check_target_policy")
    def test_response_limit_and_artifact_tamper_fail_closed(self, policy_check):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            backend, _, _ = _backend(root, content_size=100)
            small_application = WeirServiceApplication(
                backend, _client_registry(), max_response_bytes=512
            )
            with WeirService(small_application) as service:
                with self.assertRaises(WeirClientError) as raised:
                    _http_client(service).read(
                        _acquisition(_read_request("large-response"))
                    )
                self.assertEqual(raised.exception.reason_code, "response_too_large")

            application = WeirServiceApplication(backend, _client_registry())
            with WeirService(application) as service:
                client = _http_client(service)
                response = client.read(_acquisition(_read_request("tamper")))
                digest = (response.capture.raw_artifact_ref or "").removeprefix(
                    "weir-artifact:sha256:"
                )
                path = root / "artifacts" / "sha256" / digest[:2] / f"{digest}.json"
                path.write_bytes(b'{"text":"tampered"}')
                with self.assertRaises(WeirClientError) as raised:
                    client.materialize_evidence(
                        response.evidence_reference.evidence_ref_id
                    )
                self.assertEqual(raised.exception.status, 409)
                self.assertEqual(
                    raised.exception.reason_code, "artifact_hash_mismatch"
                )

    def test_command_status_survives_service_and_store_restart(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            database = root / "browser.sqlite3"
            command_store = SQLiteSessionStore(database)
            started = command_store.begin_command(
                "command-complete", "observe", "sha256:request"
            )
            command_store.complete_command(
                "command-complete",
                {"session_id": "session-1", "revision": 2},
                attempt_token=started.attempt_token,
            )
            failed = command_store.begin_command(
                "command-failed", "navigate", "sha256:failed"
            )
            command_store.fail_command(
                "command-failed",
                "sensitive adapter error text",
                attempt_token=failed.attempt_token,
            )
            backend, _, _ = _backend(root / "captures", command_store=command_store)
            application = WeirServiceApplication(backend, _client_registry())
            with WeirService(application) as service:
                fade = _http_client(service, fade=True)
                completed = fade.get_command_status("command-complete")
                failed_status = fade.get_command_status("command-failed")
                self.assertIsNone(fade.get_command_status("missing-command"))
                with self.assertRaises(WeirClientError) as raised:
                    _http_client(service).get_command_status("command-complete")
                self.assertEqual(raised.exception.reason_code, "scope_denied")
            command_store.close()

            self.assertEqual(completed.result["revision"], 2)
            self.assertTrue(failed_status.error_present)
            self.assertNotIn("sensitive adapter", json.dumps(failed_status.to_dict()))

            reopened = SQLiteSessionStore(database)
            try:
                backend, _, _ = _backend(root / "captures", command_store=reopened)
                application = WeirServiceApplication(backend, _client_registry())
                with WeirService(application) as service:
                    after_restart = _http_client(
                        service, fade=True
                    ).get_command_status("command-complete")
                self.assertEqual(after_restart, completed)
            finally:
                reopened.close()


if __name__ == "__main__":
    unittest.main()
