import os
import json
import secrets
import sys
import threading
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from weir.actions import ExecutionPermit
from weir.browser.admission import (CredentialProtectionEvidence, ProductionControlEvidence, ProductionProcessBinding,
                                   WorkerContainmentEvidence, WorkerResourceLimits)
from weir.browser.effect_driver import FADE_AUTHORITY_ID, action_request_digest
from weir.browser.enrolled_fill import MARKER, GRANT
from weir.browser.field_service import prepare_enrolled_fill
from weir.browser.linux_fill_driver import LinuxEnrolledFillDriver
from weir.browser.store import SQLiteSessionStore
from weir.contract import canonical_digest
from weir.engines.base import ControllerConflict, EnginePolicyBlocked
from weir.models import DataClass
from weir.persistence import CaptureStore
from weir.proposals import ActionProposalStore
from weir.service import ClientCredential, ClientRegistry
from weir.work_context import WorkContext, WorkContextSource

with patch.object(sys, "path", [str(Path(__file__).resolve().parents[1] / "scripts"), *sys.path]):
    from verify_enrolled_fill import QualificationAuthority, utc


class ControlledBrowser:
    def __init__(self, field):
        self.field = field
        self.calls = 0
        self.value = ""
        self.identity = canonical_digest("document")
        self.before = self.during = self.shutdown = lambda: None

    def evidence(self):
        now = utc()
        return ProductionControlEvidence.create(attestation_id="qa-linux", platform="linux", service_identity="uid-900",
            worker_identity="uid-900", worker_id="linux-enrolled-field", worker_instance_id="instance-fixture",
            containment=WorkerContainmentEvidence("linux", 42, True, True, WorkerResourceLimits(536870912, 128), True),
            process_binding=ProductionProcessBinding("host", 1, 1, 12, "kernel-binding"),
            restricted_identity=True, credential_protection=(CredentialProtectionEvidence(
                FADE_AUTHORITY_ID, "qa-only", canonical_digest("private"), True),),
            lifecycle_supervisor="systemd", lifecycle_instance_id="instance-fixture", lifecycle_healthy=True,
            egress_policy_id="qa-only", egress_policy_digest=canonical_digest("isolation"), egress_enforced=True,
            verified_at=now.isoformat(), expires_at=(now + timedelta(seconds=10)).isoformat())

    def observe_field(self):
        self.before()
        return {"value": self.value, "document_identity": self.identity, "enrollment_digest": self.field.digest}

    def ready(self):
        pass

    def fill_field(self, identity):
        if identity != self.identity:
            raise ValueError("Node changed")
        self.calls += 1
        self.value = MARKER
        self.during()

    def contain(self):
        pass

    def incident_evidence(self):
        return {}

    def verify_discard_and_exit(self):
        self.shutdown()
        return {"effect_browser": {"invocation": "unit-one"}, "discard_browser": {"invocation": "unit-two"}}


@unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux file locking and protected descriptors")
class EnrolledDriverTests(unittest.TestCase):
    def setUp(self):
        tmp = self.enterContext(TemporaryDirectory())
        self.root = Path(tmp)
        self.qa = QualificationAuthority(self.root)
        self.store = self.enterContext(SQLiteSessionStore(self.root / "store.db"))
        self.captures = CaptureStore(self.root / "captures")
        self.proposals = ActionProposalStore(self.root / "proposals", self.captures, self.store)
        self.browser = ControlledBrowser(self.qa.field)
        context = WorkContext.create(context_id="context", run_id="run", correlation_id="corr", assignment_id="assignment",
                                     source=WorkContextSource.AUTOWORK, created_at=utc().isoformat())
        clients = ClientRegistry([ClientCredential(FADE_AUTHORITY_ID, secrets.token_urlsafe(35),
                                 frozenset({"action:execute", "action:status"}), frozenset({DataClass.PUBLIC}))])
        self.app, self.p = prepare_enrolled_fill(store=self.store, proposals=self.proposals, context=context,
            authority=self.qa.authority, clients=clients, backend=object(), open_controller=lambda _: self.browser)
        self.driver = self.app.action_driver
        self.command = "command-one"
        now = utc()
        self.permit = ExecutionPermit.create(permit_id="permit-one", proposal_hash=self.p.proposal_hash,
            work_context_hash=self.p.work_context_hash, owner_run_id=self.p.owner_run_id, session_id=self.p.session_id,
            session_epoch=self.p.session_epoch, action_type=self.p.action_type, risk=self.p.risk, approval_ref="approval-one",
            issuer_id=FADE_AUTHORITY_ID, issued_at=now.isoformat(), expires_at=(now + timedelta(seconds=70)).isoformat())
        self.proof = self.qa.capsule(self.command, self.p.action_id, self.p.proposal_hash, self.p.work_context_hash)
        self.args = dict(command_id=self.command, request_digest=action_request_digest(self.command,self.p,self.permit),
                         submitted_proposal=self.p, permit=self.permit)

    def approve(self, proof=None):
        proof = proof or self.proof
        self.qa.authority.accept_approval(self.permit.approval_ref, proof, proof.step_up_ref, utc())

    def withdraw(self):
        current = json.loads((self.qa.authority.ingress / "current.json").read_text())
        p = self.qa.capsule("withdraw", "withdraw-first-unsaved-field", self.qa.field.digest,
                            canonical_digest({"grant": GRANT, "operation": "withdraw",
                                              "predecessor": current["generation"]}), enrollment=True)
        self.qa.authority.withdraw(p, p.step_up_ref, utc())

    def test_missing_binding_wrong_key_owner_target_and_expired_capsule_deny(self):
        with self.assertRaises((OSError, ValueError, RuntimeError)):
            self.driver.execute(**self.args)
        invalid = [replace(self.proof, signature="A" * 86),
                   self.qa.capsule(self.command, self.p.action_id, self.p.proposal_hash, self.p.work_context_hash,
                                   owner="another-owner")]
        for proof in invalid:
            with self.assertRaises((ValueError, RuntimeError)):
                self.approve(proof)
        with self.assertRaises((ValueError, RuntimeError)):
            self.qa.authority.accept_approval(self.permit.approval_ref, self.proof, self.proof.step_up_ref,
                                               utc() + timedelta(minutes=3))
        self.approve(self.qa.capsule(self.command, "different-action", self.p.proposal_hash, self.p.work_context_hash))
        with self.assertRaises((ValueError, RuntimeError)):
            self.driver.execute(**self.args)
        with self.assertRaises(RuntimeError):
            self.approve()
        self.assertEqual(self.browser.calls, 0)
        self.assertIsNone(self.store.action_reservation(self.permit.permit_id))

    def test_withdraw_before_dispatch_spends_without_fill(self):
        self.approve()
        original = self.driver.worker.observe
        def observe(*args, **kwargs):
            if kwargs["stage"] == "before":
                self.withdraw()
            return original(*args, **kwargs)
        self.driver.worker.observe = observe
        self.assertEqual(self.driver.execute(**self.args).state, "blocked")
        self.assertEqual(self.browser.calls, 0)
        with self.qa.authority.journal() as (_, rows):
            self.assertEqual([row["state"] for row in rows], ["available","reserved"])

    def test_withdraw_after_marker_reconciles_the_original(self):
        self.approve()
        self.browser.during = self.withdraw
        r = self.driver.execute(**self.args)
        self.assertEqual(r.state, "completed")
        self.assertEqual(self.driver.execute(**self.args).to_dict(), r.to_dict())
        self.assertEqual(self.browser.calls, 1)

    def test_live_status_and_duplicate_do_not_recover_a_live_worker(self):
        self.approve()
        started, release = threading.Event(), threading.Event()
        def wait():
            started.set()
            if not release.wait(5):
                raise TimeoutError("Test observer did not release the action")
        self.browser.during = wait
        result = []
        thread = threading.Thread(target=lambda: result.append(self.driver.execute(**self.args)))
        thread.start()
        try:
            self.assertTrue(started.wait(4))
            self.assertEqual(self.driver.status(self.command).state, "executing")
            self.assertEqual(self.driver.execute(**self.args).state, "executing")
        finally:
            release.set()
            thread.join(7)
        self.assertEqual(result[0].state, "completed")
        self.assertEqual(self.browser.calls, 1)

    def test_wrong_readback_quarantines_without_a_post_effect_capture(self):
        self.approve()
        self.browser.during = lambda: setattr(self.browser, "value", "wrong")
        r = self.driver.execute(**self.args)
        self.assertEqual(r.state, "outcome_unknown")
        self.assertEqual(len(r.receipt.capture_ids),1)
        self.assertEqual(self.driver.execute(**self.args).state, "outcome_unknown")
        self.assertEqual(self.browser.calls,1)

    def test_shutdown_failure_never_produces_completed_receipt(self):
        self.approve()
        self.browser.shutdown = lambda: (_ for _ in ()).throw(OSError("uncertain exit"))
        self.assertEqual(self.driver.execute(**self.args).state, "outcome_unknown")
        self.assertEqual(self.driver.execute(**self.args).state, "outcome_unknown")
        self.assertEqual(self.browser.calls,1)

    def test_replaced_document_has_zero_fills(self):
        self.approve()
        self.browser.identity = canonical_digest("new loader")
        with self.assertRaises(EnginePolicyBlocked):
            self.driver.execute(**self.args)
        self.assertIsNone(self.store.action_reservation(self.permit.permit_id))
        self.assertEqual(self.browser.calls,0)

    def reopen(self):
        def no_browser(_):
            self.fail("A spent grant opened another browser")
        return prepare_enrolled_fill(store=self.store, proposals=self.proposals, authority=self.qa.authority,
            clients=self.app.clients, backend=object(), context=None, open_controller=no_browser)

    def test_human_replacement_invalidates_prior_approval_and_prior_challenges(self):
        self.approve()
        self.withdraw()
        current = json.loads((self.qa.authority.ingress / "current.json").read_text())
        operation = {"grant": GRANT, "operation": "replace", "predecessor": current["generation"]}
        decision = self.qa.capsule("replace", "replace-first-unsaved-field", self.qa.field.digest,
                                   canonical_digest(operation), enrollment=True)
        self.qa.authority.accept_enrollment(self.qa.field, decision, decision.step_up_ref, utc())
        self.qa.refresh()
        with self.assertRaises(EnginePolicyBlocked):
            self.driver.execute(**self.args)
        self.assertIsNone(self.store.action_reservation(self.permit.permit_id))

    def test_status_after_session_ledger_rollback_never_reports_unseen(self):
        self.approve()
        with SQLiteSessionStore(self.root / "backup.db") as backup:
            self.store.database.backup(backup.database)
            self.assertEqual(self.driver.execute(**self.args).state, "completed")
            backup.database.backup(self.store.database)
        recovered, proposal = self.reopen()
        self.assertIsNone(proposal)
        self.assertEqual(recovered.action_driver.required_data_classes(self.command), frozenset({DataClass.PUBLIC}))
        with self.assertRaisesRegex(ControllerConflict, "lost a witnessed dispatch"):
            recovered.action_driver.status(self.command)
        with self.assertRaises(ControllerConflict):
            recovered.action_driver.execute(**self.args)
        self.assertEqual(self.browser.calls, 1)

    def test_older_witness_does_not_rearm_after_a_spend(self):
        path = self.qa.authority.witness / "grant.jsonl"
        old = path.read_bytes()
        self.approve()
        self.driver.execute(**self.args)
        path.write_bytes(old)
        with self.assertRaisesRegex(EnginePolicyBlocked, "predates"):
            self.reopen()
        with self.assertRaises(EnginePolicyBlocked):
            self.driver.status(self.command)

    def test_restarting_spent_service_accepts_only_exact_replay(self):
        self.approve()
        first = self.driver.execute(**self.args)
        reopened, proposal = self.reopen()
        self.assertIsNone(proposal)
        self.assertEqual(reopened.action_driver.execute(**self.args).to_dict(), first.to_dict())
        other = dict(self.args, command_id="different-command")
        other["request_digest"] = action_request_digest(other["command_id"], self.p, self.permit)
        with self.assertRaises(RuntimeError):
            reopened.action_driver.execute(**other)
        self.assertEqual(self.browser.calls, 1)

    def test_missing_role_or_changed_worker_cannot_spend_the_grant(self):
        self.approve()
        with patch.object(self.driver.worker, "ready", side_effect=OSError("role unavailable")):
            with self.assertRaises(OSError):
                self.driver.execute(**self.args)
        changed = self.browser.evidence
        with patch.object(self.driver.worker, "_evidence", side_effect=lambda:
                          replace(changed(), worker_instance_id="instance-replaced")):
            with self.assertRaises(EnginePolicyBlocked):
                self.driver.execute(**self.args)
        self.assertIsNone(self.store.action_reservation(self.permit.permit_id))

    def test_stale_or_revoked_approval_cannot_consume_the_reservation(self):
        self.approve()
        with self.qa.authority.lock() as ingress:
            with self.assertRaises(EnginePolicyBlocked):
                self.qa.authority.enrollment(ingress, utc() + timedelta(seconds=40))
        self.qa.authority.record_revocations(self.qa.field.digest, utc(), [self.proof.capsule_hash])
        with self.assertRaises(EnginePolicyBlocked):
            self.driver.execute(**self.args)
        self.assertIsNone(self.store.action_reservation(self.permit.permit_id))

    def crash(self, marked):
        self.approve()
        pid = os.fork()
        if pid == 0:
            try:
                with SQLiteSessionStore(self.root / "store.db") as child:
                    proposals = ActionProposalStore(self.root / "proposals", self.captures, child)
                    worker = self.driver.worker
                    worker.store = child
                    driver = LinuxEnrolledFillDriver(child, proposals, worker, self.qa.field,
                                                     self.qa.authority, self.driver.host)
                    if marked == "witness-reserve":
                        reserve = self.qa.authority.reserve
                        def cut(binding):
                            reserve(binding)
                            os._exit(41)
                        self.qa.authority.reserve = cut
                    elif marked == "ledger-dispatch":
                        self.qa.authority.mark = lambda _: os._exit(41)
                    elif marked:
                        worker.apply = lambda *_: os._exit(41)
                    else:
                        worker.observe = lambda *_, **kw: os._exit(41)
                    driver.execute(**self.args)
            finally:
                os._exit(19)
        self.assertEqual(os.waitstatus_to_exitcode(os.waitpid(pid,0)[1]),41)
        expected = "outcome_unknown" if marked in (True, "ledger-dispatch") else "cancelled"
        self.assertEqual(self.driver.status(self.command).state,expected)
        self.assertEqual(self.driver.execute(**self.args).state,expected)
        self.assertEqual(self.browser.calls,0)

    def test_crash_before_dispatch(self):
        self.crash(False)

    def test_crash_after_marker(self):
        self.crash(True)

    def test_crash_after_witness_reserve_before_sqlite_commit(self):
        self.crash("witness-reserve")
        self.assertIsNone(self.store.action_reservation(self.permit.permit_id))
        reopened, _ = self.reopen()
        self.assertEqual(reopened.action_driver.status(self.command).state, "cancelled")

    def test_crash_between_dispatch_markers(self):
        self.crash("ledger-dispatch")
