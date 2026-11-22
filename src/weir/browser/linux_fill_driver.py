"""The Linux action route for one enrolled, unsaved public textbox."""

from __future__ import annotations

from dataclasses import asdict, replace

from weir.actions import ExecutionReceipt, ReceiptResult, Verification, VerificationConfidence
from weir.browser.admission import ProductionAdmission
from weir.browser.effect_driver import ActionExecutionStatus, BrowserActionDriver, FADE_AUTHORITY_ID, action_request_digest
from weir.browser.enrolled_fill import EnrolledField, GRANT, LinuxFillAuthority, MARKER, require
from weir.contract import canonical_digest
from weir.engines.base import ControllerConflict, EnginePolicyBlocked
from weir.models import DataClass


class LinuxEnrolledFillDriver(BrowserActionDriver):
    """The trusted supervisor supplies the host observer and the scoped effect channel."""

    def __init__(self, store, proposals, worker, field: EnrolledField, authority: LinuxFillAuthority,
                 admission: ProductionAdmission, *, clock=None):
        field.validate()
        if not isinstance(admission, ProductionAdmission) or not isinstance(authority, LinuxFillAuthority):
            raise TypeError("The Linux fill requires independent host evidence and protected decisions")
        self.authority = authority
        self.host = admission
        super().__init__(store, proposals, worker, field, clock=clock, driver_id="linux-enrolled-fill")

    def require_external_action(self, *, caller_id, action_driver):
        # Closed workers can still answer duplicates from the durable ledger.
        # A new reservation and the dispatch marker each require fresh host proof.
        require(caller_id == FADE_AUTHORITY_ID and action_driver is self, "Only Fade may submit an action")

    def _current_host(self):
        require(self.worker.production_binding is not None and self.worker.containment_evidence.platform == "linux",
                "A current Linux process binding is required")
        self.host.require_external_action(caller_id=FADE_AUTHORITY_ID, action_driver=self)
        self.worker.check_isolation()

    def execute(self, *, command_id, request_digest, submitted_proposal, permit):
        with self.authority.lock(execution=True, wait=False) as owner:
            if owner is None:
                if (permit.issuer_id != FADE_AUTHORITY_ID
                        or action_request_digest(command_id, submitted_proposal, permit) != request_digest):
                    raise EnginePolicyBlocked("The active command binding does not match")
                reserved = self.store.action_reservation(permit.permit_id)
                if reserved is None:
                    raise ControllerConflict("Another process is reserving the deployment grant")
                self._require_replay_binding(reserved, proposal=submitted_proposal, permit=permit,
                                             command_id=command_id, request_digest=request_digest)
                return self._status(reserved)
            orphan = self._missing_reservation(command_id)
            if orphan is not None:
                require(request_digest == orphan.request_digest and permit.permit_id == orphan.permit_id
                        and permit.issuer_id == FADE_AUTHORITY_ID
                        and action_request_digest(command_id, submitted_proposal, permit) == request_digest,
                        "The cancelled command cannot be replaced")
                return orphan
            return super().execute(command_id=command_id, request_digest=request_digest,
                                   submitted_proposal=submitted_proposal, permit=permit)

    def status(self, command_id, *, recover=True):
        with self.authority.lock(execution=True, wait=False) as owner:
            reservation = self.store.action_reservation_by_command(command_id)
            if reservation is None:
                if owner is None:
                    raise ControllerConflict("The active reservation has not yet committed")
                return self._missing_reservation(command_id)
            if owner is None or not recover:
                return self._status(reservation)
            return self._recover(reservation, approval_ref=None)

    def _missing_reservation(self, command):
        if self.store.action_reservation_by_command(command) is not None:
            return None
        with self.authority.journal() as (_, rows):
            if len(rows) == 1 or rows[1]["command"] != command:
                return None
            if len(rows) == 3:
                raise ControllerConflict("The ledger lost a witnessed dispatch and requires reconciliation")
            receipt = ExecutionReceipt.from_dict(rows[1]["cancelled_receipt"])
            return ActionExecutionStatus(command, receipt.permit_id, rows[1]["request_digest"], "cancelled", receipt)

    def required_data_classes(self, command_id):
        with self.authority.journal() as (_, rows):
            if len(rows) > 1 and rows[1]["command"] == command_id:
                return frozenset({DataClass.PUBLIC})
        return super().required_data_classes(command_id)

    def _binding(self, ingress, p, permit, command, digest):
        self._current_host()
        now = self._now()
        field, enroll, decision = self.authority.authorization(ingress, p, permit, command, now)
        require(field == self.policy, "The enrolled website or field was replaced")
        permit.validate_for(p, now)
        field.check_proposal(p, self.store)
        approved = self.proposal_store.approved_observation(p)
        require(approved.accessibility_snapshot["enrollment_version"] == enroll.capsule_hash,
                "The approved capture belongs to an earlier enrollment")
        identity = field.observation(approved, "")
        return {"state": "reserved", "grant": GRANT, "command": command, "request_digest": digest,
                "permit": permit.permit_hash, "proposal": p.proposal_hash, "enrollment": field.digest,
                "capsule": decision.capsule_hash, "nonce": canonical_digest(decision.nonce),
                "document": identity, "worker": self.worker_instance_id, "field": asdict(field),
                "deployment": self.authority.deployment, "enrollment_version": enroll.capsule_hash}

    def _reserve_execution(self, permit, proposal, **kwargs):
        self._current_host()
        self.worker.ready()
        self.worker.confirm_empty(self.proposal_store.approved_observation(proposal))
        with self.authority.lock() as ingress:
            binding = self._binding(ingress, proposal, permit, kwargs["command_id"], kwargs["request_digest"])
            def spend(reservation):
                require(self.store.enrolled_grant_requests() == [reservation.request_digest],
                        "An earlier reservation already spent the grant in this ledger")
                cancelled = self._receipt(reservation, approval_ref=None, result=ReceiptResult.CANCELLED,
                    capture_ids=(), failure_class=None, executed_by=self.driver_id,
                    verification=Verification(None, VerificationConfidence.BLOCKED, ()))
                self.authority.reserve({**binding, "cancelled_receipt": cancelled.to_dict()})
            return self.store.reserve_action_execution(permit, proposal, **kwargs, before_commit=spend)

    def _mark_dispatch(self, reservation_ref, **kwargs):
        p, permit = kwargs["proposal"], kwargs["permit"]
        res = self.store.action_reservation(permit.permit_id)
        with self.authority.lock() as ingress:
            binding = self._binding(ingress, p, permit, res.command_id, res.request_digest)
            # The kernel lock orders local withdrawal with the durable marker.
            # A crash after either marker spends the grant and never repeats it.
            with self.authority.journal() as (_, rows):
                require(len(rows) == 2 and {k: v for k, v in rows[1].items() if k != "cancelled_receipt"} == binding,
                        "The external spend witness has changed")
                original = rows[1]
            self.store.mark_action_dispatching(reservation_ref, **kwargs)
            self.authority.mark(original)

    def _validate_before(self, p, before):
        super()._validate_before(p, before)
        approved = self.proposal_store.approved_observation(p)
        require(self.policy.observation(before, "") == self.policy.observation(approved, ""),
                "The browser replaced the approved document or node")

    def _validate_after(self, p, before, after):
        super()._validate_after(p, before, after)
        self._current_host()
        require(self.policy.observation(after, MARKER) == self.policy.observation(before, ""),
                "The independent snapshot did not verify the original node")

    def _execute_reserved(self, reservation, proposal, permit, lease):
        try:
            return super()._execute_reserved(reservation, proposal, permit, lease)
        finally:
            try:
                self.worker.contain()
            finally:
                receipt = self.store.load_receipt(reservation.action_id)
                if receipt and receipt["result"] == ReceiptResult.OUTCOME_UNKNOWN.value:
                    self.authority.retain_lifecycle(reservation.command_id,
                        {"quarantined_receipt": receipt["receipt_hash"], "shutdown": self.worker.incident_evidence()})

    def _finalize_verified(self, reservation, permit, before, after, executed_by, verification):
        # This call must verify containment through exit, empty discard in a
        # separately admitted browser and the external receivers before success.
        proof = self.worker.verify_discard_and_exit(self.policy)
        ref = self.authority.retain_lifecycle(reservation.command_id, proof)
        verification = replace(verification, supporting_evidence_refs=(*verification.supporting_evidence_refs, ref))
        return super()._finalize_verified(reservation, permit, before, after, executed_by, verification)

    def _finalize_definite(self, reservation, **kwargs):
        marker = self.store.action_dispatch_marker(reservation.reservation_ref)
        if marker is not None:
            return self._finalize_unknown(reservation, marker.approval_ref, marker.before_capture_id,
                                          self.worker_id)
        return super()._finalize_definite(reservation, **kwargs)

    def _recover(self, reservation, *, approval_ref):
        with self.authority.journal() as (_, rows):
            require(len(rows) >= 2 and rows[1]["request_digest"] == reservation.request_digest
                    and rows[1]["permit"] == reservation.permit_hash, "Ledger and spend witness disagree")
            marker = self.store.action_dispatch_marker(reservation.reservation_ref)
            require(len(rows) != 3 or marker is not None, "Dispatch ledger rollback requires reconciliation")
            terminal = self.store.load_receipt(reservation.action_id)
            if terminal and terminal["result"] == ReceiptResult.COMPLETED.value:
                require(len(rows) == 3 and marker is not None, "Completed receipt lacks witnessed dispatch")
        return super()._recover(reservation, approval_ref=approval_ref)
