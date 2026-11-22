"""Supervisor-side field adapter. Observer and effect transports have disjoint operations."""

from __future__ import annotations

import secrets
from datetime import datetime, timezone

from weir.actions import ActionType
from weir.browser.effect_driver import EffectResult
from weir.browser.enrolled_fill import MARKER, require
from weir.browser.models import Observation, ObservedElement
from weir.models import DataClass, ReaderResult, RequestMode, WebCapture, WebRequest


class PinnedFieldEffect:
    """The effect adapter has a single fixed target operation."""

    def __init__(self, fill):
        self._fill = fill

    def apply(self, identity):
        self._fill(identity)


class EnrolledFieldWorker:
    production_process_transport = True
    worker_id = "linux-enrolled-field"

    def __init__(self, store, captures, field, controller, enrollment_version):
        self.store = store
        self.captures = captures
        self.field = field
        self.enrollment_version = enrollment_version
        self._evidence = controller.evidence
        self._observe = controller.observe_field
        self._effect = PinnedFieldEffect(controller.fill_field)
        self.ready = controller.ready
        self.contain = controller.contain
        self._discard = controller.verify_discard_and_exit
        self.incident_evidence = controller.incident_evidence
        proof = controller.evidence()
        self.worker_instance_id = proof.worker_instance_id
        self.production_binding = proof.process_binding
        self.containment_evidence = proof.containment
        self._identity = None
        self._before = None

    def check_isolation(self):
        proof = self._evidence()
        require(proof.process_binding == self.production_binding
                and proof.worker_instance_id == self.worker_instance_id
                and proof.containment == self.containment_evidence, "The admitted Linux browser changed")

    def confirm_empty(self, approved):
        snapshot = self._observe()
        require(snapshot == {k: approved.accessibility_snapshot[k] for k in
                ("value", "document_identity", "enrollment_digest")} and snapshot["value"] == "",
                "The current field differs from the approved empty field")

    def observe(self, session_id, *, command_id, stage):
        require(stage in {"approved", "before", "after"}, "Unknown observation phase")
        self.check_isolation()
        session = self.store.get_session(session_id)
        context = self.store.work_context(session_id)
        snapshot = self._observe()
        require(snapshot["enrollment_digest"] == self.field.digest
                and snapshot["value"] == (MARKER if stage == "after" else "")
                and self._identity in (None, snapshot["document_identity"]),
                "The observer could not verify the pinned field and exact value")
        now = datetime.now(timezone.utc).isoformat()
        ref = secrets.token_hex(16)
        capture_id = "webcap-" + ref
        observation = Observation.create(
            observation_id="obs-" + ref, session_id=session_id, session_epoch=session.epoch,
            session_revision=session.revision + 1, capture_id=capture_id, captured_at=now,
            url=self.field.url, title="Enrolled public field",
            elements=[ObservedElement("field-" + ref, "textbox", self.field.name, self.field.test_id,
                                      "filled" if stage == "after" else "empty")],
            accessibility_snapshot={**snapshot, "enrollment_version": self.enrollment_version})
        self.field.observation(observation, snapshot["value"])
        self._identity = snapshot["document_identity"]
        request = WebRequest(request_id=command_id, run_id=context.run_id, mode=RequestMode.OBSERVE,
                             data_class=DataClass.PUBLIC, auth_context="browser_profile",
                             intent="Verify the enrolled unsaved field", url=self.field.url,
                             profile_id=session.profile_id, allowed_domains=list(session.allowed_domains),
                             preferred_engine=session.engine, evidence_required=True,
                             side_effects_allowed=False, capture_policy="full_evidence")
        result = ReaderResult(engine=session.engine, engine_version="linux-enrolled-field-v1",
                              requested_url=self.field.url, final_url=self.field.url, title=observation.title,
                              auth_scope="profile:" + session.profile_id, content={
                                  "kind": "browser_observation", "observation": observation.to_dict(),
                                  "work_context": context.to_dict(), "worker_notes": []})
        capture = WebCapture.from_reader_result(result, request, capture_id=capture_id, captured_at=now)
        _, persistence = self.captures.persist(capture, request)
        require(persistence.stored, "The independent field observation was not retained")
        self.store.advance_field_observation(session, observation)
        if stage == "before":
            self._before = observation
        return observation

    def apply(self, command):
        command.validate()
        before = self._before
        require(before is not None and command.worker_id == self.worker_id
                and command.worker_instance_id == self.worker_instance_id and command.action_type is ActionType.FILL
                and command.parameter_data_class is DataClass.PUBLIC and command.parameters() == {"value": MARKER}
                and (command.target.observation_id, command.target.element_ref, command.target.name, command.target.test_id)
                == (before.observation_id, before.elements[0].ref, self.field.name, self.field.test_id),
                "Private effect command differs from the observed empty field")
        self._before = None
        self.check_isolation()
        self._effect.apply(self._identity)
        return EffectResult(self.worker_id, self.worker_instance_id, True)

    def verify_discard_and_exit(self, field):
        require(field == self.field, "Discard enrollment changed")
        return self._discard()
