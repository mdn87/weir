"""Local, read-only interpretation of broker-registered browser observations."""

from __future__ import annotations

import io
from dataclasses import asdict, dataclass
from pathlib import Path

from weir.browser.broker import BrowserSessionBroker, profile_policy_digest
from weir.browser.models import BrowserSession, Observation
from weir.browser.policy import check_browser_target_policy
from weir.browser.store import SQLiteSessionStore
from weir.contract import canonical_digest
from weir.engines.base import EnginePolicyBlocked
from weir.models import DataClass, ReaderResult, TrustLabel, WebCapture
from weir.persistence import CaptureStore
from weir.profiles import SiteProfile, SiteProfileRegistry
from weir.visual import (
    Answer,
    Region,
    ValueQuery,
    agreement,
    candidate,
    crop_image,
    png_bytes,
    read_region,
    structured_value,
)
from weir.work_context import WorkContext


@dataclass(frozen=True)
class Source:
    capture: WebCapture
    observation: Observation
    session: BrowserSession
    profile: SiteProfile

    def reference(self) -> dict:
        return {
            "capture_id": self.capture.capture_id,
            "artifact_ref": self.capture.raw_artifact_ref,
            "observation_hash": self.observation.observation_hash,
            "session_id": self.observation.session_id,
            "session_revision": self.observation.session_revision,
            "session_epoch": self.observation.session_epoch,
            "captured_at": self.observation.captured_at,
            "url": self.observation.url,
            "data_class": self.session.data_class.value,
            "trust": self.capture.trust.value,
        }

    def structured(self, query: ValueQuery) -> Answer:
        obs = self.observation
        return structured_value(
            query, (e.name for e in obs.elements if e.name), obs.accessibility_snapshot
        )

    def require_pixels(self) -> None:
        if self.profile.retention.get("screenshots") != "full_evidence":
            raise EnginePolicyBlocked("the bound site profile does not permit retained pixels")


class VisualReadings:
    def __init__(
        self, ledger: SQLiteSessionStore, store: CaptureStore, profiles: SiteProfileRegistry
    ) -> None:
        self.ledger, self.store, self.profiles = ledger, store, profiles

    def source(self, capture_id: str) -> Source:
        cap = self.store.load_capture(capture_id)
        self.store.verify_capture(cap)
        if not isinstance(cap.content, dict) or cap.content.get("kind") != "browser_observation":
            raise ValueError("expected a retained browser observation")
        obs = Observation.from_dict(cap.content["observation"])
        session = self.ledger.get_session(obs.session_id)
        command = self.ledger.command_status(cap.request_id)
        context = self.ledger.work_context(obs.session_id)
        result = (
            command.result
            if command and command.operation == "observe" and command.status == "completed"
            else {}
        )
        if not (
            result
            and cap.raw_artifact_ref
            and capture_id == cap.capture_id == obs.capture_id == result.get("capture_id")
            and obs.observation_id == result.get("observation_id")
            and session.session_id == result.get("session_id")
            and obs.session_revision == result.get("revision")
            and cap.raw_artifact_ref == result.get("persistence", {}).get("artifact_ref")
            and cap.content.get("work_context") == context.to_dict()
            and context.run_id == session.owner_run_id
            and obs.url == cap.final_url
            and obs.captured_at == cap.captured_at
            and cap.trust == TrustLabel.UNTRUSTED_EXTERNAL_CONTENT
            and obs.artifact_refs
            == ([cap.screenshot_artifact_ref] if cap.screenshot_artifact_ref else [])
        ):
            raise ValueError("source does not match its registered browser observation")
        binding = self.ledger.profile_binding(session.session_id)
        profile = self.profiles.get(binding.site_profile_id)
        host = check_browser_target_policy(
            obs.url, session.allowed_domains, session.data_class, resolve=False
        )
        if (
            session.data_class == DataClass.RESTRICTED
            or profile is None
            or not profile.matches_host(host)
            or profile_policy_digest(profile) != binding.policy_digest
            or binding.credential_scope != "read_only"
        ):
            raise EnginePolicyBlocked(
                "bound profile or retention policy no longer permits this reading"
            )
        return Source(cap, obs, session, profile)

    def read(self, capture_id: str, query: ValueQuery, region: Region | None = None) -> dict:
        source = self.source(capture_id)
        answer = source.structured(query)
        method = "structured"
        crop_ref, used_region, candidates = None, None, []
        request = BrowserSessionBroker.evidence_request(
            source.capture.request_id, source.session, source.observation.url
        )
        if answer.status in {"missing", "unreadable"} and region is not None:
            method = "screenshot"
            source.require_pixels()
            if source.capture.screenshot_artifact_ref:
                crop = crop_image(
                    self.store.load_blob(source.capture.screenshot_artifact_ref), region
                )
                pixels = png_bytes(crop)
                crop_ref = self.store.persist_blob(pixels, request)
                if not crop_ref:
                    raise EnginePolicyBlocked("the capture store did not retain the requested crop")
                used_region = asdict(region)
                reads = read_region(pixels)
                answers = [candidate(query, reading["text"]) for reading in reads]
                candidates = [
                    {**reading, **asdict(parsed)}
                    for reading, parsed in zip(reads, answers, strict=True)
                ]
                answer = agreement(answers)
            else:
                answer = Answer("screenshot_missing")
        body = {
            "kind": "dashboard_value",
            "version": 2,
            "source": source.reference(),
            "label": query.label,
            "choices": list(query.choices),
            "method": method,
            "status": answer.status,
            "value": answer.value,
            "region": used_region,
            "crop_ref": crop_ref,
            "readings": candidates,
        }
        reading_id = _reading_id(body)
        capture = WebCapture.from_reader_result(
            ReaderResult(
                engine="visual-reading",
                requested_url=source.observation.url,
                final_url=source.observation.url,
                auth_scope="profile:" + source.session.profile_id,
                content=body,
            ),
            request,
            capture_id=reading_id,
            captured_at=source.observation.captured_at,
        )
        _, persistence = self.store.persist(capture, request)
        if not persistence.artifact_ref:
            raise EnginePolicyBlocked("the capture store did not retain this reading")
        self.ledger.bind_visual_reading(
            capture.content_hash, capture_id, persistence.artifact_ref, register=True
        )
        return {"reading_id": reading_id, **body}

    def show(self, reading_id: str, export_crop: Path | None = None) -> dict:
        capture = self.store.load_capture(reading_id)
        self.store.verify_capture(capture)
        body = capture.content
        if (
            not isinstance(body, dict)
            or body.get("kind") != "dashboard_value"
            or body.get("version") != 2
            or _reading_id(body) != reading_id
            or capture.capture_id != reading_id
        ):
            raise ValueError("expected a content-addressed dashboard reading")
        source = self.source(body["source"]["capture_id"])
        self.ledger.bind_visual_reading(
            capture.content_hash,
            source.capture.capture_id,
            capture.raw_artifact_ref,
            register=False,
        )
        if body["source"] != source.reference():
            raise ValueError("reading does not match its registered source")
        query = ValueQuery(body["label"], tuple(body["choices"]))
        original_answer = source.structured(query)
        if body["method"] == "structured":
            if body["readings"] or body["crop_ref"] is not None or body["region"] is not None:
                raise ValueError("structured reading has unexpected pixel evidence")
            expected = original_answer
        elif body["method"] == "screenshot" and original_answer.status in {"missing", "unreadable"}:
            source.require_pixels()
            has_screen = bool(source.capture.screenshot_artifact_ref)
            if has_screen != bool(body["crop_ref"]) or has_screen != (body["region"] is not None):
                raise ValueError("reading lacks the expected screenshot or region")
            if not has_screen and body["readings"]:
                raise ValueError("reading has candidates without a screenshot")
            expected = (
                _verified_agreement(query, body["readings"])
                if has_screen
                else Answer("screenshot_missing")
            )
        else:
            raise ValueError("reading method does not match the original observation")
        if expected.status != body["status"] or expected.value != body["value"]:
            raise ValueError("reading disagrees with the retained candidates")
        if body["crop_ref"]:
            source.require_pixels()
            region = Region(**body["region"])
            original = crop_image(
                self.store.load_blob(source.capture.screenshot_artifact_ref), region
            )
            pixels = self.store.load_blob(body["crop_ref"])
            from PIL import Image

            with Image.open(io.BytesIO(pixels), formats=["PNG"]) as saved:
                if (
                    saved.size != original.size
                    or saved.mode != "RGB"
                    or saved.n_frames != 1
                    or saved.tobytes() != original.tobytes()
                ):
                    raise ValueError("retained crop differs from the source pixels")
            if export_crop is not None:
                with export_crop.open("xb") as stream:
                    stream.write(pixels)
        elif export_crop is not None:
            raise ValueError("this reading has no retained crop")
        return {"reading_id": reading_id, **body}


def _reading_id(body: dict) -> str:
    return "visual-" + canonical_digest(body).removeprefix("sha256:")


def _verified_agreement(query: ValueQuery, readings: list[dict]) -> Answer:
    if not readings:
        return Answer("reader_unavailable")
    readers = [r["reader"] for r in readings]
    if readers not in (
        ["aire.windows", "aire.rapidocr"],
        ["aire.windows", "aire.windows.contrast"],
        ["aire.rapidocr", "aire.rapidocr.contrast"],
    ):
        raise ValueError("unexpected local OCR reader combination")
    answers = []
    for reading in readings:
        raw = reading["text"]
        if not isinstance(raw, str) or len(raw) > 4096:
            raise ValueError("invalid retained OCR text")
        parsed = candidate(query, raw)
        if parsed != Answer(reading["status"], reading["value"]):
            raise ValueError("retained OCR text disagrees with the candidate value")
        answers.append(parsed)
    return agreement(answers)


def observe_value(
    broker: BrowserSessionBroker,
    session_id: str,
    context: WorkContext,
    query: ValueQuery,
    *,
    expected_revision: int,
    expected_epoch: int,
    operation_id: str,
    region: Region | None = None,
) -> dict:
    """Use the existing owner's session. Request pixels only after structured observation misses."""
    from weir.contract import validate_identifier

    validate_identifier(operation_id, "operation_id")
    op = canonical_digest(
        [operation_id, query.label, query.choices, asdict(region) if region else None]
    )[7:]
    readings = VisualReadings(broker.store, broker.capture_store, broker.profiles)
    first = broker.observe(
        session_id,
        context,
        expected_revision=expected_revision,
        expected_epoch=expected_epoch,
        operation_id=f"visual-{op}-text",
    )
    source = readings.source(first.capture.capture_id)
    if region and source.structured(query).status in {"missing", "unreadable"}:
        first = broker.observe(
            session_id,
            context,
            expected_revision=first.observation.session_revision,
            expected_epoch=expected_epoch,
            operation_id=f"visual-{op}-pixels",
            include_screenshot=True,
        )
    return readings.read(first.capture.capture_id, query, region)
