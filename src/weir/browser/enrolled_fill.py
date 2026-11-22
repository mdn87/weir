"""Authority for the first Linux fill. The HTTP caller cannot supply any of these records."""

from __future__ import annotations

import json
import ipaddress
import os
import re
import secrets
import stat
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from weir.actions import ActionType, ConditionKind, Risk
from weir.browser.models import SemanticLocator, SessionState
from weir.contract import canonical_digest, canonical_json_bytes, is_sha256, parse_timestamp, validate_identifier
from weir.engines.base import EnginePolicyBlocked, IdempotencyConflict
from weir.models import DataClass
from weir.remote_decision import RemoteDecision, RemoteDecisionCapsule


MARKER = "WEIR-CANARY"
GRANT = "weir-first-unsaved-fill-v1"
POLICY = "weir-linux-unsaved-fill-v1"
ENROLL_ACTION = "enroll-first-unsaved-field"
FRESHNESS = timedelta(seconds=30)


def require(condition, message):
    if not condition:
        raise EnginePolicyBlocked(message)


@dataclass(frozen=True)
class EnrolledField:
    url: str
    name: str
    test_id: str
    profile_id: str
    profile_digest: str
    credential_binding_id: str
    body_digest: str
    headers_digest: str
    tls_fingerprint: str
    peer_address: str

    def validate(self):
        u = urlsplit(self.url)
        if (not self.url.isascii() or u.scheme != "https" or not u.hostname or u.username is not None
                or u.password is not None or not re.fullmatch(r"[a-z0-9.-]+(?::[1-9][0-9]{0,4})?", u.netloc)
                or u.port == 0 or not re.fullmatch(r"/[a-zA-Z0-9/_~.-]*", u.path)
                or "//" in u.path
                or any(part in {".", ".."} for part in u.path.split("/"))
                or self.url != "https://" + u.netloc + u.path):
            raise ValueError("Enrollment requires an exact canonical HTTPS origin and path")
        for key in ("profile_id", "credential_binding_id", "test_id"):
            validate_identifier(getattr(self, key), key)
        if str(ipaddress.ip_address(self.peer_address)) != self.peer_address or "%" in self.peer_address:
            raise ValueError("Enrollment requires one canonical peer address")
        if not re.fullmatch(r"[A-Za-z0-9][ A-Za-z0-9_-]{0,79}", self.name):
            raise ValueError("Unusable enrolled accessible name")
        if not all(is_sha256(v) for v in (self.profile_digest, self.body_digest, self.headers_digest,
                                          self.tls_fingerprint)):
            raise ValueError("Enrollment requires saved response and profile digests")

    @property
    def digest(self):
        self.validate()
        return canonical_digest({"grant": GRANT, "policy": POLICY, **asdict(self)})

    @property
    def locator(self):
        return SemanticLocator(role="textbox", name=self.name, test_id=self.test_id)

    def observation(self, obs, value):
        obs.validate()
        snap = obs.accessibility_snapshot
        require(obs.url == self.url and isinstance(snap, dict)
                and snap.get("enrollment_digest") == self.digest and snap.get("value") == value
                and len(obs.elements) == 1, "The trusted observation differs from the enrolled field")
        field, = obs.elements
        require((field.role, field.name, field.test_id, field.state)
                == ("textbox", self.name, self.test_id, "empty" if value == "" else "filled"),
                "The observed element differs from the enrolled textbox")
        identity = snap.get("document_identity")
        require(is_sha256(identity), "A pinned document and node identity is required")
        return identity

    def validate_observation(self, obs):
        obs.validate()
        require(obs.url == self.url, "The observer left the enrolled page")

    def check_proposal(self, p, store):
        session = store.get_session(p.session_id)
        binding = store.profile_binding(p.session_id)
        res = store.profile_reservation(p.session_id)
        require(p.action_type is ActionType.FILL and p.risk is Risk.UNKNOWN and p.requires_approval is True
                and p.parameter_data_class is DataClass.PUBLIC and session.data_class is DataClass.PUBLIC
                and p.parameters == {"value": MARKER} and p.semantic_locator == self.locator
                and session.current_url == self.url and session.state in {SessionState.ACTIVE, SessionState.PAUSED}
                and binding.site_profile_id == self.profile_id and binding.policy_digest == self.profile_digest
                and res.credential_binding_id == self.credential_binding_id and res.state == "active",
                "Proposal, session or registered anonymous profile does not match enrollment")
        for conditions, value in ((p.preconditions, "empty"), (p.expected_postconditions, "filled")):
            matches = [c for c in conditions if c.kind is ConditionKind.ELEMENT_STATE_EQUALS]
            require(len(matches) == 1 and matches[0].expected == value and matches[0].locator == self.locator
                    and matches[0].target == p.resolved_target, "The exact field condition is missing")


@dataclass(frozen=True)
class DecisionTrust:
    issuer: str
    key_id: str
    device: str
    owner: str
    audience: str
    public_key: Ed25519PublicKey

    def verify(self, capsule, at, *, enrollment=False):
        capsule.validate_at(at, expected_issuer_id=self.issuer, expected_device_id=self.device,
                            expected_audience=self.audience + (".enrollment" if enrollment else ""),
                            public_keys={self.key_id: self.public_key})
        require(capsule.actor_id == self.owner and capsule.decision is RemoteDecision.APPROVE
                and at < parse_timestamp(capsule.expires_at, "expires_at"),
                "The designated owner's current approval is required")


def _directory(path):
    fd = os.open(path, os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    info = os.fstat(fd)
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        os.close(fd)
        raise EnginePolicyBlocked("The authority directory must be private to its service owner")
    return fd


def _private_fd(directory, name, flags, *, limit=65536):
    fd = os.open(name, flags | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid()
            or info.st_mode & 0o077 or (limit is not None and info.st_size > limit)):
        os.close(fd)
        raise EnginePolicyBlocked("Invalid protected authority record")
    return fd


def _read(directory, name):
    with os.fdopen(_private_fd(directory, name, os.O_RDONLY), "rb") as stream:
        return json.loads(stream.read(65537))


def _publish(directory, name, record, *, replace=False):
    """Publish only complete, synced records. Immutable approval mappings may only be repeated exactly."""
    tmp = ".pending-" + secrets.token_hex(12)
    raw = canonical_json_bytes(record)
    require(len(raw) <= 65536, "Protected authority record is too large")
    fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC, 0o600, dir_fd=directory)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(raw)
            out.flush()
            os.fsync(out.fileno())
        if replace:
            os.replace(tmp, name, src_dir_fd=directory, dst_dir_fd=directory)
        else:
            try:
                os.link(tmp, name, src_dir_fd=directory, dst_dir_fd=directory)
            except FileExistsError:
                require(_read(directory, name) == record, "The protected decision reference was already bound")
            os.unlink(tmp, dir_fd=directory)
        os.fsync(directory)
    finally:
        try:
            os.unlink(tmp, dir_fd=directory)
        except FileNotFoundError:
            pass


class LinuxFillAuthority:
    """Single grant with separate protected ingress and append-only rollback witness.

    Both directories and the live witness are provisioned out of band. Opening
    an absent or damaged witness never initializes or refills it.
    """

    def __init__(self, ingress: Path, witness: Path, trust: DecisionTrust, *, deployment=None, profile=None):
        self.ingress = Path(ingress)
        self.witness = Path(witness)
        self.trust = trust
        self.deployment = deployment
        self.profile = profile
        if self.ingress.resolve() == self.witness.resolve():
            raise ValueError("The grant witness must be separate from decision ingress")

    @contextmanager
    def lock(self, *, execution=False, wait=True):
        import fcntl

        fd = _directory(self.witness if execution else self.ingress)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | (0 if wait else fcntl.LOCK_NB))
            except BlockingIOError:
                yield None
            else:
                yield fd
        finally:
            os.close(fd)

    def enrollment(self, ingress, now):
        state = _read(ingress, "current.json")
        field = EnrolledField(**state["field"])
        if self.deployment is not None:
            require((field.profile_id, field.profile_digest, field.credential_binding_id) == self.profile
                    and ipaddress.ip_address(field.peer_address).is_global, "Field differs from commissioned profile")
        reviewed_at = parse_timestamp(state["enrolled_at"], "enrolled_at")
        checked = parse_timestamp(state["revocations_checked_at"], "revocations_checked_at")
        require(state["active"] is True and reviewed_at <= now and checked <= now < checked + FRESHNESS
                and state["revoked"] == [], "Enrollment or revocation evidence is unavailable or stale")
        enroll = RemoteDecisionCapsule.from_dict(state["enrollment_decision"])
        self.trust.verify(enroll, reviewed_at, enrollment=True)
        purpose = state.get("purpose", {"grant": GRANT, "operation": "enroll"})
        action = ENROLL_ACTION if purpose["operation"] == "enroll" else "replace-first-unsaved-field"
        require(enroll.proposal_hash == field.digest and enroll.action_id == action
                and enroll.work_context_hash == canonical_digest(purpose)
                and enroll.step_up_ref == state["enrollment_step_up_ref"], "Enrollment decision mismatch")
        return field, enroll

    def authorization(self, ingress, p, permit, command, now):
        field, enroll = self.enrollment(ingress, now)
        # Hash the reference before using it as a filename. This is the
        # immutable ingress mapping, written only by the trusted approval receiver.
        name = canonical_digest(permit.approval_ref).split(":")[1] + ".json"
        try:
            record = _read(ingress, name)
        except FileNotFoundError as exc:
            raise EnginePolicyBlocked("The protected approval reference is unavailable") from exc
        capsule = RemoteDecisionCapsule.from_dict(record["capsule"])
        self.trust.verify(capsule, now)
        require(record["approval_ref"] == permit.approval_ref and record["capsule_hash"] == capsule.capsule_hash
                and record["enrolled_by"] == enroll.capsule_hash
                and record["step_up_ref"] == capsule.step_up_ref and capsule.step_up_ref != enroll.step_up_ref
                and capsule.nonce != enroll.nonce and capsule.capsule_id != enroll.capsule_id
                and (capsule.command_id, capsule.action_id, capsule.proposal_hash, capsule.work_context_hash)
                == (command, p.action_id, p.proposal_hash, p.work_context_hash),
                "The signed decision differs from the submitted action or enrollment")
        return field, enroll, capsule

    def accept_approval(self, approval_ref, capsule, step_up_ref, now):
        """Trusted local ingress after passkey verification. Never an HTTP action route."""
        validate_identifier(approval_ref, "approval_ref")
        self.trust.verify(capsule, now)
        require(capsule.step_up_ref == step_up_ref, "Passkey decision reference mismatch")
        with self.lock() as ingress:
            _, enrolled = self.enrollment(ingress, now)
            require(capsule.step_up_ref != enrolled.step_up_ref and capsule.nonce != enrolled.nonce,
                    "Enrollment cannot approve a fill")
            name = canonical_digest(approval_ref).split(":")[1] + ".json"
            _publish(ingress, name, {"approval_ref": approval_ref, "capsule": capsule.to_dict(),
                                     "capsule_hash": capsule.capsule_hash, "step_up_ref": step_up_ref,
                                     "enrolled_by": enrolled.capsule_hash})

    def accept_enrollment(self, field, capsule, step_up_ref, now):
        field.validate()
        self.trust.verify(capsule, now, enrollment=True)
        require(capsule.step_up_ref == step_up_ref and capsule.proposal_hash == field.digest,
                "The owner did not approve this field")
        if self.deployment is not None:
            require(ipaddress.ip_address(field.peer_address).is_global, "Live enrollment requires a public peer")
        with self.lock() as ingress:
            with self.journal() as (_, rows):
                require(len(rows) == 1, "The grant has already been spent")
            try:
                previous = _read(ingress, "current.json")
            except FileNotFoundError:
                previous = None
            if previous and previous["active"] and previous["enrollment_decision"] == capsule.to_dict():
                return
            purpose = {"grant": GRANT, "operation": "enroll"}
            action = ENROLL_ACTION
            if previous:
                purpose = {"grant": GRANT, "operation": "replace", "predecessor": previous["generation"]}
                action = "replace-first-unsaved-field"
                require(step_up_ref != previous["enrollment_step_up_ref"], "Replacement requires a fresh passkey")
            require(capsule.action_id == action and capsule.work_context_hash == canonical_digest(purpose),
                    "The enrollment decision does not bind the current generation")
            # Enrollment does not imply recent knowledge of revocations. The
            # independent ingress must supply a fresh check before any browser starts.
            _publish(ingress, "current.json", {
                "field": asdict(field), "active": True, "enrolled_at": now.isoformat(),
                "revocations_checked_at": "1970-01-01T00:00:00+00:00", "revoked": [],
                "enrollment_decision": capsule.to_dict(), "enrollment_step_up_ref": step_up_ref,
                "purpose": purpose, "generation": capsule.capsule_hash}, replace=previous is not None)

    def record_revocations(self, field_digest, checked_at, revoked):
        """Trusted host's acknowledged refresh, serialized with the final dispatch marker."""
        with self.lock() as ingress:
            current = _read(ingress, "current.json")
            require(checked_at.tzinfo is not None and EnrolledField(**current["field"]).digest == field_digest
                    and checked_at >= parse_timestamp(current["revocations_checked_at"], "checked_at")
                    and checked_at <= datetime.now(timezone.utc)
                    and isinstance(revoked, list) and all(is_sha256(x) for x in revoked),
                    "Stale or mismatched revocation publication")
            current["revocations_checked_at"] = checked_at.isoformat()
            current["revoked"] = sorted(set(current["revoked"]) | set(revoked))
            _publish(ingress, "current.json", current, replace=True)

    def withdraw(self, decision, step_up_ref, now):
        self.trust.verify(decision, now, enrollment=True)
        with self.lock() as ingress:
            record = _read(ingress, "current.json")
            field = EnrolledField(**record["field"])
            require(decision.action_id == "withdraw-first-unsaved-field" and decision.proposal_hash == field.digest
                    and decision.work_context_hash == canonical_digest({"grant": GRANT, "operation": "withdraw",
                                                                       "predecessor": record["generation"]})
                    and decision.step_up_ref == step_up_ref and step_up_ref != record["enrollment_step_up_ref"],
                    "The owner did not approve withdrawal of this field")
            record["active"] = False
            record["generation"] = decision.capsule_hash
            _publish(ingress, "current.json", record, replace=True)

    @contextmanager
    def journal(self):
        import fcntl
        from array import array

        directory = _directory(self.witness)
        try:
            fd = _private_fd(directory, "grant.jsonl", os.O_RDWR | os.O_APPEND)
            with os.fdopen(fd, "r+b", buffering=0) as stream:
                fcntl.flock(fd, fcntl.LOCK_EX)
                if self.deployment is not None:
                    flags = array("l", [0])
                    fcntl.ioctl(fd, 0x80086601, flags, True)  # FS_IOC_GETFLAGS on the qualified x86-64 host
                    require(flags[0] & 0x20, "The commissioned spend witness must be kernel append-only")
                raw = stream.read(65537)
                require(raw.endswith(b"\n") and len(raw) <= 65536, "Incomplete durable grant witness")
                rows = [json.loads(line) for line in raw.splitlines()]
                initial = {"grant": GRANT, "state": "available"}
                if self.deployment is not None:
                    initial["deployment"] = self.deployment
                require(1 <= len(rows) <= 3 and rows[0] == initial
                        and (len(rows) == 1 or (rows[1].get("state") == "reserved" and rows[1].get("grant") == GRANT
                             and rows[1].get("deployment") == self.deployment and is_sha256(rows[1].get("request_digest"))))
                        and (len(rows) < 3 or rows[2] == {"state": "dispatch", "binding": canonical_digest(rows[1])}),
                        "The grant witness contains inconsistent transitions")
                yield stream, rows
        finally:
            os.close(directory)

    def retain_lifecycle(self, command, evidence):
        record = {"command": command, "grant": GRANT, "evidence": evidence}
        digest = canonical_digest(record)
        with self.lock() as ingress:
            _publish(ingress, "lifecycle-" + digest.split(":")[1] + ".json", record)
        return digest

    @staticmethod
    def append(stream, row):
        raw = canonical_json_bytes(row) + b"\n"
        if stream.write(raw) != len(raw):
            raise OSError("Incomplete durable grant witness")
        os.fsync(stream.fileno())

    def reserve(self, binding):
        with self.journal() as (stream, rows):
            if len(rows) != 1:
                raise IdempotencyConflict("The deployment-wide grant has already been spent")
            self.append(stream, binding)

    def mark(self, binding):
        with self.journal() as (stream, rows):
            require(len(rows) == 2 and rows[1] == binding, "The grant does not match this reservation")
            self.append(stream, {"state": "dispatch", "binding": canonical_digest(binding)})
