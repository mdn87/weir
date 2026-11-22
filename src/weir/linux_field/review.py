"""Read-only owner views of WEIR's one unsaved field. An owner view has no execution authority."""

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import re
import secrets
import stat
import sys

from weir.browser.enrolled_document import HEADERS, byte_digest, inert_page
from weir.browser.enrolled_fill import ENROLL_ACTION, GRANT, MARKER, require
from weir.browser.models import SessionState
from weir.contract import canonical_digest, parse_timestamp
from weir.remote_decision import RemoteDecisionCapsule

REHEARSAL_AUDIENCE = "weir.rehearsal.first-fill"


def page_template():
    name, test_id = "WEIR canary", "weir-canary"
    html = inert_page(name, test_id)
    return {"name": name, "test_id": test_id, "html": html.decode("ascii"), "headers": HEADERS,
            "body_digest": byte_digest(html), "headers_digest": canonical_digest(HEADERS)}


def local_readiness(config: Path, state: Path, witness: Path):
    """Inspect metadata only. Presence says nothing about signatures or a human decision."""
    if sys.platform != "linux":
        return {"host_state": "unsupported", "checks": {}, "live_authority_checked": False}
    checks = {}
    for name, path, directory in (
        ("deployment", config / "deployment.json", False), ("service", config / "service.json", False),
        ("session_ledger", state / "sessions.sqlite3", False), ("work_context", state / "work-context.json", False),
        ("decision_ingress", state / "decisions", True), ("grant_witness", witness / "grant.jsonl", False),
    ):
        try:
            parent, info = path.parent.lstat(), path.lstat()
            protected = (stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0 and not parent.st_mode & 0o022
                         and info.st_uid == 0 and not info.st_mode & 0o077 and
                         (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1))
            checks[name] = "present" if protected else "unsafe"
        except FileNotFoundError:
            checks[name] = "missing"
        except OSError:
            checks[name] = "unavailable"
    checks["separate_witness_mount"] = "present" if os.path.ismount(witness) else "missing"
    return {"host_state": "inputs_present" if all(v == "present" for v in checks.values()) else "incomplete",
            "checks": checks, "live_authority_checked": False}


def preview_field(field):
    field.validate()
    require(re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,79}", field.test_id),
            "The owner review requires a readable field identifier")
    require(field.body_digest == byte_digest(inert_page(field.name, field.test_id))
            and field.headers_digest == canonical_digest(HEADERS), "The field does not match the eligible template")
    return {"url": field.url, "field_name": field.name, "test_id": field.test_id, "before": "", "after": MARKER,
            "use_limit": 1, "discard": "close-browser-and-read-again"}


def owner_review(field, trust, *, now=None, proposal=None, proposals=None):
    """Construct a passkey review only for the private rehearsal."""
    require(trust.audience == REHEARSAL_AUDIENCE, "Passkey reviews are available only for rehearsals")
    now = now or datetime.now(timezone.utc)
    display = preview_field(field)
    expires = now + timedelta(minutes=5)
    phase, action, digest = "enroll", ENROLL_ACTION, field.digest
    context = canonical_digest({"grant": GRANT, "operation": "enroll"})
    if proposal is not None:
        registered = proposals.load(proposal.proposal_hash)
        require(registered.to_dict() == proposal.to_dict(), "The retained proposal changed")
        field.check_proposal(registered, proposals.session_store)
        observation = proposals.approved_observation(registered)
        field.observation(observation, "")
        session = proposals.session_store.get_session(registered.session_id)
        require(session.state is SessionState.ACTIVE and session.revision == registered.session_revision
                and session.epoch == registered.session_epoch,
                "The retained observation is no longer current")
        expires = min(expires, parse_timestamp(registered.expires_at, "expires_at"))
        require(now < expires, "The proposal expired")
        phase, action, digest, context = "fill", registered.action_id, registered.proposal_hash, registered.work_context_hash
    card = {"schema": "weir.field-review/v1", "phase": phase, "actor_id": trust.owner, "device_id": trust.device,
            "audience": trust.audience + (".enrollment" if phase == "enroll" else ""),
            "action_id": action,
            "proposal_hash": digest, "work_context_hash": context, **display,
            "issued_at": now.isoformat(), "expires_at": expires.isoformat()}
    card["command_id"] = "field-" + phase + "-" + canonical_digest(card).split(":")[1][:40]
    return {**card, "review_hash": canonical_digest(card)}


def publish_review(directory, card):
    """Publish a complete owner view to a preprovisioned, read-only group share."""
    from weir.contract import canonical_json_bytes
    fd = os.open(directory, os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    tmp = ".review-" + secrets.token_hex(12)
    try:
        info = os.fstat(fd)
        require(info.st_uid == os.geteuid() and not info.st_mode & 0o027,
                "The review directory must be private to the publisher and its reader group")
        raw = canonical_json_bytes(card) + b"\n"
        with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440, dir_fd=fd), "wb") as out:
            os.fchmod(out.fileno(), 0o440)
            out.write(raw)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, "review.json", src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        try:
            os.unlink(tmp, dir_fd=fd)
        except FileNotFoundError:
            pass
        os.close(fd)


def accept_rehearsal_review(authority, field, card, event, step_up, *, proposal=None, proposals=None, now=None):
    """WEIR reloads its own evidence and the independent MC passkey record before acknowledging Fade."""
    now = now or datetime.now(timezone.utc)
    require(authority.deployment is None and authority.trust.audience == REHEARSAL_AUDIENCE,
            "This ingress accepts disposable rehearsal authority only")
    require(set(event) == {"review_hash", "capsule", "approval_ref"} and event["review_hash"] == card["review_hash"],
            "Fade selected another review")
    issued = parse_timestamp(card["issued_at"], "issued_at")
    require(issued <= now < parse_timestamp(card["expires_at"], "expires_at")
            and card == owner_review(field, authority.trust, now=issued, proposal=proposal, proposals=proposals),
            "The owner view has expired or differs from the protected source")
    capsule = RemoteDecisionCapsule.from_dict(event["capsule"])
    enrollment = card["phase"] == "enroll"
    authority.trust.verify(capsule, now, enrollment=enrollment)
    require(parse_timestamp(capsule.issued_at, "issued_at") <= now < parse_timestamp(capsule.expires_at, "expires_at"),
            "The signed owner decision is outside its validity window")
    for name in ("command_id", "action_id", "proposal_hash", "work_context_hash", "audience", "actor_id", "device_id"):
        require(getattr(capsule, name) == card[name], "The capsule differs from the owner view")
    require(step_up == {"review_hash": card["review_hash"], "actor_id": card["actor_id"],
                        "step_up_ref": capsule.step_up_ref}, "The independent passkey record does not match")
    ref = event["approval_ref"]
    if enrollment:
        require(ref is None, "Enrollment cannot issue an action approval")
        authority.accept_enrollment(field, capsule, step_up["step_up_ref"], now)
    else:
        with authority.lock() as directory:
            enrolled, _ = authority.enrollment(directory, now)
            require(enrolled == field, "The enrolled field changed after review")
        command = {k: card[k] for k in ("command_id", "proposal_hash", "action_id", "work_context_hash")}
        decision = {"actor_id": card["actor_id"], "command": {**command, "schema_version": 1,
                                                               "decision": "approved", "reason": None}}
        require(ref == "approval-" + canonical_digest(decision)[7:39], "Fade approval reference differs from the decision")
        authority.accept_approval(ref, capsule, step_up["step_up_ref"], now)
    return {"review_hash": card["review_hash"], "capsule_hash": capsule.capsule_hash, "approval_ref": ref}
