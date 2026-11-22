"""Approve and witness one title on the private Mission Control rehearsal task."""

import base64
import json
import os
import re
import socket
import sys
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from weir.contract import canonical_digest, canonical_json_bytes, parse_timestamp
from weir.remote_decision import RemoteDecisionCapsule

ACTION = "rename-private-task-v1"
AUDIENCE = "weir.rehearsal.saved-task"
COMMAND = re.compile(r"saved-[a-f0-9]{32}")
SCOPE = ("deployment", "tenant_id", "workspace_id", "actor_id", "command_id")
LIMIT = 32_768
# Non-format default ignorables in Unicode 17 DerivedCoreProperties.txt.
# https://www.unicode.org/Public/17.0.0/ucd/DerivedCoreProperties.txt
IGNORABLE = re.compile(
    "[\u034f\u115f-\u1160\u17b4-\u17b5\u180b-\u180f\u2065\u3164"
    "\ufe00-\ufe0f\uffa0\ufff0-\ufff8\U000e0000-\U000e0fff]"
)


class SavedTaskError(ValueError):
    pass


def require(ok):
    if not ok:
        raise SavedTaskError("The saved task evidence or authority does not match.")


def check_view(view, digest, *, owner, deployment, tenant, workspace):
    require(
        isinstance(view, dict)
        and set(view)
        == set(SCOPE)
        | {
            "schema",
            "action_id",
            "task_id",
            "generation",
            "revision",
            "before",
            "after",
            "undo_of",
            "delivery",
            "data_class",
            "use_limit",
            "issued_at",
            "expires_at",
            "work_context_hash",
        }
    )
    require(
        view["schema"] == "weir.saved-task-review/v1"
        and view["action_id"] == ACTION
        and view["task_id"] == "rehearsal-task"
        and view["delivery"] == "private-task-and-owner-receipt"
        and view["data_class"] == "internal"
        and type(view["use_limit"]) is int
        and view["use_limit"] == 1
    )
    require(
        (view["actor_id"], view["deployment"], view["tenant_id"], view["workspace_id"])
        == (owner, deployment, tenant, workspace)
    )
    require(
        all(
            type(view[k]) is int and view[k] > 0
            for k in ("tenant_id", "workspace_id", "revision", "issued_at", "expires_at")
        )
    )
    require(0 < view["expires_at"] - view["issued_at"] <= 300 and view["before"] != view["after"])
    require(
        COMMAND.fullmatch(view["command_id"])
        and re.fullmatch("[0-9a-f]{32}", view["generation"])
        and (view["undo_of"] is None or COMMAND.fullmatch(view["undo_of"]))
    )
    for title in (view["before"], view["after"]):
        require(
            isinstance(title, str)
            and title == title.strip()
            and unicodedata.is_normalized("NFC", title)
            and 0 < len(title.encode("utf-16-le")) <= 1000
            and all(unicodedata.category(c) not in {"Cc", "Cf", "Cs", "Zl", "Zp"} for c in title)
            and not IGNORABLE.search(title)
        )
    require(
        view["work_context_hash"] == canonical_digest({k: view[k] for k in SCOPE})
        and digest == canonical_digest(view)
    )


def check_receipt(view, source):
    receipt = source["receipt"]
    expected = {k: view[k] for k in ("command_id", "generation", "before", "after")}
    require(type(receipt) is dict and type(receipt.get("saved_at")) is int)
    require(view["issued_at"] <= receipt["saved_at"] < view["expires_at"])
    require(
        receipt
        == {
            **expected,
            "proposal_hash": canonical_digest(view),
            "revision": view["revision"] + 1,
            "saved_at": receipt["saved_at"],
        }
    )
    task = source["task"]
    require(
        task["generation"] == receipt["generation"]
        and type(task["revision"]) is int
        and task["revision"] >= receipt["revision"]
    )
    current = task["revision"] == receipt["revision"]
    require(not current or task["title"] == receipt["after"])
    return {
        "state": "verified",
        "receipt": receipt,
        "current": current,
        "current_revision": task["revision"],
        "current_title": task["title"],
    }


def public_key(value):
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(value, validate=True))


def check_authority(view, step_up, capsule_doc, permit, pins, now):
    capsule = RemoteDecisionCapsule.from_dict(capsule_doc)
    capsule.validate_at(
        now,
        expected_issuer_id="mc.saved-task",
        expected_audience=AUDIENCE,
        expected_device_id="saved-task-rehearsal",
        public_keys={"mc-saved-task": public_key(pins["owner_key"])},
    )
    issued = parse_timestamp(capsule.issued_at, "issued_at")
    expires = parse_timestamp(capsule.expires_at, "expires_at")
    require(issued <= now < expires and 0 < (expires - issued).total_seconds() <= 120)
    require(
        capsule.decision == "approve"
        and capsule.step_up_ref == step_up
        and capsule.proposal_hash == canonical_digest(view)
        and all(
            getattr(capsule, k) == view[k]
            for k in ("actor_id", "command_id", "action_id", "work_context_hash")
        )
    )
    expected = {
        "schema": "fade.saved-task-permit/v1",
        "issuer": "fade.saved-task",
        "audience": AUDIENCE,
        "command_id": capsule.command_id,
        "proposal_hash": capsule.proposal_hash,
        "work_context_hash": capsule.work_context_hash,
        "capsule_hash": capsule.capsule_hash,
        "expires_at": capsule.expires_at,
        "use_limit": 1,
    }
    require(
        pins["owner_key"] != pins["fade_key"]
        and set(permit) == set(expected) | {"signature"}
        and canonical_json_bytes({k: permit[k] for k in expected}) == canonical_json_bytes(expected)
    )
    public_key(pins["fade_key"]).verify(
        base64.b64decode(permit["signature"], validate=True), canonical_json_bytes(expected)
    )


def exchange(path, request):
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(12)
        client.connect(str(path))
        client.sendall(canonical_json_bytes(request))
        client.shutdown(socket.SHUT_WR)
        with client.makefile("rb") as stream:
            data = stream.read(LIMIT + 1)
    require(len(data) <= LIMIT)
    response = json.loads(data)
    require(response.get("ok") is True)
    return response["result"]


def reserve(directory, command, digest):
    """Publish the attempt durably before handing the command to the effect principal."""
    try:
        with (directory / command).open("x", encoding="ascii") as marker:
            marker.write(digest)
            marker.flush()
            os.fsync(marker.fileno())
    except FileExistsError:
        return False
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return True


def workflow(request, pins, call, journal):
    require(
        set(request) == {"operation", "command_id"}
        and request["operation"] in {"verify", "execute"}
    )
    command = request["command_id"]
    require(isinstance(command, str) and COMMAND.fullmatch(command))
    lookup = {"command_id": command}
    digest = None

    def read():
        source = call("reader", lookup)
        view = source["view"]
        check_view(
            view,
            source["proposal_hash"],
            owner=pins["owner"],
            deployment=pins["deployment"],
            tenant=pins["tenant"],
            workspace=pins["workspace"],
        )
        require(
            view["command_id"] == command and (digest is None or source["proposal_hash"] == digest)
        )
        return source

    source = read()
    view, digest = source["view"], source["proposal_hash"]
    if source["receipt"] is not None:
        return check_receipt(view, source)
    if source["state"] != "approved":
        require(source["state"] in {"pending", "declined", "withdrawn", "expired", "stale"})
        return {"state": source["state"]}
    if (journal / command).exists():
        return {"state": "outcome_unknown"}
    if request["operation"] == "verify":
        return {"state": "approved"}
    capsule = call("issuer", lookup)
    permit = call("fade", {"capsule": capsule})
    now = datetime.now(timezone.utc)
    require(view["issued_at"] <= now.timestamp() < view["expires_at"])
    check_authority(view, source["step_up_ref"], capsule, permit, pins, now)
    if reserve(journal, command, digest):
        try:
            call("effect", {**lookup, "capsule": capsule, "permit": permit})
        except Exception:
            pass  # Only the independent source can establish what committed.
    try:
        source = read()
        if source["receipt"] is not None:
            return check_receipt(view, source)
        if source["state"] in {"declined", "withdrawn", "expired", "stale"}:
            return {"state": source["state"]}
    except Exception:
        pass
    return {"state": "outcome_unknown"}


def main():
    try:
        require(os.environ.get("WEIR_SAVED_TASK_REHEARSAL") == "1" and sys.platform == "linux")
        root = Path(os.environ["WEIR_SAVED_TASK_ROOT"])
        require(root.is_absolute() and root.resolve() == root)
        pins = json.loads((root / "pins.json").read_bytes())
        raw = sys.stdin.buffer.read(LIMIT + 1)
        require(len(raw) <= LIMIT)
        result = workflow(
            json.loads(raw),
            pins,
            lambda role, r: exchange(root / (role + ".sock"), r),
            root / "attempts",
        )
        reply = {"ok": True, "result": result}
    except Exception:
        reply = {"ok": False, "error": "Saved task verification is unavailable."}
    sys.stdout.buffer.write(canonical_json_bytes(reply) + b"\n")
    return 0 if reply["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
