"""Verify the live systemd worker before releasing a read-only dashboard document."""

from __future__ import annotations

import json
import os
import re
import socket
import struct
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from weir.browser.admission import (
    CredentialProtectionEvidence, ProductionAdmission, ProductionControlEvidence,
    ProductionProcessBinding, WorkerContainmentEvidence, WorkerResourceLimits,
)
from weir.contract import canonical_digest
from weir.browser.protocol import WorkerCapability, WorkerDescriptor
from weir.review_board import MAX_HTML


SOCKET_PATH = "/run/weir-review-browser/observe.sock"
CALLER = "mission-control-review"
WORKER = "linux-review-browser"
LIMITS = WorkerResourceLimits(512 * 1024 * 1024, 128)
FRAME_LIMIT = MAX_HTML * 6 + 2048  # A JSON-escaped document can grow sixfold.
REQUIRED = {
    "DynamicUser": "yes", "NoNewPrivileges": "yes", "PrivateNetwork": "yes",
    "ProtectHome": "yes", "ProtectSystem": "strict", "ProtectControlGroups": "yes",
    "KillMode": "control-group", "PrivateTmp": "yes", "PrivatePIDs": "yes", "PrivateIPC": "yes",
    "ActiveState": "active",
    "FragmentPath": "/etc/systemd/system/weir-review-browser@.service",
    "CapabilityBoundingSet": "", "RestrictAddressFamilies": "AF_UNIX", "BindPaths": "",
}


def send_message(sock, value):
    sock.sendall(json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n")


def receive_message(reader):
    line = reader.readline(FRAME_LIMIT + 1)
    if len(line) > FRAME_LIMIT or not line.endswith(b"\n"):
        raise OSError("The isolated browser did not return a complete message.")
    value = json.loads(line)
    if not isinstance(value, dict):
        raise OSError("Unexpected isolated browser response.")
    return value


def _start_ticks(pid):
    # Linux /proc/PID/stat field 22 after the parenthesized command name.
    return int(Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19])


def _credentials(sock):
    size = struct.calcsize("3i")
    marker, controls, flags, _ = sock.recvmsg(1, socket.CMSG_SPACE(size))
    if marker != b"W" or flags & socket.MSG_CTRUNC:
        raise OSError("Browser service identity is unavailable.")
    for level, kind, payload in controls:
        if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(payload) == size:
            pid, uid, _ = struct.unpack("3i", payload)
            if pid > 1 and uid not in {0, os.geteuid()}:
                return pid, uid
    raise OSError("The isolated browser must run as a separate unprivileged service.")


def inspect_worker(pid, uid):
    started = _start_ticks(pid)
    groups = Path(f"/proc/{pid}/cgroup").read_text().splitlines()
    if len(groups) != 1 or not groups[0].startswith("0::/"):
        raise OSError("A unified service cgroup is required.")
    group = groups[0][3:]
    unit = Path(group).name
    if not re.fullmatch(r"weir-review-browser@[a-zA-Z0-9._:@\\-]+\.service", unit):
        raise OSError("The peer is outside the review browser service.")
    props = [*REQUIRED, "InvocationID", "MainPID", "ControlGroup", "TemporaryFileSystem", "BindReadOnlyPaths"]
    output = subprocess.run(
        ["/usr/bin/systemctl", "show", "--property=" + ",".join(props), "--", unit],
        capture_output=True, timeout=5, check=True, text=True,
    )
    values = dict(line.split("=", 1) for line in output.stdout.splitlines() if "=" in line)
    if any(values.get(key) != value for key, value in REQUIRED.items()):
        raise OSError("The browser service isolation settings are incomplete.")
    masks = {entry.split(":", 1)[0] for entry in values["TemporaryFileSystem"].split()}
    if not {"/srv", "/run", "/var"}.issubset(masks):
        raise OSError("The browser can see host service state.")
    binds = values["BindReadOnlyPaths"].split()
    if len(binds) != 1 or binds[0].split(":")[0] != "/srv/lugos/runtimes/weir-operator-reports/0.6.0":
        raise OSError("Unexpected files are mounted inside the browser service.")
    invocation = values["InvocationID"]
    if (values["MainPID"] != str(pid) or values["ControlGroup"] != group
            or not re.fullmatch(r"[0-9a-f]{32}", invocation)):
        raise OSError("The connected browser process is outside the active service instance.")
    cgroup = Path("/sys/fs/cgroup") / group.lstrip("/")
    if ((cgroup / "memory.max").read_text().strip() != str(LIMITS.memory_bytes)
            or (cgroup / "pids.max").read_text().strip() != str(LIMITS.process_count)
            or str(pid) not in (cgroup / "cgroup.procs").read_text().splitlines()):
        raise OSError("The browser has no verified memory and process limits.")
    status = Path(f"/proc/{pid}/status").read_text().splitlines()
    if not any(line.split() == ["Uid:", *([str(uid)] * 4)] for line in status):
        raise OSError("The browser service UID has changed.")
    if started != _start_ticks(pid):
        raise OSError("The connected browser process was replaced.")
    now = datetime.now(timezone.utc)
    identity = "uid-" + str(uid)
    instance = "instance-" + invocation
    containment = WorkerContainmentEvidence("linux", pid, True, True, LIMITS, True)
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    binding = ProductionProcessBinding(socket.gethostname(), 1, _start_ticks(1), started,
                                       f"boot-{boot}-cgroup-{cgroup.stat().st_ino}")
    proof = ProductionControlEvidence.create(
        attestation_id="linux-" + invocation, platform="linux", service_identity=identity,
        worker_identity=identity, worker_id=WORKER, worker_instance_id=instance,
        containment=containment, process_binding=binding, restricted_identity=True,
        credential_protection=(CredentialProtectionEvidence(
            CALLER, "broker-only-review-grant",
            canonical_digest({"uid": uid, "masks": sorted(masks), "bindings": binds}), True),),
        lifecycle_supervisor="systemd", lifecycle_instance_id=instance, lifecycle_healthy=True,
        egress_policy_id="private-network-unix-only", egress_policy_digest=canonical_digest(REQUIRED),
        egress_enforced=True, verified_at=now.isoformat(), expires_at=(now + timedelta(seconds=30)).isoformat(),
    )
    return proof, cgroup


def _admit(pid, uid, expected, *, browser_started):
    proof, group = inspect_worker(pid, uid)
    if browser_started:
        names = []
        for member in (group / "cgroup.procs").read_text().splitlines():
            try:
                names.append(Path(f"/proc/{int(member)}/comm").read_text().strip())
            except FileNotFoundError:
                continue
        if not any(name.startswith(("chrome", "headless_shell")) for name in names):
            raise OSError("Chromium has no process in the admitted service cgroup.")
    # Keep the lifetime and cgroup of the kernel-authenticated peer. Compare each
    # later inspection to that original connection, including after the DOM read.
    original = expected or proof
    descriptor = WorkerDescriptor(WORKER, "linux-chromium", frozenset({WorkerCapability.OBSERVE}),
                                  instance_id=original.worker_instance_id)
    transport = _ConnectedWorker(descriptor, original.containment, original.process_binding)
    ProductionAdmission(lambda: proof, expected_platform="linux").require_browser_worker(transport, caller_id=CALLER)
    return proof


@dataclass(frozen=True)
class _ConnectedWorker:
    descriptor: WorkerDescriptor
    containment_evidence: WorkerContainmentEvidence
    production_binding: ProductionProcessBinding
    production_process_transport = True


def read_in_browser(url, fetch):
    path = os.environ.get("WEIR_REVIEW_BROWSER_SOCKET", SOCKET_PATH)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(45)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        sock.connect(path)
        pid, uid = _credentials(sock)
        proof = _admit(pid, uid, None, browser_started=False)
        send_message(sock, {"url": url})
        with sock.makefile("rb") as reader:
            if receive_message(reader) != {"read": url}:
                raise OSError("The browser did not request the enrolled task board.")
            proof = _admit(pid, uid, proof, browser_started=True)
            html = fetch()
            observed_at = datetime.now(timezone.utc).isoformat()
            send_message(sock, {"html": html})
            message = receive_message(reader)
            if set(message) != {"result"} or not isinstance(message["result"], dict):
                raise OSError("Browser observation failed.")
            _admit(pid, uid, proof, browser_started=True)
            send_message(sock, {"finish": True})
    return message["result"], html, observed_at, proof
