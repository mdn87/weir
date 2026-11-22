"""Host-only Linux runtime for the enrolled field, shared by acceptance and deployment."""

import base64
import json
import os
import re
import secrets
import select
import socket
import subprocess
import sys
import threading
from contextlib import ExitStack, contextmanager
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from linux_canary_host import Receivers, ServiceWitness, start_ticks
from linux_canary_driver import RUNTIME
from weir.browser.admission import (CredentialProtectionEvidence, ProductionControlEvidence,
                                    ProductionProcessBinding, WorkerContainmentEvidence, WorkerResourceLimits)
from weir.browser.effect_driver import FADE_AUTHORITY_ID
from weir.browser.enrolled_fill import require
from weir.browser.field_peers import FieldPeer
from weir.contract import canonical_digest
from weir.browser.enrolled_document import EnrolledDocument
from weir.browser.field_controller import LinuxFieldController

_launch_lock = threading.Lock()
_CONFIG = Path("/etc/weir/enrolled-fill")
_WITNESS = Path("/var/lib/weir-grant-witness")
_INGRESS = Path("/var/lib/weir-enrolled-fill/decisions")


def verify_task_events(lines):
    """task_newtask prints clone_flags in hex at creation, even for a thread already reaped."""
    for line in lines.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        flags = re.search(r"\btask_newtask: .*\bclone_flags=([0-9a-fA-F]+)\b", line)
        require(flags is not None and int(flags[1], 16) & 0x10000,
                "A pinned browser started a separate process or executed another program")


class LifetimeWitness:
    """Pin browser lifetimes and trace only their cgroup's admitted tasks from document pin to exit."""

    def __init__(self, unit, receivers):
        self.service = ServiceWitness(unit)
        self.receivers = receivers
        self.trace = None
        self.pidfds = []
        self.exit_record = None
        self.failure_record = None

    def pin_document(self):
        self.service.check()
        group = self.service.group
        self.trace = Path("/sys/kernel/tracing/instances") / ("weir-field-" + secrets.token_hex(12))
        self.trace.mkdir()
        self._write("tracing_on", "0")
        self._write("options/event-fork", "1")
        self._write("options/pause-on-trace", "0")
        self._write("buffer_size_kb", "256")
        require((self.trace / "options/pause-on-trace").read_text().strip() == "0"
                and int((self.trace / "buffer_size_kb").read_text().split()[0]) >= 256,
                "The lifetime trace cannot retain continuous evidence")
        tasks = sorted((group / "cgroup.threads").read_text().split())
        require(tasks, "No Linux browser tasks at document pin")
        self._write("set_event_pid", " ".join(tasks))
        self._write("events/task/task_newtask/enable", "1")
        self._write("events/sched/sched_process_exec/enable", "1")
        self._write("tracing_on", "1")
        require(tasks == sorted((group / "cgroup.threads").read_text().split()), "Browser changed while pinning tasks")
        for pid, ticks in {self.service.browser, *self.service.renderers}:
            fd = os.pidfd_open(int(pid))
            self.pidfds.append(fd)
            require(start_ticks(pid) == ticks, "Pinned browser lifetime changed")

    def _write(self, name, value):
        (self.trace / name).write_text(value)

    def _trace_ok(self):
        require(self.trace is not None and (self.trace / "tracing_on").read_text().strip() == "1",
                "Continuous browser evidence is absent")
        lines = (self.trace / "trace").read_text()
        for stat in self.trace.glob("per_cpu/cpu*/stats"):
            fields = dict(line.split(":", 1) for line in stat.read_text().splitlines() if ":" in line)
            require(all(int(fields[k]) == 0 for k in ("overrun", "commit overrun", "dropped events")),
                    "The browser lifetime trace lost events")
        verify_task_events(lines)
        return canonical_digest(lines)

    def evidence(self):
        self.service.check()
        self._trace_ok()
        require(not select.select(self.pidfds, [], [], 0)[0], "A pinned browser process exited early")
        self.receivers.require_silent()
        inv, group, pid, ticks, boot = self.service.identity
        actor = "uid-" + str(Path(f"/proc/{pid}").stat().st_uid)
        instance = "instance-" + inv
        limits = WorkerResourceLimits(int((self.service.group / "memory.max").read_text()),
                                      int((self.service.group / "pids.max").read_text()))
        now = datetime.now(timezone.utc)
        return ProductionControlEvidence.create(
            attestation_id="linux-" + inv, platform="linux", service_identity=actor, worker_identity=actor,
            worker_id="linux-enrolled-field", worker_instance_id=instance,
            containment=WorkerContainmentEvidence("linux", pid, True, True, limits, True),
            process_binding=ProductionProcessBinding(socket.gethostname(), 1, int(start_ticks(1)), int(ticks),
                                                     f"boot-{boot}-cgroup-{group}"),
            restricted_identity=True, credential_protection=(CredentialProtectionEvidence(
                FADE_AUTHORITY_ID, "host-only-fill-authority", "sha256:" + self.service.policy_hash, True),),
            lifecycle_supervisor="systemd", lifecycle_instance_id=instance, lifecycle_healthy=True,
            egress_policy_id="isolated-unix-only", egress_policy_digest="sha256:" + self.service.policy_hash,
            egress_enforced=True, verified_at=now.isoformat(), expires_at=(now + timedelta(seconds=15)).isoformat())

    def verify_exit(self):
        require(self.exit_record is not None, "The browser shutdown evidence is missing")
        return self.exit_record

    def stop(self):
        subprocess.run(["/usr/bin/systemctl", "stop", self.service.unit], capture_output=True, timeout=10)

    def finish(self):
        try:
            self.service.confirm_exit()
            trace_hash = self._trace_ok()
            require(self.pidfds and len(select.select(self.pidfds, [], [], 0)[0]) == len(self.pidfds),
                    "A pinned browser process survived shutdown")
            self.receivers.require_silent()
            self.receivers.positive_control()
            self.exit_record = {"invocation": self.service.identity[0], "boot": self.service.identity[4],
                "cgroup_inode": self.service.identity[1], "cgroup_removed": not self.service.group.exists(),
                "exited_lifetimes": sorted(self.service.members), "exited_pidfds": len(self.pidfds),
                "trace_digest": trace_hash, "unit_policy_digest": "sha256:" + self.service.policy_hash,
                "controlled_receivers": sorted(self.receivers.sockets), "unexpected_deliveries": 0}
        except Exception as exc:
            self.failure_record = {"invocation": self.service.identity[0] if self.service.identity else None,
                                   "failure": type(exc).__name__, "shutdown_verified": False}
            raise
        finally:
            for fd in self.pidfds:
                os.close(fd)
            if self.trace is not None:
                self._write("tracing_on", "0")
                self.trace.rmdir()


@contextmanager
def browser_service():
    from playwright.sync_api import sync_playwright

    unit = "weir-enrolled-field-" + secrets.token_hex(8)
    with Receivers() as receivers:
        receivers.positive_control()
        witness = LifetimeWitness(unit, receivers)
        values = {"WEIR_REHEARSAL_UNIT": unit, "WEIR_REHEARSAL_PORT": str(receivers.port),
                  "WEIR_REHEARSAL_UNIX": receivers.unix_path,
                  "PLAYWRIGHT_NODEJS_PATH": str(Path(__file__).with_name("linux_canary_driver.py").resolve())}
        with _launch_lock:
            old = {key: os.environ.get(key) for key in values}
            os.environ.update(values)
            try:
                runtime = sync_playwright().start()
            finally:
                for key, val in old.items():
                    if val is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = val
        try:
            browser = runtime.chromium.launch(headless=True, chromium_sandbox=True)
            try:
                yield browser, witness
            finally:
                browser.close()
        finally:
            try:
                runtime.stop()
            finally:
                if witness.service.group is not None:
                    witness.finish()


@contextmanager
def field_peer(role):
    """Launch a distinct dynamic principal with only a private Unix socket."""
    from weir.browser.field_peers import peer_main
    with _launch_peer(role, peer_main) as peer:
        yield peer


@contextmanager
def _launch_peer(role, entrypoint):
    import inspect
    import pwd
    require(role in {"read", "fill"}, "Unknown field role")
    user = "weir-role-" + role
    unit = user + "-" + secrets.token_hex(8)
    with ExitStack() as stack:
        local, remote = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        stack.enter_context(local)
        stack.enter_context(remote)
        local.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        # Use the fixed stdlib peer implementation without mounting a host checkout.
        code = ("import os,json,socket\n" + inspect.getsource(entrypoint)
                + "\n" + entrypoint.__name__ + "(" + repr(role) + ")")
        argv = ["/usr/bin/systemd-run", "--pipe", "--wait", "--quiet", "--collect", "--unit=" + unit]
        for setting in ("DynamicUser=yes", "User=" + user, "PrivateNetwork=yes", "RestrictAddressFamilies=AF_UNIX",
                        "PrivatePIDs=yes", "PrivateTmp=yes", "PrivateIPC=yes", "PrivateDevices=yes",
                        "ProtectSystem=strict", "ProtectHome=yes", "NoNewPrivileges=yes", "CapabilityBoundingSet=",
                        "TemporaryFileSystem=/run:ro /srv:ro /var:ro", "RuntimeMaxSec=420", "Restart=no"):
            argv.append("--property=" + setting)
        proc = subprocess.Popen([*argv, "--", "/usr/bin/python3", "-I", "-c", code], stdin=remote,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
        remote.close()
        try:
            require(select.select([local], [], [], 8)[0], "Field role did not start")
            pid = int(subprocess.check_output(["systemctl", "show", unit, "-p", "MainPID", "--value"], timeout=3))
            uid = int(next(line.split()[1] for line in Path(f"/proc/{pid}/status").read_text().splitlines()
                           if line.startswith("Uid:")))
            require(uid == pwd.getpwnam(user).pw_uid and uid > 0
                    and any(line.endswith("/" + unit + ".service") for line in
                            Path(f"/proc/{pid}/cgroup").read_text().splitlines()), "Wrong field service principal")
            yield FieldPeer(local, pid, uid, role)
        finally:
            local.close()
            proc.wait(timeout=8)


def _reader_command(field):
    import weir

    source = Path(weir.__file__).resolve().parent
    code = ("import base64,json,os,socket,sys;sys.path.insert(0,'/opt/weir-source');"
            "from weir.browser.enrolled_document import EnrolledField,read_connected;"
            "f=EnrolledField(**json.loads(sys.argv[1]));"
            "s=socket.socket(fileno=os.dup(0));s.settimeout(5);d=read_connected(f,s);"
            "print(json.dumps([base64.b64encode(d.body).decode(),d.headers,d.peer_fingerprint]))")
    argv = ["/usr/bin/systemd-run", "--pipe", "--wait", "--collect", "--quiet",
            "--unit=weir-field-reader-" + secrets.token_hex(8)]
    for prop in ("DynamicUser=yes", "User=weir-field-read", "PrivateNetwork=yes", "RestrictAddressFamilies=AF_UNIX",
                 "NoNewPrivileges=yes", "PrivatePIDs=yes", "PrivateTmp=yes", "PrivateIPC=yes",
                 "PrivateDevices=yes", "ProtectSystem=strict", "ProtectHome=yes", "CapabilityBoundingSet=",
                 "SystemCallFilter=~io_uring_setup io_uring_enter io_uring_register", "SystemCallErrorNumber=EPERM",
                 "TemporaryFileSystem=/srv:ro /var:ro /run:ro /opt:ro", "RuntimeMaxSec=15", "Restart=no",
                 f"BindReadOnlyPaths={RUNTIME} {source}:/opt/weir-source/weir"):
        argv.append("--property=" + prop)
    return [*argv, "--", str(RUNTIME / "bin/python"), "-I", "-c", code, json.dumps(asdict(field))]


def read_in_service(field):
    """The reader gets only this TCP connection. The browser receives only verified bytes."""
    field.validate()
    cmd = _reader_command(field)
    with socket.create_connection((field.peer_address, urlsplit(field.url).port or 443), timeout=5) as upstream:
        process = subprocess.Popen(cmd, stdin=upstream, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   close_fds=True)
    try:
        output, _ = process.communicate(timeout=20)
        require(process.returncode == 0 and len(output) <= 32768, "The isolated HTTPS reader denied the source")
        body, headers, cert = json.loads(output)
        document = EnrolledDocument(base64.b64decode(body, validate=True), tuple(map(tuple, headers)), cert)
        document.verify(field)
        return document
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=3)


@contextmanager
def enrolled_host_controller(field):
    with field_peer("read") as observer, field_peer("fill") as effect:
        controller = LinuxFieldController(field, browser_service=browser_service, read_source=read_in_service,
                                         observer=observer, effect=effect)
        try:
            yield controller
        finally:
            controller.contain()


def commissioned_authority(store):
    """Only this factory selects production trust, host identity and rollback storage."""
    import platform
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from weir.browser.enrolled_fill import DecisionTrust, GRANT, LinuxFillAuthority, _directory, _read
    from weir.contract import is_sha256, validate_identifier

    require(os.geteuid() == 0 and platform.machine() == "x86_64", "Unsupported enrolled-field supervisor")
    fd = _directory(_CONFIG)
    try:
        config = _read(fd, "deployment.json")
    finally:
        os.close(fd)
    host = canonical_digest(Path("/etc/machine-id").read_text().strip())
    require(config["machine_digest"] == host and config["audience"] == "weir.production.first-fill"
            and config["grant"] == GRANT, "The protected trust record belongs to another host or grant")
    for key in ("issuer", "key_id", "device", "owner", "profile_id", "credential_binding_id"):
        validate_identifier(config[key], key)
    require(is_sha256(config["profile_digest"]), "Anonymous registry policy digest is missing")
    public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(config["public_key"], validate=True))
    trust = DecisionTrust(config["issuer"], config["key_id"], config["device"], config["owner"],
                          config["audience"], public_key)
    witness, ingress = _WITNESS, _INGRESS
    file = store.database.execute("PRAGMA database_list").fetchone()[2]
    filesystem = subprocess.check_output(["/usr/bin/findmnt", "-n", "-o", "FSTYPE", "--mountpoint", str(witness)],
                                         text=True, timeout=3).strip()
    require(file and filesystem in {"ext4", "xfs"} and witness.is_mount()
            and witness.stat().st_dev not in {Path(file).stat().st_dev, ingress.stat().st_dev},
            "The append-only grant requires its own durable filesystem outside ledger restoration")
    authority = LinuxFillAuthority(ingress, witness, trust, deployment=canonical_digest(config),
                                  profile=(config["profile_id"], config["profile_digest"], config["credential_binding_id"]))
    with authority.journal():
        pass
    return authority


@contextmanager
def prepare_host_fill(*, store, proposals, context, clients, backend):
    from weir.browser.field_service import prepare_enrolled_fill

    with ExitStack() as stack:
        yield prepare_enrolled_fill(store=store, proposals=proposals, context=context, clients=clients, backend=backend,
                                    authority=commissioned_authority(store),
                                    open_controller=lambda field: stack.enter_context(enrolled_host_controller(field)))


def main():
    """Host entry point for protected ingress and the loopback Fade action service."""
    import argparse
    from weir.broker import AcquisitionBroker
    from weir.browser.enrolled_fill import EnrolledField, _directory, _private_fd, _read
    from weir.browser.store import SQLiteSessionStore
    from weir.client import InProcessWeirClient
    from weir.contract import parse_timestamp
    from weir.models import DataClass
    from weir.persistence import CaptureStore
    from weir.proposals import ActionProposalStore
    from weir.remote_decision import RemoteDecisionCapsule
    from weir.service import (ACTION_EXECUTE_SCOPE, ACTION_STATUS_SCOPE, PROPOSAL_READ_FULL_SCOPE,
                              ClientCredential, ClientRegistry, WeirService)
    from weir.work_context import WorkContext

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("serve", "enroll", "withdraw", "approve", "revocations"))
    args = parser.parse_args()
    os.umask(0o077)
    state = _INGRESS.parent
    with ExitStack() as stack:
        state_fd = _directory(state)
        stack.callback(os.close, state_fd)
        # Commissioning creates the ledger and provisions it independently of the external witness.
        ledger_fd = _private_fd(state_fd, "sessions.sqlite3", os.O_RDONLY, limit=None)
        os.close(ledger_fd)
        store = stack.enter_context(SQLiteSessionStore(state / "sessions.sqlite3"))
        if args.operation != "serve":
            authority = commissioned_authority(store)
            inbox = _directory(_INGRESS)
            stack.callback(os.close, inbox)
            event = _read(inbox, args.operation + "-event.json")
            now = datetime.now(timezone.utc)
            if args.operation == "revocations":
                authority.record_revocations(event["field_digest"], parse_timestamp(event["checked_at"], "checked_at"),
                                             event["revoked"])
            else:
                decision = RemoteDecisionCapsule.from_dict(event["capsule"])
                proof = event["step_up_ref"]
                if args.operation == "enroll":
                    authority.accept_enrollment(EnrolledField(**event["field"]), decision, proof, now)
                elif args.operation == "approve":
                    authority.accept_approval(event["approval_ref"], decision, proof, now)
                else:
                    authority.withdraw(decision, proof, now)
            return
        config = _directory(_CONFIG)
        stack.callback(os.close, config)
        supervisor = _read(config, "service.json")
        context = WorkContext.from_dict(_read(state_fd, "work-context.json"))
        # The installer projects the GLAS-managed caller secret into systemd's credential directory.
        credential_dir = _directory(os.environ["CREDENTIALS_DIRECTORY"])
        stack.callback(os.close, credential_dir)
        with os.fdopen(_private_fd(credential_dir, "fade-weir-authority", os.O_RDONLY, limit=300), "rb") as stream:
            secret = stream.read(300).decode("ascii").strip()
        clients = ClientRegistry([ClientCredential(FADE_AUTHORITY_ID, secret, frozenset({
            ACTION_EXECUTE_SCOPE, ACTION_STATUS_SCOPE, PROPOSAL_READ_FULL_SCOPE}), frozenset({DataClass.PUBLIC}))])
        captures = CaptureStore(state / "captures")
        proposals = ActionProposalStore(state / "proposals", captures, store)
        backend = InProcessWeirClient(AcquisitionBroker(store=captures), captures, command_store=store,
                                      proposal_store=proposals)
        app, proposal = stack.enter_context(prepare_host_fill(store=store, proposals=proposals, context=context,
                                                              clients=clients, backend=backend))
        server = WeirService(app, port=supervisor["port"])
        stack.callback(server.close)
        print(json.dumps({"port": server.address[1], "proposal_hash": proposal.proposal_hash if proposal else None}),
              flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
