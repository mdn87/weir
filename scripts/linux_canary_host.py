"""Host-side witnesses for the isolated, fixed Linux fill rehearsal."""

import hashlib
import json
import os
import select
import socket
import subprocess
import time
from contextlib import ExitStack
from pathlib import Path
from tempfile import TemporaryDirectory

from linux_canary_driver import PROPERTIES, RUNTIME, UNIT_RE


def start_ticks(pid):
    return (Path("/proc") / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()[19]


class Receivers(ExitStack):
    """Keep all six receivers open and positively check them on both sides of the run."""

    def __init__(self):
        super().__init__()
        self.sockets = {}

    def __enter__(self):
        super().__enter__()
        try:
            directory = self.enter_context(TemporaryDirectory(dir="/tmp", prefix="weir-fill-rx-"))
            os.chmod(directory, 0o755)
            self.unix_path = str(Path(directory) / "receiver")
            self.port = 0
            for family, name, host in [(socket.AF_INET, "ipv4", "127.0.0.1"),
                                       (socket.AF_INET6, "ipv6", "::1")]:
                for kind, label in [(socket.SOCK_STREAM, "tcp"), (socket.SOCK_DGRAM, "udp")]:
                    sock = self.enter_context(socket.socket(family, kind))
                    if family == socket.AF_INET6:
                        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    sock.bind((host, self.port))
                    self.port = sock.getsockname()[1]
                    self._add(name + "_" + label, sock)
            for label, address in (("unix_path", self.unix_path),
                                   ("unix_abstract", "\0weir-fill-rx-" + str(self.port))):
                sock = self.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
                sock.bind(address)
                self._add(label, sock)
            os.chmod(self.unix_path, 0o666)
            return self
        except BaseException:
            self.close()
            raise

    def _add(self, name, sock):
        if sock.type == socket.SOCK_STREAM:
            sock.listen(16)
        sock.settimeout(2)
        self.sockets[name] = sock

    def positive_control(self):
        for receiver in self.sockets.values():
            with socket.socket(receiver.family, receiver.type) as sender:
                sender.settimeout(2)
                sender.connect(receiver.getsockname())
                sender.sendall(b"C")
            if receiver.type == socket.SOCK_DGRAM:
                value = receiver.recv(2)
            else:
                conn, _ = receiver.accept()
                with conn:
                    conn.settimeout(2)
                    value = conn.recv(2)
            if value != b"C":
                raise RuntimeError("Unexpected delivery at a host receiver")
        self.require_silent()

    def require_silent(self):
        if select.select(list(self.sockets.values()), [], [], 0)[0]:
            raise RuntimeError("A host receiver observed unexpected traffic")


class ServiceWitness:
    def __init__(self, unit):
        if not UNIT_RE.fullmatch(unit):
            raise ValueError("Unknown rehearsal service")
        self.unit = unit + ".service"
        self.identity = None
        self.members = set()
        self.group = None
        self.peak = 0
        self.renderers = set()
        self.browser = None
        self.policy_hash = None

    def check(self):
        output = subprocess.check_output(
            ["/usr/bin/systemctl", "show", "--all", self.unit], text=True, timeout=4)
        props = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
        required = ("DynamicUser", "User", "PrivateNetwork", "RestrictAddressFamilies", "PrivatePIDs",
                    "PrivateIPC", "PrivateTmp", "PrivateDevices", "ProtectHome", "ProtectSystem",
                    "ProtectControlGroups", "NoNewPrivileges", "CapabilityBoundingSet", "Restart",
                    "KillMode", "Delegate", "ProtectKernelTunables", "ProtectKernelModules")
        for key in required:
            expected = "weir-enrolled" if key == "User" and self.unit.startswith("weir-enrolled-field-") else PROPERTIES[key]
            if props.get(key) != expected:
                raise RuntimeError("Unexpected service property " + key)
        masks = {p.split(":")[0] for p in props["TemporaryFileSystem"].split()}
        binds = [p.split(":")[0] for p in props["BindReadOnlyPaths"].split()]
        calls = props["SystemCallFilter"].split()
        if (props["ActiveState"] != "active" or masks != {"/srv", "/run", "/var"}
                or binds != [str(RUNTIME)] or props["BindPaths"] or not calls
                or not calls[0].startswith("~")
                or not {"io_uring_setup", "io_uring_enter", "io_uring_register"}.issubset(
                    {item.lstrip("~").split(":")[0] for item in calls})):
            raise RuntimeError("The sealed runtime, syscall filter or mounts have changed")
        group = Path("/sys/fs/cgroup") / props["ControlGroup"].lstrip("/")
        pid = int(props["MainPID"])
        if (group.name != self.unit or (group / "memory.max").read_text().strip() != "536870912"
                or (group / "pids.max").read_text().strip() != "128"):
            raise RuntimeError("Unexpected cgroup or resource limits")
        keys = (*required, "SystemCallFilter", "SystemCallErrorNumber", "SystemCallArchitectures",
                "TemporaryFileSystem", "BindReadOnlyPaths", "BindPaths", "MemoryMax", "TasksMax")
        digest = hashlib.sha256(json.dumps({k: props[k] for k in keys}, sort_keys=True).encode()).hexdigest()
        if self.policy_hash not in (None, digest):
            raise RuntimeError("The effective service policy changed during observation")
        self.policy_hash = digest
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        identity = (props["InvocationID"], group.stat().st_ino, pid, start_ticks(pid), boot_id)
        if not identity[0] or self.identity not in (None, identity):
            raise RuntimeError("The service invocation changed")
        self.identity, self.group = identity, group
        proc = Path("/proc")
        isolated_net = (proc / str(pid) / "ns/net").stat().st_ino
        if isolated_net == (proc / "self/ns/net").stat().st_ino:
            raise RuntimeError("The service shares the host network namespace")
        driver_ns = (proc / str(pid) / "ns/pid").stat().st_ino
        status = dict(line.split(":", 1) for line in (proc / str(pid) / "status").read_text().splitlines())
        uids = {int(v) for v in status["Uid"].split()}
        driver_exe = (proc / str(pid) / "exe").resolve(strict=True)
        if (driver_ns == (proc / "self/ns/pid").stat().st_ino or len(uids) != 1 or 0 in uids
                or os.geteuid() in uids or not driver_exe.is_relative_to(RUNTIME)
                or driver_exe.name != "node" or status["NoNewPrivs"].strip() != "1"
                or status["Seccomp"].strip() != "2" or int(status["CapEff"], 16) != 0):
            raise RuntimeError("The service lacks a private PID namespace or principal")
        browsers = set()
        renderers = set()
        roles = set()
        count = 0
        for member in (group / "cgroup.procs").read_text().split():
            base = proc / member
            try:
                ticks = start_ticks(member)
                # Chromium rewrites some child argv vectors into a space-separated
                # process title. The executable still comes from the kernel.
                cmd = (base / "cmdline").read_bytes().replace(b"\0", b" ").split()
                executable = (base / "exe").resolve(strict=True)
                flags = (base / "status").read_text().splitlines()
                child_ns = (base / "ns/pid").stat().st_ino
            except FileNotFoundError:
                continue
            count += 1
            is_chromium = executable.is_relative_to(RUNTIME / "browsers")
            if self.unit.startswith("weir-enrolled-field-") and not (
                    (int(member) == pid and executable == driver_exe)
                    or (is_chromium and executable.name == "chrome-headless-shell")):
                raise RuntimeError("An unqualified executable entered the enrolled browser service")
            roles.add((executable.name, tuple(os.fsdecode(a) for a in cmd if a.startswith(b"--type="))))
            self.members.add((member, ticks))
            if any(arg in cmd for arg in (b"--no-sandbox", b"--disable-setuid-sandbox",
                                          b"--disable-seccomp-filter-sandbox", b"--single-process",
                                          b"--no-zygote-sandbox-and-run-in-process")):
                raise RuntimeError("A browser process disabled its sandbox")
            if is_chromium and b"--type=renderer" in cmd:
                if child_ns == driver_ns or not any(line.split() == ["Seccomp:", "2"] for line in flags):
                    raise RuntimeError("Chromium renderer sandbox evidence is missing")
                renderers.add((member, ticks))
            elif is_chromium and b"--remote-debugging-pipe" in cmd and not any(a.startswith(b"--type=") for a in cmd):
                browsers.add((member, ticks))
        if len(browsers) != 1 or not renderers:
            raise RuntimeError(f"Missing Chromium browser or renderer in the service cgroup: {roles!r}")
        browser, = browsers
        if self.browser not in (None, browser) or (self.renderers and self.renderers != renderers):
            raise RuntimeError("The pinned Chromium process was replaced")
        self.browser = browser
        self.renderers = renderers
        self.peak = max(count, self.peak)

    def confirm_exit(self):
        if self.group is None:
            raise RuntimeError("No observed browser service to check for exit")
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            remaining = []
            for pid, ticks in self.members:
                try:
                    if start_ticks(pid) == ticks:
                        remaining.append(pid)
                except FileNotFoundError:
                    pass
            if not remaining and not self.group.exists():
                return
            time.sleep(0.05)
        raise RuntimeError("Service cgroup or an observed browser descendant survived shutdown")
