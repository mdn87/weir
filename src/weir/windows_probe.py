"""Deny-only worker used to verify host isolation; exposes no browser actions."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import functools
import os
from pathlib import Path
import socket
import subprocess
import sys
from uuid import uuid4

from weir.browser.protocol import WorkerDescriptor
from weir.engines.base import EngineProbe


def _supervisor_access_denied(supervisor_pid: int) -> bool:
    # _winapi uses kernel APIs without ctypes' GUI-related DLL initialization.
    # The service's Session 0 AppContainer intentionally has no interactive desktop.
    import _winapi
    denied = True
    # Test write, VM operation, thread creation and handle duplication separately:
    # denial of a combined request establishes only that at least one bit failed.
    for access in (0x20, 0x8, 0x2, 0x40):
        try:
            handle = _winapi.OpenProcess(access, False, supervisor_pid)
        except OSError as exc:
            denied = denied and exc.winerror == 5
        else:
            _winapi.CloseHandle(handle)
            denied = False
    return denied


def isolation_probe(supervisor_pid: int, credential_paths: list[str], ports: dict[str, int]) -> dict:
    denied = _supervisor_access_denied(supervisor_pid)
    result = {"supervisor_access_denied": denied, "credential_access_denied": bool(credential_paths),
              "network_attempts_complete": True, "socket_errors": {}}
    for path in credential_paths:
        try:
            with Path(path).open("rb") as source:
                source.read(1)
            result["credential_access_denied"] = False
        except PermissionError:
            pass
        except OSError:
            result["credential_access_denied"] = False
    for label, family, address in (("ipv4", socket.AF_INET, "127.0.0.1"), ("ipv6", socket.AF_INET6, "::1")):
        for protocol, kind in (("tcp", socket.SOCK_STREAM), ("udp", socket.SOCK_DGRAM)):
            port = ports[f"{protocol}_{label}"]
            with socket.socket(family, kind) as connection:
                connection.settimeout(2)
                try:
                    if kind == socket.SOCK_STREAM:
                        connection.connect((address, port))
                    else:
                        connection.sendto(b"weir-denial-probe", (address, port))
                    # UDP send success can mean the firewall silently dropped it.
                    # Only the supervisor's listener readback establishes delivery.
                    if kind == socket.SOCK_STREAM:
                        result["network_attempts_complete"] = False
                except OSError as exc:
                    if not isinstance(exc, TimeoutError) and exc.winerror != 10013:
                        result["network_attempts_complete"] = False
                    result["socket_errors"][f"{protocol}_{label}"] = {"winerror": exc.winerror, "errno": exc.errno}
    return result


class AdmissionProbeWorker:
    def __init__(self, supervisor_pid: int, credential_paths: list[str], ports: dict[str, int]):
        self.descriptor = WorkerDescriptor("weir-admission-probe", "admission-probe", frozenset(), "1", "probe-" + uuid4().hex)
        self.supervisor_pid, self.credential_paths, self.ports = supervisor_pid, credential_paths, ports
        self._sentinel = None

    def probe(self) -> EngineProbe:
        if self._sentinel is None or self._sentinel.poll() is not None:
            self._sentinel = subprocess.Popen([sys.executable, "-I", "-B", "-c", "import time; time.sleep(86400)"],
                                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                              stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
        own = isolation_probe(self.supervisor_pid, self.credential_paths, self.ports)
        args = [sys.executable, "-I", "-B", "-m", "weir.windows_probe", "--supervisor", str(self.supervisor_pid), "--ports", json.dumps(self.ports)]
        for path in self.credential_paths:
            args.extend(["--credential", path])
        try:
            child = subprocess.run(args, capture_output=True, text=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW, check=True)
            descendant = json.loads(child.stdout)
            success = all(value is True for key, value in own.items() if key != "socket_errors") and all(value is True for key, value in descendant.items() if key != "socket_errors") and descendant.keys() == own.keys()
        except (OSError, ValueError, subprocess.SubprocessError):
            descendant, success = {"probe_failed": True}, False
        return EngineProbe("admission-probe", success, "1", json.dumps({"worker": own, "descendant": descendant, "sentinel_pid": self._sentinel.pid}, sort_keys=True))

    def shutdown(self) -> None:
        if self._sentinel is not None and self._sentinel.poll() is None:
            self._sentinel.terminate()
            self._sentinel.wait(timeout=5)


@contextmanager
def positive_control_listeners():
    """Scoped loopback listeners prove the same targets work outside isolation."""
    listeners, ports = _bind_controls()
    try:
        yield ports, listeners
    finally:
        for listener in listeners:
            listener.close()


def _bind_controls():
    listeners = []
    try:
        ports = {}
        for label, family, address in (("ipv4", socket.AF_INET, "127.0.0.1"), ("ipv6", socket.AF_INET6, "::1")):
            tcp = socket.socket(family, socket.SOCK_STREAM)
            listeners.append(tcp)
            if family == socket.AF_INET6:
                tcp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            tcp.bind((address, 0))
            tcp.listen(4)
            tcp.settimeout(2)
            tcp_port = tcp.getsockname()[1]
            ports[f"tcp_{label}"] = tcp_port
            with socket.socket(family, socket.SOCK_STREAM) as check:
                check.settimeout(2)
                check.connect((address, tcp_port))
                accepted, _ = tcp.accept()
                accepted.close()
            udp = socket.socket(family, socket.SOCK_DGRAM)
            listeners.append(udp)
            if family == socket.AF_INET6:
                udp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            udp.bind((address, 0))
            udp.settimeout(2)
            udp_port = udp.getsockname()[1]
            ports[f"udp_{label}"] = udp_port
            with socket.socket(family, socket.SOCK_DGRAM) as check:
                check.sendto(b"positive-control", (address, udp_port))
                if udp.recvfrom(128)[0] != b"positive-control":
                    raise OSError("positive UDP control failed")
        return listeners, ports
    except BaseException:
        for listener in listeners:
            listener.close()
        raise


def delivered_packets(listeners: list[socket.socket]) -> int:
    """Read actual endpoint effects after both worker and descendant finish."""
    delivered = 0
    for listener in listeners:
        listener.setblocking(False)
        while True:
            try:
                if listener.type == socket.SOCK_STREAM:
                    accepted, _ = listener.accept()
                    accepted.close()
                else:
                    listener.recvfrom(128)
                delivered += 1
            except BlockingIOError:
                break
    return delivered


def smoke(credential: str) -> int:
    from weir.browser.admission import WorkerResourceLimits
    from weir.browser.process_worker import ProcessBrowserWorker
    from weir.browser.windows_process import inspect_named_job, inspect_process
    from weir.browser.windows_sandbox import appcontainer_sid

    sid = appcontainer_sid("Lugos.WeirAdmission")

    def verifier(pid, limits, containment):
        token = inspect_process(pid)
        if token["appcontainer_sid"] != sid or token["capabilities"] or token["integrity"] != "S-1-16-4096":
            raise RuntimeError("worker was not isolated before its factory")
        return containment

    with positive_control_listeners() as (port, listeners):
        with ProcessBrowserWorker(functools.partial(AdmissionProbeWorker, os.getpid(), [credential], port),
                                  resource_limits=WorkerResourceLimits(536870912, 8), containment_verifier=verifier,
                                  windows_appcontainer_sid=sid, start_timeout_seconds=10) as worker:
            result = worker.probe()
            count = delivered_packets(listeners)
            checks = json.loads(result.detail)
            job = inspect_named_job(worker.production_job_name, worker.process_id)
            sentinel = inspect_process(checks["sentinel_pid"])
            passed = result.available and count == 0 and job["member"] and inspect_named_job(worker.production_job_name, sentinel["pid"])["member"]
            report = {"passed": passed, "delivered_packets": count, "positive_controls": 4, "checks": checks,
                      "containment": worker.refresh_containment_evidence().to_dict(), "job": job,
                      "binding": worker.production_binding.to_dict()}
        try:
            descendant_dead = inspect_process(sentinel["pid"])["created"] != sentinel["created"]
        except OSError:
            descendant_dead = True
        report["descendant_cleanup"] = descendant_dead
        report["passed"] = passed and descendant_dead
        print(json.dumps(report, sort_keys=True))
        return 0 if report["passed"] else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--supervisor", type=int)
    parser.add_argument("--ports", type=json.loads)
    parser.add_argument("--credential", action="append", default=[])
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    if args.smoke:
        if len(args.credential) != 1:
            parser.error("smoke requires one existing credential canary file")
        return smoke(args.credential[0])
    if args.supervisor is None or args.ports is None:
        parser.error("supervisor and ports are required")
    print(json.dumps(isolation_probe(args.supervisor, args.credential, args.ports), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
