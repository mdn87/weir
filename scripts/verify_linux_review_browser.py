"""Run on the report host as its normal bridge user. Does not use an account."""

import json
import os
import socket
import subprocess
import time
import uuid
from pathlib import Path

from weir.browser.linux_report import (
    SOCKET_PATH, _admit, _credentials, inspect_worker, read_in_browser, receive_message, send_message,
)
from weir.review_board import source_url


def record_processes(group):
    return {pid: Path("/proc", pid, "stat").read_text().rsplit(")", 1)[1].split()[19]
            for pid in (group / "cgroup.procs").read_text().splitlines() if Path("/proc", pid).exists()}


def wait_for_cleanup(group, members):
    for _ in range(150):
        live = []
        for pid, start in members.items():
            try:
                if Path("/proc", pid, "stat").read_text().rsplit(")", 1)[1].split()[19] == start:
                    live.append(pid)
            except FileNotFoundError:
                pass
        if not live and not group.exists():
            return
        time.sleep(0.1)
    raise RuntimeError("Browser processes or cgroup survived after the request ended.")


def interrupt_read(*, stop_service):
    # Interrupt only the instance created by this connection, after Chromium has started.
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(45)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        client.connect(SOCKET_PATH)
        pid, uid = _credentials(client)
        current, group = inspect_worker(pid, uid)
        send_message(client, {"url": source_url()})
        with client.makefile("rb") as reader:
            if receive_message(reader) != {"read": source_url()}:
                raise RuntimeError("No document request from the browser.")
            _admit(pid, uid, current, browser_started=True)
            members = record_processes(group)
            peak_bytes = int((group / "memory.peak").read_text())
            tasks = int((group / "pids.current").read_text())
            if stop_service:
                def host_read(*args):
                    return subprocess.check_output(["sudo", "-n", *args], text=True).strip()
                if host_read("readlink", f"/proc/{pid}/ns/net") == host_read("readlink", "/proc/1/ns/net"):
                    raise RuntimeError("The service shares the host network namespace.")
                for directory in ("/srv/lugos/state/weir-operator-reports", "/home/matt", "/run/dbus/system_bus_socket"):
                    if subprocess.run(["sudo", "-n", "test", "-e", f"/proc/{pid}/root{directory}"]).returncode != 1:
                        raise RuntimeError("The sandbox exposes host data or its service bus.")
                subprocess.run(["sudo", "-n", "systemctl", "stop", "--", group.name], check=True)
    wait_for_cleanup(group, members)
    return len(members), peak_bytes, tasks


def main():
    title = "Review " + uuid.uuid4().hex
    source = f'<main data-weir-review-board="1" data-workspace-id="4" data-total="1"><li data-task-id="5"><span data-task-title>{title}</span></li></main>'
    view, original, observed, proof = read_in_browser(source_url(), lambda: source)
    if view != {"workspace": 4, "total": 1, "tasks": [{"id": 5, "title": title}]} or original != source:
        raise RuntimeError("The isolated browser read did not match the challenge.")
    disconnected, peak_bytes, tasks = interrupt_read(stop_service=False)
    stopped, _, _ = interrupt_read(stop_service=True)
    try:
        inspect_worker(os.getpid(), os.geteuid())
    except OSError:
        pass
    else:
        raise RuntimeError("An ordinary process was accepted as the report service.")
    print(json.dumps({"observed_at": observed, "field_read": True, "platform": proof.platform,
                      "run_id": proof.attestation_id, "limits": proof.containment.resource_limits.to_dict(),
                      "peak_bytes": peak_bytes, "observed_threads": tasks, "processes_reaped_on_disconnect": disconnected,
                      "processes_reaped_on_stop": stopped, "separate_network_namespace": True, "host_state_hidden": True,
                      "ordinary_process_denied": True, "disconnected_cgroup_removed": True,
                      "egress_policy": proof.egress_policy_id}, indent=2))


if __name__ == "__main__":
    main()
