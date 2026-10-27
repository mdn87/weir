"""SCM entry point for the explicitly installed, deny-only Windows admission probe."""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes as w
from datetime import datetime, timezone
import functools
import json
import os
from pathlib import Path
import threading
import time

from weir.browser.admission import ProductionAdmission, WorkerResourceLimits
from weir.browser.process_worker import ProcessBrowserWorker
from weir.browser.windows_host import (
    WindowsDeployment, WindowsHostInspector, read_host_snapshot,
    validate_host_snapshot, validate_worker_isolation,
)
from weir.browser.windows_process import inspect_process
from weir.browser.windows_sandbox import appcontainer_sid, ensure_appcontainer_profile
from weir.engines.base import EnginePolicyBlocked
from weir.windows_probe import AdmissionProbeWorker, delivered_packets, positive_control_listeners


def load_deployment(path: Path) -> WindowsDeployment:
    if path.stat().st_size > 65536:
        raise ValueError("deployment configuration is too large")
    config = WindowsDeployment.from_dict(json.loads(path.read_text(encoding="utf-8-sig")))
    if path.absolute() != Path(config.root) / "deployment.json":
        raise ValueError("configuration must be in its protected deployment root")
    if config.appcontainer_sid != appcontainer_sid(config.appcontainer_name):
        raise ValueError("AppContainer identity does not match its configured name")
    return config


def _write_status(config: WindowsDeployment, payload: dict) -> None:
    payload = {"schema_version": 1, "service": config.service_name,
               "heartbeat_at": datetime.now(timezone.utc).isoformat(),
               "supervisor_pid": os.getpid(), "action_endpoint_enabled": False, **payload}
    path = Path(config.root) / "status" / "health.json"
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _failure_detail(exc: BaseException) -> str:
    if isinstance(exc, EnginePolicyBlocked):
        return str(exc)
    if isinstance(exc, OSError):
        return f"{type(exc).__name__}: winerror={getattr(exc, 'winerror', None)}, errno={exc.errno}"
    return type(exc).__name__


def run_supervisor(config: WindowsDeployment, stop: threading.Event) -> None:
    # Preflight runs before the process transport, worker imports, or factory starts.
    _write_status(config, {"state": "preflight", "worker_operations": 0})
    facts = read_host_snapshot(config)
    validate_host_snapshot(config, facts, supervisor_pid=os.getpid(), worker_pid=None)
    ensure_appcontainer_profile(config.appcontainer_name)

    def pre_start(process_id, limits, containment):
        token = inspect_process(process_id)
        validate_worker_isolation(config, token)
        if token["created"] < inspect_process(os.getpid())["created"]:
            raise EnginePolicyBlocked("worker process generation is invalid")
        return containment

    operations = 0
    with positive_control_listeners() as (ports, listeners):
        factory = functools.partial(AdmissionProbeWorker, os.getpid(), [item["path"] for item in config.credentials], ports)
        with ProcessBrowserWorker(factory, resource_limits=WorkerResourceLimits(config.memory_bytes, config.process_count),
                                  containment_verifier=pre_start, windows_appcontainer_sid=config.appcontainer_sid,
                                  start_timeout_seconds=20) as worker:
            inspector = WindowsHostInspector(config, worker)
            last = None

            def live_evidence():
                nonlocal last
                last = inspector()
                return last

            gate = ProductionAdmission(live_evidence, expected_platform="windows")
            while not stop.is_set():
                try:
                    gate.require_browser_worker(worker, caller_id="lugos-mcp")
                    result = worker.probe()
                    operations += 1
                    count = delivered_packets(listeners)
                    if not result.available or count != 0:
                        raise EnginePolicyBlocked("worker isolation probe failed")
                    _write_status(config, {"state": "admitted", "worker_operations": operations,
                                          "evidence": last.to_dict(), "isolation_probe": json.loads(result.detail),
                                          "job_object_name": worker.production_job_name,
                                          "delivered_packets": count, "positive_controls": 4})
                except (EnginePolicyBlocked, OSError, ValueError) as exc:
                    _write_status(config, {"state": "denied", "reason_code": "host_controls_denied",
                                          "detail": _failure_detail(exc),
                                          "worker_pid": worker.process_id, "worker_operations": operations})
                if not worker.is_alive:
                    raise RuntimeError("admission worker exited")
                stop.wait(5)
    _write_status(config, {"state": "stopped", "worker_operations": operations})


def serve(config: WindowsDeployment) -> int:
    if os.name != "nt":
        raise OSError("SCM service requires Windows")
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    stop = threading.Event()
    exit_code = 0
    status_handle = None

    class ServiceStatus(ctypes.Structure):
        _fields_ = [(name, w.DWORD) for name in ("type", "state", "accepted", "win32_exit", "service_exit", "checkpoint", "wait_hint")]

    handler_type = ctypes.WINFUNCTYPE(w.DWORD, w.DWORD, w.DWORD, ctypes.c_void_p, ctypes.c_void_p)
    main_type = ctypes.WINFUNCTYPE(None, w.DWORD, ctypes.POINTER(w.LPWSTR))

    class ServiceEntry(ctypes.Structure):
        _fields_ = [("name", w.LPWSTR), ("main", main_type)]

    register = advapi.RegisterServiceCtrlHandlerExW
    register.argtypes, register.restype = [w.LPCWSTR, handler_type, ctypes.c_void_p], w.HANDLE
    set_status = advapi.SetServiceStatus
    set_status.argtypes, set_status.restype = [w.HANDLE, ctypes.POINTER(ServiceStatus)], w.BOOL
    dispatch = advapi.StartServiceCtrlDispatcherW
    dispatch.argtypes, dispatch.restype = [ctypes.POINTER(ServiceEntry)], w.BOOL

    def report(state, error=0):
        status = ServiceStatus(0x10, state, 0x5 if state == 4 else 0, error, 0, 1 if state in (2, 3) else 0, 60000 if state in (2, 3) else 0)
        if not set_status(status_handle, ctypes.byref(status)):
            stop.set()

    @handler_type
    def handler(control, _event, _data, _context):
        if control in (1, 5):
            report(3)
            stop.set()
        elif control == 4:
            report(3 if stop.is_set() else 4)
        return 0

    @main_type
    def service_main(_argc, _argv):
        nonlocal status_handle, exit_code
        status_handle = register(config.service_name, handler, None)
        if not status_handle:
            exit_code = 1
            return
        report(2)
        report(4)
        try:
            run_supervisor(config, stop)
        except BaseException as exc:
            exit_code = 1
            try:
                _write_status(config, {"state": "failed", "reason_code": "supervisor_failed",
                                      "detail": _failure_detail(exc)})
            except OSError:
                pass
        finally:
            report(1, exit_code)

    entries = (ServiceEntry * 2)(ServiceEntry(config.service_name, service_main), ServiceEntry(None, main_type()))
    if not dispatch(entries):
        raise ctypes.WinError(ctypes.get_last_error())
    return exit_code


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    return serve(load_deployment(args.config))


if __name__ == "__main__":
    raise SystemExit(main())
