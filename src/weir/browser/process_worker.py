from __future__ import annotations

import base64
import binascii
import json
import math
import multiprocessing
import os
import signal
import threading
import time
import weakref
from contextlib import AbstractContextManager
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from multiprocessing.connection import Connection, wait
from typing import Any, Callable

from weir.browser.models import ObservedElement
from weir.browser.protocol import (
    BrowserWorker,
    SessionSpec,
    WorkerCapability,
    WorkerCommand,
    WorkerDescriptor,
    WorkerObservation,
    canonical_digest,
)
from weir.contract import parse_timestamp, validate_identifier
from weir.engines.base import EngineProbe, FailureClass, WeirEngineError
from weir.models import DataClass

WorkerFactory = Callable[[], BrowserWorker]
DEFAULT_MAX_WORKER_REQUEST_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_WORKER_RESPONSE_BYTES = 24 * 1024 * 1024


def _is_valid_timeout(value: Any) -> bool:
    if not isinstance(value, (int, float)) or isinstance(value, bool) or value <= 0:
        return False
    try:
        return math.isfinite(value) and value <= threading.TIMEOUT_MAX
    except OverflowError:
        return False


class WorkerProcessError(WeirEngineError):
    pass


class WorkerProcessStartupError(WorkerProcessError):
    default_failure_class = FailureClass.ENGINE_UNAVAILABLE


class WorkerProcessLost(WorkerProcessError):
    default_failure_class = FailureClass.SESSION_LOST


class WorkerProcessTimeout(WorkerProcessLost):
    pass


class WorkerProcessProtocolError(WorkerProcessLost):
    pass


class WorkerRemoteError(WorkerProcessError):
    pass


class WorkerProcessRequestError(WorkerProcessError):
    default_failure_class = FailureClass.POLICY_BLOCKED


class _ConnectionIoTimeout(TimeoutError):
    pass


@dataclass(frozen=True, slots=True)
class WorkerDeathAttestation:
    worker_id: str
    worker_instance_id: str
    process_id: int
    exit_code: int | None
    reason: str
    observed_at: str
    worker_exited_gracefully: bool
    process_tree_confirmed_dead: bool
    attestation_hash: str = ""

    @classmethod
    def create(
        cls,
        *,
        worker_id: str,
        worker_instance_id: str,
        process_id: int,
        exit_code: int | None,
        reason: str,
        worker_exited_gracefully: bool,
        process_tree_confirmed_dead: bool,
    ) -> WorkerDeathAttestation:
        attestation = cls(
            worker_id=worker_id,
            worker_instance_id=worker_instance_id,
            process_id=process_id,
            exit_code=exit_code,
            reason=reason,
            observed_at=datetime.now(timezone.utc).isoformat(),
            worker_exited_gracefully=worker_exited_gracefully,
            process_tree_confirmed_dead=process_tree_confirmed_dead,
        )
        attestation = replace(
            attestation, attestation_hash=canonical_digest(attestation._hash_basis())
        )
        attestation.validate()
        return attestation

    def _hash_basis(self) -> dict[str, Any]:
        return {
            "worker_id": self.worker_id,
            "worker_instance_id": self.worker_instance_id,
            "process_id": self.process_id,
            "exit_code": self.exit_code,
            "reason": self.reason,
            "observed_at": self.observed_at,
            "worker_exited_gracefully": self.worker_exited_gracefully,
            "process_tree_confirmed_dead": self.process_tree_confirmed_dead,
        }

    def validate(self) -> None:
        validate_identifier(self.worker_id, "worker_id")
        validate_identifier(self.worker_instance_id, "worker_instance_id")
        validate_identifier(self.reason, "reason", max_length=64)
        if type(self.process_id) is not int or self.process_id < 1:
            raise ValueError("worker death process_id must be a positive integer")
        if self.exit_code is not None and type(self.exit_code) is not int:
            raise ValueError("worker death exit_code must be an integer or null")
        if (
            type(self.worker_exited_gracefully) is not bool
            or type(self.process_tree_confirmed_dead) is not bool
        ):
            raise ValueError("worker death flags must be booleans")
        parse_timestamp(self.observed_at, "observed_at")
        if self.attestation_hash != canonical_digest(self._hash_basis()):
            raise ValueError("worker death attestation hash is invalid")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {**self._hash_basis(), "attestation_hash": self.attestation_hash}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> WorkerDeathAttestation:
        required = {
            "worker_id",
            "worker_instance_id",
            "process_id",
            "exit_code",
            "reason",
            "observed_at",
            "worker_exited_gracefully",
            "process_tree_confirmed_dead",
            "attestation_hash",
        }
        if not isinstance(value, dict) or set(value) != required:
            raise ValueError(
                "WorkerDeathAttestation has missing or unknown fields"
            )
        attestation = cls(**value)
        attestation.validate()
        return attestation


class ProcessBrowserWorker(AbstractContextManager["ProcessBrowserWorker"]):
    """Run one stateful BrowserWorker in a deadline-killable process tree."""

    def __init__(
        self,
        factory: WorkerFactory,
        *,
        start_timeout_seconds: float = 15.0,
        call_timeout_seconds: float = 30.0,
        shutdown_timeout_seconds: float = 5.0,
        start_method: str = "spawn",
        max_request_bytes: int = DEFAULT_MAX_WORKER_REQUEST_BYTES,
        max_response_bytes: int = DEFAULT_MAX_WORKER_RESPONSE_BYTES,
    ) -> None:
        for name, value in (
            ("start_timeout_seconds", start_timeout_seconds),
            ("call_timeout_seconds", call_timeout_seconds),
            ("shutdown_timeout_seconds", shutdown_timeout_seconds),
        ):
            if not _is_valid_timeout(value):
                raise ValueError(
                    f"{name} must be positive, finite, and within the platform timeout limit"
                )
        if not callable(factory):
            raise TypeError("worker factory must be callable")
        for name, value in (
            ("max_request_bytes", max_request_bytes),
            ("max_response_bytes", max_response_bytes),
        ):
            if type(value) is not int or value < 1024:
                raise ValueError(f"{name} must be an integer of at least 1024")
        try:
            context = multiprocessing.get_context(start_method)
        except ValueError as exc:
            raise ValueError(f"unsupported multiprocessing start method {start_method!r}") from exc

        self._start_timeout = float(start_timeout_seconds)
        self._call_timeout = float(call_timeout_seconds)
        self._shutdown_timeout = float(shutdown_timeout_seconds)
        self._max_request_bytes = max_request_bytes
        self._max_response_bytes = max_response_bytes
        self._lock = threading.RLock()
        self._request_id = 0
        self._closed = False
        self._death_attestation: WorkerDeathAttestation | None = None
        self._descriptor: WorkerDescriptor | None = None
        self._tree: _ProcessTree | None = None
        self._watchdog_sender: Connection | None = None
        self._exit_observed = threading.Event()
        self._exit_monitor: threading.Thread | None = None
        self._abandon_finalizer: weakref.finalize | None = None

        parent_connection, child_connection = context.Pipe(duplex=True)
        watchdog_receiver: Connection | None = None
        if os.name != "nt":
            watchdog_receiver, self._watchdog_sender = context.Pipe(duplex=False)
        self._connection = parent_connection
        self._process = context.Process(
            target=_worker_process_main,
            args=(
                child_connection,
                factory,
                watchdog_receiver,
                self._watchdog_sender,
                max_request_bytes,
                max_response_bytes,
            ),
            name="weir-browser-worker",
            daemon=True,
        )
        try:
            self._process.start()
        except Exception:
            parent_connection.close()
            child_connection.close()
            if watchdog_receiver is not None:
                watchdog_receiver.close()
            self._close_watchdog()
            raise WorkerProcessStartupError(
                "WEIR could not start the browser worker process"
            ) from None
        child_connection.close()
        if watchdog_receiver is not None:
            watchdog_receiver.close()
        self._process_id = self._process.pid
        if self._process_id is None:
            self._terminate_uninitialized()
            raise WorkerProcessStartupError("browser worker process has no process ID")

        try:
            bootstrap = self._receive_startup("bootstrap")
            if bootstrap.get("process_id") != self._process_id:
                raise WorkerProcessStartupError(
                    "browser worker bootstrap process identity is invalid"
                )
            watchdog_process_id = bootstrap.get("watchdog_process_id")
            if os.name != "nt" and (
                type(watchdog_process_id) is not int or watchdog_process_id < 1
            ):
                raise WorkerProcessStartupError("browser worker watchdog identity is invalid")
            self._tree = _create_process_tree(
                self._process_id,
                watchdog_process_id=watchdog_process_id,
            )
            self._send_message({"kind": "start"}, timeout=self._start_timeout)
            ready = self._receive_startup("ready")
            descriptor = _descriptor_from_wire(ready.get("descriptor"))
            _validate_descriptor(descriptor)
            self._descriptor = descriptor
            self._process_sentinel = self._process.sentinel
            self._abandon_finalizer = weakref.finalize(
                self,
                _abandon_worker_process,
                self._process,
                self._connection,
                self._tree,
                self._watchdog_sender,
                self._shutdown_timeout,
            )
            self._exit_monitor = threading.Thread(
                target=_monitor_worker_exit,
                args=(
                    weakref.ref(self),
                    self._process_sentinel,
                    self._exit_observed,
                ),
                name=f"weir-worker-exit-{self._process_id}",
                daemon=True,
            )
            self._exit_monitor.start()
        except Exception:
            self._finish_process("startup_failed", graceful=False)
            raise

    @property
    def descriptor(self) -> WorkerDescriptor:
        if self._descriptor is None:
            raise WorkerProcessStartupError("browser worker did not publish a descriptor")
        return self._descriptor

    @property
    def process_id(self) -> int:
        return self._process_id

    @property
    def is_alive(self) -> bool:
        return not self._closed and self._process.is_alive()

    @property
    def death_attestation(self) -> WorkerDeathAttestation | None:
        return self._death_attestation

    def probe(self) -> EngineProbe:
        result = self._rpc("probe", timeout=self._call_timeout)
        return self._expect(result, EngineProbe, "probe")

    def open_session(self, spec: SessionSpec, command: WorkerCommand) -> str:
        result = self._command_rpc("open_session", command, spec, command)
        if not isinstance(result, str) or not result:
            self._fail_protocol("open_session returned an invalid context identifier")
        return result

    def attach_session(self, spec: SessionSpec, command: WorkerCommand) -> bool:
        result = self._command_rpc("attach_session", command, spec, command)
        if type(result) is not bool:
            self._fail_protocol("attach_session returned a non-boolean result")
        return result

    def navigate(self, session_id: str, url: str, command: WorkerCommand) -> str:
        result = self._command_rpc("navigate", command, session_id, url, command)
        if not isinstance(result, str) or not result:
            self._fail_protocol("navigate returned an invalid URL")
        return result

    def observe(
        self,
        session_id: str,
        command: WorkerCommand,
        *,
        include_screenshot: bool = False,
    ) -> WorkerObservation:
        result = self._command_rpc(
            "observe",
            command,
            session_id,
            command,
            include_screenshot=include_screenshot,
        )
        return self._expect(result, WorkerObservation, "observe")

    def screenshot(self, session_id: str, command: WorkerCommand) -> bytes:
        result = self._command_rpc("screenshot", command, session_id, command)
        return self._expect(result, bytes, "screenshot")

    def fence_session(self, session_id: str, command: WorkerCommand) -> None:
        result = self._command_rpc("fence_session", command, session_id, command)
        if result is not None:
            self._fail_protocol("fence_session returned an unexpected result")

    def close_session(self, session_id: str, command: WorkerCommand) -> None:
        result = self._command_rpc("close_session", command, session_id, command)
        if result is not None:
            self._fail_protocol("close_session returned an unexpected result")

    def shutdown(self) -> WorkerDeathAttestation:
        with self._lock:
            if self._death_attestation is not None:
                return self._death_attestation
            if self._closed or not self._process.is_alive():
                return self._finish_process("worker_exited", graceful=False)
            try:
                self._rpc("shutdown", timeout=self._shutdown_timeout)
            except WorkerProcessError:
                self._finish_process("shutdown_failed", graceful=False)
                raise
            return self._finish_process("shutdown", graceful=True)

    def close(self) -> None:
        self.shutdown()

    def __enter__(self) -> ProcessBrowserWorker:
        return self

    def __exit__(self, *_: object) -> None:
        self.shutdown()

    def _command_rpc(
        self,
        operation: str,
        command: WorkerCommand,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        command.validate()
        deadline = parse_timestamp(command.deadline_at, "deadline_at")
        return self._rpc(
            operation,
            *args,
            timeout=self._call_timeout,
            deadline=deadline,
            **kwargs,
        )

    def _rpc(
        self,
        operation: str,
        *args: Any,
        timeout: float,
        deadline: datetime | None = None,
        **kwargs: Any,
    ) -> Any:
        started = time.monotonic()
        lock_timeout = _remaining_timeout(started, timeout, deadline)
        if lock_timeout <= 0 or not self._lock.acquire(timeout=lock_timeout):
            failure_class = (
                FailureClass.COMMAND_EXPIRED
                if deadline is not None
                else FailureClass.ENGINE_UNAVAILABLE
            )
            raise WorkerProcessTimeout(
                "browser worker deadline expired before process dispatch",
                failure_class,
            )
        try:
            if self._closed or not self._process.is_alive():
                self._finish_process("worker_exited", graceful=False)
                raise WorkerProcessLost("browser worker process is not alive")
            remaining = _remaining_timeout(started, timeout, deadline)
            if remaining <= 0:
                raise WorkerProcessTimeout(
                    "browser worker command expired before process dispatch",
                    FailureClass.COMMAND_EXPIRED,
                )
            self._request_id += 1
            request_id = self._request_id
            try:
                self._send_message(
                    {
                        "kind": "call",
                        "request_id": request_id,
                        "operation": operation,
                        "arguments": _call_arguments_to_wire(
                            operation,
                            args,
                            kwargs,
                        ),
                    },
                    timeout=remaining,
                )
            except ValueError:
                raise WorkerProcessRequestError(
                    "browser worker request violates the IPC boundary"
                ) from None
            except _ConnectionIoTimeout:
                self._finish_process("deadline_exceeded", graceful=False)
                raise WorkerProcessTimeout(
                    "browser worker IPC send exceeded its process deadline"
                ) from None
            except (BrokenPipeError, EOFError, OSError):
                self._finish_process("ipc_send_failed", graceful=False)
                raise WorkerProcessLost("browser worker IPC send failed") from None

            remaining = _remaining_timeout(started, timeout, deadline)
            if remaining <= 0:
                self._finish_process("deadline_exceeded", graceful=False)
                raise WorkerProcessTimeout("browser worker exceeded its process deadline")
            try:
                response = self._receive_message(
                    timeout=remaining,
                    decoder=lambda payload: _decode_rpc_response(
                        payload,
                        operation=operation,
                        request_id=request_id,
                    ),
                )
            except _ConnectionIoTimeout:
                self._finish_process("deadline_exceeded", graceful=False)
                raise WorkerProcessTimeout("browser worker exceeded its process deadline") from None
            except (EOFError, OSError):
                self._finish_process("worker_exited", graceful=False)
                raise WorkerProcessLost("browser worker exited without a result") from None
            except (TypeError, ValueError):
                self._fail_protocol("browser worker returned an invalid RPC payload")
            if _remaining_timeout(started, timeout, deadline) <= 0:
                self._finish_process("deadline_exceeded", graceful=False)
                raise WorkerProcessTimeout(
                    "browser worker result arrived after its process deadline"
                )
            if not isinstance(response, dict) or response.get("request_id") != request_id:
                self._fail_protocol("browser worker returned an invalid RPC envelope")
            if response.get("kind") == "result":
                return response.get("result")
            if response.get("kind") != "error":
                self._fail_protocol("browser worker returned an unknown RPC result")
            try:
                failure_class = FailureClass(response.get("failure_class"))
            except (TypeError, ValueError):
                failure_class = FailureClass.ENGINE_FAILURE
            raise WorkerRemoteError(
                f"browser worker {operation} failed",
                failure_class,
            )
        finally:
            self._lock.release()

    def _receive_startup(self, expected_kind: str) -> dict[str, Any]:
        try:
            message = self._receive_message(timeout=self._start_timeout)
        except _ConnectionIoTimeout:
            raise WorkerProcessStartupError(
                f"browser worker did not complete {expected_kind} before its deadline"
            ) from None
        except (EOFError, OSError, TypeError, ValueError):
            raise WorkerProcessStartupError(
                f"browser worker exited during {expected_kind}"
            ) from None
        if not isinstance(message, dict):
            raise WorkerProcessStartupError("browser worker startup message is invalid")
        if message.get("kind") == "startup_error":
            raise WorkerProcessStartupError("browser worker factory failed safely")
        if message.get("kind") != expected_kind:
            raise WorkerProcessStartupError(
                f"browser worker did not publish the expected {expected_kind} message"
            )
        return message

    def _send_message(self, message: dict[str, Any], *, timeout: float) -> None:
        started = time.monotonic()
        payload = _encode_message(message, self._max_request_bytes)
        _connection_call(
            lambda: self._connection.send_bytes(payload),
            timeout - (time.monotonic() - started),
        )

    def _receive_message(
        self,
        *,
        timeout: float,
        decoder: Callable[[bytes], Any] | None = None,
    ) -> Any:
        decode = _decode_message if decoder is None else decoder
        return _connection_call(
            lambda: decode(self._connection.recv_bytes(self._max_response_bytes)),
            timeout,
        )

    def _expect(self, result: Any, expected: type[Any], operation: str) -> Any:
        if not isinstance(result, expected):
            self._fail_protocol(f"{operation} returned an invalid result type")
        return result

    def _fail_protocol(self, message: str) -> None:
        self._finish_process("protocol_violation", graceful=False)
        raise WorkerProcessProtocolError(message)

    def _finish_process(self, reason: str, *, graceful: bool) -> WorkerDeathAttestation:
        if self._death_attestation is not None:
            return self._death_attestation
        self._closed = True
        if graceful:
            self._process.join(timeout=self._shutdown_timeout)
        tree_termination_requested = False
        if self._tree is not None:
            tree_termination_requested = self._tree.terminate()
        self._close_watchdog()
        if self._process.is_alive():
            self._process.terminate()
            self._process.join(timeout=self._shutdown_timeout)
        if self._process.is_alive() and hasattr(self._process, "kill"):
            self._process.kill()
            self._process.join(timeout=self._shutdown_timeout)
        tree_dead = False
        if self._tree is not None:
            tree_dead = tree_termination_requested and self._tree.confirmed_dead(
                self._shutdown_timeout
            )
            self._tree.close()
        if self._process.is_alive():
            tree_dead = False
        try:
            self._connection.close()
        except OSError:
            pass
        process_alive = self._process.is_alive()
        exit_code = None if process_alive else self._process.exitcode
        if (
            not process_alive
            and self._exit_monitor is not None
            and threading.current_thread() is not self._exit_monitor
        ):
            self._exit_observed.wait(self._shutdown_timeout)
        descriptor = self._descriptor
        worker_id = "uninitialized-worker" if descriptor is None else descriptor.worker_id
        instance_id = (
            f"process-{self._process_id}"
            if descriptor is None or not descriptor.instance_id
            else descriptor.instance_id
        )
        self._death_attestation = WorkerDeathAttestation.create(
            worker_id=worker_id,
            worker_instance_id=instance_id,
            process_id=self._process_id,
            exit_code=exit_code,
            reason=reason,
            worker_exited_gracefully=graceful and exit_code == 0,
            process_tree_confirmed_dead=tree_dead and not process_alive,
        )
        if not process_alive:
            self._process.close()
        if self._abandon_finalizer is not None and self._abandon_finalizer.alive:
            self._abandon_finalizer.detach()
        return self._death_attestation

    def _terminate_uninitialized(self) -> None:
        try:
            self._close_watchdog()
            if self._process.is_alive():
                self._process.terminate()
                self._process.join(timeout=self._shutdown_timeout)
        finally:
            self._connection.close()
            if not self._process.is_alive():
                self._process.close()

    def _close_watchdog(self) -> None:
        watchdog = self._watchdog_sender
        self._watchdog_sender = None
        if watchdog is not None:
            watchdog.close()


def _monitor_worker_exit(
    worker_reference: weakref.ReferenceType[ProcessBrowserWorker],
    process_sentinel: int,
    exit_observed: threading.Event,
) -> None:
    """Reap an exited worker without retaining an otherwise abandoned wrapper."""

    try:
        ready = wait([process_sentinel])
    except (OSError, ValueError):
        return
    if process_sentinel not in ready:
        return
    exit_observed.set()
    worker = worker_reference()
    if worker is None:
        return
    with worker._lock:
        if worker._death_attestation is None:
            worker._finish_process("worker_exited", graceful=False)


def _abandon_worker_process(
    process: multiprocessing.Process,
    connection: Connection,
    tree: _ProcessTree | None,
    watchdog_sender: Connection | None,
    shutdown_timeout: float,
) -> None:
    """Best-effort process-tree cleanup when a live wrapper is garbage-collected."""

    if tree is not None:
        try:
            tree.terminate()
        except Exception:
            pass
    if watchdog_sender is not None:
        try:
            watchdog_sender.close()
        except Exception:
            pass
    try:
        if process.is_alive():
            process.terminate()
            process.join(timeout=shutdown_timeout)
        if process.is_alive() and hasattr(process, "kill"):
            process.kill()
            process.join(timeout=shutdown_timeout)
    except Exception:
        pass
    if tree is not None:
        try:
            tree.confirmed_dead(shutdown_timeout)
        except Exception:
            pass
        try:
            tree.close()
        except Exception:
            pass
    try:
        connection.close()
    except Exception:
        pass
    try:
        if not process.is_alive():
            process.close()
    except Exception:
        pass


class _ProcessTree:
    def terminate(self) -> bool:
        raise NotImplementedError

    def confirmed_dead(self, timeout: float) -> bool:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError


class _PosixProcessTree(_ProcessTree):
    def __init__(self, process_group_id: int, watchdog_process_id: int) -> None:
        self.process_group_id = process_group_id
        self.watchdog_process_id = watchdog_process_id
        self._terminated = False

    def terminate(self) -> bool:
        if self._terminated:
            return True
        if not self._known_member_owns_group():
            try:
                os.killpg(self.process_group_id, 0)
            except ProcessLookupError:
                self._terminated = True
                return True
            except (OSError, PermissionError):
                return False
            return False
        try:
            os.killpg(self.process_group_id, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except (OSError, PermissionError):
            return False
        self._terminated = True
        return True

    def confirmed_dead(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while True:
            try:
                os.killpg(self.process_group_id, 0)
            except ProcessLookupError:
                return True
            except (OSError, PermissionError):
                return False
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.01)

    def close(self) -> None:
        return None

    def _known_member_owns_group(self) -> bool:
        for process_id in (self.process_group_id, self.watchdog_process_id):
            try:
                actual_group = os.getpgid(process_id)
                if actual_group == self.process_group_id:
                    return True
            except ProcessLookupError:
                continue
            except (OSError, PermissionError):
                return False
        return False


class _WindowsProcessTree(_ProcessTree):
    def __init__(self, process_id: int) -> None:
        import ctypes
        from ctypes import wintypes

        class IoCounters(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_ulonglong),
                ("WriteOperationCount", ctypes.c_ulonglong),
                ("OtherOperationCount", ctypes.c_ulonglong),
                ("ReadTransferCount", ctypes.c_ulonglong),
                ("WriteTransferCount", ctypes.c_ulonglong),
                ("OtherTransferCount", ctypes.c_ulonglong),
            ]

        class BasicLimitInformation(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class ExtendedLimitInformation(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", BasicLimitInformation),
                ("IoInfo", IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        class BasicAccountingInformation(ctypes.Structure):
            _fields_ = [
                ("TotalUserTime", ctypes.c_longlong),
                ("TotalKernelTime", ctypes.c_longlong),
                ("ThisPeriodTotalUserTime", ctypes.c_longlong),
                ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
                ("TotalPageFaultCount", wintypes.DWORD),
                ("TotalProcesses", wintypes.DWORD),
                ("ActiveProcesses", wintypes.DWORD),
                ("TotalTerminatedProcesses", wintypes.DWORD),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_job = kernel32.CreateJobObjectW
        create_job.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        create_job.restype = wintypes.HANDLE
        set_information = kernel32.SetInformationJobObject
        set_information.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        set_information.restype = wintypes.BOOL
        open_process = kernel32.OpenProcess
        open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        open_process.restype = wintypes.HANDLE
        assign_process = kernel32.AssignProcessToJobObject
        assign_process.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        assign_process.restype = wintypes.BOOL
        self._terminate_job = kernel32.TerminateJobObject
        self._terminate_job.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self._terminate_job.restype = wintypes.BOOL
        self._query_information = kernel32.QueryInformationJobObject
        self._query_information.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.c_void_p,
        ]
        self._query_information.restype = wintypes.BOOL
        self._close_handle = kernel32.CloseHandle
        self._close_handle.argtypes = [wintypes.HANDLE]
        self._close_handle.restype = wintypes.BOOL

        job = create_job(None, None)
        if not job:
            raise ctypes.WinError(ctypes.get_last_error())
        process = None
        try:
            limits = ExtendedLimitInformation()
            limits.BasicLimitInformation.LimitFlags = 0x00002000
            if not set_information(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
                raise ctypes.WinError(ctypes.get_last_error())
            process = open_process(0x0001 | 0x0100 | 0x1000, False, process_id)
            if not process:
                raise ctypes.WinError(ctypes.get_last_error())
            if not assign_process(job, process):
                raise ctypes.WinError(ctypes.get_last_error())
        except Exception:
            self._close_handle(job)
            raise
        finally:
            if process:
                self._close_handle(process)
        self._job = job
        self._accounting_type = BasicAccountingInformation

    def terminate(self) -> bool:
        if self._job is None:
            return True
        active = self._active_process_count()
        if active == 0:
            return True
        return bool(self._terminate_job(self._job, 1))

    def confirmed_dead(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while True:
            active = self._active_process_count()
            if active == 0:
                return True
            if active is None or time.monotonic() >= deadline:
                return False
            time.sleep(0.01)

    def close(self) -> None:
        if self._job is None:
            return
        job = self._job
        self._job = None
        self._close_handle(job)

    def _active_process_count(self) -> int | None:
        import ctypes

        if self._job is None:
            return 0
        accounting = self._accounting_type()
        if not self._query_information(
            self._job,
            1,
            ctypes.byref(accounting),
            ctypes.sizeof(accounting),
            None,
        ):
            return None
        return int(accounting.ActiveProcesses)


def _create_process_tree(
    process_id: int,
    *,
    watchdog_process_id: int | None,
) -> _ProcessTree:
    try:
        if os.name == "nt":
            return _WindowsProcessTree(process_id)
        if watchdog_process_id is None:
            raise WorkerProcessStartupError("POSIX browser worker has no parent-death watchdog")
        return _PosixProcessTree(process_id, watchdog_process_id)
    except Exception as exc:
        raise WorkerProcessStartupError(
            "browser worker could not enter an OS-enforced process tree"
        ) from exc


def _worker_process_main(
    connection: Connection,
    factory: WorkerFactory,
    parent_liveness: Connection | None,
    inherited_parent_sender: Connection | None,
    max_request_bytes: int,
    max_response_bytes: int,
) -> None:
    worker: BrowserWorker | None = None
    shutdown_attempted = False
    watchdog: tuple[int, int] | None = None
    try:
        if inherited_parent_sender is not None:
            inherited_parent_sender.close()
        if os.name != "nt":
            os.setsid()
            watchdog = _start_parent_watchdog(
                connection,
                parent_liveness,
            )
            watchdog_process_id = watchdog[0]
        else:
            watchdog_process_id = None
            if parent_liveness is not None:
                parent_liveness.close()
        _child_send(
            connection,
            {
                "kind": "bootstrap",
                "process_id": os.getpid(),
                "watchdog_process_id": watchdog_process_id,
            },
            max_response_bytes,
        )
        start = _child_receive(connection, max_request_bytes)
        if not isinstance(start, dict) or start.get("kind") != "start":
            return
        try:
            worker = factory()
            descriptor = worker.descriptor
            _validate_descriptor(descriptor)
        except Exception:
            _child_send(connection, {"kind": "startup_error"}, max_response_bytes)
            return
        _child_send(
            connection,
            {"kind": "ready", "descriptor": _descriptor_to_wire(descriptor)},
            max_response_bytes,
        )
        while True:
            try:
                message = _child_receive(connection, max_request_bytes)
            except EOFError:
                return
            if (
                not isinstance(message, dict)
                or set(message) != {"kind", "request_id", "operation", "arguments"}
                or message.get("kind") != "call"
            ):
                return
            request_id = message.get("request_id")
            operation = message.get("operation")
            if type(request_id) is not int or operation not in _WORKER_OPERATIONS:
                return
            try:
                args, kwargs = _call_arguments_from_wire(
                    operation,
                    message.get("arguments"),
                )
                if operation == "shutdown":
                    shutdown = getattr(worker, "shutdown", None)
                    shutdown_attempted = True
                    result = None if shutdown is None else shutdown()
                else:
                    result = getattr(worker, operation)(*args, **kwargs)
                _child_send(
                    connection,
                    {
                        "kind": "result",
                        "request_id": request_id,
                        "result": _result_to_wire(operation, result),
                    },
                    max_response_bytes,
                )
            except Exception as exc:
                failure_class = (
                    exc.failure_class
                    if isinstance(exc, WeirEngineError)
                    else FailureClass.ENGINE_FAILURE
                )
                _child_send(
                    connection,
                    {
                        "kind": "error",
                        "request_id": request_id,
                        "failure_class": failure_class.value,
                    },
                    max_response_bytes,
                )
            if operation == "shutdown":
                return
    except (BrokenPipeError, EOFError, OSError, TypeError, ValueError):
        return
    finally:
        if worker is not None and not shutdown_attempted:
            shutdown = getattr(worker, "shutdown", None)
            if shutdown is not None:
                try:
                    shutdown()
                except Exception:
                    pass
        _stop_parent_watchdog(watchdog)
        connection.close()


def _start_parent_watchdog(
    worker_connection: Connection,
    parent_liveness: Connection | None,
) -> tuple[int, int]:
    if parent_liveness is None or not hasattr(os, "fork"):
        raise RuntimeError("POSIX worker parent-death watchdog is unavailable")
    import select

    process_group_id = os.getpgrp()
    control_reader, control_sender = os.pipe()
    watchdog_process_id = os.fork()
    if watchdog_process_id:
        os.close(control_reader)
        parent_liveness.close()
        return watchdog_process_id, control_sender

    os.close(control_sender)
    worker_connection.close()
    try:
        parent_reader = parent_liveness.fileno()
        readable, _, _ = select.select(
            [parent_reader, control_reader],
            [],
            [],
        )
        if parent_reader not in readable:
            command = os.read(control_reader, 1)
            if command == b"S":
                os._exit(0)
    finally:
        try:
            os.killpg(process_group_id, signal.SIGKILL)
        finally:
            os._exit(0)


def _stop_parent_watchdog(watchdog: tuple[int, int] | None) -> None:
    if watchdog is None:
        return
    process_id, control_sender = watchdog
    try:
        try:
            os.write(control_sender, b"S")
        except OSError:
            pass
    finally:
        os.close(control_sender)
    try:
        os.waitpid(process_id, 0)
    except ChildProcessError:
        pass


def _remaining_timeout(
    started: float,
    timeout: float,
    deadline: datetime | None,
) -> float:
    remaining = timeout - (time.monotonic() - started)
    if deadline is not None:
        remaining = min(
            remaining,
            (deadline - datetime.now(timezone.utc)).total_seconds(),
        )
    return remaining


def _connection_call(callback: Callable[[], Any], timeout: float) -> Any:
    if timeout <= 0:
        raise _ConnectionIoTimeout
    completed = threading.Event()
    outcome: list[tuple[bool, Any]] = []

    def invoke() -> None:
        try:
            outcome.append((True, callback()))
        except BaseException as exc:
            outcome.append((False, exc))
        finally:
            completed.set()

    thread = threading.Thread(
        target=invoke,
        name="weir-worker-ipc",
        daemon=True,
    )
    thread.start()
    if not completed.wait(timeout):
        raise _ConnectionIoTimeout
    succeeded, value = outcome[0]
    if succeeded:
        return value
    if isinstance(value, BaseException):
        raise value
    raise RuntimeError("worker IPC failed without an exception")


def _call_arguments_to_wire(
    operation: str,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> dict[str, Any]:
    if operation not in _WORKER_OPERATIONS:
        raise ValueError("unknown browser worker operation")
    if operation in {"probe", "shutdown"}:
        if args or kwargs:
            raise ValueError("browser worker operation received unexpected arguments")
        return {}
    if operation in {"open_session", "attach_session"}:
        if len(args) != 2 or kwargs:
            raise ValueError("browser worker operation received invalid arguments")
        spec, command = args
        if not isinstance(spec, SessionSpec) or not isinstance(command, WorkerCommand):
            raise ValueError("browser worker operation received invalid arguments")
        return {"spec": spec.to_dict(), "command": command.to_dict()}
    if operation == "navigate":
        if len(args) != 3 or kwargs:
            raise ValueError("browser worker operation received invalid arguments")
        session_id, url, command = args
        _require_nonempty_string(session_id, "session_id")
        _require_nonempty_string(url, "url")
        if not isinstance(command, WorkerCommand):
            raise ValueError("browser worker operation received invalid command")
        return {
            "session_id": session_id,
            "url": url,
            "command": command.to_dict(),
        }
    if operation == "observe":
        if len(args) != 2 or set(kwargs) != {"include_screenshot"}:
            raise ValueError("browser worker operation received invalid arguments")
        session_id, command = args
        include_screenshot = kwargs["include_screenshot"]
        _require_nonempty_string(session_id, "session_id")
        if not isinstance(command, WorkerCommand) or type(include_screenshot) is not bool:
            raise ValueError("browser worker operation received invalid arguments")
        return {
            "session_id": session_id,
            "command": command.to_dict(),
            "include_screenshot": include_screenshot,
        }
    if len(args) != 2 or kwargs:
        raise ValueError("browser worker operation received invalid arguments")
    session_id, command = args
    _require_nonempty_string(session_id, "session_id")
    if not isinstance(command, WorkerCommand):
        raise ValueError("browser worker operation received invalid command")
    return {"session_id": session_id, "command": command.to_dict()}


def _call_arguments_from_wire(
    operation: str,
    value: Any,
) -> tuple[tuple[Any, ...], dict[str, Any]]:
    if operation in {"probe", "shutdown"}:
        _require_exact_object(value, set(), "worker arguments")
        return (), {}
    if operation in {"open_session", "attach_session"}:
        arguments = _require_exact_object(
            value,
            {"spec", "command"},
            "worker arguments",
        )
        return (
            _session_spec_from_wire(arguments["spec"]),
            _worker_command_from_wire(arguments["command"]),
        ), {}
    if operation == "navigate":
        arguments = _require_exact_object(
            value,
            {"session_id", "url", "command"},
            "worker arguments",
        )
        return (
            _require_nonempty_string(arguments["session_id"], "session_id"),
            _require_nonempty_string(arguments["url"], "url"),
            _worker_command_from_wire(arguments["command"]),
        ), {}
    if operation == "observe":
        arguments = _require_exact_object(
            value,
            {"session_id", "command", "include_screenshot"},
            "worker arguments",
        )
        include_screenshot = arguments["include_screenshot"]
        if type(include_screenshot) is not bool:
            raise ValueError("worker include_screenshot must be a boolean")
        return (
            _require_nonempty_string(arguments["session_id"], "session_id"),
            _worker_command_from_wire(arguments["command"]),
        ), {"include_screenshot": include_screenshot}
    if operation in {"screenshot", "fence_session", "close_session"}:
        arguments = _require_exact_object(
            value,
            {"session_id", "command"},
            "worker arguments",
        )
        return (
            _require_nonempty_string(arguments["session_id"], "session_id"),
            _worker_command_from_wire(arguments["command"]),
        ), {}
    raise ValueError("unknown browser worker operation")


def _session_spec_from_wire(value: Any) -> SessionSpec:
    fields = _require_exact_object(
        value,
        {
            "session_id",
            "worker_session_id",
            "owner_run_id",
            "profile_id",
            "credential_binding_id",
            "site_profile_id",
            "credential_scope",
            "data_class",
            "allowed_domains",
            "initial_url",
        },
        "SessionSpec",
    )
    allowed_domains = fields["allowed_domains"]
    if not isinstance(allowed_domains, list) or any(
        not isinstance(domain, str) or not domain for domain in allowed_domains
    ):
        raise ValueError("SessionSpec allowed_domains must be a string array")
    try:
        data_class = DataClass(fields["data_class"])
    except (TypeError, ValueError):
        raise ValueError("SessionSpec data_class is invalid") from None
    return SessionSpec(
        session_id=_require_nonempty_string(fields["session_id"], "session_id"),
        worker_session_id=_require_nonempty_string(
            fields["worker_session_id"],
            "worker_session_id",
        ),
        owner_run_id=_require_nonempty_string(fields["owner_run_id"], "owner_run_id"),
        profile_id=_require_nonempty_string(fields["profile_id"], "profile_id"),
        credential_binding_id=_require_nonempty_string(
            fields["credential_binding_id"],
            "credential_binding_id",
        ),
        site_profile_id=_require_nonempty_string(
            fields["site_profile_id"],
            "site_profile_id",
        ),
        credential_scope=_require_nonempty_string(
            fields["credential_scope"],
            "credential_scope",
        ),
        data_class=data_class,
        allowed_domains=tuple(allowed_domains),
        initial_url=_require_nonempty_string(fields["initial_url"], "initial_url"),
    )


def _worker_command_from_wire(value: Any) -> WorkerCommand:
    fields = _require_exact_object(
        value,
        {
            "protocol_version",
            "command_id",
            "operation",
            "session_id",
            "worker_session_id",
            "owner_run_id",
            "expected_revision",
            "session_epoch",
            "lease_fence",
            "deadline_at",
            "request_digest",
        },
        "WorkerCommand",
    )
    command = WorkerCommand(**fields)
    command.validate()
    return command


def _descriptor_to_wire(descriptor: WorkerDescriptor) -> dict[str, Any]:
    _validate_descriptor(descriptor)
    return {
        "worker_id": descriptor.worker_id,
        "engine": descriptor.engine,
        "capabilities": sorted(capability.value for capability in descriptor.capabilities),
        "version": descriptor.version,
        "instance_id": descriptor.instance_id,
    }


def _descriptor_from_wire(value: Any) -> WorkerDescriptor:
    fields = _require_exact_object(
        value,
        {"worker_id", "engine", "capabilities", "version", "instance_id"},
        "WorkerDescriptor",
    )
    raw_capabilities = fields["capabilities"]
    if not isinstance(raw_capabilities, list) or any(
        not isinstance(capability, str) for capability in raw_capabilities
    ):
        raise ValueError("WorkerDescriptor capabilities must be a string array")
    if len(raw_capabilities) != len(set(raw_capabilities)):
        raise ValueError("WorkerDescriptor capabilities cannot contain duplicates")
    try:
        capabilities = frozenset(WorkerCapability(capability) for capability in raw_capabilities)
    except ValueError:
        raise ValueError("WorkerDescriptor capability is invalid") from None
    descriptor = WorkerDescriptor(
        worker_id=_require_nonempty_string(fields["worker_id"], "worker_id"),
        engine=_require_nonempty_string(fields["engine"], "engine"),
        capabilities=capabilities,
        version=_require_optional_string(fields["version"], "version"),
        instance_id=_require_optional_string(fields["instance_id"], "instance_id"),
    )
    _validate_descriptor(descriptor)
    return descriptor


def _result_to_wire(operation: str, result: Any) -> Any:
    if operation == "probe":
        if not isinstance(result, EngineProbe):
            raise ValueError("probe returned an invalid result")
        return {
            "engine": _require_nonempty_string(result.engine, "engine"),
            "available": _require_boolean(result.available, "available"),
            "version": _require_optional_string(result.version, "version"),
            "detail": _require_optional_string(result.detail, "detail"),
        }
    if operation in {"open_session", "navigate"}:
        return _require_nonempty_string(result, f"{operation} result")
    if operation == "attach_session":
        return _require_boolean(result, "attach_session result")
    if operation == "observe":
        if not isinstance(result, WorkerObservation):
            raise ValueError("observe returned an invalid result")
        if not isinstance(result.elements, tuple) or any(
            not isinstance(element, ObservedElement) for element in result.elements
        ):
            raise ValueError("observe returned invalid elements")
        if not isinstance(result.notes, tuple) or any(
            not isinstance(note, str) for note in result.notes
        ):
            raise ValueError("observe returned invalid notes")
        screenshot = result.screenshot
        if screenshot is not None and not isinstance(screenshot, bytes):
            raise ValueError("observe returned an invalid screenshot")
        return {
            "url": _require_nonempty_string(result.url, "observation url"),
            "title": _require_optional_string(result.title, "observation title"),
            "elements": [element.to_dict() for element in result.elements],
            "accessibility_snapshot": _require_optional_string(
                result.accessibility_snapshot,
                "accessibility_snapshot",
            ),
            "notes": list(result.notes),
            "screenshot": None if screenshot is None else _bytes_to_wire(screenshot),
        }
    if operation == "screenshot":
        if not isinstance(result, bytes):
            raise ValueError("screenshot returned an invalid result")
        return _bytes_to_wire(result)
    if operation in {"fence_session", "close_session", "shutdown"}:
        if result is not None:
            raise ValueError(f"{operation} returned an unexpected result")
        return None
    raise ValueError("unknown browser worker operation")


def _result_from_wire(operation: str, value: Any) -> Any:
    if operation == "probe":
        fields = _require_exact_object(
            value,
            {"engine", "available", "version", "detail"},
            "EngineProbe",
        )
        return EngineProbe(
            engine=_require_nonempty_string(fields["engine"], "engine"),
            available=_require_boolean(fields["available"], "available"),
            version=_require_optional_string(fields["version"], "version"),
            detail=_require_optional_string(fields["detail"], "detail"),
        )
    if operation in {"open_session", "navigate"}:
        return _require_nonempty_string(value, f"{operation} result")
    if operation == "attach_session":
        return _require_boolean(value, "attach_session result")
    if operation == "observe":
        fields = _require_exact_object(
            value,
            {
                "url",
                "title",
                "elements",
                "accessibility_snapshot",
                "notes",
                "screenshot",
            },
            "WorkerObservation",
        )
        raw_elements = fields["elements"]
        raw_notes = fields["notes"]
        if not isinstance(raw_elements, list):
            raise ValueError("WorkerObservation elements must be an array")
        if not isinstance(raw_notes, list) or any(not isinstance(note, str) for note in raw_notes):
            raise ValueError("WorkerObservation notes must be a string array")
        screenshot = fields["screenshot"]
        return WorkerObservation(
            url=_require_nonempty_string(fields["url"], "observation url"),
            title=_require_optional_string(fields["title"], "observation title"),
            elements=tuple(ObservedElement.from_dict(element) for element in raw_elements),
            accessibility_snapshot=_require_optional_string(
                fields["accessibility_snapshot"],
                "accessibility_snapshot",
            ),
            notes=tuple(raw_notes),
            screenshot=None if screenshot is None else _bytes_from_wire(screenshot),
        )
    if operation == "screenshot":
        return _bytes_from_wire(value)
    if operation in {"fence_session", "close_session", "shutdown"}:
        if value is not None:
            raise ValueError(f"{operation} returned an unexpected result")
        return None
    raise ValueError("unknown browser worker operation")


def _decode_rpc_response(
    payload: bytes,
    *,
    operation: str,
    request_id: int,
) -> dict[str, Any]:
    message = _decode_message(payload)
    if not isinstance(message, dict):
        raise ValueError("worker RPC response must be an object")
    kind = message.get("kind")
    if kind == "result":
        fields = _require_exact_object(
            message,
            {"kind", "request_id", "result"},
            "worker result envelope",
        )
        if type(fields["request_id"]) is not int or fields["request_id"] != request_id:
            raise ValueError("worker result request_id is invalid")
        return {
            "kind": "result",
            "request_id": request_id,
            "result": _result_from_wire(operation, fields["result"]),
        }
    if kind == "error":
        fields = _require_exact_object(
            message,
            {"kind", "request_id", "failure_class"},
            "worker error envelope",
        )
        if type(fields["request_id"]) is not int or fields["request_id"] != request_id:
            raise ValueError("worker error request_id is invalid")
        raw_failure_class = _require_nonempty_string(
            fields["failure_class"],
            "failure_class",
        )
        try:
            failure_class = FailureClass(raw_failure_class).value
        except ValueError:
            raise ValueError("worker error failure_class is invalid") from None
        return {
            "kind": "error",
            "request_id": request_id,
            "failure_class": failure_class,
        }
    raise ValueError("worker RPC response kind is invalid")


def _bytes_to_wire(value: bytes) -> dict[str, str]:
    return {"base64": base64.b64encode(value).decode("ascii")}


def _bytes_from_wire(value: Any) -> bytes:
    fields = _require_exact_object(value, {"base64"}, "binary worker result")
    encoded = fields["base64"]
    if not isinstance(encoded, str):
        raise ValueError("binary worker result must be base64 text")
    try:
        return base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("binary worker result is invalid base64") from None


def _require_exact_object(
    value: Any,
    fields: set[str] | frozenset[str],
    name: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"{name} must be an object")
    if set(value) != set(fields):
        raise ValueError(f"{name} has invalid fields")
    return value


def _require_nonempty_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _require_optional_string(value: Any, name: str) -> str | None:
    if value is not None and not isinstance(value, str):
        raise ValueError(f"{name} must be a string or null")
    return value


def _require_boolean(value: Any, name: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{name} must be a boolean")
    return value


def _reject_json_constant(value: str) -> Any:
    raise ValueError(f"invalid JSON constant {value!r}")


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("worker IPC message contains duplicate object keys")
        result[key] = value
    return result


def _encode_message(message: dict[str, Any], maximum_bytes: int) -> bytes:
    try:
        payload = json.dumps(
            message,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError):
        raise ValueError("worker IPC message is not JSON serializable") from None
    if len(payload) > maximum_bytes:
        raise ValueError("worker IPC message exceeds its size limit")
    return payload


def _decode_message(payload: bytes) -> Any:
    try:
        return json.loads(
            payload.decode("utf-8"),
            parse_constant=_reject_json_constant,
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError, RecursionError):
        raise ValueError("worker IPC message is invalid JSON") from None


def _child_send(
    connection: Connection,
    message: dict[str, Any],
    maximum_bytes: int,
) -> None:
    connection.send_bytes(_encode_message(message, maximum_bytes))


def _child_receive(connection: Connection, maximum_bytes: int) -> Any:
    return _decode_message(connection.recv_bytes(maximum_bytes))


def _validate_descriptor(descriptor: Any) -> None:
    if not isinstance(descriptor, WorkerDescriptor):
        raise WorkerProcessStartupError("browser worker descriptor has an invalid type")
    validate_identifier(descriptor.worker_id, "worker_id")
    validate_identifier(descriptor.engine, "engine")
    if not isinstance(descriptor.capabilities, frozenset):
        raise WorkerProcessStartupError("browser worker capabilities are invalid")
    if any(not isinstance(capability, WorkerCapability) for capability in descriptor.capabilities):
        raise WorkerProcessStartupError("browser worker capabilities are invalid")
    if descriptor.version is not None and (
        not isinstance(descriptor.version, str)
        or not descriptor.version
        or len(descriptor.version) > 128
    ):
        raise WorkerProcessStartupError("browser worker version is invalid")
    if not descriptor.instance_id:
        raise WorkerProcessStartupError(
            "out-of-process browser workers require a stable instance_id"
        )
    validate_identifier(descriptor.instance_id, "worker_instance_id")


_WORKER_OPERATIONS = frozenset(
    {
        "probe",
        "open_session",
        "attach_session",
        "navigate",
        "observe",
        "screenshot",
        "fence_session",
        "close_session",
        "shutdown",
    }
)


__all__ = [
    "ProcessBrowserWorker",
    "WorkerDeathAttestation",
    "WorkerFactory",
    "WorkerProcessError",
    "WorkerProcessLost",
    "WorkerProcessProtocolError",
    "WorkerProcessRequestError",
    "WorkerProcessStartupError",
    "WorkerProcessTimeout",
    "WorkerRemoteError",
]
