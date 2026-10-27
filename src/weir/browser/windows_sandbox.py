"""Create a no-capability AppContainer process with an exact inherited-handle set.

The process keeps its primary service SID but cannot access resources without the
AppContainer SID as well. No supervisor/token handles are passed into the sandbox.
"""
from __future__ import annotations

import os
import subprocess
import sys


def ensure_appcontainer_profile(name: str) -> str:
    """Explicit deployment operation; never called by an admission request."""
    import ctypes
    from ctypes import wintypes as w

    expected = appcontainer_sid(name)
    userenv, advapi = ctypes.WinDLL("userenv"), ctypes.WinDLL("advapi32")
    create = userenv.CreateAppContainerProfile
    create.argtypes = [w.LPCWSTR, w.LPCWSTR, w.LPCWSTR, ctypes.c_void_p, w.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    create.restype = ctypes.c_long
    advapi.FreeSid.argtypes, advapi.FreeSid.restype = [ctypes.c_void_p], ctypes.c_void_p
    sid = ctypes.c_void_p()
    result = create(name, name, "WEIR deny-only worker isolation", None, 0, ctypes.byref(sid))
    try:
        if result < 0 and result != -2147024713:  # HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)
            raise OSError(result, "AppContainer profile creation failed")
        return expected
    finally:
        if sid:
            advapi.FreeSid(sid)


def appcontainer_sid(name: str) -> str:
    import ctypes
    from ctypes import wintypes as w

    if not name or len(name) > 64 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-" for c in name):
        raise ValueError("invalid AppContainer name")
    userenv = ctypes.WinDLL("userenv", use_last_error=True)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    derive = userenv.DeriveAppContainerSidFromAppContainerName
    derive.argtypes, derive.restype = [w.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)], ctypes.c_long
    convert = advapi.ConvertSidToStringSidW
    convert.argtypes, convert.restype = [ctypes.c_void_p, ctypes.POINTER(w.LPWSTR)], w.BOOL
    advapi.FreeSid.argtypes, advapi.FreeSid.restype = [ctypes.c_void_p], ctypes.c_void_p
    kernel.LocalFree.argtypes, kernel.LocalFree.restype = [ctypes.c_void_p], ctypes.c_void_p
    pointer, text = ctypes.c_void_p(), w.LPWSTR()
    result = derive(name, ctypes.byref(pointer))
    if result < 0:
        raise OSError(result, "AppContainer SID derivation failed")
    try:
        if not convert(pointer, ctypes.byref(text)):
            raise ctypes.WinError(ctypes.get_last_error())
        return text.value
    finally:
        if text:
            kernel.LocalFree(ctypes.cast(text, ctypes.c_void_p))
        advapi.FreeSid(pointer)


def create_appcontainer_process(argv: list[str], sid: str, handles: tuple[int, ...] = (), *, cwd: str | None = None) -> tuple[int, int]:
    """Return an owned process handle and PID; caller must close the handle."""
    import ctypes
    from ctypes import wintypes as w

    class Startup(ctypes.Structure):
        _fields_ = [("cb", w.DWORD), ("reserved", w.LPWSTR), ("desktop", w.LPWSTR), ("title", w.LPWSTR),
                    ("x", w.DWORD), ("y", w.DWORD), ("xsize", w.DWORD), ("ysize", w.DWORD),
                    ("xchars", w.DWORD), ("ychars", w.DWORD), ("fill", w.DWORD), ("flags", w.DWORD),
                    ("show", w.WORD), ("reserved_size", w.WORD), ("reserved_bytes", ctypes.c_void_p),
                    ("stdin", w.HANDLE), ("stdout", w.HANDLE), ("stderr", w.HANDLE)]

    class ExtendedStartup(ctypes.Structure):
        _fields_ = [("info", Startup), ("attributes", ctypes.c_void_p)]

    class ProcessInfo(ctypes.Structure):
        _fields_ = [("process", w.HANDLE), ("thread", w.HANDLE), ("pid", w.DWORD), ("tid", w.DWORD)]

    class Capabilities(ctypes.Structure):
        _fields_ = [("sid", ctypes.c_void_p), ("capabilities", ctypes.c_void_p), ("count", w.DWORD), ("reserved", w.DWORD)]

    kernel, advapi = ctypes.WinDLL("kernel32", use_last_error=True), ctypes.WinDLL("advapi32", use_last_error=True)
    initialize = kernel.InitializeProcThreadAttributeList
    initialize.argtypes, initialize.restype = [ctypes.c_void_p, w.DWORD, w.DWORD, ctypes.POINTER(ctypes.c_size_t)], w.BOOL
    update = kernel.UpdateProcThreadAttribute
    update.argtypes, update.restype = [ctypes.c_void_p, w.DWORD, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p], w.BOOL
    delete = kernel.DeleteProcThreadAttributeList
    delete.argtypes, delete.restype = [ctypes.c_void_p], None
    convert = advapi.ConvertStringSidToSidW
    convert.argtypes, convert.restype = [w.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)], w.BOOL
    free = kernel.LocalFree
    free.argtypes, free.restype = [ctypes.c_void_p], ctypes.c_void_p
    close = kernel.CloseHandle
    close.argtypes, close.restype = [w.HANDLE], w.BOOL
    create = kernel.CreateProcessW
    create.argtypes, create.restype = [w.LPCWSTR, w.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, w.BOOL, w.DWORD, ctypes.c_void_p, w.LPCWSTR, ctypes.c_void_p, ctypes.POINTER(ProcessInfo)], w.BOOL

    def require(ok):
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())

    size = ctypes.c_size_t()
    count = 2 if handles else 1
    initialize(None, count, 0, ctypes.byref(size))
    attributes = ctypes.create_string_buffer(size.value)
    require(initialize(attributes, count, 0, ctypes.byref(size)))
    sid_pointer = ctypes.c_void_p()
    try:
        require(convert(sid, ctypes.byref(sid_pointer)))
        capabilities = Capabilities(sid_pointer, None, 0, 0)
        require(update(attributes, 0, 0x00020009, ctypes.byref(capabilities), ctypes.sizeof(capabilities), None, None))
        if handles:
            inherited = (w.HANDLE * len(handles))(*handles)
            require(update(attributes, 0, 0x00020002, inherited, ctypes.sizeof(inherited), None, None))
        startup = ExtendedStartup()
        startup.info.cb, startup.attributes = ctypes.sizeof(startup), ctypes.cast(attributes, ctypes.c_void_p)
        info = ProcessInfo()
        command = ctypes.create_unicode_buffer(subprocess.list2cmdline(argv))
        # No application environment, user-site paths, or proxy configuration enters
        # the child. Its protected interpreter uses an explicit ._pth file.
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        safe_environment = {key: os.environ[key] for key in (
            "SystemDrive", "USERPROFILE", "LOCALAPPDATA", "APPDATA", "ProgramData", "PUBLIC", "TEMP", "TMP",
        ) if key in os.environ}
        safe_environment.update(SystemRoot=system_root, WINDIR=system_root, PATH=system_root + "\\System32")
        environment = ctypes.create_unicode_buffer("\0".join(
            key + "=" + value for key, value in sorted(safe_environment.items(), key=lambda x: x[0].casefold())
        ) + "\0\0")
        require(create(argv[0], command, None, None, bool(handles), 0x00080000 | 0x08000000 | 0x00000400,
                       environment, cwd or system_root + "\\System32", ctypes.byref(startup), ctypes.byref(info)))
        close(info.thread)
        return int(info.process), int(info.pid)
    finally:
        if sid_pointer:
            free(sid_pointer)
        delete(attributes)


def sandbox_process_type(sid: str):
    """Use multiprocessing's lifecycle with a restricted Win32 creation path."""
    import _winapi
    import msvcrt
    from multiprocessing import connection, context, spawn, util
    from multiprocessing.context import reduction, set_spawning_popen
    from multiprocessing.popen_spawn_win32 import Popen as BasePopen

    class SandboxPopen(BasePopen):
        def __init__(self, process_obj):
            prep = spawn.get_preparation_data(process_obj._name)
            prep["dir"] = os.path.dirname(sys.executable)
            prep["orig_dir"] = prep["dir"]
            read_handle, write_handle = _winapi.CreatePipe(None, 0)
            os.set_handle_inheritable(read_handle, True)
            write_fd = msvcrt.open_osfhandle(write_handle, 0)
            self.pid = self.returncode = self._handle = None
            try:
                with open(write_fd, "wb", closefd=True) as to_child:
                    argv = spawn.get_command_line(pipe_handle=read_handle)
                    self._handle, self.pid = create_appcontainer_process(argv, sid, (read_handle,))
                    self.sentinel = self._handle
                    self.finalizer = util.Finalize(self, _winapi.CloseHandle, (self._handle,))

                    def reduce_pipe(pipe):
                        access = (_winapi.FILE_GENERIC_READ if pipe.readable else 0) | (_winapi.FILE_GENERIC_WRITE if pipe.writable else 0)
                        handle = _winapi.DuplicateHandle(_winapi.GetCurrentProcess(), pipe.fileno(), self._handle, access, False, 0)
                        return connection.PipeConnection, (handle, pipe.readable, pipe.writable)

                    def dump(value):
                        pickler = reduction.ForkingPickler(to_child, 4)
                        pickler.dispatch_table[connection.PipeConnection] = reduce_pipe
                        pickler.dump(value)

                    set_spawning_popen(self)
                    try:
                        dump(prep)
                        dump(process_obj)
                    finally:
                        set_spawning_popen(None)
            except BaseException:
                if self._handle is not None:
                    self.terminate()
                    self.wait(5)
                    self.close()
                raise
            finally:
                _winapi.CloseHandle(read_handle)

    class SandboxProcess(context.SpawnProcess):
        @staticmethod
        def _Popen(process_obj):
            return SandboxPopen(process_obj)

    # Spawn pickles the process type: use a module-level standard Process object and
    # keep only its constructor's _Popen override on the parent-side type.
    SandboxProcess.__reduce__ = lambda self: (_restore_process, (self.__dict__,))
    return SandboxProcess


def _restore_process(state):
    from multiprocessing.context import SpawnProcess
    process = SpawnProcess.__new__(SpawnProcess)
    process.__dict__.update(state)
    return process
