"""Read-only Win32 process/token inspection; no token or privilege modification."""
from __future__ import annotations

import os


def inspect_process(process_id: int) -> dict:
    if os.name != "nt":
        raise OSError("Win32 process inspection requires Windows")
    if type(process_id) is not int or process_id < 1:
        raise ValueError("invalid process ID")
    import ctypes
    from ctypes import wintypes as w

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)

    def bind(dll, name, args, result):
        method = getattr(dll, name)
        method.argtypes, method.restype = args, result
        return method

    open_process = bind(kernel, "OpenProcess", [w.DWORD, w.BOOL, w.DWORD], w.HANDLE)
    close = bind(kernel, "CloseHandle", [w.HANDLE], w.BOOL)
    wait = bind(kernel, "WaitForSingleObject", [w.HANDLE, w.DWORD], w.DWORD)
    image = bind(kernel, "QueryFullProcessImageNameW", [w.HANDLE, w.DWORD, w.LPWSTR, ctypes.POINTER(w.DWORD)], w.BOOL)
    times = bind(kernel, "GetProcessTimes", [w.HANDLE] + [ctypes.POINTER(w.FILETIME)] * 4, w.BOOL)
    open_token = bind(advapi, "OpenProcessToken", [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)], w.BOOL)
    get_info = bind(advapi, "GetTokenInformation", [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD)], w.BOOL)
    sid_string = bind(advapi, "ConvertSidToStringSidW", [ctypes.c_void_p, ctypes.POINTER(w.LPWSTR)], w.BOOL)
    free = bind(kernel, "LocalFree", [ctypes.c_void_p], ctypes.c_void_p)

    class SidAttributes(ctypes.Structure):
        _fields_ = [("sid", ctypes.c_void_p), ("attributes", w.DWORD)]

    class Groups(ctypes.Structure):
        _fields_ = [("count", w.DWORD), ("groups", SidAttributes * 1)]

    class Luid(ctypes.Structure):
        _fields_ = [("low", w.DWORD), ("high", w.LONG)]

    class Privilege(ctypes.Structure):
        _fields_ = [("luid", Luid), ("attributes", w.DWORD)]

    class Privileges(ctypes.Structure):
        _fields_ = [("count", w.DWORD), ("privileges", Privilege * 1)]

    privilege_name = bind(advapi, "LookupPrivilegeNameW", [w.LPCWSTR, ctypes.POINTER(Luid), w.LPWSTR, ctypes.POINTER(w.DWORD)], w.BOOL)

    def require(ok):
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())

    def sid(value):
        result = w.LPWSTR()
        require(sid_string(value, ctypes.byref(result)))
        try:
            return result.value
        finally:
            free(ctypes.cast(result, ctypes.c_void_p))

    process = open_process(0x1000 | 0x00100000, False, process_id)
    require(process)
    token = w.HANDLE()
    try:
        if wait(process, 0) != 0x102:
            raise OSError("process has exited")
        require(open_token(process, 0x0008, ctypes.byref(token)))

        def info(kind):
            size = w.DWORD()
            get_info(token, kind, None, 0, ctypes.byref(size))
            if not 1 <= size.value <= 65536:
                raise OSError("invalid process token information size")
            buffer = ctypes.create_string_buffer(size.value)
            require(get_info(token, kind, buffer, size.value, ctypes.byref(size)))
            return buffer

        user = info(1)
        user_sid = sid(SidAttributes.from_buffer(user).sid)
        group_data = info(2)
        count = w.DWORD.from_buffer(group_data).value
        if Groups.groups.offset + count * ctypes.sizeof(SidAttributes) > len(group_data):
            raise OSError("invalid token group bounds")
        groups = (SidAttributes * count).from_buffer(group_data, Groups.groups.offset)
        group_sids = sorted(sid(group.sid) for group in groups)
        integrity_data = info(25)
        integrity = sid(SidAttributes.from_buffer(integrity_data).sid)
        is_appcontainer = bool(w.DWORD.from_buffer(info(29)).value)
        container_sid = None
        capability_sids = []
        if is_appcontainer:
            container_data = info(31)
            container_sid = sid(ctypes.c_void_p.from_buffer(container_data).value)
            capability_data = info(30)
            capability_count = w.DWORD.from_buffer(capability_data).value
            if Groups.groups.offset + capability_count * ctypes.sizeof(SidAttributes) > len(capability_data):
                raise OSError("invalid token capability bounds")
            capabilities = (SidAttributes * capability_count).from_buffer(capability_data, Groups.groups.offset)
            capability_sids = sorted(sid(cap.sid) for cap in capabilities)
        privilege_data = info(3)
        count = w.DWORD.from_buffer(privilege_data).value
        if Privileges.privileges.offset + count * ctypes.sizeof(Privilege) > len(privilege_data):
            raise OSError("invalid token privilege bounds")
        privileges = (Privilege * count).from_buffer(privilege_data, Privileges.privileges.offset)
        names = []
        for privilege in privileges:
            name = ctypes.create_unicode_buffer(256)
            length = w.DWORD(len(name))
            require(privilege_name(None, ctypes.byref(privilege.luid), name, ctypes.byref(length)))
            names.append(name.value)
        executable = ctypes.create_unicode_buffer(32768)
        length = w.DWORD(len(executable))
        require(image(process, 0, executable, ctypes.byref(length)))
        created, exited, kernel_time, user_time = w.FILETIME(), w.FILETIME(), w.FILETIME(), w.FILETIME()
        require(times(process, ctypes.byref(created), ctypes.byref(exited), ctypes.byref(kernel_time), ctypes.byref(user_time)))
        return {"pid": process_id, "sid": user_sid, "groups": group_sids,
                "privileges": sorted(names), "executable": executable.value,
                "integrity": integrity, "appcontainer_sid": container_sid, "capabilities": capability_sids,
                "created": (created.dwHighDateTime << 32) | created.dwLowDateTime}
    finally:
        if token:
            close(token)
        close(process)


def inspect_named_job(name: str, worker_pid: int) -> dict:
    """Independent verifier opens the protected named job with query-only rights."""
    import ctypes
    import re
    from ctypes import wintypes as w

    if not re.fullmatch(r"Global\\WeirAdmission-\d+-[0-9a-f]{32}", name):
        raise ValueError("invalid WEIR Job Object name")
    class Basic(ctypes.Structure):
        _fields_ = [("process_time", ctypes.c_longlong), ("job_time", ctypes.c_longlong), ("flags", w.DWORD),
                    ("minimum_ws", ctypes.c_size_t), ("maximum_ws", ctypes.c_size_t), ("process_limit", w.DWORD),
                    ("affinity", ctypes.c_size_t), ("priority", w.DWORD), ("scheduling", w.DWORD)]
    class Extended(ctypes.Structure):
        _fields_ = [("basic", Basic), ("io", ctypes.c_ulonglong * 6), ("process_memory", ctypes.c_size_t),
                    ("job_memory", ctypes.c_size_t), ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t)]
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenJobObjectW.argtypes, kernel.OpenJobObjectW.restype = [w.DWORD, w.BOOL, w.LPCWSTR], w.HANDLE
    kernel.OpenProcess.argtypes, kernel.OpenProcess.restype = [w.DWORD, w.BOOL, w.DWORD], w.HANDLE
    kernel.CloseHandle.argtypes, kernel.CloseHandle.restype = [w.HANDLE], w.BOOL
    kernel.IsProcessInJob.argtypes, kernel.IsProcessInJob.restype = [w.HANDLE, w.HANDLE, ctypes.POINTER(w.BOOL)], w.BOOL
    kernel.QueryInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD, ctypes.c_void_p]
    kernel.QueryInformationJobObject.restype = w.BOOL
    job, process = kernel.OpenJobObjectW(4, False, name), None
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        process = kernel.OpenProcess(0x1000, False, worker_pid)
        if not process:
            raise ctypes.WinError(ctypes.get_last_error())
        member, limits = w.BOOL(), Extended()
        if not kernel.IsProcessInJob(process, job, ctypes.byref(member)) or not kernel.QueryInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits), None):
            raise ctypes.WinError(ctypes.get_last_error())
        return {"member": bool(member.value), "flags": limits.basic.flags,
                "process_count": limits.basic.process_limit, "memory_bytes": limits.job_memory}
    finally:
        if process:
            kernel.CloseHandle(process)
        kernel.CloseHandle(job)


__all__ = ["inspect_process", "inspect_named_job"]
