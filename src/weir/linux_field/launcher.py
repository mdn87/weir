#!/usr/bin/python3
"""Launch only the sealed Playwright driver in a transient Linux rehearsal service."""

import os
import re
import sys
from pathlib import Path


RUNTIME = Path("/srv/lugos/runtimes/weir-operator-reports/0.6.0")
UNIT_RE = re.compile(r"weir-(?:fill-rehearsal|enrolled-field)-[0-9a-f]{16}")
PROPERTIES = {
    "DynamicUser": "yes", "User": "weir-fill-stage", "PrivateNetwork": "yes",
    "RestrictAddressFamilies": "AF_UNIX", "PrivatePIDs": "yes", "PrivateIPC": "yes",
    "PrivateTmp": "yes", "PrivateDevices": "yes", "ProtectHome": "yes",
    "ProtectSystem": "strict", "ProtectControlGroups": "yes", "NoNewPrivileges": "yes",
    "ProtectKernelTunables": "yes", "ProtectKernelModules": "yes",
    "CapabilityBoundingSet": "", "Delegate": "no", "KillMode": "control-group",
    "SystemCallFilter": "~io_uring_setup io_uring_enter io_uring_register",
    "SystemCallArchitectures": "native", "SystemCallErrorNumber": "EPERM", "Restart": "no",
    "TemporaryFileSystem": "/srv:ro /run:ro /var:ro",
    "BindReadOnlyPaths": str(RUNTIME), "MemoryMax": "512M", "TasksMax": "128",
    "RuntimeMaxSec": "90", "TimeoutStopSec": "3", "UMask": "0077",
    "LimitCORE": "0",
}

# This process must pass all four probes before exec replaces it with Node. The
# host owns the positive-control receivers. The controller never passes a socket.
PREFLIGHT = r"""
import errno, os, socket, stat, sys
for fd in (0, 1):
    if not stat.S_ISFIFO(os.fstat(fd).st_mode):
        raise RuntimeError("Expected private Playwright pipes")
null = os.open("/dev/null", os.O_WRONLY)
os.dup2(null, 2)
os.close(null)
os.closerange(3, min(os.sysconf("SC_OPEN_MAX"), 1048576))
for family, address in [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")]:
    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
        try:
            s = socket.socket(family, kind)
        except OSError as exc:
            if exc.errno in (errno.EAFNOSUPPORT, errno.EPERM, errno.EACCES):
                continue
            raise
        with s:
            s.settimeout(1)
            if kind == socket.SOCK_STREAM:
                s.connect((address, int(sys.argv[1])))
                s.sendall(b"W")
            else:
                s.sendto(b"W", (address, int(sys.argv[1])))
        raise RuntimeError("An Internet socket was available inside the browser service")
for address in (sys.argv[2], "\x00weir-fill-rx-" + sys.argv[1]):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        try:
            s.connect(address)
        except OSError as exc:
            if exc.errno in (errno.ENOENT, errno.ECONNREFUSED, errno.EACCES):
                continue
            raise
        s.sendall(b"W")
        raise RuntimeError("A host Unix receiver was reachable")
os.execv(sys.argv[3], sys.argv[3:])
"""


def main():
    unit = os.environ.get("WEIR_REHEARSAL_UNIT", "")
    port = int(os.environ["WEIR_REHEARSAL_PORT"])
    unix_socket = os.environ["WEIR_REHEARSAL_UNIX"]
    driver, = RUNTIME.glob("lib/python*/site-packages/playwright/driver")
    cli = str(driver / "package" / "cli.js")
    if (not UNIT_RE.fullmatch(unit) or not 1024 <= port <= 65535
            or not re.fullmatch(r"/tmp/weir-fill-rx-[a-z0-9_]{8}/receiver", unix_socket)
            or sys.argv[1:] != [cli, "run-driver"]):
        raise ValueError("Expected the sealed Linux rehearsal driver")
    argv = ["/usr/bin/systemd-run", "--quiet", "--pipe", "--wait", "--collect",
            "--service-type=exec", "--unit=" + unit]
    properties = PROPERTIES | ({"User": "weir-enrolled", "RuntimeMaxSec": "420"}
                               if unit.startswith("weir-enrolled-field-") else {})
    argv.extend("--property=" + key + "=" + value for key, value in properties.items())
    argv.extend(["--setenv=HOME=/tmp", "--setenv=PLAYWRIGHT_BROWSERS_PATH=" + str(RUNTIME / "browsers"),
                 "--", str(RUNTIME / "bin/python"), "-I", "-c", PREFLIGHT, str(port), unix_socket,
                 str(driver / "node"), cli, "run-driver"])
    os.execv(argv[0], argv)


if __name__ == "__main__":
    main()
