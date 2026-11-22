"""Fixed offline Chromium field diagnostic for the Windows compatibility proof."""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import subprocess
import time
from uuid import uuid4

from weir.browser.protocol import WorkerDescriptor
from weir.engines.base import EngineProbe
from weir.windows_probe import AdmissionProbeWorker


def _loader_result(argv: list[str], deadline: float) -> dict:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {"error": "deadline"}
    try:
        child = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               creationflags=subprocess.CREATE_NO_WINDOW, timeout=min(2, remaining))
    except subprocess.TimeoutExpired:
        return {"error": "timeout"}
    except OSError as exc:
        return {"error": "start_failed", "winerror": getattr(exc, "winerror", None)}
    return {"exit_code": child.returncode & 0xffffffff}


def _system_library_checks(probe: Path) -> dict:
    # Each fixed library starts in a fresh child of the same admitted worker.
    modules = ("kernel32.dll", "weir-intentionally-absent.dll", "win32u.dll", "gdi32.dll", "user32.dll",
               "dbghelp.dll", "ws2_32.dll", "crypt32.dll", "advapi32.dll", "ole32.dll", "iphlpapi.dll",
               "shell32.dll", "userenv.dll", "winmm.dll")
    deadline = time.monotonic() + 6
    static = _loader_result([str(probe.with_name("weir-user32-startup.exe"))], deadline)
    results = {name: _loader_result([str(probe), name], deadline) for name in modules}
    expected = {"kernel32.dll": 0, "ws2_32.dll": 0, "weir-intentionally-absent.dll": 126}
    return {"controls_passed": all(results[name].get("exit_code") == code for name, code in expected.items()),
            "complete": "exit_code" in static and all("exit_code" in result for result in results.values()),
            "libraries": results, "static_user32": static}


def _driver_startup_check(node: Path) -> dict:
    """Distinguish a native loader exit from a Playwright CLI failure in Session 0."""
    checks = {}
    for name, arguments, prefix in (
        ("node", ["--version"], b"v"),
        ("playwright_cli", [str(node.parent / "package" / "cli.js"), "--version"], b"Version "),
    ):
        try:
            result = subprocess.run([str(node), *arguments], stdin=subprocess.DEVNULL, capture_output=True,
                                    creationflags=subprocess.CREATE_NO_WINDOW, timeout=4)
        except (OSError, subprocess.TimeoutExpired) as exc:
            checks[name] = {"error_type": type(exc).__name__, "winerror": getattr(exc, "winerror", None)}
            break
        version_printed = result.stdout.startswith(prefix)
        checks[name] = {"exit_code": f"0x{result.returncode & 0xffffffff:08x}", "version_printed": version_printed}
        if name == "node" and (result.returncode & 0xffffffff) == 0xc0000142:
            probe = node.with_name("weir-loader-probe.exe")
            checks["system_libraries"] = _system_library_checks(probe) if probe.is_file() else {"error": "not_bundled"}
        if result.returncode or not version_printed:
            break
    return checks


class ChromiumFieldProbe:
    """Keep the fixed page alive for independent process inspection until shutdown."""

    def __init__(self, *, service_sandbox: bool = False):
        self.descriptor = WorkerDescriptor("weir-chromium-probe", "chromium-field-probe", frozenset(),
                                           "1", "probe-" + uuid4().hex)
        self._resources = ExitStack()
        self._result = None
        self._service_sandbox = service_sandbox

    def probe(self) -> EngineProbe:
        if self._result is not None:
            return self._result
        stage = "import_playwright"
        driver_connected = False
        child_stdio_verified = False
        try:
            import playwright
            from playwright.sync_api import sync_playwright

            # The matching headless shell is installed inside the hashed runtime.
            os.environ["PLAYWRIGHT_BROWSERS_PATH"] = "0"
            node = Path(playwright.__file__).parent / "driver" / "node.exe"
            os.environ["PLAYWRIGHT_NODEJS_PATH"] = str(node)
            if self._service_sandbox:
                # Host admission already verifies that every release path is free of
                # reparse points. Node can use those paths without inspecting the volume root.
                os.environ["NODE_OPTIONS"] = "--preserve-symlinks --preserve-symlinks-main"
            stage = "start_driver"
            driver = self._resources.enter_context(sync_playwright())
            driver_connected = True
            if self._service_sandbox:
                # Exercise the driver's own bounded child-stdio path before launching Chromium.
                stage = "driver_child_stdio"
                subprocess.run(
                    [str(node), "-e", "require('node:child_process').execFile(process.execPath, ['--version'], "
                     "(error, output) => { process.exitCode = error || output.trim() !== process.version ? 1 : 0 })"],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    creationflags=subprocess.CREATE_NO_WINDOW, timeout=6, check=True,
                )
                child_stdio_verified = True
            stage = "launch_chromium"
            browser = driver.chromium.launch(headless=True, chromium_sandbox=True,
                                             args=["--no-proxy-server"], timeout=10000)
            self._resources.callback(browser.close)
            stage = "read_field"
            context = browser.new_context(offline=True, java_script_enabled=False, service_workers="block")
            self._resources.callback(context.close)
            page = context.new_page()
            page.set_default_timeout(5000)
            page.set_content('<label>WEIR proof<input readonly value="weir-observation"></label>')
            field = page.get_by_role("textbox", name="WEIR proof", exact=True)
            if field.count() != 1 or field.input_value() != "weir-observation":
                raise ValueError("fixed field mismatch")
            stage = "identify_processes"
            session = browser.new_browser_cdp_session()
            try:
                processes = session.send("SystemInfo.getProcessInfo")["processInfo"]
            finally:
                session.detach()
            pids = {kind: sorted(p["id"] for p in processes if p["type"] == kind)
                    for kind in ("browser", "renderer")}
            if len(pids["browser"]) != 1 or not pids["renderer"]:
                raise ValueError("missing live browser or renderer")
            details = {"stage": "field_observed", "field_match": True, "processes": pids}
            if self._service_sandbox:
                details.update(driver_connected=driver_connected, child_stdio_verified=child_stdio_verified)
            self._result = EngineProbe(self.descriptor.engine, True, browser.version, json.dumps(details))
        except Exception as exc:
            self.shutdown()
            # Raw driver diagnostics can contain environment details or command lines.
            details = {"stage": stage, "error_type": type(exc).__name__, "winerror": getattr(exc, "winerror", None)}
            if self._service_sandbox:
                details.update(driver_connected=driver_connected, child_stdio_verified=child_stdio_verified)
                if stage == "start_driver":
                    details["driver_pipe_closed"] = str(exc) == "Connection closed while reading from the driver"
                    details["startup_check"] = _driver_startup_check(node)
            trace = exc.__traceback__
            while trace:
                frame = trace.tb_frame
                if (frame.f_globals.get("__name__"), frame.f_code.co_name) in {
                    ("socket", "_fallback_socketpair"), ("asyncio.windows_utils", "pipe"),
                    ("subprocess", "_execute_child"), ("asyncio.windows_events", "__init__"),
                }:
                    details["component"] = frame.f_globals["__name__"] + "." + frame.f_code.co_name
                trace = trace.tb_next
            self._result = EngineProbe(self.descriptor.engine, False, None, json.dumps(details))
        return self._result

    def shutdown(self) -> None:
        self._resources.close()


class ServiceChromiumProbe(ChromiumFieldProbe):
    def __init__(self, supervisor_pid, credential_paths, ports):
        super().__init__(service_sandbox=True)
        self._isolation = AdmissionProbeWorker(supervisor_pid, credential_paths, ports)

    def probe(self) -> EngineProbe:
        if self._isolation is None:
            return super().probe()
        try:
            isolation = self._isolation.probe()
        finally:
            # Release the generic probe's sentinel before Chromium consumes its Job quota.
            self._isolation.shutdown()
            self._isolation = None
        return isolation


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--desktop-control", action="store_true")
    modes.add_argument("--desktop-loader-control", action="store_true")
    if parser.parse_args().desktop_loader_control:
        import playwright

        probe = Path(playwright.__file__).parent / "driver" / "weir-loader-probe.exe"
        checks = _system_library_checks(probe)
        print(json.dumps(checks))
        expected = all(value.get("exit_code") == (126 if name == "weir-intentionally-absent.dll" else 0)
                       for name, value in checks["libraries"].items())
        return 0 if checks["complete"] and expected and checks["static_user32"].get("exit_code") == 37 else 1
    worker = ChromiumFieldProbe()
    try:
        result = worker.probe()
        print(json.dumps({"mode": "desktop_control", "available": result.available,
                          "version": result.version, **json.loads(result.detail)}))
        return 0 if result.available else 1
    finally:
        worker.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
