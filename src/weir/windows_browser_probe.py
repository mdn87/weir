"""Fixed offline Chromium field diagnostic for the Windows compatibility proof."""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import json
import os
from uuid import uuid4

from weir.browser.protocol import WorkerDescriptor
from weir.engines.base import EngineProbe
from weir.windows_probe import AdmissionProbeWorker


class ChromiumFieldProbe:
    """Keep the fixed page alive for independent process inspection until shutdown."""

    def __init__(self):
        self.descriptor = WorkerDescriptor("weir-chromium-probe", "chromium-field-probe", frozenset(),
                                           "1", "probe-" + uuid4().hex)
        self._resources = ExitStack()
        self._result = None

    def probe(self) -> EngineProbe:
        if self._result is not None:
            return self._result
        stage = "import_playwright"
        try:
            from playwright.sync_api import sync_playwright

            # The matching headless shell is installed inside the hashed runtime.
            os.environ["PLAYWRIGHT_BROWSERS_PATH"] = "0"
            stage = "start_driver"
            driver = self._resources.enter_context(sync_playwright())
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
            self._result = EngineProbe(self.descriptor.engine, True, browser.version, json.dumps(details))
        except Exception as exc:
            self.shutdown()
            # Raw driver diagnostics can contain environment details or command lines.
            details = {"stage": stage, "error_type": type(exc).__name__, "winerror": getattr(exc, "winerror", None)}
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
        super().__init__()
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
    parser.add_argument("--desktop-control", action="store_true", required=True)
    parser.parse_args()
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
