"""Rehearse one unsaved fill through Fade, WEIR and isolated Chromium on lugos-host."""

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import sys
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from importlib.metadata import version
from pathlib import Path

from linux_canary_host import Receivers, ServiceWitness
from run_fade_weir_action_canary import PlaywrightFixtureEffectWorker, run_canary


ORIGIN = "http://127.0.0.1"
URL = ORIGIN + "/fixture-form"
MARKER = "WEIR-CANARY"
HTML = ('<!doctype html><html><head><title>WEIR rehearsal</title></head><body>'
        '<input type="text" aria-label="Fixture value" data-testid="fixture-value">'
        '</body></html>')


class Fixture:
    origin = ORIGIN
    url = URL


class FieldObserver:
    """Only two fixed read methods reach this controller-owned protocol session."""

    def __init__(self, session):
        self._session = session
        self.identity = None

    def value(self):
        tree = self._session.send("Page.getFrameTree")["frameTree"]
        frame = tree["frame"]
        snap = self._session.send("DOMSnapshot.captureSnapshot", {"computedStyles": []})
        strings = snap["strings"]
        doc, = snap["documents"]
        nodes = doc["nodes"]
        inputs = [i for i, name in enumerate(nodes["nodeName"]) if strings[name] == "INPUT"]
        index, = inputs
        attrs = [strings[i] for i in nodes["attributes"][index]]
        if (dict(zip(attrs[::2], attrs[1::2])) !=
                {"type": "text", "aria-label": "Fixture value", "data-testid": "fixture-value"}
                or tree.get("childFrames") or frame["url"] != URL
                or strings[doc["documentURL"]] != URL or strings[doc["frameId"]] != frame["id"]):
            raise RuntimeError("The observed document or field differs from the fixture")
        identity = (frame["id"], frame["loaderId"], nodes["backendNodeId"][index])
        if self.identity is not None and identity != self.identity:
            raise RuntimeError("The enrolled document or its field was replaced")
        self.identity = identity
        values = nodes["inputValue"]
        string_index = dict(zip(values["index"], values["value"]))[index]
        # Blink's snapshot uses -1 for the empty string.
        if string_index == -1:
            return ""
        if not 0 <= string_index < len(strings):
            raise RuntimeError("The DOM snapshot did not encode a known input value")
        return strings[string_index]


class FixtureBrowser:
    def __init__(self, runtime, witness):
        self.browser = runtime.chromium.launch(headless=True, chromium_sandbox=True)
        ctx = self.browser.new_context(offline=True, java_script_enabled=False, service_workers="block",
                                       accept_downloads=False)
        ctx.set_default_timeout(5000)
        self.page = ctx.new_page()
        self.requests = 0

        def serve(route):
            self.requests += 1
            req = route.request
            if (self.requests != 1 or req.url != URL or req.method != "GET"
                    or not req.is_navigation_request() or req.frame != self.page.main_frame):
                return route.abort()
            route.fulfill(status=200, body=HTML, headers={
                "content-type": "text/html; charset=utf-8", "cache-control": "no-store",
                "content-security-policy": "default-src 'none'; form-action 'none'; base-uri 'none'",
            })

        ctx.route("**/*", serve)
        self.page.goto(URL, wait_until="load", timeout=15000)
        self.observer = FieldObserver(ctx.new_cdp_session(self.page))
        self.witness = witness

    def read(self):
        self.witness.check()
        if self.requests != 1:
            raise RuntimeError("The browser attempted an extra request")
        return self.observer.value()


class IsolatedFixtureWorker(PlaywrightFixtureEffectWorker):
    marker = MARKER

    def __init__(self, *args, witness):
        self.witness = witness
        self.observed_values = []
        self.after_observations = 0
        super().__init__(*args)

    def _start(self):
        from playwright.sync_api import sync_playwright

        self._playwright = sync_playwright().start()
        try:
            self.fixture = FixtureBrowser(self._playwright, self.witness)
            self._browser = self.fixture.browser
            self._page = self.fixture.page
            self._context = self._page.context
            field = self._page.get_by_role("textbox", name="Fixture value", exact=True)
            if field.count() != 1 or self.fixture.read() != "":
                raise RuntimeError("The new rehearsal field must be unique and empty")
            self.field_handle = field.element_handle()
        except BaseException:
            self._playwright.stop()
            raise

    def _read_value(self):
        value = self.fixture.read()
        if value not in ("", MARKER):
            raise RuntimeError("Unexpected value in the rehearsal field")
        self.observed_values.append(value)
        return value

    def _fill_marker(self):
        if self.apply_calls != 1 or self._read_value() != "":
            raise RuntimeError("Only one fill of the original empty field is permitted")
        self.field_handle.fill(MARKER)

    def _observe(self, session_id, command_id, stage):
        result = super()._observe(session_id, command_id, stage)
        if stage == "after":
            if self.observed_values[-1] != MARKER:
                raise RuntimeError("The independent DOM readback did not match the marker")
            self.after_observations += 1
        return result

    def effect_count(self):
        # Completed fills with independent after-captures. Dispatch attempts are
        # counted separately by the shared driver harness.
        return self.after_observations


def recovered_receipt(run_dir, command, expected, fade_source):
    from weir.actions import ExecutionPermit
    from weir.browser.effect_driver import BrowserActionDriver, FADE_AUTHORITY_ID, SyntheticFixtureEffectPolicy
    from weir.browser.store import SQLiteSessionStore
    from weir.models import DataClass
    from weir.persistence import CaptureStore
    from weir.proposals import ActionProposalStore
    from weir.service import (ACTION_EXECUTE_SCOPE, ClientCredential, ClientRegistry,
                              ServiceRequestError, WeirServiceApplication)

    sys.path.insert(0, str(fade_source))
    from fade.weir_authority import AuthorityRunStore

    class ClosedWorker:
        worker_id = "closed-rehearsal-worker"
        worker_instance_id = "closed-rehearsal-instance"

        def observe(self, *args, **kwargs):
            raise AssertionError("A recovered command attempted to use the closed browser")

        apply = observe

    store = SQLiteSessionStore(run_dir / "browser.sqlite3")
    try:
        reservation = store.action_reservation_by_command(command)
        proposals = ActionProposalStore(run_dir / "proposals", CaptureStore(run_dir / "captures"), store)
        proposal = proposals.load(reservation.proposal_hash)
        record = AuthorityRunStore(run_dir / "fade-runs").load(command)
        permit = ExecutionPermit.from_dict(record["permit"])
        driver = BrowserActionDriver(store, proposals, ClosedWorker(),
                                     SyntheticFixtureEffectPolicy("synthetic-action-fixture", ORIGIN))
        status = driver.status(command)
        replay = driver.execute(command_id=command, request_digest=reservation.request_digest,
                                submitted_proposal=proposal, permit=permit)
        if (status is None or replay.to_dict() != status.to_dict() or replay.state != "completed"
                or replay.receipt.receipt_hash != expected):
            raise RuntimeError("The restarted dispatcher did not return the original receipt")

        # Submit that same valid test permit to the ordinary service with no
        # synthetic admission configured. Its public action endpoint must deny.
        secret = secrets.token_urlsafe(36)
        clients = ClientRegistry([ClientCredential(FADE_AUTHORITY_ID, secret,
                                 frozenset({ACTION_EXECUTE_SCOPE}), frozenset({DataClass.PUBLIC}))])
        default = WeirServiceApplication(object(), clients, proposal_store=proposals,
                                         session_store=store, action_driver=driver)
        body = {"schema_version": 1, "command_id": command, "request_digest": reservation.request_digest,
                "proposal": proposal.to_dict(), "permit": permit.to_dict()}
        deadline = datetime.now(timezone.utc) + timedelta(seconds=15)
        try:
            default.handle("POST", "/v1/actions/execute",
                           {"Authorization": "Bearer " + secret, "X-Weir-Client-Id": FADE_AUTHORITY_ID,
                            "X-Weir-Deadline": deadline.isoformat()},
                           json.dumps(body).encode())
        except ServiceRequestError as exc:
            if exc.status != 503 or exc.reason_code != "action_admission_unavailable":
                raise
        else:
            raise RuntimeError("The standard service admitted a rehearsal permit")
    finally:
        store.close()


def rehearse(run_dir, fade_source):
    from playwright.sync_api import sync_playwright

    os.umask(0o077)
    reports_path = run_dir / "fade-weir.json"
    ledger = run_dir / "private"
    run_dir.mkdir(parents=True, exist_ok=False)
    launcher = Path(__file__).with_name("linux_canary_driver.py").resolve()
    os.environ["PLAYWRIGHT_NODEJS_PATH"] = str(launcher)
    witnesses = []

    def new_service():
        unit = "weir-fill-rehearsal-" + secrets.token_hex(8)
        os.environ["WEIR_REHEARSAL_UNIT"] = unit
        witness = ServiceWitness(unit)
        witnesses.append(witness)
        return witness

    with Receivers() as receivers:
        os.environ["WEIR_REHEARSAL_PORT"] = str(receivers.port)
        os.environ["WEIR_REHEARSAL_UNIX"] = receivers.unix_path
        receivers.positive_control()
        first = new_service()
        evidence = run_canary(ledger, reports_path, fade_source,
                              fixture_factory=lambda: nullcontext(Fixture()),
                              worker_factory=lambda *args: IsolatedFixtureWorker(*args, witness=first))
        first.confirm_exit()
        receivers.require_silent()
        binding = evidence["bindings"]
        subprocess.run([sys.executable, "-E", "-s", str(Path(__file__).resolve()), "recover",
                        str(ledger), binding["command_id"], binding["receipt_hash"], str(fade_source)],
                       check=True, timeout=10)
        second = new_service()
        with sync_playwright() as runtime:
            fresh = FixtureBrowser(runtime, second)
            try:
                chromium_version = fresh.browser.version
                if fresh.read() != "":
                    raise RuntimeError("The discarded value appeared in a fresh browser")
            finally:
                fresh.browser.close()
        second.confirm_exit()
        if first.identity[0] == second.identity[0] or first.policy_hash != second.policy_hash:
            raise RuntimeError("Discard verification requires a fresh service with the same policy")
        receivers.require_silent()
        receivers.positive_control()
        return {
            "schema": "weir-linux-unsaved-fill-rehearsal/v1", "scope": "offline fixed public fixture",
            "run_id": evidence["run_id"], "finished_at": datetime.now(timezone.utc).isoformat(),
            "weir_version": version("lugos-weir"), "playwright_version": version("playwright"),
            "chromium_version": chromium_version, "resolved_unit_policy_sha256": first.policy_hash,
            "fixture_sha256": hashlib.sha256(HTML.encode()).hexdigest(), "receipt_hash": binding["receipt_hash"],
            "authority": evidence["assertions"], "separate_dom_snapshot_verified_exact_value": True,
            "same_loader_and_backend_node": True, "fresh_browser_empty": True,
            "receipt_reopened_in_new_process": True, "closed_browser_replay_returned_same_receipt": True,
            "ordinary_service_denied_rehearsal_permit": True, "closed_service_trees": len(witnesses),
            "service_invocations": [w.identity[0] for w in witnesses],
            "maximum_observed_processes": [w.peak for w in witnesses],
            "memory_limit_bytes": 536870912, "task_limit": 128,
            "receiver_controls_before_and_after": sorted(receivers.sockets), "unexpected_deliveries": 0,
            "production_destination_enrolled": False, "production_action_performed": False,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    run = modes.add_parser("run")
    run.add_argument("run_dir", type=Path)
    run.add_argument("--fade-source", required=True, type=Path)
    recover = modes.add_parser("recover")
    recover.add_argument("ledger", type=Path)
    recover.add_argument("command")
    recover.add_argument("receipt_hash")
    recover.add_argument("fade_source", type=Path)
    args = parser.parse_args()
    if args.mode == "recover":
        recovered_receipt(args.ledger, args.command, args.receipt_hash, args.fade_source)
    else:
        result = rehearse(args.run_dir.resolve(), args.fade_source.resolve())
        print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
