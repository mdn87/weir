"""The trusted controller owns Chromium, independent field reads and lifecycle proof."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from datetime import datetime, timezone
from threading import Timer

from weir.browser.enrolled_document import EnrolledTab
from weir.browser.enrolled_fill import require
from weir.browser.effect_driver import FADE_AUTHORITY_ID


class LinuxFieldController:
    def __init__(self, field, *, browser_service, read_source, observer, effect):
        require(observer.uid != effect.uid and observer.operation == "read" and effect.operation == "fill",
                "Observation and effect require separate Linux principals")
        self.field, self._browser_service, self._reader = field, browser_service, read_source
        self._observer, self._effect = observer, effect
        self._executor = ThreadPoolExecutor(max_workers=1)
        self._closed = False
        self._stopped = False
        self._timer = None
        try:
            self._call(self._start)
            self._timer = Timer(360, self.contain)
            self._timer.daemon = True
            self._timer.start()
        except BaseException:
            self.contain()
            raise

    def _call(self, fn, *args):
        future = self._executor.submit(fn, *args)
        try:
            return future.result(timeout=45)
        except TimeoutError:
            if not future.done() and getattr(self, "_witness", None) is not None:
                self._witness.stop()
            raise

    def _start(self):
        self._stack = ExitStack()
        self._browser, self._witness = self._stack.enter_context(self._browser_service())
        document = self._reader(self.field)
        self._tab = EnrolledTab(self._browser, self.field, document)
        self._witness.pin_document()
        self._initial = self._witness.evidence()

    def evidence(self):
        return self._call(self._witness.evidence)

    def ready(self):
        self._call(self._observer.ready)
        self._call(self._effect.ready)

    def observe_field(self):
        return self._call(self._observe, self._tab)

    def _observe(self, tab):
        return self._observer.serve("read", self.field.digest, lambda _: tab.read())

    def fill_field(self, identity):
        def fill(pinned):
            self._witness.evidence()
            return self._tab.fill_once(pinned)
        return self._call(self._effect.serve, "fill", identity, fill)

    def _close_browser(self):
        if not self._closed:
            self._stack.close()
            self._closed = True

    def _discard(self):
        self._witness.evidence()
        self._close_browser()
        first = self._witness.verify_exit()
        with self._browser_service() as (browser, witness):
            self._discard_witness = witness
            # A separate admitted reader fetches the enrolled document again.
            fresh = EnrolledTab(browser, self.field, self._reader(self.field))
            witness.pin_document()
            proof = witness.evidence()
            proof.require_current(datetime.now(timezone.utc), caller_id=FADE_AUTHORITY_ID, expected_platform="linux")
            require(proof.worker_instance_id != self._initial.worker_instance_id
                    and proof.egress_policy_digest == self._initial.egress_policy_digest
                    and self._observe(fresh)["value"] == "",
                    "Discard requires an empty field in a separately admitted browser")
            witness.evidence()
        return {"effect_browser": first, "discard_browser": witness.verify_exit()}

    def verify_discard_and_exit(self):
        return self._call(self._discard)

    def incident_evidence(self):
        result = {}
        for role, attr in (("effect_browser", "_witness"), ("discard_browser", "_discard_witness")):
            witness = getattr(self, attr, None)
            if witness is not None:
                result[role] = witness.exit_record or witness.failure_record or {"shutdown_verified": False}
        return result

    def contain(self):
        if not self._stopped:
            if self._timer is not None:
                self._timer.cancel()
            try:
                self._call(self._close_browser)
            finally:
                self._executor.shutdown(wait=False, cancel_futures=True)
                self._stopped = True
