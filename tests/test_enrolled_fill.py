import unittest
from dataclasses import replace

from weir.browser.enrolled_document import EnrolledDocument, HEADERS, byte_digest, inert_page
from weir.browser.enrolled_fill import EnrolledField
from weir.contract import canonical_digest
from weir.engines.base import EnginePolicyBlocked

from weir.linux_field.runtime import verify_task_events


def target(url="https://canary.example/field"):
    return EnrolledField(url=url, name="Fixture value", test_id="fixture-value",
                         profile_id="public-canary", profile_digest=canonical_digest("policy"),
                         credential_binding_id="anonymous-canary", body_digest=canonical_digest("body"),
                         headers_digest=canonical_digest("headers"), tls_fingerprint=canonical_digest("cert"),
                         peer_address="192.0.2.8")


class EnrollmentTests(unittest.TestCase):
    def test_exact_page_and_version_define_the_enrollment(self):
        self.assertNotEqual(target().digest, target("https://canary.example/other").digest)
        for url in ("http://canary.example/field", "https://u@canary.example/field",
                    "https://canary.example/field?", "https://canary.example/field#",
                    "https://canary.example/../field", "https://canary.example/%2e/field"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                target(url).validate()

    def test_only_the_enrolled_inert_template_can_be_rendered(self):
        field = target()
        body = inert_page(field.name, field.test_id)
        field = replace(field, body_digest=byte_digest(body), headers_digest=canonical_digest(HEADERS))
        page = EnrolledDocument(body, tuple(HEADERS.items()), field.tls_fingerprint)
        page.verify(field)
        for extra in ((("Set-Cookie", "a=b"),), (("Refresh", "0"),), (("Content-Type", "text/html"),)):
            with self.subTest(extra=extra), self.assertRaises(EnginePolicyBlocked):
                replace(page, headers=page.headers + extra).verify(field)
        for suffix in (b"<form></form>", b"<iframe></iframe>", b"<script></script>", b"<img src='/asset'>"):
            new = body + suffix
            with self.subTest(suffix=suffix), self.assertRaises(EnginePolicyBlocked):
                replace(page, body=new).verify(replace(field, body_digest=byte_digest(new)))
        with self.assertRaises(EnginePolicyBlocked):
            replace(page, peer_fingerprint=canonical_digest("replaced-cert")).verify(field)

    def test_lifetime_trace_classifies_reaped_threads_at_creation(self):
        verify_task_events("worker-42: task_newtask: pid=43 comm=worker clone_flags=3d0f00 oom_score_adj=0")
        for event in ("task_newtask: pid=43 comm=worker clone_flags=1200011 oom_score_adj=0",
                      "sched_process_exec: filename=/usr/bin/true", "lost events"):
            with self.subTest(event=event), self.assertRaises(EnginePolicyBlocked):
                verify_task_events(event)
