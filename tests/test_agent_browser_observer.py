import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from weir.browser.agent_browser_observer import AgentBrowserObserverWorker
from weir.browser.protocol import SessionSpec, WorkerCapability, WorkerCommand
from weir.engines.base import EnginePolicyBlocked
from weir.models import DataClass


class FakeRunner:
    def __init__(self) -> None:
        self.calls = []
        self.url = "http://127.0.0.1:8765/start"

    def __call__(self, argv, timeout):
        self.calls.append((list(argv), timeout))
        if "open" in argv:
            self.url = argv[argv.index("open") + 1]
            return 0, '{"success":true,"data":{}}', ""
        if "snapshot" in argv:
            return (
                0,
                '{"success":true,"data":{"snapshot":"- button \\"Save\\"",'
                '"refs":{"e1":{"role":"button","name":"Save",'
                '"testId":"save","disabled":false}}},'
                '"_boundary":{"nonce":"abc","origin":"http://127.0.0.1"}}',
                "",
            )
        if "get" in argv:
            name = argv[argv.index("get") + 1]
            value = self.url if name == "url" else "Fixture"
            return 0, f'{{"success":true,"data":{{"value":"{value}"}}}}', ""
        if "close" in argv:
            return 0, "", ""
        return 1, "", "unexpected command"


def _spec(profile_id="ephemeral:test"):
    return SessionSpec(
        session_id="session-1",
        worker_session_id="pending-1",
        owner_run_id="run-1",
        profile_id=profile_id,
        site_profile_id="ephemeral-test",
        credential_scope="ephemeral",
        data_class=DataClass.BWA_INTERNAL,
        allowed_domains=("127.0.0.1",),
        initial_url="http://127.0.0.1:8765/start",
    )


def _command(operation, worker_session_id, payload, command_id=None):
    return WorkerCommand.build(
        command_id=command_id or f"cmd-{operation}",
        operation=operation,
        session_id="session-1",
        worker_session_id=worker_session_id,
        owner_run_id="run-1",
        expected_revision=0,
        session_epoch=1,
        lease_fence=1,
        deadline_at=datetime.now(timezone.utc) + timedelta(minutes=1),
        payload=payload,
    )


class AgentBrowserObserverTests(unittest.TestCase):
    def test_ephemeral_session_is_allowlisted_and_normalized(self):
        runner = FakeRunner()
        worker = AgentBrowserObserverWorker(binary="mock-agent-browser", runner=runner)
        spec = _spec()
        worker_session_id = worker.open_session(
            spec, _command("open", "pending-1", {"spec": spec.to_dict()})
        )
        observation = worker.observe(
            spec.session_id,
            _command(
                "observe", worker_session_id, {"session_id": spec.session_id}
            ),
        )
        self.assertEqual(observation.url, spec.initial_url)
        self.assertEqual(observation.title, "Fixture")
        self.assertEqual(observation.elements[0].ref, "e1")
        self.assertEqual(observation.elements[0].name, "Save")
        self.assertIn("content boundary", observation.notes[0])
        self.assertFalse(worker.descriptor.supports(WorkerCapability.SCREENSHOT))

        forbidden = {
            "--profile",
            "--state",
            "--restore",
            "--session-name",
            "--cdp",
            "--auto-connect",
            "--args",
        }
        for argv, _ in runner.calls:
            self.assertTrue(forbidden.isdisjoint(argv))
            self.assertIn("--allowed-domains", argv)
            self.assertIn("--content-boundaries", argv)

    def test_persistent_profile_is_rejected_before_process_launch(self):
        runner = FakeRunner()
        worker = AgentBrowserObserverWorker(binary="mock-agent-browser", runner=runner)
        spec = _spec("real-chrome-profile")
        with self.assertRaisesRegex(EnginePolicyBlocked, "ephemeral"):
            worker.open_session(
                spec, _command("open", "pending-1", {"spec": spec.to_dict()})
            )
        self.assertEqual(runner.calls, [])

    def test_failed_post_open_validation_closes_ephemeral_cli_session(self):
        class EscapingRunner(FakeRunner):
            def __call__(self, argv, timeout):
                if "get" in argv and argv[argv.index("get") + 1] == "url":
                    self.calls.append((list(argv), timeout))
                    return 0, '{"success":true,"data":{"value":"http://localhost/"}}', ""
                return super().__call__(argv, timeout)

        runner = EscapingRunner()
        worker = AgentBrowserObserverWorker(binary="mock-agent-browser", runner=runner)
        spec = _spec()
        with self.assertRaisesRegex(EnginePolicyBlocked, "outside allowed_domains"):
            worker.open_session(
                spec, _command("open", "pending-1", {"spec": spec.to_dict()})
            )
        self.assertTrue(any("close" in argv for argv, _ in runner.calls))

    def test_navigation_and_close_preserve_explicit_session_identity(self):
        runner = FakeRunner()
        worker = AgentBrowserObserverWorker(binary="mock-agent-browser", runner=runner)
        spec = _spec()
        worker_session_id = worker.open_session(
            spec, _command("open", "pending-1", {"spec": spec.to_dict()})
        )
        final_url = worker.navigate(
            spec.session_id,
            "http://127.0.0.1:8765/next",
            _command(
                "navigate",
                worker_session_id,
                {
                    "session_id": spec.session_id,
                    "url": "http://127.0.0.1:8765/next",
                },
            ),
        )
        self.assertEqual(final_url, "http://127.0.0.1:8765/next")
        worker.close_session(
            spec.session_id,
            _command(
                "close", worker_session_id, {"session_id": spec.session_id}
            ),
        )

    def test_attach_requires_the_complete_session_identity(self):
        runner = FakeRunner()
        worker = AgentBrowserObserverWorker(binary="mock-agent-browser", runner=runner)
        opened = _spec()
        worker_session_id = worker.open_session(
            opened, _command("open", "pending-1", {"spec": opened.to_dict()})
        )
        attached = replace(opened, worker_session_id=worker_session_id)
        self.assertTrue(
            worker.attach_session(
                attached,
                _command(
                    "attach",
                    worker_session_id,
                    {"spec": attached.to_dict()},
                    command_id="attach-complete-identity",
                ),
            )
        )

        mismatches = (
            replace(attached, site_profile_id="other-site"),
            replace(attached, credential_scope="admin"),
            replace(attached, data_class=DataClass.PUBLIC),
        )
        for index, mismatched in enumerate(mismatches, start=1):
            with self.subTest(spec=mismatched):
                self.assertFalse(
                    worker.attach_session(
                        mismatched,
                        _command(
                            "attach",
                            worker_session_id,
                            {"spec": mismatched.to_dict()},
                            command_id=f"attach-mismatch-{index}",
                        ),
                    )
                )


if __name__ == "__main__":
    unittest.main()
