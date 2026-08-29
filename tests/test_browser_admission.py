from __future__ import annotations

import json
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest import mock

from weir.browser.admission import (
    CredentialProtectionEvidence,
    LocalSyntheticActionAdmission,
    ProductionAdmission,
    ProductionControlEvidence,
    WorkerContainmentEvidence,
    WorkerResourceLimits,
)
from weir.browser.broker import BrowserSessionBroker
from weir.browser.effect_driver import SyntheticFixtureEffectPolicy
from weir.contract import canonical_digest
from weir.engines.base import EnginePolicyBlocked

NOW = datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc)
LIMITS = WorkerResourceLimits(512 * 1024 * 1024, 16)
CONTAINMENT = WorkerContainmentEvidence(
    platform="windows",
    process_id=4242,
    process_tree_enforced=True,
    kill_on_supervisor_exit=True,
    resource_limits=LIMITS,
    resource_limits_enforced=True,
)
CREDENTIAL = CredentialProtectionEvidence(
    caller_id="fade-weir-authority",
    source_id="windows-credential-manager-fade",
    acl_policy_digest=canonical_digest({"owner": "weir-service", "readers": ["fade"]}),
    protected=True,
)


def _evidence(**overrides: object) -> ProductionControlEvidence:
    values: dict[str, object] = {
        "attestation_id": "admission-4242",
        "platform": "windows",
        "service_identity": "S-1-5-21-weir-service",
        "worker_identity": "S-1-5-21-weir-service",
        "worker_id": "production-worker",
        "worker_instance_id": "production-worker-instance",
        "containment": CONTAINMENT,
        "restricted_identity": True,
        "credential_protection": (CREDENTIAL,),
        "lifecycle_supervisor": "windows-service-control-manager",
        "lifecycle_instance_id": "weir-production-service",
        "lifecycle_healthy": True,
        "egress_policy_id": "weir-production-egress-v1",
        "egress_policy_digest": canonical_digest(
            {"default": "deny", "allow": ["evidence.example:443"]}
        ),
        "egress_enforced": True,
        "verified_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=2)).isoformat(),
    }
    values.update(overrides)
    return ProductionControlEvidence.create(**values)  # type: ignore[arg-type]


class BrowserAdmissionContractTests(unittest.TestCase):
    def test_round_trip_is_exact_and_contains_no_credential_value(self) -> None:
        evidence = _evidence()
        payload = evidence.to_dict()
        restored = ProductionControlEvidence.from_dict(payload)

        self.assertEqual(restored, evidence)
        serialized = json.dumps(payload, sort_keys=True)
        self.assertNotIn("cookie", serialized.casefold())
        self.assertNotIn("bearer", serialized.casefold())
        self.assertNotIn("credential_value", serialized.casefold())

        with self.assertRaises(ValueError):
            ProductionControlEvidence.from_dict({**payload, "extra": True})

    def test_tamper_stale_and_incomplete_controls_fail_closed(self) -> None:
        evidence = _evidence()
        with self.assertRaisesRegex(ValueError, "hash does not match"):
            replace(
                evidence, lifecycle_instance_id="different-service-instance"
            ).validate()
        with self.assertRaisesRegex(ValueError, "worker identity"):
            _evidence(worker_identity="different-worker-account")

        with self.assertRaisesRegex(EnginePolicyBlocked, "not current"):
            evidence.require_current(
                NOW + timedelta(minutes=3),
                caller_id="fade-weir-authority",
                expected_platform="windows",
            )
        with self.assertRaisesRegex(EnginePolicyBlocked, "credential protection"):
            evidence.require_current(
                NOW,
                caller_id="another-caller",
                expected_platform="windows",
            )
        with self.assertRaisesRegex(EnginePolicyBlocked, "controls are incomplete"):
            _evidence(egress_enforced=False).require_current(
                NOW,
                caller_id="fade-weir-authority",
                expected_platform="windows",
            )

    def test_invalid_resource_and_credential_evidence_is_rejected(self) -> None:
        for limits in (
            WorkerResourceLimits(1, 16),
            WorkerResourceLimits(512 * 1024 * 1024, 0),
        ):
            with self.assertRaises(ValueError):
                limits.validate()

        with self.assertRaises(ValueError):
            CredentialProtectionEvidence(
                caller_id="fade-weir-authority",
                source_id="source",
                acl_policy_digest="not-a-digest",
                protected=True,
            ).validate()

    def test_production_gate_binds_exact_process_worker_and_caller(self) -> None:
        evidence = _evidence()
        admission = ProductionAdmission(
            lambda: evidence,
            clock=lambda: NOW,
            expected_platform="windows",
        )
        worker = SimpleNamespace(
            production_process_transport=True,
            containment_evidence=CONTAINMENT,
            descriptor=SimpleNamespace(
                worker_id=evidence.worker_id,
                instance_id=evidence.worker_instance_id,
            ),
            worker_id=evidence.worker_id,
            worker_instance_id=evidence.worker_instance_id,
        )

        admission.require_browser_worker(worker, caller_id="fade-weir-authority")
        admission.require_external_action(
            caller_id="fade-weir-authority",
            action_driver=SimpleNamespace(worker=worker),
        )

        with self.assertRaisesRegex(EnginePolicyBlocked, "process transport"):
            admission.require_browser_worker(
                SimpleNamespace(
                    production_process_transport=False,
                    containment_evidence=CONTAINMENT,
                    descriptor=worker.descriptor,
                ),
                caller_id="fade-weir-authority",
            )
        with self.assertRaisesRegex(EnginePolicyBlocked, "process worker"):
            admission.require_external_action(
                caller_id="fade-weir-authority",
                action_driver=SimpleNamespace(
                    worker=replace(CONTAINMENT, process_id=9999)
                ),
            )

    def test_provider_failure_and_local_canary_boundary_fail_closed(self) -> None:
        def broken_provider() -> ProductionControlEvidence:
            raise OSError("host inspector unavailable")

        admission = ProductionAdmission(
            broken_provider,
            clock=lambda: NOW,
            expected_platform="windows",
        )
        with self.assertRaisesRegex(EnginePolicyBlocked, "unavailable"):
            admission.require_browser_worker(object(), caller_id="fade-weir-authority")

        local = LocalSyntheticActionAdmission("approved-local-fixture")
        local.require_external_action(
            caller_id="fade-weir-authority",
            action_driver=SimpleNamespace(
                policy=SyntheticFixtureEffectPolicy(
                    "synthetic-action-fixture",
                    "http://127.0.0.1:8765",
                )
            ),
        )
        with self.assertRaisesRegex(EnginePolicyBlocked, "synthetic fixture"):
            local.require_external_action(
                caller_id="fade-weir-authority",
                action_driver=SimpleNamespace(policy=object()),
            )

    def test_production_broker_rejects_in_process_worker_before_use(self) -> None:
        evidence = _evidence()
        admission = ProductionAdmission(
            lambda: evidence,
            clock=lambda: NOW,
            expected_platform="windows",
        )
        worker = SimpleNamespace(
            descriptor=SimpleNamespace(worker_id=evidence.worker_id),
            production_process_transport=False,
            containment_evidence=CONTAINMENT,
        )
        broker = BrowserSessionBroker(
            [worker],
            store=mock.Mock(),
            capture_store=mock.Mock(),
            profiles=mock.Mock(),
            production_admission=admission,
            production_caller_id="fade-weir-authority",
        )

        with self.assertRaisesRegex(EnginePolicyBlocked, "process transport"):
            broker._worker(evidence.worker_id)  # noqa: SLF001 - admission boundary

        with self.assertRaises(ValueError):
            BrowserSessionBroker(
                [worker],
                store=mock.Mock(),
                capture_store=mock.Mock(),
                profiles=mock.Mock(),
                production_admission=admission,
            )


if __name__ == "__main__":
    unittest.main()
