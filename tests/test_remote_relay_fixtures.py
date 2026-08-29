from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
import sys
import unittest
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import FormatChecker, ValidationError
from jsonschema.validators import Draft202012Validator
from referencing import Registry, Resource
from weir.contract import ContractViolation, canonical_digest, contains_forbidden_key
from weir.remote_decision import (
    RemoteDecisionAcknowledgement,
    RemoteDecisionAuditRecord,
    RemoteDecisionCapsule,
    RemoteDecisionQueueRecord,
    RemoteDecisionRevocation,
    _b64url_decode,
)

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts"
FIXTURE_PATH = CONTRACTS / "fixtures" / "remote-relay-v1.json"


class RemoteRelayFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        cls.schemas: dict[str, dict[str, Any]] = {}
        resources = []
        for name in cls.manifest["schema_digests"]:
            schema = json.loads((CONTRACTS / name).read_text(encoding="utf-8"))
            cls.schemas[name] = schema
            resources.append((schema["$id"], Resource.from_contents(schema)))
        cls.registry = Registry().with_resources(resources)
        cls.public_keys = {
            key_id: Ed25519PublicKey.from_public_bytes(
                _b64url_decode(value, size=32, name="test public key")
            )
            for key_id, value in cls.manifest["test_public_keys"].items()
        }

    @classmethod
    def validator(cls, name: str) -> Draft202012Validator:
        return Draft202012Validator(
            cls.schemas[name],
            format_checker=FormatChecker(),
            registry=cls.registry,
        )

    def test_schemas_are_well_formed_and_pinned(self) -> None:
        for name, schema in self.schemas.items():
            with self.subTest(schema=name):
                Draft202012Validator.check_schema(schema)
                self.assertEqual(
                    canonical_digest(schema), self.manifest["schema_digests"][name]
                )

    def test_positive_fixtures_validate_and_round_trip(self) -> None:
        parsers = {
            "remote-decision-capsule.schema.json": RemoteDecisionCapsule.from_dict,
            "remote-decision-ack.schema.json": RemoteDecisionAcknowledgement.from_dict,
            "remote-decision-queue-state.schema.json": RemoteDecisionQueueRecord.from_dict,
            "remote-decision-revocation.schema.json": RemoteDecisionRevocation.from_dict,
            "remote-decision-audit.schema.json": RemoteDecisionAuditRecord.from_dict,
        }
        for fixture in self.manifest["positive"]:
            with self.subTest(fixture=fixture["name"]):
                document = fixture["document"]
                self.validator(fixture["schema"]).validate(document)
                self.assertEqual(
                    canonical_digest(document), fixture["canonical_sha256"]
                )
                restored = parsers[fixture["schema"]](copy.deepcopy(document))
                self.assertEqual(restored.to_dict(), document)

    def test_signed_capsules_verify_against_frozen_public_key(self) -> None:
        for fixture in self.manifest["positive"]:
            if fixture["schema"] != "remote-decision-capsule.schema.json":
                continue
            capsule = RemoteDecisionCapsule.from_dict(copy.deepcopy(fixture["document"]))
            capsule.validate_at(
                datetime.fromisoformat(capsule.issued_at),
                expected_issuer_id=capsule.issuer_id,
                expected_audience=capsule.audience,
                expected_device_id=capsule.device_id,
                public_keys=self.public_keys,
            )

    def test_negative_fixtures_reject_with_frozen_reason(self) -> None:
        for fixture in self.manifest["negative"]:
            with self.subTest(fixture=fixture["name"]):
                document = copy.deepcopy(fixture["document"])
                validator = fixture["validator"]
                if validator == "schema":
                    with self.assertRaises(ValidationError):
                        self.validator(fixture["schema"]).validate(document)
                    continue
                with self.assertRaises((ContractViolation, ValueError)) as raised:
                    capsule = RemoteDecisionCapsule.from_dict(document)
                    if validator == "capsule_signature":
                        capsule.validate_at(
                            datetime.fromisoformat(fixture["validation_time"]),
                            expected_issuer_id=capsule.issuer_id,
                            expected_audience=capsule.audience,
                            expected_device_id=capsule.device_id,
                            public_keys=self.public_keys,
                        )
                    elif validator == "capsule_runtime":
                        capsule.validate_at(
                            datetime.fromisoformat(fixture["validation_time"]),
                            expected_issuer_id=fixture["expected_issuer_id"],
                            expected_audience=fixture["expected_audience"],
                            expected_device_id=fixture["expected_device_id"],
                            public_keys=self.public_keys,
                        )
                    elif validator == "capsule_unknown_key":
                        capsule.validate_at(
                            datetime.fromisoformat(fixture["validation_time"]),
                            expected_issuer_id=capsule.issuer_id,
                            expected_audience=capsule.audience,
                            expected_device_id=capsule.device_id,
                            public_keys={},
                        )
                    elif validator != "capsule_parse":  # pragma: no cover
                        self.fail(f"unknown validator {validator!r}")
                self.assertEqual(
                    getattr(raised.exception, "reason_code", None),
                    fixture["reason_code"],
                )

    def test_capsule_and_audit_are_parameter_free(self) -> None:
        prohibited = {
            "parameters",
            "payload",
            "dom",
            "prompt",
            "credentials",
            "cookies",
            "profile_id",
            "permit",
        }
        for fixture in self.manifest["positive"]:
            if fixture["schema"] in {
                "remote-decision-capsule.schema.json",
                "remote-decision-audit.schema.json",
            }:
                document = fixture["document"]
                self.assertFalse(contains_forbidden_key(document))
                self.assertTrue(prohibited.isdisjoint(document))

    def test_fixture_generator_is_reproducible(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "generate_remote_relay_fixtures.py")],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        expected = hashlib.sha256(FIXTURE_PATH.read_bytes()).hexdigest()
        digest_line = (
            CONTRACTS / "fixtures" / "remote-relay-v1.sha256"
        ).read_text(encoding="ascii")
        self.assertEqual(digest_line, f"{expected}  remote-relay-v1.json\n")

    @unittest.skipUnless(shutil.which("node"), "Node is required for TS fixture parity")
    def test_typescript_consumer_verifies_hashes_and_signatures(self) -> None:
        result = subprocess.run(
            ["node", str(ROOT / "scripts" / "verify_remote_relay_fixtures.ts")],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("verified 8 remote relay fixtures", result.stdout)


if __name__ == "__main__":
    unittest.main()
