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

from jsonschema import FormatChecker, ValidationError
from jsonschema.validators import Draft202012Validator
from referencing import Registry, Resource
from weir.actions import (
    ActionProposal,
    ExecutionPermit,
    ExecutionReceipt,
    QuarantineRecord,
    QuarantineState,
)
from weir.contract import (
    FADE_FORBIDDEN_KEYS,
    ContractViolation,
    canonical_digest,
    canonical_json_bytes,
    contains_forbidden_key,
)
from weir.events import CorrelationHeader, WeirActionEvent
from weir.evidence import AcquisitionEnvelope, EvidenceReference
from weir.models import DataClass, RequestMode, WebRequest
from weir.persistence import FileCaptureCache
from weir.work_context import WorkContext

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts"
FIXTURE_PATH = CONTRACTS / "fixtures" / "batch-0-v1.json"


class ContractFreezeFixtureTests(unittest.TestCase):
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

    @classmethod
    def validator(cls, name: str) -> Draft202012Validator:
        return Draft202012Validator(
            cls.schemas[name],
            format_checker=FormatChecker(),
            registry=cls.registry,
        )

    def test_all_frozen_schemas_are_well_formed_and_pinned(self):
        for name, schema in self.schemas.items():
            with self.subTest(schema=name):
                Draft202012Validator.check_schema(schema)
                self.assertEqual(
                    canonical_digest(schema), self.manifest["schema_digests"][name]
                )

    def test_every_positive_fixture_validates_and_round_trips(self):
        parsers = {
            "work-context.schema.json": WorkContext.from_dict,
            "acquisition-envelope.schema.json": AcquisitionEnvelope.from_dict,
            "evidence-reference.schema.json": EvidenceReference.from_dict,
            "action-proposal.schema.json": ActionProposal.from_dict,
            "execution-permit.schema.json": ExecutionPermit.from_dict,
            "execution-receipt.schema.json": ExecutionReceipt.from_dict,
            "quarantine-record.schema.json": QuarantineRecord.from_dict,
            "correlation-header.schema.json": CorrelationHeader.from_dict,
            "weir-action-event.schema.json": WeirActionEvent.from_dict,
        }
        for fixture in self.manifest["positive"]:
            with self.subTest(fixture=fixture["name"]):
                document = fixture["document"]
                self.validator(fixture["schema"]).validate(document)
                self.assertEqual(
                    canonical_digest(document), fixture["canonical_sha256"]
                )
                parser = parsers.get(fixture["schema"])
                if parser is not None:
                    parsed = parser(copy.deepcopy(document))
                    self.assertEqual(parsed.to_dict(), document)

    def test_negative_fixtures_reject_with_the_frozen_reason(self):
        for fixture in self.manifest["negative"]:
            with self.subTest(fixture=fixture["name"]):
                document = copy.deepcopy(fixture["document"])
                validator = fixture["validator"]
                if validator == "schema":
                    with self.assertRaises(ValidationError):
                        self.validator(fixture["schema"]).validate(document)
                    continue
                with self.assertRaises(ValueError) as raised:
                    if validator == "work_context_runtime":
                        WorkContext.from_dict(document)
                    elif validator == "evidence_input_runtime":
                        EvidenceReference.from_dict(document).require_materialized_content()
                    elif validator == "evidence_reference_runtime":
                        EvidenceReference.from_dict(document)
                    elif validator == "acquisition_envelope_runtime":
                        AcquisitionEnvelope.from_dict(document)
                    elif validator == "permit_clock_runtime":
                        permit = ExecutionPermit.from_dict(document)
                        permit.validate_at(
                            datetime.fromisoformat(fixture["validation_time"])
                        )
                    elif validator == "execution_receipt_runtime":
                        ExecutionReceipt.from_dict(document)
                    else:  # pragma: no cover - fixture manifest is closed below
                        self.fail(f"unknown fixture validator {validator!r}")
                actual = getattr(raised.exception, "reason_code", None)
                if actual is None and fixture["reason_code"] == "context_hash_mismatch":
                    self.assertIn("context_hash", str(raised.exception))
                else:
                    self.assertEqual(actual, fixture["reason_code"])

    def test_materialized_artifact_is_exact_canonical_content_json(self):
        fixture = next(
            item
            for item in self.manifest["positive"]
            if item["name"] == "evidence_reference.content"
        )
        reference = EvidenceReference.from_dict(fixture["document"])
        content = {"items": [{"id": "listing-1", "price_minor": 2500}]}
        payload = canonical_json_bytes(content)
        self.assertEqual(reference.verify_materialized_artifact(payload), content)

        noncanonical_payload = json.dumps(content).encode("utf-8")
        noncanonical_document = copy.deepcopy(fixture["document"])
        noncanonical_digest = hashlib.sha256(noncanonical_payload).hexdigest()
        noncanonical_document["content_hash"] = f"sha256:{noncanonical_digest}"
        noncanonical_document["artifact_ref"] = (
            f"weir-artifact:sha256:{noncanonical_digest}"
        )
        basis = copy.deepcopy(noncanonical_document)
        basis.pop("reference_hash")
        noncanonical_document["reference_hash"] = canonical_digest(basis)
        noncanonical_reference = EvidenceReference.from_dict(noncanonical_document)
        with self.assertRaisesRegex(ContractViolation, "canonical JSON"):
            noncanonical_reference.verify_materialized_artifact(noncanonical_payload)

    def test_cache_identity_includes_capture_policy_and_capture_limit(self):
        base = WebRequest(
            request_id="request-cache",
            run_id="run-cache",
            mode=RequestMode.READ,
            data_class=DataClass.PUBLIC,
            url="https://example.test/cache",
            capture_policy="metadata",
        )
        content = WebRequest.from_dict({**base.to_dict(), "capture_policy": "content"})
        metadata_key = FileCaptureCache.key_for(base, ["http"], 1024)
        content_key = FileCaptureCache.key_for(content, ["http"], 1024)
        larger_key = FileCaptureCache.key_for(content, ["http"], 2048)
        self.assertEqual(len({metadata_key, content_key, larger_key}), 3)

    def test_full_authority_contracts_survive_fade_key_screen(self):
        for fixture in self.manifest["positive"]:
            if fixture["schema"] in {
                "action-proposal.schema.json",
                "execution-permit.schema.json",
            }:
                with self.subTest(fixture=fixture["name"]):
                    self.assertFalse(contains_forbidden_key(fixture["document"]))
        self.assertEqual(
            set(self.manifest["fade_forbidden_keys"]), set(FADE_FORBIDDEN_KEYS)
        )

    def test_permit_is_valid_only_for_its_exact_proposal_and_weir_clock(self):
        documents = {
            item["name"]: item["document"] for item in self.manifest["positive"]
        }
        proposal = ActionProposal.from_dict(
            copy.deepcopy(documents["action_proposal.full_authority"])
        )
        permit = ExecutionPermit.from_dict(
            copy.deepcopy(documents["execution_permit.one_use"])
        )
        permit.validate_for(proposal, datetime.fromisoformat("2026-08-27T12:00:20+00:00"))

        other = copy.deepcopy(proposal.to_dict())
        other["work_context_hash"] = "sha256:" + "f" * 64
        basis = copy.deepcopy(other)
        basis.pop("proposal_hash")
        other["proposal_hash"] = canonical_digest(basis)
        with self.assertRaises(ContractViolation) as raised:
            permit.validate_for(
                ActionProposal.from_dict(other),
                datetime.fromisoformat("2026-08-27T12:00:20+00:00"),
            )
        self.assertEqual(raised.exception.reason_code, "permit_binding_mismatch")

    def test_quarantine_clearance_is_an_append_only_operator_successor(self):
        documents = {
            item["name"]: item["document"] for item in self.manifest["positive"]
        }
        active = QuarantineRecord.from_dict(copy.deepcopy(documents["quarantine.active"]))
        cleared = QuarantineRecord.from_dict(
            copy.deepcopy(documents["quarantine.operator_cleared"])
        )
        self.assertEqual(active.state, QuarantineState.ACTIVE)
        self.assertEqual(cleared.state, QuarantineState.CLEARED)
        self.assertEqual(cleared.supersedes_hash, active.record_hash)
        self.assertNotEqual(cleared.record_hash, active.record_hash)

    def test_public_event_is_redacted_at_construction(self):
        event = next(
            item["document"]
            for item in self.manifest["positive"]
            if item["name"] == "weir_action_event.redacted"
        )
        serialized = json.dumps(event, sort_keys=True)
        for field in (
            "parameters",
            "form_values",
            "raw_dom",
            "page_body",
            "profile_id",
        ):
            self.assertNotIn(f'"{field}"', serialized)

    def test_fixture_generator_is_reproducible(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "generate_contract_fixtures.py")],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        expected = hashlib.sha256(FIXTURE_PATH.read_bytes()).hexdigest()
        digest_line = (CONTRACTS / "fixtures" / "batch-0-v1.sha256").read_text(
            encoding="ascii"
        )
        self.assertEqual(digest_line, f"{expected}  batch-0-v1.json\n")

    @unittest.skipUnless(shutil.which("node"), "Node is required for TS fixture parity")
    def test_typescript_consumer_obtains_the_same_hashes(self):
        result = subprocess.run(
            ["node", str(ROOT / "scripts" / "verify_contract_fixtures.ts")],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("verified 13 positive fixtures", result.stdout)


if __name__ == "__main__":
    unittest.main()
