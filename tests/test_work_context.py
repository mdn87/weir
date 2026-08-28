import json
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

from jsonschema import FormatChecker
from jsonschema.validators import Draft202012Validator
from weir.work_context import WorkContext, WorkContextSource


class WorkContextTests(unittest.TestCase):
    def test_explicit_context_is_hashed_and_matches_contract(self):
        context = WorkContext.create(
            context_id="ctx-1",
            objective_id="objective-1",
            run_id="run-1",
            assignment_id="assignment-1",
            correlation_id="request-1",
            source=WorkContextSource.OGMI,
            evidence_refs=["weir-capture:input-1"],
            created_at="2026-08-27T12:00:00+00:00",
        )
        schema = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "contracts"
                / "work-context.schema.json"
            ).read_text(encoding="utf-8")
        )
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(
            context.to_dict()
        )

    def test_root_context_is_immutable_after_creation(self):
        context = WorkContext.create(
            context_id="ctx-1",
            run_id="run-1",
            correlation_id="request-1",
            source=WorkContextSource.CALLER,
            created_at="2026-08-27T12:00:00+00:00",
        )
        with self.assertRaises(FrozenInstanceError):
            context.run_id = "run-2"  # type: ignore[misc]

        value = context.to_dict()
        value["run_id"] = "run-2"
        with self.assertRaisesRegex(ValueError, "context_hash"):
            WorkContext.from_dict(value)

    def test_system_sources_require_their_authority_identity(self):
        with self.assertRaisesRegex(ValueError, "objective_id"):
            WorkContext.create(
                context_id="ctx-1",
                run_id="run-1",
                correlation_id="request-1",
                source=WorkContextSource.OGMI,
                created_at="2026-08-27T12:00:00+00:00",
            )

    def test_creation_does_not_treat_a_string_as_an_evidence_array(self):
        with self.assertRaisesRegex(ValueError, "evidence_refs must be an array"):
            WorkContext.create(
                context_id="ctx-1",
                run_id="run-1",
                correlation_id="request-1",
                source=WorkContextSource.CALLER,
                evidence_refs="weir-capture:not-an-array",  # type: ignore[arg-type]
                created_at="2026-08-27T12:00:00+00:00",
            )

    def test_optional_identities_and_evidence_keep_schema_types_at_runtime(self):
        context = WorkContext.create(
            context_id="ctx-1",
            run_id="run-1",
            correlation_id="request-1",
            source=WorkContextSource.CALLER,
            created_at="2026-08-27T12:00:00+00:00",
        )
        invalid_identity = context.to_dict()
        invalid_identity["objective_id"] = 7
        with self.assertRaisesRegex(ValueError, "objective_id"):
            WorkContext.from_dict(invalid_identity)

        invalid_evidence = context.to_dict()
        invalid_evidence["evidence_refs"] = "not-an-array"
        with self.assertRaisesRegex(ValueError, "evidence_refs"):
            WorkContext.from_dict(invalid_evidence)
        with self.assertRaisesRegex(ValueError, "assignment_id"):
            WorkContext.create(
                context_id="ctx-2",
                run_id="run-1",
                correlation_id="request-1",
                source=WorkContextSource.AUTOWORK,
                created_at="2026-08-27T12:00:00+00:00",
            )


if __name__ == "__main__":
    unittest.main()
