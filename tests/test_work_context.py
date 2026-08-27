import json
import unittest
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

    def test_context_tampering_is_detected(self):
        context = WorkContext.create(
            context_id="ctx-1",
            run_id="run-1",
            correlation_id="request-1",
            source=WorkContextSource.CALLER,
            created_at="2026-08-27T12:00:00+00:00",
        )
        context.run_id = "run-2"
        with self.assertRaisesRegex(ValueError, "context_hash"):
            context.validate()

    def test_system_sources_require_their_authority_identity(self):
        with self.assertRaisesRegex(ValueError, "objective_id"):
            WorkContext.create(
                context_id="ctx-1",
                run_id="run-1",
                correlation_id="request-1",
                source=WorkContextSource.OGMI,
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
        context.objective_id = 7
        with self.assertRaisesRegex(ValueError, "objective_id"):
            context.validate()

        context.objective_id = None
        context.evidence_refs = ()
        with self.assertRaisesRegex(ValueError, "evidence_refs"):
            context.validate()
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
