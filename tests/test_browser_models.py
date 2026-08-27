import json
import unittest
from pathlib import Path

from jsonschema import FormatChecker, ValidationError
from jsonschema.validators import Draft202012Validator
from weir.browser.locators import (
    LocatorAmbiguousError,
    LocatorNotFoundError,
    StaleObservationError,
    resolve_locator,
)
from weir.browser.models import (
    BrowserSession,
    ControllerKind,
    ControllerLease,
    NameMatch,
    Observation,
    ObservedElement,
    ResolvedTarget,
    SemanticLocator,
    SessionState,
)
from weir.models import DataClass

CONTRACTS = Path(__file__).resolve().parents[1] / "contracts"
NOW = "2026-08-27T07:00:00+00:00"
LATER = "2026-08-27T08:00:00+00:00"


def _validator(schema_name: str) -> Draft202012Validator:
    schema = json.loads((CONTRACTS / schema_name).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _lease() -> ControllerLease:
    return ControllerLease(
        session_id="browser-1",
        lease_id="lease-1",
        controller_id="run-automation",
        kind=ControllerKind.AUTOMATION,
        fencing_token="runtime-secret-token",
        generation=4,
        expires_at=LATER,
    )


def _session() -> BrowserSession:
    return BrowserSession(
        session_id="browser-1",
        owner_run_id="run-owner",
        engine="playwright",
        worker_id="browser-worker-1",
        worker_session_id="pw-context-2",
        profile_id="ebay-personal",
        data_class=DataClass.PERSONAL,
        allowed_domains=["ebay.com", "www.ebay.com"],
        state=SessionState.ACTIVE,
        revision=7,
        epoch=2,
        current_url="https://www.ebay.com/mye/myebay/watchlist",
        created_at=NOW,
        updated_at=NOW,
        expires_at=LATER,
        controller_lease=_lease().public_view(),
    )


def _elements() -> list[ObservedElement]:
    return [
        ObservedElement(
            ref="element-1",
            role="button",
            name="Submit order",
            test_id="submit-order",
            state="enabled",
        ),
        ObservedElement(
            ref="element-2",
            role="button",
            name="SUBMIT ORDER",
            test_id="submit-order-secondary",
            state="disabled",
        ),
        ObservedElement(
            ref="element-3",
            role="link",
            name="Cancel",
            test_id=None,
            state="enabled",
        ),
    ]


def _observation(**overrides) -> Observation:
    values = {
        "observation_id": "observation-1",
        "session_id": "browser-1",
        "session_revision": 7,
        "session_epoch": 2,
        "capture_id": "webcap-1",
        "captured_at": NOW,
        "url": "https://www.ebay.com/checkout",
        "title": "Checkout",
        "elements": _elements(),
        "accessibility_snapshot": {
            "role": "document",
            "children": [{"role": "button", "name": "Submit order"}],
        },
        "artifact_refs": ["weir-artifact:sha256:abc"],
    }
    values.update(overrides)
    return Observation.create(**values)


class ControllerLeaseTests(unittest.TestCase):
    def test_public_view_matches_schema_and_redacts_fencing_token(self):
        lease = _lease()
        public = lease.to_public_dict()

        _validator("controller-lease.schema.json").validate(public)
        self.assertNotIn("fencing_token", public)
        self.assertNotIn("runtime-secret-token", json.dumps(public))
        self.assertNotIn("runtime-secret-token", repr(lease))

    def test_to_dict_is_always_the_redacted_public_view(self):
        self.assertEqual(_lease().to_dict(), _lease().public_view().to_dict())

    def test_internal_lease_rehydration_requires_token_out_of_band(self):
        restored = ControllerLease.from_dict(
            _lease().to_public_dict(), fencing_token="new-runtime-token"
        )
        self.assertEqual(restored.fencing_token, "new-runtime-token")
        self.assertEqual(restored.kind, ControllerKind.AUTOMATION)

    def test_public_contract_rejects_a_leaked_token(self):
        public = _lease().to_public_dict()
        public["fencing_token"] = "leaked"
        with self.assertRaises(ValidationError):
            _validator("controller-lease.schema.json").validate(public)


class BrowserSessionTests(unittest.TestCase):
    def test_session_round_trip_matches_schema(self):
        value = _session().to_dict()
        _validator("browser-session.schema.json").validate(value)
        self.assertEqual(BrowserSession.from_dict(value).to_dict(), value)

    def test_session_rejects_non_normalized_or_duplicate_domains(self):
        session = _session()
        session.allowed_domains = ["EBAY.COM"]
        with self.assertRaisesRegex(ValueError, "normalized domain"):
            session.validate()

        session.allowed_domains = ["ebay.com", "ebay.com"]
        with self.assertRaisesRegex(ValueError, "unique normalized"):
            session.validate()

    def test_session_rejects_lease_for_another_session(self):
        session = _session()
        lease_value = _lease().to_public_dict()
        lease_value["session_id"] = "browser-2"
        session.controller_lease = _lease().public_view().from_dict(lease_value)
        with self.assertRaisesRegex(ValueError, "must match"):
            session.validate()

    def test_session_from_dict_rejects_unknown_fields(self):
        value = _session().to_dict()
        value["fencing_token"] = "must-never-appear"
        with self.assertRaisesRegex(ValueError, "unknown fields"):
            BrowserSession.from_dict(value)

    def test_schema_rejects_unnormalized_domain(self):
        value = _session().to_dict()
        value["allowed_domains"] = ["Example.COM"]
        with self.assertRaises(ValidationError):
            _validator("browser-session.schema.json").validate(value)


class ObservationTests(unittest.TestCase):
    def test_observation_round_trip_matches_schema(self):
        value = _observation().to_dict()
        _validator("observation.schema.json").validate(value)
        self.assertEqual(Observation.from_dict(value).to_dict(), value)

    def test_content_hash_is_deterministic_and_ignores_envelope_identity(self):
        first = _observation()
        second = _observation(
            observation_id="observation-2",
            captured_at="2026-08-27T07:01:00+00:00",
        )
        self.assertEqual(first.observation_hash, second.observation_hash)

    def test_content_hash_covers_session_revision_and_accessibility_content(self):
        first = _observation()
        newer = _observation(session_revision=8)
        changed = _observation(accessibility_snapshot={"role": "dialog"})
        self.assertNotEqual(first.observation_hash, newer.observation_hash)
        self.assertNotEqual(first.observation_hash, changed.observation_hash)

    def test_round_trip_rejects_tampered_content(self):
        value = _observation().to_dict()
        value["elements"][0]["name"] = "Place order"
        with self.assertRaisesRegex(ValueError, "does not match"):
            Observation.from_dict(value)

    def test_duplicate_element_refs_are_rejected(self):
        elements = _elements()
        elements[1] = ObservedElement(
            ref="element-1", role="button", name="Other", state="enabled"
        )
        with self.assertRaisesRegex(ValueError, "refs must be unique"):
            _observation(elements=elements)

    def test_non_json_accessibility_snapshot_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "JSON-compatible"):
            _observation(accessibility_snapshot={"bad": object()})


class SemanticLocatorTests(unittest.TestCase):
    def test_locator_round_trip_matches_schema(self):
        locator = SemanticLocator(
            role="button",
            name="Submit order",
            name_match=NameMatch.EXACT,
            test_id=None,
            required_state="enabled",
        )
        value = locator.to_dict()
        _validator("semantic-locator.schema.json").validate(value)
        self.assertEqual(SemanticLocator.from_dict(value).to_dict(), value)

    def test_exact_name_is_case_sensitive(self):
        target = resolve_locator(
            SemanticLocator(role="button", name="Submit order"), _observation()
        )
        self.assertEqual(target.element_ref, "element-1")

        with self.assertRaises(LocatorNotFoundError):
            resolve_locator(
                SemanticLocator(role="button", name="submit order"), _observation()
            )

    def test_casefold_name_requires_unique_match(self):
        with self.assertRaises(LocatorAmbiguousError) as caught:
            resolve_locator(
                SemanticLocator(
                    role="button",
                    name="submit order",
                    name_match=NameMatch.CASEFOLD,
                ),
                _observation(),
            )
        self.assertEqual(caught.exception.code, "locator_ambiguous")
        self.assertEqual(caught.exception.match_count, 2)

    def test_test_id_and_required_state_disambiguate(self):
        by_test_id = resolve_locator(
            SemanticLocator(test_id="submit-order-secondary"), _observation()
        )
        by_state = resolve_locator(
            SemanticLocator(
                role="button",
                name="submit order",
                name_match=NameMatch.CASEFOLD,
                required_state="enabled",
            ),
            _observation(),
        )
        self.assertEqual(by_test_id.element_ref, "element-2")
        self.assertEqual(by_state.element_ref, "element-1")

    def test_ordinal_is_zero_based_and_deterministic(self):
        locator = SemanticLocator(
            role="button",
            name="submit order",
            name_match=NameMatch.CASEFOLD,
            ordinal=1,
        )
        first = resolve_locator(locator, _observation())
        second = resolve_locator(locator, _observation())
        self.assertEqual(first.element_ref, "element-2")
        self.assertEqual(first.to_dict(), second.to_dict())

    def test_out_of_range_ordinal_has_stable_not_found_error(self):
        with self.assertRaises(LocatorNotFoundError) as caught:
            resolve_locator(
                SemanticLocator(role="button", ordinal=5), _observation()
            )
        self.assertEqual(caught.exception.code, "locator_not_found")
        self.assertIn("ordinal 5", str(caught.exception))

    def test_stale_session_revision_and_epoch_are_rejected(self):
        locator = SemanticLocator(test_id="submit-order")
        for kwargs in (
            {"expected_session_id": "browser-2"},
            {"expected_revision": 8},
            {"expected_epoch": 3},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(StaleObservationError) as caught:
                    resolve_locator(locator, _observation(), **kwargs)
                self.assertEqual(caught.exception.code, "stale_observation")

    def test_resolved_target_round_trip(self):
        target = resolve_locator(
            SemanticLocator(test_id="submit-order"),
            _observation(),
            expected_session_id="browser-1",
            expected_revision=7,
            expected_epoch=2,
        )
        value = target.to_dict()
        self.assertEqual(ResolvedTarget.from_dict(value).to_dict(), value)
        self.assertEqual(target.session_revision, 7)
        self.assertTrue(target.locator_hash.startswith("sha256:"))

    def test_empty_locator_is_rejected_by_model_and_schema(self):
        locator = SemanticLocator()
        with self.assertRaisesRegex(ValueError, "requires role"):
            locator.validate()

        value = {
            "contract_version": "0.2",
            "role": None,
            "name": None,
            "name_match": "exact",
            "test_id": None,
            "required_state": None,
            "ordinal": None,
        }
        with self.assertRaises(ValidationError):
            _validator("semantic-locator.schema.json").validate(value)


if __name__ == "__main__":
    unittest.main()
