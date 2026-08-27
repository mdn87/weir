import json
import tempfile
import unittest
from pathlib import Path

import yaml
from jsonschema import FormatChecker
from jsonschema.validators import Draft202012Validator
from weir.actions import Risk
from weir.engines.base import EnginePolicyBlocked
from weir.models import DataClass, RequestMode, WebRequest

from weir.profiles import SiteProfile, SiteProfileRegistry

ROOT = Path(__file__).resolve().parents[1]


def _request(
    url: str, mode: RequestMode = RequestMode.READ, profile_id: str | None = None
) -> WebRequest:
    return WebRequest(
        request_id="r1",
        run_id="run1",
        mode=mode,
        data_class=DataClass.PUBLIC,
        auth_context="app" if profile_id else "none",
        profile_id=profile_id,
        url=url,
    )


class SiteProfileTests(unittest.TestCase):
    def test_repository_profiles_match_the_contract_and_runtime_loader(self):
        schema = json.loads(
            (ROOT / "contracts" / "site-profile.schema.json").read_text(encoding="utf-8")
        )
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        for path in (ROOT / "profiles").glob("*.yaml"):
            validator.validate(yaml.safe_load(path.read_text(encoding="utf-8")))

        registry = SiteProfileRegistry.from_directory(ROOT / "profiles")
        self.assertIn("github-public", [profile.id for profile in registry.all()])
        self.assertIn("ebay-marketplace", [profile.id for profile in registry.all()])

        template = next(
            profile
            for profile in registry.all()
            if profile.id == "example-authenticated-portal"
        )
        self.assertIn(Risk.EXTERNAL_SUBMIT, template.approval_risks)
        self.assertEqual(
            template.known_failures["login_expired"], "pause_for_reauthentication"
        )
        self.assertEqual(template.retention["har"], "metadata_only")
        self.assertTrue(template.notes)

    def test_packaged_resource_loader_accepts_traversable_profile_data(self):
        registry = SiteProfileRegistry.from_resource_directory(ROOT / "profiles")
        self.assertIn("github-public", [profile.id for profile in registry.all()])
        self.assertIn("ebay-marketplace", [profile.id for profile in registry.all()])

    def test_domain_match_uses_a_label_boundary(self):
        registry = SiteProfileRegistry.from_directory(ROOT / "profiles")
        self.assertEqual(
            registry.resolve(_request("https://api.github.com/repos/x/y")).id, "github-public"
        )
        self.assertIsNone(registry.resolve(_request("https://notgithub.com/repos/x/y")))

    def test_most_specific_matching_domain_wins(self):
        broad = SiteProfile.from_dict(
            {
                "contract_version": "0.1",
                "id": "broad",
                "domains": ["example.com", "an-unrelated-but-long-domain.example"],
                "preferred_engines": ["http"],
                "auth_mode": "none",
                "allowed_modes": ["read"],
            }
        )
        narrow = SiteProfile.from_dict(
            {
                "contract_version": "0.1",
                "id": "narrow",
                "domains": ["api.example.com"],
                "preferred_engines": ["oc"],
                "auth_mode": "none",
                "allowed_modes": ["read"],
            }
        )
        registry = SiteProfileRegistry([broad, narrow])
        self.assertEqual(registry.resolve(_request("https://api.example.com/data")), narrow)

    def test_duplicate_domain_ownership_is_rejected(self):
        values = {
            "contract_version": "0.1",
            "domains": ["example.com"],
            "preferred_engines": ["http"],
            "auth_mode": "none",
            "allowed_modes": ["read"],
        }
        first = SiteProfile.from_dict(dict(values, id="first"))
        second = SiteProfile.from_dict(dict(values, id="second"))
        with self.assertRaisesRegex(ValueError, "owned by both"):
            SiteProfileRegistry([first, second])

    def test_search_source_selects_site_profile_without_conflating_the_auth_profile(self):
        registry = SiteProfileRegistry.from_directory(ROOT / "profiles")
        request = WebRequest(
            request_id="r1",
            run_id="run1",
            mode=RequestMode.SEARCH,
            data_class=DataClass.PUBLIC,
            auth_context="app",
            profile_id="ebay-app",
            query="keyboard",
            source="ebay",
        )
        self.assertEqual(registry.resolve(request).id, "ebay-marketplace")

    def test_profile_orders_candidates_without_removing_fallbacks(self):
        profile = SiteProfile.from_dict(
            {
                "contract_version": "0.1",
                "id": "example",
                "domains": ["example.com"],
                "preferred_engines": ["agent-browser-read", "oc"],
                "auth_mode": "none",
                "allowed_modes": ["read"],
            }
        )
        ordered, selected = SiteProfileRegistry([profile]).apply(
            _request("https://example.com/page"), ["http", "oc", "agent-browser-read"]
        )
        self.assertEqual(ordered, ["agent-browser-read", "oc", "http"])
        self.assertEqual(selected, profile)

    def test_profile_rejects_a_mode_it_does_not_allow(self):
        profile = SiteProfile.from_dict(
            {
                "contract_version": "0.1",
                "id": "read-only",
                "domains": ["example.com"],
                "preferred_engines": ["oc"],
                "auth_mode": "none",
                "allowed_modes": ["read"],
            }
        )
        request = _request("https://example.com", RequestMode.OBSERVE)
        with self.assertRaises(EnginePolicyBlocked):
            SiteProfileRegistry([profile]).apply(request, [])

    def test_profile_enforces_its_authentication_mode(self):
        profile = SiteProfile.from_dict(
            {
                "contract_version": "0.1",
                "id": "public-only",
                "domains": ["example.com"],
                "preferred_engines": ["oc"],
                "auth_mode": "none",
                "allowed_modes": ["read"],
            }
        )
        request = _request("https://example.com", profile_id="browser-profile")
        with self.assertRaisesRegex(EnginePolicyBlocked, "authenticated access"):
            SiteProfileRegistry([profile]).apply(request, ["oc"])

    def test_retention_policy_is_typed_and_fails_closed_on_typos(self):
        value = {
            "contract_version": "0.1",
            "id": "bad-retention",
            "domains": ["example.com"],
            "preferred_engines": ["playwright-observer"],
            "auth_mode": "dedicated_profile",
            "allowed_modes": ["observe"],
            "retention": {"screenshots": "full-evidnce"},
        }
        with self.assertRaisesRegex(ValueError, "invalid 'screenshots'"):
            SiteProfile.from_dict(value)

    def test_invalid_yaml_is_reported_with_its_path(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "broken.yaml"
            path.write_text("id: [", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "broken.yaml"):
                SiteProfileRegistry.from_directory(Path(temp))


if __name__ == "__main__":
    unittest.main()
