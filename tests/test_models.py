import unittest

from weir.models import DataClass, RequestMode, WebRequest


class WebRequestTests(unittest.TestCase):
    def test_read_request_is_side_effect_free(self):
        request = WebRequest(
            request_id="r1",
            run_id="run1",
            mode=RequestMode.READ,
            data_class=DataClass.PUBLIC,
            auth_context="none",
            url="https://example.com",
        )
        request.validate()
        self.assertFalse(request.side_effects_allowed)

    def test_read_request_rejects_side_effects(self):
        request = WebRequest(
            request_id="r1",
            run_id="run1",
            mode=RequestMode.READ,
            data_class=DataClass.PUBLIC,
            auth_context="none",
            url="https://example.com",
            side_effects_allowed=True,
        )
        with self.assertRaises(ValueError):
            request.validate()

    def test_profile_requires_auth_context(self):
        request = WebRequest(
            request_id="r1",
            run_id="run1",
            mode=RequestMode.READ,
            data_class=DataClass.PUBLIC,
            auth_context="none",
            profile_id="personal-browser",
            url="https://example.com",
        )
        with self.assertRaises(ValueError):
            request.validate()

    def test_constraints_must_be_json_compatible(self):
        request = WebRequest(
            request_id="req-4",
            run_id="run-1",
            mode=RequestMode.SEARCH,
            data_class=DataClass.PUBLIC,
            auth_context="app",
            profile_id="ebay-app",
            query="keyboard",
            source="ebay",
        )
        for invalid in [
            {"brands": {"Keychron"}},
            {"brands": ("Keychron",)},
            {1: "non-string key"},
            {"score": float("nan")},
        ]:
            with self.subTest(invalid=invalid):
                request.constraints = invalid
                with self.assertRaisesRegex(ValueError, "JSON-compatible"):
                    request.validate()

    def test_search_source_must_be_a_normalized_name(self):
        request = WebRequest(
            request_id="req-5",
            run_id="run-1",
            mode=RequestMode.SEARCH,
            data_class=DataClass.PUBLIC,
            auth_context="app",
            profile_id="ebay-app",
            query="keyboard",
            source="eBay marketplace",
        )
        with self.assertRaisesRegex(ValueError, "normalized lowercase"):
            request.validate()

    def test_allowed_domains_reject_malformed_labels(self):
        request = WebRequest(
            request_id="req-6",
            run_id="run-1",
            mode=RequestMode.READ,
            data_class=DataClass.PUBLIC,
            auth_context="none",
            url="https://example.com",
            allowed_domains=["example..com"],
        )
        with self.assertRaisesRegex(ValueError, "normalized lowercase domain names"):
            request.validate()


if __name__ == "__main__":
    unittest.main()
