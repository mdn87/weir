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


if __name__ == "__main__":
    unittest.main()
