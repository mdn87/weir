import unittest
from unittest.mock import patch

from weir.browser.policy import (
    check_browser_resource_policy,
    check_browser_target_policy,
    host_is_allowed,
)
from weir.engines.base import EnginePolicyBlocked
from weir.models import DataClass

PUBLIC_ADDRESS = [(None, None, None, None, ("93.184.216.34", 0))]
PRIVATE_ADDRESS = [(None, None, None, None, ("127.0.0.1", 0))]


class BrowserPolicyTests(unittest.TestCase):
    def test_requires_an_explicit_allowlist(self):
        with self.assertRaisesRegex(EnginePolicyBlocked, "explicit domain allowlist"):
            check_browser_target_policy(
                "https://example.com", [], DataClass.PUBLIC, resolve=False
            )

    def test_domain_matching_uses_a_label_boundary(self):
        self.assertTrue(host_is_allowed("api.example.com", ["example.com"]))
        self.assertFalse(host_is_allowed("notexample.com", ["example.com"]))

    @patch("weir.browser.policy.socket.getaddrinfo", return_value=PRIVATE_ADDRESS)
    def test_public_sessions_reject_private_addresses(self, _resolve):
        with self.assertRaisesRegex(EnginePolicyBlocked, "non-public address"):
            check_browser_target_policy(
                "http://internal.example.test",
                ["internal.example.test"],
                DataClass.PUBLIC,
            )

    @patch("weir.browser.policy.socket.getaddrinfo", return_value=PRIVATE_ADDRESS)
    def test_internal_sessions_allow_explicit_private_targets(self, _resolve):
        self.assertEqual(
            check_browser_target_policy(
                "http://internal.example.test/path",
                ["internal.example.test"],
                DataClass.BWA_INTERNAL,
            ),
            "internal.example.test",
        )

    @patch("weir.browser.policy.socket.getaddrinfo", return_value=PUBLIC_ADDRESS)
    def test_rejects_cross_domain_redirects(self, _resolve):
        with self.assertRaisesRegex(EnginePolicyBlocked, "outside allowed_domains"):
            check_browser_target_policy(
                "https://evil.example/redirect", ["example.com"], DataClass.PUBLIC
            )

    def test_rejects_credentials_and_active_non_http_schemes(self):
        for url in (
            "https://user:pass@example.com/",
            "file:///etc/passwd",
            "javascript:alert(1)",
        ):
            with self.subTest(url=url), self.assertRaises(EnginePolicyBlocked):
                check_browser_target_policy(
                    url, ["example.com"], DataClass.PUBLIC, resolve=False
                )

    def test_allows_renderer_local_subresources_only_on_resource_path(self):
        for url in ("about:blank", "data:text/plain,ok", "blob:https://example.com/id"):
            check_browser_resource_policy(url, ["example.com"], DataClass.PUBLIC)
            with self.assertRaises(EnginePolicyBlocked):
                check_browser_target_policy(
                    url, ["example.com"], DataClass.PUBLIC, resolve=False
                )


if __name__ == "__main__":
    unittest.main()
