import unittest

from weir.engines.base import EnginePolicyBlocked
from weir.engines.http_connector import check_target_policy


class TargetPolicyTests(unittest.TestCase):
    def test_rejects_non_http_schemes(self):
        for url in ["ftp://example.com/file", "file:///etc/passwd", "javascript:alert(1)"]:
            with self.assertRaises(EnginePolicyBlocked):
                check_target_policy(url, [])

    def test_rejects_credentials_in_url(self):
        with self.assertRaises(EnginePolicyBlocked):
            check_target_policy("https://user:pass@example.com/", [])

    def test_rejects_loopback_and_private_literals(self):
        for url in [
            "http://127.0.0.1/admin",
            "http://10.0.0.5/",
            "http://192.168.1.1/",
            "http://169.254.169.254/latest/meta-data",
            "http://[::1]/",
        ]:
            with self.assertRaises(EnginePolicyBlocked):
                check_target_policy(url, [])

    def test_rejects_localhost_name(self):
        with self.assertRaises(EnginePolicyBlocked):
            check_target_policy("http://localhost:8080/", [])

    def test_rejects_host_outside_allowed_domains(self):
        with self.assertRaises(EnginePolicyBlocked):
            check_target_policy("https://evil.example.org/", ["github.com"])

    def test_allowed_domain_suffix_match_requires_dot_boundary(self):
        with self.assertRaises(EnginePolicyBlocked):
            check_target_policy("https://notgithub.com/", ["github.com"])


if __name__ == "__main__":
    unittest.main()
