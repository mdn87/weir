import contextlib
import io
import json
import unittest

from weir.cli import main


class ReadBoundaryPolicyTests(unittest.TestCase):
    def _run(self, argv: list[str]) -> tuple[int, str]:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = main(argv)
        return code, stderr.getvalue()

    def test_private_target_is_blocked_before_any_engine(self):
        for url in ["http://127.0.0.1/", "http://192.168.1.1/admin", "http://169.254.169.254/latest"]:
            code, err = self._run(["read", url, "--engine", "oc"])
            self.assertEqual(code, 2)
            payload = json.loads(err)
            self.assertEqual(payload["class"], "policy_blocked")

    def test_non_http_scheme_is_blocked(self):
        code, err = self._run(["read", "file:///etc/passwd", "--engine", "auto"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(err)["class"], "policy_blocked")

    def test_fake_engine_bypasses_boundary_for_tests_only(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = main(["read", "fake://ok/page", "--engine", "fake"])
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(stdout.getvalue())["ok"])


if __name__ == "__main__":
    unittest.main()
