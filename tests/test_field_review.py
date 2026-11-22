import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


class FieldReviewTests(unittest.TestCase):
    def test_commissioned_audience_cannot_create_a_passkey_review(self):
        from weir.engines.base import EnginePolicyBlocked
        from weir.linux_field.review import owner_review
        with self.assertRaises(EnginePolicyBlocked):
            owner_review(None, SimpleNamespace(audience="weir.production.first-fill"))

    def test_installed_operator_commands_do_not_need_a_source_checkout(self):
        with tempfile.TemporaryDirectory() as temp:
            result = subprocess.run([sys.executable, "-m", "weir.linux_field.cli", "template"],
                                    cwd=temp, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            template = json.loads(result.stdout)
            self.assertIn('aria-label="WEIR canary"', template["html"])
            self.assertEqual(template["headers"]["cache-control"], "no-store")

    def test_empty_host_status_never_creates_the_grant_or_ledger(self):
        from weir.linux_field.review import local_readiness
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with patch("weir.linux_field.review.sys.platform", "linux"):
                result = local_readiness(root / "config", root / "state", root / "witness")
            self.assertEqual(result["host_state"], "incomplete")
            self.assertEqual(list(root.iterdir()), [])
