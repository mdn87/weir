from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts.build_windows_runtime import configure_appcontainer_pipes
from weir.windows_browser_probe import _driver_startup_check


class WindowsRuntimeTests(unittest.TestCase):
    def test_browser_runtime_uses_the_container_namespace(self):
        with TemporaryDirectory() as folder:
            module = Path(folder) / "Lib" / "asyncio" / "windows_utils.py"
            module.parent.mkdir(parents=True)
            original = rb"prefix=r'\\.\pipe\python-pipe-{:d}-{:d}-'.format(" + b"\r\n"
            module.write_bytes(original)
            configure_appcontainer_pipes(Path(folder))
            expected = original.replace(b"python-pipe-", b"LOCAL\\python-pipe-")
            self.assertEqual(module.read_bytes(), expected)
            configure_appcontainer_pipes(Path(folder))
            self.assertEqual(module.read_bytes(), expected)

    def test_unrecognized_pipe_implementation_stops_the_build(self):
        with TemporaryDirectory() as folder:
            module = Path(folder) / "Lib" / "asyncio" / "windows_utils.py"
            module.parent.mkdir(parents=True)
            module.write_bytes(b"# Different upstream implementation\n")
            with self.assertRaisesRegex(ValueError, "pipe prefix"):
                configure_appcontainer_pipes(Path(folder))
            self.assertEqual(module.read_bytes(), b"# Different upstream implementation\n")

    def test_native_loader_exit_is_reported_before_the_cli_runs(self):
        failure = subprocess.CompletedProcess([], 0xC0000142, b"", b"private diagnostic text")
        with patch.object(subprocess, "CREATE_NO_WINDOW", 0, create=True), \
             patch.object(subprocess, "run", return_value=failure) as run:
            checks = _driver_startup_check(Path("driver/node.exe"))
        self.assertEqual(checks, {"node": {"exit_code": "0xc0000142", "version_printed": False}})
        run.assert_called_once()
