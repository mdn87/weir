from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts.build_windows_runtime import configure_appcontainer_pipes
from weir.windows_browser_probe import _driver_startup_check, _system_library_checks


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
        with TemporaryDirectory() as directory, patch.object(subprocess, "CREATE_NO_WINDOW", 0, create=True), \
             patch.object(subprocess, "run", return_value=failure) as run:
            checks = _driver_startup_check(Path(directory) / "node.exe")
        self.assertEqual(checks, {"node": {"exit_code": "0xc0000142", "version_printed": False},
                                  "system_libraries": {"error": "not_bundled"}})
        run.assert_called_once()

    def test_native_loader_exit_runs_only_the_bundled_probe(self):
        with TemporaryDirectory() as directory, patch.object(subprocess, "CREATE_NO_WINDOW", 0, create=True), \
             patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0xc0000142, b"", b"")), \
             patch("weir.windows_browser_probe._system_library_checks", return_value={"complete": True}) as check:
            probe = Path(directory) / "weir-loader-probe.exe"
            probe.touch()
            result = _driver_startup_check(probe.with_name("node.exe"))
            check.assert_called_once_with(probe)
            self.assertEqual(result["system_libraries"], {"complete": True})

    def test_library_check_distinguishes_the_absent_control_from_failed_initialization(self):
        def run(argv, **kwargs):
            self.assertEqual(kwargs['stdout'], subprocess.DEVNULL)
            self.assertEqual(kwargs['stderr'], subprocess.DEVNULL)
            if len(argv) == 1:
                return subprocess.CompletedProcess(argv, 0xc0000142)
            result = {'weir-intentionally-absent.dll': 126, 'user32.dll': 1114}.get(argv[1], 0)
            return subprocess.CompletedProcess(argv, result)

        with patch.object(subprocess, 'CREATE_NO_WINDOW', 0, create=True), patch.object(subprocess, 'run', run):
            checks = _system_library_checks(Path('sealed/weir-loader-probe.exe'))
        self.assertTrue(checks['controls_passed'] and checks['complete'])
        self.assertEqual(checks['libraries']['user32.dll'], {"exit_code": 1114})
        self.assertEqual(checks['static_user32'], {"exit_code": 0xc0000142})

    def test_unobserved_libraries_are_distinct_from_native_exit_codes(self):
        def run(argv, **kwargs):
            if len(argv) == 1:
                raise FileNotFoundError()
            if argv[1] == 'user32.dll':
                raise subprocess.TimeoutExpired('probe', 2)
            return subprocess.CompletedProcess(argv, 126 if argv[1] == 'weir-intentionally-absent.dll' else 0)

        with patch.object(subprocess, 'CREATE_NO_WINDOW', 0, create=True), \
             patch.object(subprocess, 'run', run):
            checks = _system_library_checks(Path('sealed/weir-loader-probe.exe'))
        self.assertFalse(checks['complete'])
        self.assertTrue(checks['controls_passed'])
        self.assertEqual(checks['libraries']['user32.dll'], {"error": "timeout"})
        self.assertEqual(checks['static_user32']['error'], 'start_failed')
