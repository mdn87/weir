import tempfile
import unittest
from pathlib import Path
from unittest import mock

from weir.engines.base import EngineFailure
from weir.engines.ebay_connector import _canonical_url
from weir.engines.shims import safe_argv

NPM_SHIM = (
    "@ECHO off\r\nGOTO start\r\n:find_dp0\r\nSET dp0=%~dp0\r\nEXIT /b\r\n:start\r\n"
    'endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & "%_prog%"  '
    '"%dp0%\\..\\tool\\src\\cli.js" %*\r\n'
)

TRACKING_URL = "https://www.ebay.com/itm/377439547044?_trkparms=abc&hash=item57e0d2:g:xyz"


class SafeArgvTests(unittest.TestCase):
    def test_plain_binaries_pass_through(self):
        self.assertEqual(safe_argv("/usr/bin/oc", ["open", TRACKING_URL]), ["/usr/bin/oc", "open", TRACKING_URL])

    def test_npm_shim_is_unwrapped_to_node(self):
        with tempfile.TemporaryDirectory() as tmp:
            shim = Path(tmp) / "tool.CMD"
            shim.write_text(NPM_SHIM, encoding="utf-8")
            script = Path(tmp) / ".." / "tool" / "src"
            script = Path(tmp) / "tool" / "src"
            # shim resolves %dp0%\..\tool\src\cli.js relative to the shim dir
            target = Path(tmp).parent / "tool" / "src" / "cli.js"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("", encoding="utf-8")
            try:
                with mock.patch("weir.engines.shims.shutil.which", return_value="C:/node/node.exe"):
                    argv = safe_argv(str(shim), ["open", TRACKING_URL])
                self.assertEqual(argv[0], "C:/node/node.exe")
                self.assertTrue(argv[1].endswith("cli.js"))
                self.assertEqual(argv[2:], ["open", TRACKING_URL])
            finally:
                target.unlink()

    def test_unresolvable_shim_refuses_metacharacters(self):
        with tempfile.TemporaryDirectory() as tmp:
            shim = Path(tmp) / "tool.CMD"
            shim.write_text("@ECHO off\r\nsomething-unrecognized\r\n", encoding="utf-8")
            with self.assertRaises(EngineFailure):
                safe_argv(str(shim), ["open", TRACKING_URL])
            # clean arguments still pass through the shim
            argv = safe_argv(str(shim), ["open", "https://www.ebay.com/itm/377439547044"])
            self.assertEqual(argv[0], str(shim))


class CanonicalUrlTests(unittest.TestCase):
    def test_tracking_parameters_are_stripped(self):
        self.assertEqual(_canonical_url(TRACKING_URL), "https://www.ebay.com/itm/377439547044")

    def test_clean_urls_are_unchanged(self):
        self.assertEqual(
            _canonical_url("https://www.ebay.de/itm/12345"), "https://www.ebay.de/itm/12345"
        )

    def test_empty_url_stays_empty(self):
        self.assertEqual(_canonical_url(""), "")


if __name__ == "__main__":
    unittest.main()
