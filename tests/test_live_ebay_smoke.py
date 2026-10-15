"""Opt-in live smoke for the CLI surface Lode consumes.

Skipped unless WEIR_LIVE_SMOKE=1 and eBay application credentials are set
(WEIR_EBAY_CLIENT_ID/WEIR_EBAY_CLIENT_SECRET or EBAY_CLIENT_ID/EBAY_CLIENT_SECRET).
It makes a handful of read-only Browse API calls and never contacts sellers.

    WEIR_LIVE_SMOKE=1 python -m unittest -v tests.test_live_ebay_smoke
"""

import json
import os
import shutil
import subprocess
import sys
import unittest
import urllib.parse
from pathlib import Path

from jsonschema import FormatChecker
from jsonschema.validators import Draft202012Validator
from referencing import Registry, Resource

CONTRACTS = Path(__file__).resolve().parents[1] / "contracts"
QUERY = os.environ.get("WEIR_LIVE_SMOKE_QUERY", "RTX 3090 24GB")
NO_MATCH_QUERY = "zzqx weir smoke no such listing 7f3a9c"


def _credentials_present() -> bool:
    def has(*names: str) -> bool:
        return any(os.environ.get(name) for name in names)

    return has("WEIR_EBAY_CLIENT_ID", "EBAY_CLIENT_ID") and has(
        "WEIR_EBAY_CLIENT_SECRET", "EBAY_CLIENT_SECRET"
    )


def _weir(*args: str) -> tuple[int, dict]:
    proc = subprocess.run(
        [sys.executable, "-m", "weir.cli", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=300,
    )
    stream = proc.stdout if proc.returncode == 0 else proc.stderr
    return proc.returncode, json.loads(stream)


@unittest.skipUnless(
    os.environ.get("WEIR_LIVE_SMOKE") == "1" and _credentials_present(),
    "live smoke is opt-in: set WEIR_LIVE_SMOKE=1 and eBay application credentials",
)
class LiveEbaySmokeTests(unittest.TestCase):
    def test_search_then_reread_the_first_listing(self):
        code, envelope = _weir("search", QUERY, "--source", "ebay", "--pages", "1")
        self.assertEqual(code, 0, envelope)
        content = envelope["capture"]["content"]
        listings = content["listings"]
        self.assertGreater(len(listings), 0, "live query returned no listings")

        resources = []
        for name in ("marketplace-listing", "marketplace-search-result"):
            schema = json.loads((CONTRACTS / f"{name}.schema.json").read_text(encoding="utf-8"))
            resources.append((schema["$id"], Resource.from_contents(schema)))
        registry = Registry().with_resources(resources)
        validator = Draft202012Validator(
            registry.contents("https://lugos.local/weir/marketplace-search-result.schema.json"),
            registry=registry,
            format_checker=FormatChecker(),
        )
        self.assertEqual(list(validator.iter_errors(content)), [])
        for listing in listings:
            parts = urllib.parse.urlsplit(listing["canonical_url"])
            self.assertEqual((parts.query, parts.fragment), ("", ""))

        first = listings[0]
        code, read = _weir("read", first["canonical_url"], "--engine", "ebay")
        self.assertEqual(code, 0, read)
        reread = read["capture"]["content"]["listing"]
        self.assertEqual(reread["source_item_id"], first["source_item_id"])
        self.assertEqual(reread["canonical_url"], first["canonical_url"])

    def test_no_match_query_is_an_explicit_zero_total(self):
        code, envelope = _weir("search", NO_MATCH_QUERY, "--source", "ebay")
        self.assertEqual(code, 0, envelope)
        content = envelope["capture"]["content"]
        self.assertEqual(content["listings"], [])
        self.assertEqual(content["pagination"]["total_reported"], 0)

    @unittest.skipIf(
        shutil.which("oc") or shutil.which("agent-browser"),
        "page readers are installed; this checks the reader-less hosted runner",
    )
    def test_enrich_without_page_readers_fails_clearly(self):
        code, error = _weir("enrich", "https://www.ebay.com/itm/316000000001")
        self.assertEqual(code, 2)
        self.assertEqual(error["class"], "engine_unavailable")


if __name__ == "__main__":
    unittest.main()
