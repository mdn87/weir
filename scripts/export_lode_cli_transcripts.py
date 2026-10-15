"""Record `weir search` / `weir enrich` CLI transcripts for Lode's WeirCollector.

Each scenario runs `weir.cli.main` in-process against a stubbed eBay Browse
API or stubbed page readers -- no network, no credentials, no reader CLIs --
and records exactly what Lode's subprocess runner receives: argv, exit code,
stdout and stderr. `tests/test_lode_cli_contract.py` asserts on these
transcripts; Lode vendors the written files under `tests/fixtures/weir/` so
its parser is tested against real WEIR output for the pinned commit.

Usage: python scripts/export_lode_cli_transcripts.py OUT_DIR
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import urllib.request
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any
from unittest import mock

from weir.cli import main as weir_main
from weir.engines.agent_browser_reader import AgentBrowserReader
from weir.engines.base import EngineProbe, ReaderEngine
from weir.engines.ebay_connector import EbayConnector
from weir.engines.oc_reader import OcReader
from weir.models import ReaderResult, WebRequest
from weir.router import EngineRegistry

RUN_ID = "lode-contract"
QUERY = "RTX 3090 24GB"
ITEM_URL = "https://www.ebay.com/itm/316000000001"
CREDENTIALS = {"EBAY_CLIENT_ID": "contract-client", "EBAY_CLIENT_SECRET": "contract-secret"}
TOKEN = json.dumps({"access_token": "contract-token", "expires_in": 7200}).encode()

FIXED_PRICE = {
    "itemId": "v1|316000000001|0",
    "legacyItemId": "316000000001",
    "title": "NVIDIA GeForce RTX 3090 Founders Edition 24GB GDDR6X",
    "itemWebUrl": "https://www.ebay.com/itm/316000000001?_trkparms=ispr%3D1&hash=item4992:g:abc",
    "price": {"value": "689.99", "currency": "USD"},
    "shippingOptions": [
        {"shippingCostType": "FIXED", "shippingCost": {"value": "0.00", "currency": "USD"}}
    ],
    "condition": "Used",
    "conditionId": "3000",
    "buyingOptions": ["FIXED_PRICE", "BEST_OFFER"],
    "itemCreationDate": "2026-10-12T15:04:05.000Z",
    "image": {"imageUrl": "https://i.ebayimg.com/images/g/abc/s-l225.jpg"},
}
AUCTION_CALCULATED_SHIPPING = {
    "itemId": "v1|316000000002|0",
    "legacyItemId": "316000000002",
    "title": "EVGA RTX 3090 FTW3 Ultra 24GB - parts or repair",
    "itemWebUrl": "https://www.ebay.com/itm/316000000002",
    "price": {"value": "310.00", "currency": "USD"},
    "currentBidPrice": {"value": "310.00", "currency": "USD"},
    "shippingOptions": [{"shippingCostType": "CALCULATED"}],
    "condition": "For parts or not working",
    "conditionId": "7000",
    "buyingOptions": ["AUCTION"],
    "itemEndDate": "2026-10-15T01:00:00.000Z",
}
PRICE_UNKNOWN = {
    "itemId": "v1|316000000003|0",
    "title": "RTX 3090 24GB (price on request)",
    "itemWebUrl": "https://www.ebay.com/itm/316000000003",
    "shippingOptions": [],
}
SECOND_PAGE_ITEM = {
    "itemId": "v1|316000000004|0",
    "title": "Zotac RTX 3090 Trinity 24GB",
    "itemWebUrl": "https://www.ebay.com/itm/316000000004",
    "price": {"value": "640.00", "currency": "USD"},
    "shippingOptions": [{"shippingCost": {"value": "24.50", "currency": "USD"}}],
    "condition": "Used",
    "conditionId": "3000",
}
NEXT_PAGE = (
    "https://api.ebay.com/buy/browse/v1/item_summary/search?q=RTX+3090+24GB&limit=50&offset=50"
)

Transport = Callable[[urllib.request.Request], tuple[int, bytes]]


def _browse(pages: list[tuple[int, Any]]) -> Transport:
    """Token endpoint succeeds; Browse calls return `pages` in order (last repeats)."""

    remaining = list(pages)

    def transport(req: urllib.request.Request) -> tuple[int, bytes]:
        if "/oauth2/token" in req.full_url:
            return 200, TOKEN
        status, body = remaining.pop(0) if len(remaining) > 1 else remaining[0]
        payload = body if isinstance(body, bytes) else json.dumps(body).encode()
        return status, payload

    return transport


class _StubPageReader(ReaderEngine):
    """Stands in for `oc` so enrichment output can be recorded without the CLI."""

    id = "oc"

    def probe(self) -> EngineProbe:
        return EngineProbe(self.id, True, version="stub")

    def read(self, request: WebRequest) -> ReaderResult:
        return ReaderResult(
            engine=self.id,
            requested_url=request.url or "",
            final_url=request.url or "",
            title="NVIDIA GeForce RTX 3090 Founders Edition 24GB GDDR6X | eBay",
            content={
                "blocks": [
                    {"type": "heading", "text": "NVIDIA GeForce RTX 3090 Founders Edition"},
                    {"type": "text", "text": "Tested, no artifacts. Original box included."},
                ]
            },
        )


def _search_argv(pages: int = 1, query: str = QUERY) -> list[str]:
    return ["search", query, "--source", "ebay", "--pages", str(pages), "--run-id", RUN_ID]


ENRICH_ARGV = ["enrich", ITEM_URL, "--run-id", RUN_ID]

# Scenario keys: argv; transport (stub Browse API factory); credentials (default True);
# readers (page-reader engines for enrich); empty_path; urlopen_error (real transport path).
SCENARIOS: dict[str, dict[str, Any]] = {
    "search-ok": {
        "argv": _search_argv(pages=2),
        "transport": lambda: _browse(
            [
                (
                    200,
                    {
                        "total": 4,
                        "itemSummaries": [
                            FIXED_PRICE,
                            AUCTION_CALCULATED_SHIPPING,
                            PRICE_UNKNOWN,
                        ],
                        "next": NEXT_PAGE,
                    },
                ),
                (200, {"total": 4, "itemSummaries": [SECOND_PAGE_ITEM]}),
            ]
        ),
    },
    "search-no-matches": {
        "argv": _search_argv(query="zzqx no such item 7f3a"),
        "transport": lambda: _browse([(200, {"total": 0, "limit": 50, "offset": 0})]),
    },
    "search-missing-credentials": {"argv": _search_argv(), "credentials": False},
    "search-access-denied": {
        "argv": _search_argv(),
        "transport": lambda: _browse([(403, {"errors": [{"errorId": 1100}]})]),
    },
    "search-throttled": {
        "argv": _search_argv(),
        "transport": lambda: _browse([(429, {"errors": [{"errorId": 2001}]})]),
    },
    "search-timeout": {"argv": _search_argv(), "urlopen_error": TimeoutError("timed out")},
    "search-malformed-body": {
        "argv": _search_argv(),
        "transport": lambda: _browse([(200, b"<html>maintenance</html>")]),
    },
    "search-unusable-listings": {
        "argv": _search_argv(),
        "transport": lambda: _browse(
            [(200, {"total": 2, "itemSummaries": [{"itemId": "v1|1|0"}, {"title": "no id"}]})]
        ),
    },
    "enrich-page": {"argv": ENRICH_ARGV, "readers": lambda: [_StubPageReader()]},
    "enrich-no-readers": {
        # The hosted runner installs no page-reader CLIs; this is what it sees.
        "argv": ENRICH_ARGV,
        "readers": lambda: [OcReader(), AgentBrowserReader()],
        "empty_path": True,
    },
}


@contextlib.contextmanager
def _scenario_environment(spec: dict[str, Any]) -> Iterator[None]:
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("WEIR_", "EBAY_"))
    }
    if spec.get("credentials", True):
        env.update(CREDENTIALS)
    with contextlib.ExitStack() as stack:
        if spec.get("empty_path"):
            env["PATH"] = stack.enter_context(tempfile.TemporaryDirectory())
        stack.enter_context(mock.patch.dict(os.environ, env, clear=True))
        transport = spec.get("transport")
        engines: list[Any] = [
            EbayConnector(
                transport=transport() if transport else None, sleeper=lambda _seconds: None
            )
        ]
        engines.extend(spec["readers"]() if "readers" in spec else [])
        stack.enter_context(mock.patch("weir.cli.EngineRegistry", lambda: EngineRegistry(engines)))
        # Keep the public-target DNS check offline; policy itself is tested elsewhere.
        stack.enter_context(mock.patch("weir.broker.check_target_policy", lambda *_args: None))
        if "urlopen_error" in spec:
            stack.enter_context(
                mock.patch("urllib.request.urlopen", side_effect=spec["urlopen_error"])
            )
        yield


def run_scenario(name: str) -> dict[str, Any]:
    spec = SCENARIOS[name]
    stdout, stderr = io.StringIO(), io.StringIO()
    with _scenario_environment(spec):
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            returncode = weir_main(list(spec["argv"]))
    return {
        "scenario": name,
        "argv": ["weir", *spec["argv"]],
        "returncode": returncode,
        "stdout": stdout.getvalue(),
        "stderr": stderr.getvalue(),
    }


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    out_dir = Path(argv[0])
    out_dir.mkdir(parents=True, exist_ok=True)
    for name in SCENARIOS:
        path = out_dir / f"{name}.json"
        path.write_text(json.dumps(run_scenario(name), indent=2) + "\n", encoding="utf-8")
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
