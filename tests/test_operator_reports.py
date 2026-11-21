"""Release checks for operator reports across independent invocations."""

import hashlib
import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from weir.contract import ContractViolation, canonical_json_bytes
from weir.dias_reports import DiasDisplay, dias_report, publish_snapshot
from weir.engines.ebay_connector import normalize_summary
from weir.models import DataClass, ReaderResult, RequestMode, WebCapture, WebRequest
from weir.operator_rpc import dispatch
from weir.reports import MarketplaceCriteria, ReportHistory


class OperatorReportTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.captures = self.history().captures

    def search_capture(self, prices):
        observed = "2026-11-21T10:00:00Z"
        rows = []
        for item, price, shipping in prices:
            raw = {
                "itemId": item,
                "title": "Keyboard " + item,
                "itemWebUrl": "https://www.ebay.com/itm/" + item,
                "price": {"currency": "USD", "value": price},
                "condition": "Used",
                "itemLocation": {"country": "US"},
            }
            if price is None:
                raw.pop("price")
            if shipping is not None:
                raw["shippingOptions"] = [{"shippingCost": {"currency": "USD", "value": shipping}}]
            rows.append(normalize_summary(raw, observed))
        req = WebRequest(
            request_id="search-1",
            run_id="run-1",
            mode=RequestMode.SEARCH,
            query="keyboard",
            source="ebay",
            data_class=DataClass.PUBLIC,
            auth_context="app",
            profile_id="ebay-app",
            capture_policy="content",
        )
        result = ReaderResult(
            engine="ebay",
            requested_url="https://api.ebay.com/search",
            final_url="https://api.ebay.com/search",
            title="Listings",
            auth_scope="app:ebay-app",
            http_status=200,
            content={
                "source": "ebay",
                "query": "keyboard",
                "listings": rows,
                "pagination": {"pages_fetched": 1, "total_reported": len(rows), "truncated": False},
            },
        )
        cap = WebCapture.from_reader_result(result, req, captured_at=observed)
        return self.captures.persist(cap, req)[0]

    def history(self, owner="operator-one"):
        return ReportHistory(self.root / "reports", owner=owner)

    def test_dias_prerequisites_activity_history_and_revoked_access(self):
        display = DiasDisplay()
        board = {
            "schemaVersion": 1,
            "projectId": "weir",
            "projectLabel": "WEIR",
            "revision": 17,
            "sourceStatus": "consistent",
            "chips": [],
        }
        for key, stage, needs in (
            ("evidence", "done", []),
            ("report", "active", ["evidence"]),
            ("ship", "planned", ["report"]),
            ("service", "blocked", []),
        ):
            board["chips"].append(
                {
                    "chipId": key,
                    "title": key,
                    "stage": stage,
                    "prereqs": needs,
                    "evidence": [{"at": "2026-11-20T12:00:00Z", "message": "Reviewed " + key}],
                }
            )
        status = {
            "nextChipId": "report",
            "chipCounts": {"total": 4, "done": 1, "active": 1, "planned": 1, "blocked": 1},
            "statusSourceEvidence": {"state": "valid"},
        }

        def view(resource, project):
            return (
                "http://127.0.0.1:4175/api/v1/" + resource + "/" + project,
                board if resource == "chip-boards" else status,
            )

        with patch.object(display, "fetch", side_effect=view):
            first = dias_report(self.history(), display, "weir", since="2026-11-20")
            self.assertEqual(first["available"][0]["unlocks"], ["ship"])
            self.assertEqual({c["chip_id"] for c in first["waiting"]}, {"ship", "service"})
            self.assertEqual(len(first["activity"]), 4)
            board["chips"][1]["stage"] = "done"
            second = dias_report(
                self.history(), display, "weir", since="2026-11-21", previous=first["report_id"]
            )
        self.assertEqual(
            second["changes"]["chips"], [{"chip_id": "report", "from": "active", "to": "done"}]
        )
        self.assertFalse(second["activity"])
        self.assertEqual(self.history().open(first["report_id"]), first)
        denied = ReportHistory(
            self.root / "reports",
            owner="operator-one",
            permitted_jobs=frozenset({"marketplace"}),
        )
        self.assertEqual(denied.list_reports(), [])
        with self.assertRaises(PermissionError):
            denied.source(first["report_id"], 1)
        with self.assertRaises(ValueError):
            display.fetch("chip-boards", "../sessions")

    def test_currency_mismatch_zero_matches_and_nonfinite_budget(self):
        cap = self.search_capture([("12345", "9.99", "5.00")])
        report = self.history().marketplace(
            cap, MarketplaceCriteria("keyboard", currency="EUR", max_delivered="50"), run_id="run-1"
        )
        self.assertEqual(report["counts"]["excluded"], 1)
        self.assertEqual(report["rows"][0]["currency"], "USD")
        empty = self.history().marketplace(
            self.search_capture([]), MarketplaceCriteria("keyboard"), run_id="run-1"
        )
        self.assertEqual(empty["counts"], {"match": 0, "unknown": 0, "excluded": 0})
        for invalid in ("NaN", "Infinity", "-1", "1e9"):
            with self.assertRaises(ValueError):
                MarketplaceCriteria("keyboard", max_delivered=invalid)

    def test_snapshot_matches_both_official_views_and_expires(self):
        direct = DiasDisplay()
        root = self.root / "published"

        def view(resource, project):
            return direct.origin + "/api/v1/" + resource + "/" + project, {
                "projectId": project,
                "schemaVersion": 1,
                "view": resource,
            }

        with patch.object(direct, "fetch", side_effect=view):
            publish_snapshot(direct, "weir", root)
        reader = DiasDisplay(snapshot_dir=root)
        self.assertEqual(reader.fetch("chip-boards", "weir")[1]["view"], "chip-boards")
        (path,) = root.glob("*.json")
        snapshot = json.loads(path.read_text(encoding="utf-8"))
        snapshot["observed_at"] = "2020-01-01T00:00:00+00:00"
        path.write_text(json.dumps(snapshot), encoding="utf-8")
        self.assertEqual(reader.fetch("projects", "weir")[1]["view"], "projects")
        for project in ("weir", "unpublished"):
            with self.assertRaises(OSError):
                DiasDisplay(snapshot_dir=root).fetch("projects", project)
        with self.assertRaises(ValueError):
            DiasDisplay(ssh_host="other host")

    def test_owner_binding_legacy_archive_and_citation_fields(self):
        history = self.history()
        cap = self.search_capture([("12345", "15", "0")])
        report = history.marketplace(cap, MarketplaceCriteria("keyboard"), run_id="original-run")
        path = history.directory / (report["report_id"] + ".json")
        other = self.history("another-reader")
        other.directory.mkdir()
        (other.directory / path.name).write_bytes(path.read_bytes())
        with self.assertRaises(PermissionError):
            other.open(report["report_id"])
        self.assertNotEqual(other.captures.root, history.captures.root)
        with self.assertRaises(ContractViolation):
            history._source({**report["sources"][0], "observed_at": "different observation"})

        legacy = json.loads(path.read_bytes())
        legacy.pop("owner_ref")
        legacy["schema_version"] = 1
        data = canonical_json_bytes(legacy)
        old_id = "report-" + hashlib.sha256(data).hexdigest()
        history.legacy_directory.mkdir()
        (history.legacy_directory / (old_id + ".json")).write_bytes(data)
        self.assertEqual(history.open(old_id), {**legacy, "report_id": old_id})
        self.assertEqual(len(history.list_reports()), 2)

    def test_missing_price_and_shipping_above_budget(self):
        cap = self.search_capture([("10001", None, "80"), ("10002", "20", None)])
        report = self.history().marketplace(
            cap, MarketplaceCriteria("keyboard", max_delivered="50"), run_id="run-1"
        )
        self.assertEqual(
            {r["item_id"]: r["verdict"] for r in report["rows"]},
            {"10001": "excluded", "10002": "unknown"},
        )
        without_budget = self.history().marketplace(
            cap, MarketplaceCriteria("keyboard"), run_id="run-1"
        )
        self.assertEqual(without_budget["counts"]["unknown"], 2)

    def test_unavailable_source_creates_no_report_and_only_marketplace_gets_its_profile(self):
        env_file = self.root / "profile.env"
        env_file.write_text(
            "EBAY_CLIENT_ID=fixture-id\nEBAY_CLIENT_SECRET=fixture-secret\nIGNORED=fixture-other\n"
        )
        env = {
            "WEIR_LODE_EBAY_ENV_FILE": str(env_file),
            "WEIR_REPORT_DIR": str(self.root / "reports"),
        }
        request = {
            "owner": "trial",
            "permitted_jobs": ["marketplace"],
            "action": "marketplace",
            "args": {"query": "keyboard"},
        }

        def unavailable(*args, **kwargs):
            self.assertEqual(os.environ.get("WEIR_EBAY_CLIENT_ID"), "fixture-id")
            self.assertNotIn("IGNORED", os.environ)
            raise OSError("source unavailable")

        with patch.dict(os.environ, env, clear=True):
            with patch("weir.broker.AcquisitionBroker.search", side_effect=unavailable):
                with self.assertRaisesRegex(OSError, "source unavailable"):
                    dispatch(request)
            self.assertNotIn("WEIR_EBAY_CLIENT_SECRET", os.environ)
            self.assertEqual(dispatch({**request, "action": "list", "args": {}}), {"reports": []})

    def test_conditions_unknown_shipping_rerun_and_offline_reopen(self):
        cap = self.search_capture(
            [("10001", "19.99", "5.00"), ("10002", "20.00", None), ("10003", "30.00", "0.00")]
        )
        first = self.history().marketplace(
            cap,
            MarketplaceCriteria("keyboard", max_delivered="25", country="US", condition="Used"),
            run_id="run-1",
        )
        rows = {r["item_id"]: r for r in first["rows"]}
        self.assertEqual(rows["10001"]["delivered_price"], "24.99")
        self.assertEqual(rows["10001"]["verdict"], "match")
        self.assertEqual(rows["10002"]["verdict"], "unknown")
        self.assertEqual(rows["10003"]["verdict"], "excluded")
        second = self.history().marketplace(
            cap,
            MarketplaceCriteria("keyboard", max_delivered="35"),
            previous=first["report_id"],
            run_id="run-1",
        )
        self.assertEqual(second["changes"]["entered"], ["10003"])
        self.assertEqual(self.history().open(first["report_id"]), first)
        self.assertEqual(len(self.history().list_reports()), 2)
        self.assertEqual(self.history("another-operator").list_reports(), [])
        with self.assertRaises(FileNotFoundError):
            self.history("another-operator").open(first["report_id"])
        digest = cap.raw_artifact_ref.rsplit(":", 1)[1]
        (self.captures.root / "artifacts" / "sha256" / digest[:2] / (digest + ".json")).write_bytes(
            b"{}"
        )
        with self.assertRaisesRegex(ValueError, "hash"):
            self.history().open(first["report_id"])
