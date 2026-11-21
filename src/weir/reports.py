"""Operator-owned reports with immutable, independently reopenable source captures."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

from weir.contract import ContractViolation, canonical_digest, canonical_json_bytes
from weir.models import WebCapture
from weir.persistence import CaptureStore, _write_immutable

_AMOUNT = re.compile(r"(?:0|[1-9][0-9]{0,11})(?:\.[0-9]{1,6})?")
_REPORT_ID = re.compile(r"report-[0-9a-f]{64}")


@dataclass(frozen=True)
class MarketplaceCriteria:
    query: str
    max_delivered: str | None = None
    currency: str = "USD"
    country: str | None = None
    condition: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.query, str) or not 1 <= len(self.query.strip()) <= 200:
            raise ValueError("Enter an item or search phrase of at most 200 characters.")
        if self.max_delivered is not None and (
            not isinstance(self.max_delivered, str) or not _AMOUNT.fullmatch(self.max_delivered)
        ):
            raise ValueError("Maximum price including shipping must be a nonnegative decimal.")
        if not isinstance(self.currency, str) or not re.fullmatch(r"[A-Z]{3}", self.currency):
            raise ValueError("Currency must be a three-letter ISO code.")
        if self.country is not None and (
            not isinstance(self.country, str) or not re.fullmatch(r"[A-Z]{2}", self.country)
        ):
            raise ValueError("Item country must be a two-letter ISO code.")
        if self.condition is not None and (
            not isinstance(self.condition, str) or not 1 <= len(self.condition.strip()) <= 80
        ):
            raise ValueError("Condition must be a nonempty label or condition ID.")


def _money(field: Any, currency: str) -> Decimal | None:
    if isinstance(field, dict) and field.get("currency") == currency:
        value = field.get("amount")
        if isinstance(value, str) and _AMOUNT.fullmatch(value):
            return Decimal(value)
    return None


def _compare_row(item: dict, criteria: MarketplaceCriteria) -> dict:
    price = _money(item["price"], criteria.currency)
    shipping = _money(item["shipping"], criteria.currency)
    total = price + shipping if price is not None and shipping is not None else None
    condition = item.get("condition")
    location = item["raw"].get("itemLocation")
    country = location.get("country") if isinstance(location, dict) else None
    failures: list[str] = []
    unknowns: list[str] = []
    matches: list[str] = []
    currencies = [
        part["currency"]
        for part in (item["price"], item["shipping"])
        if isinstance(part, dict) and isinstance(part.get("currency"), str)
    ]
    if any(currency != criteria.currency for currency in currencies):
        failures.append("Different currency")
    elif total is None:
        unknowns.append("Price including shipping unavailable in " + criteria.currency)
    if criteria.condition:
        if not isinstance(condition, dict):
            unknowns.append("Condition unavailable")
        elif criteria.condition.casefold() in {
            str(v).casefold() for v in (condition.get("raw"), condition.get("condition_id")) if v
        }:
            matches.append("Condition matches")
        else:
            failures.append("Different condition")
    if criteria.country:
        if not country:
            unknowns.append("Item country unavailable")
        elif country == criteria.country:
            matches.append("Item country matches")
        else:
            failures.append("Different item country")
    if criteria.max_delivered is not None:
        maximum = Decimal(criteria.max_delivered)
        if any(amount is not None and amount > maximum for amount in (price, shipping, total)):
            failures.append("Over budget")
        elif total is not None:
            matches.append("Within budget including shipping")
    return {
        "item_id": item["source_item_id"],
        "title": item["title"],
        "url": item["canonical_url"],
        "price": item["price"],
        "shipping": item["shipping"],
        "currency": currencies[0] if currencies else None,
        "delivered_price": format(total, "f") if total is not None else None,
        "condition": condition,
        "country": country,
        "observed_at": item["observed_at"],
        "verdict": "excluded" if failures else "unknown" if unknowns else "match",
        "reasons": failures + unknowns + matches or ["Returned by the marketplace search"],
    }


class ReportHistory:
    """A trusted host supplies the owner and the permissions of its current reader."""

    def __init__(
        self,
        root: Path,
        *,
        owner: str,
        permitted_jobs: frozenset[str] = frozenset({"marketplace", "dias"}),
    ):
        if not owner or not isinstance(owner, str):
            raise ValueError("Reports require an authenticated operator.")
        self.owner_ref = hashlib.sha256(owner.encode("utf-8")).hexdigest()
        private = root / self.owner_ref
        private.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.directory = private / "history"
        self.legacy_directory = self.directory / self.owner_ref
        self.captures = CaptureStore(private / "sources")
        self.permitted_jobs = permitted_jobs

    def require_job(self, job: str) -> None:
        if job not in self.permitted_jobs:
            raise PermissionError("This reader does not have access to this report.")

    def save(self, job: str, report: dict, sources: list[WebCapture]) -> dict:
        self.require_job(job)
        if not sources:
            raise ValueError("A report requires source evidence.")
        citations = []
        for capture in sources:
            self.captures.verify_capture(capture)
            if not capture.raw_artifact_ref:
                raise ValueError("Report source content must be retained.")
            citations.append(
                {
                    "capture_id": capture.capture_id,
                    "url": capture.final_url,
                    "observed_at": capture.captured_at,
                    "content_hash": capture.content_hash,
                    "manifest_hash": canonical_digest(replace(capture, content=None).to_dict()),
                    **({"source_host": report["source_host"]} if job == "dias" else {}),
                }
            )
        body = {
            **report,
            "schema_version": 2,
            "owner_ref": self.owner_ref,
            "job": job,
            "sources": citations,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        payload = canonical_json_bytes(body)
        report_id = "report-" + hashlib.sha256(payload).hexdigest()
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        _write_immutable(self.directory / (report_id + ".json"), payload)
        return {**body, "report_id": report_id}

    def _manifest(self, report_id: str) -> dict:
        if not isinstance(report_id, str) or not _REPORT_ID.fullmatch(report_id):
            raise ValueError("Invalid report ID.")
        name = report_id + ".json"
        try:
            payload = (self.directory / name).read_bytes()
            legacy = False
        except FileNotFoundError:
            payload = (self.legacy_directory / name).read_bytes()
            legacy = True
        if "report-" + hashlib.sha256(payload).hexdigest() != report_id:
            raise ContractViolation("report_hash_mismatch", "Report failed its content-hash check.")
        body = json.loads(payload)
        if legacy:
            if body.get("schema_version") != 1:
                raise ContractViolation("report_version", "Invalid historical report format.")
        elif body.get("schema_version") != 2 or body.get("owner_ref") != self.owner_ref:
            raise PermissionError("Report owner mismatch.")
        self.require_job(body["job"])
        return {**body, "report_id": report_id}

    def _source(self, citation: dict) -> WebCapture:
        try:
            metadata = self.captures.load_capture(citation["capture_id"], hydrate=False)
            if (
                canonical_digest(metadata.to_dict()) != citation["manifest_hash"]
                or metadata.capture_id != citation["capture_id"]
                or metadata.final_url != citation["url"]
                or metadata.captured_at != citation["observed_at"]
                or metadata.content_hash != citation["content_hash"]
                or not metadata.raw_artifact_ref
            ):
                raise ContractViolation(
                    "report_source_mismatch",
                    "Report source manifest failed its content-hash check.",
                )
            return replace(metadata, content=self.captures.load_artifact(metadata.raw_artifact_ref))
        except FileNotFoundError as exc:
            raise ContractViolation(
                "report_source_missing", "The retained report source is missing."
            ) from exc
        except ContractViolation:
            raise
        except (ValueError, TypeError, KeyError) as exc:
            raise ContractViolation(
                "report_source_invalid", "The retained report source could not be verified."
            ) from exc

    def open(self, report_id: str) -> dict:
        report = self._manifest(report_id)
        for citation in report["sources"]:
            self._source(citation)
        return report

    def source(self, report_id: str, number: int) -> WebCapture:
        sources = self._manifest(report_id)["sources"]
        if type(number) is not int or not 1 <= number <= len(sources):
            raise ValueError("Source number is outside this report.")
        return self._source(sources[number - 1])

    def list_reports(self, limit: int = 50) -> list[dict]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("History limit must be between 1 and 100.")
        rows = []
        report_ids = {
            path.stem
            for directory in (self.directory, self.legacy_directory)
            for path in directory.glob("report-*.json")
        }
        for report_id in report_ids:
            try:
                body = self._manifest(report_id)
            except PermissionError:
                continue
            rows.append({key: body[key] for key in ("report_id", "job", "title", "created_at")})
        return sorted(rows, key=lambda row: (row["created_at"], row["report_id"]), reverse=True)[
            :limit
        ]

    def marketplace(
        self,
        capture: WebCapture,
        criteria: MarketplaceCriteria,
        *,
        previous: str | None = None,
        run_id: str,
    ) -> dict:
        self.require_job("marketplace")
        data = capture.content
        if (
            capture.engine != "ebay"
            or not isinstance(data, dict)
            or data.get("source") != "ebay"
            or data.get("query") != criteria.query
            or not isinstance(data.get("listings"), list)
        ):
            raise ValueError("The retained acquisition does not match this eBay search.")
        by_id = {}
        for item in data["listings"]:
            row = _compare_row(item, criteria)
            by_id.setdefault(row["item_id"], row)
        rank = {"match": 0, "unknown": 1, "excluded": 2}
        rows = sorted(
            by_id.values(),
            key=lambda r: (
                rank[r["verdict"]],
                r["delivered_price"] is None,
                Decimal(r["delivered_price"] or "0"),
                r["item_id"],
            ),
        )
        report = {
            "title": "Marketplace comparison for " + criteria.query,
            "run_id": run_id,
            "criteria": asdict(criteria),
            "rows": rows,
            "pagination": data["pagination"],
            "counts": {v: sum(row["verdict"] == v for row in rows) for v in rank},
        }
        if previous:
            baseline = self.open(previous)
            if (
                baseline["job"] != "marketplace"
                or baseline["criteria"]["query"].casefold() != criteria.query.casefold()
            ):
                raise ValueError("The previous report must compare the same marketplace query.")
            before = {r["item_id"] for r in baseline["rows"] if r["verdict"] == "match"}
            after = {r["item_id"] for r in rows if r["verdict"] == "match"}
            report["changes"] = {
                "previous_report": previous,
                "entered": sorted(after - before),
                "left": sorted(before - after),
            }
            # Keep listing titles from the original capture when an item disappears.
            titles = {r["item_id"]: r["title"] for r in baseline["rows"]}
            titles.update({r["item_id"]: r["title"] for r in rows})
            report["changes"]["titles"] = {key: titles[key] for key in sorted(before ^ after)}
        return self.save("marketplace", report, [capture])
