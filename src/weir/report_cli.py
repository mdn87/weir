"""Command line and human-readable output for the operator reports."""

import argparse
import json
import sys

from weir.broker import AcquisitionFailed
from weir.engines.base import WeirEngineError
from weir.operator_jobs import personal_root, run_job


def add_report_parser(sub):
    parser = sub.add_parser(
        "report", help="run and reopen marketplace comparisons and Dias project reports"
    )
    jobs = parser.add_subparsers(dest="job", required=True)
    market = jobs.add_parser("marketplace", help="compare eBay listings against your criteria")
    market.add_argument("query")
    market.add_argument("--max-delivered", help="maximum item price plus shipping, before tax")
    market.add_argument("--currency", default="USD", type=str.upper)
    market.add_argument("--condition", help="eBay condition label or ID")
    market.add_argument("--country", type=str.upper, help="two-letter item location")
    market.add_argument("--pages", type=int, default=1)
    market.add_argument("--previous", help="an earlier report on the same search")
    dias = jobs.add_parser(
        "dias", help="read a live Dias project and identify the next actionable chips"
    )
    dias.add_argument("project")
    dias.add_argument("--since", help="show chip evidence since YYYY-MM-DD")
    dias.add_argument("--previous", help="show which chips changed since this report")
    history = jobs.add_parser("list", help="show recent reports")
    history.add_argument("--limit", type=int, default=50)
    reopen = jobs.add_parser("open", help="reopen a report and verify its evidence offline")
    reopen.add_argument("report_id")
    source = jobs.add_parser("source", help="reopen the exact cited source")
    source.add_argument("report_id")
    source.add_argument("number", type=int, nargs="?", default=1)
    for command in (market, dias, history, reopen, source):
        command.add_argument("--json", action="store_true", help="emit the structured result")


def render_report(report: dict) -> str:
    if "reports" in report:
        return (
            "\n".join(
                f"{r['created_at']}  {r['title']}  {r['report_id']}" for r in report["reports"]
            )
            or "No saved reports."
        )
    if "report_id" not in report:
        return json.dumps(report, indent=2, ensure_ascii=False)
    lines = [report["title"], f"Captured {report['created_at']}", f"Report {report['report_id']}"]
    if report["job"] == "dias":
        lines.extend(
            [
                "",
                report.get("milestone") or "No current milestone recorded.",
                " · ".join(f"{n} {stage}" for stage, n in sorted(report["counts"].items())),
            ]
        )
        lines.extend(report["warnings"])
        for field, heading in (
            ("available", "Work you can do now"),
            ("waiting", "Waiting on a dependency or decision"),
            ("later", "Planned and unrefined work"),
        ):
            lines.extend(["", heading])
            if not report[field]:
                lines.append("None recorded.")
            for row in report[field]:
                lines.append(f"- {row['title']} [{row['stage']}] ({row['chip_id']})")
                if row["summary"]:
                    lines.append("  " + row["summary"])
                if row["waiting_on"]:
                    lines.append("  Needs " + ", ".join(row["waiting_on"]))
                if row["stage"] == "blocked" and row.get("last_note"):
                    lines.append("  " + row["last_note"])
                if row["unlocks"]:
                    lines.append(
                        "  Completing this clears the prerequisites for "
                        + ", ".join(row["unlocks"])
                    )
        if report["since"]:
            lines.extend(["", "Activity since " + report["since"]])
            lines.extend(f"- {e['at']}  {e['chip_id']}  {e['message']}" for e in report["activity"])
            if not report["activity"]:
                lines.append("No recorded activity in this period.")
        if "changes" in report:
            lines.extend(["", "Changes since the previous report"])
            lines.extend(
                f"- {c['chip_id']}  {c['from']} → {c['to']}" for c in report["changes"]["chips"]
            )
            if not report["changes"]["chips"]:
                lines.append("No chip stage changed.")
    else:
        criteria = report["criteria"]
        filters = [f"{k}={v}" for k, v in criteria.items() if v is not None]
        lines.extend(
            [
                "",
                "Criteria  " + " · ".join(filters),
                " · ".join(f"{n} {v}" for v, n in report["counts"].items()),
                "Prices include known shipping and exclude tax.",
            ]
        )
        if report["pagination"].get("truncated"):
            lines.append("The source has more results beyond the retrieved pages.")
        for row in report["rows"]:
            price = (
                f"{row['delivered_price']} {row['currency']}"
                if row["delivered_price"] is not None
                else "total unknown"
            )
            lines.extend(
                [
                    f"- [{row['verdict']}] {row['title']} — {price}",
                    "  " + " · ".join(row["reasons"]),
                    "  " + row["url"],
                ]
            )
        if not report["rows"]:
            lines.append("The marketplace returned zero listings.")
        if "changes" in report:
            for key in ("entered", "left"):
                lines.append(
                    f"Matches that {key}: " + (", ".join(report["changes"][key]) or "none")
                )
    lines.extend(["", "Sources"])
    lines.extend(
        f"{i}. {s['url']}  {s['observed_at']}  {s['capture_id']}"
        for i, s in enumerate(report["sources"], 1)
    )
    return "\n".join(lines)


def execute_cli(options: argparse.Namespace) -> int:
    args = {
        k: v
        for k, v in vars(options).items()
        if k not in {"command", "job", "json"} and v is not None
    }
    try:
        report = run_job(
            options.job,
            args,
            owner="personal-os-seat",
            root=personal_root(),
            permitted_jobs=frozenset({"marketplace", "dias"}),
        )
    except (TypeError, ValueError, OSError, AcquisitionFailed, WeirEngineError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
        return 2
    output = (
        json.dumps(report, indent=2, ensure_ascii=False) if options.json else render_report(report)
    )
    print(output)
    return 0
