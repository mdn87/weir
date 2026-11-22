"""Named, read-only operator jobs shared by the command line and Lugos seats."""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from weir.broker import AcquisitionBroker
from weir.dias_reports import DiasDisplay, dias_report
from weir.evidence import AcquisitionEnvelope
from weir.models import DataClass, RequestMode, WebRequest
from weir.reports import MarketplaceCriteria, ReportHistory
from weir.work_context import WorkContext, WorkContextSource

_FIELDS = {
    "marketplace": {
        "query",
        "country",
        "currency",
        "condition",
        "max_delivered",
        "pages",
        "previous",
    },
    "dias": {"project", "since", "previous"},
    "task_review": set(),
    "list": {"limit"},
    "open": {"report_id"},
    "source": {"report_id", "number"},
}


def personal_root() -> Path:
    setting = os.environ.get("WEIR_REPORT_DIR")
    if setting:
        return Path(setting).expanduser().resolve()
    parent = Path(
        os.environ.get("LOCALAPPDATA")
        or os.environ.get("XDG_DATA_HOME")
        or Path.home() / ".local/share"
    )
    return parent / "weir" / "operator-reports"


def run_job(
    action: str,
    args: dict,
    *,
    owner: str,
    root: Path,
    permitted_jobs: frozenset[str],
    context: WorkContext | None = None,
    dias_display: DiasDisplay | None = None,
    review_grant: str | None = None,
) -> dict:
    if (
        not isinstance(action, str)
        or action not in _FIELDS
        or not isinstance(args, dict)
        or set(args) - _FIELDS[action]
    ):
        raise ValueError("Unknown operator job or argument.")
    if not owner or not isinstance(owner, str):
        raise ValueError("An authenticated operator is required.")
    history = ReportHistory(root, owner=owner, permitted_jobs=permitted_jobs)
    if action == "list":
        return {"reports": history.list_reports(args.get("limit", 50))}
    if action in {"open", "source"}:
        if action == "open":
            return history.open(args.get("report_id"))
        return history.source(args.get("report_id"), args.get("number", 1)).to_dict()
    history.require_job(action)
    if context is not None:
        context.validate()
    if action == "task_review":
        from weir.review_board import task_review_report

        return task_review_report(history, owner, review_grant, context.run_id if context else None)
    if action == "dias":
        snapshot_dir = os.environ.get("WEIR_DIAS_SNAPSHOT_DIR")
        display = dias_display or DiasDisplay(
            os.environ.get("WEIR_DIAS_DISPLAY_ORIGIN", "http://127.0.0.1:4175"),
            ssh_host=os.environ.get("WEIR_DIAS_SSH_HOST"),
            snapshot_dir=Path(snapshot_dir) if snapshot_dir else None,
        )
        return dias_report(
            history,
            display,
            args.get("project"),
            since=args.get("since"),
            previous=args.get("previous"),
            run_id=context.run_id if context else None,
        )

    from weir.cli import _profile_registry

    if "query" not in args:
        raise ValueError("Enter the marketplace item or search phrase.")
    criteria = MarketplaceCriteria(
        **{k: v for k, v in args.items() if k not in {"pages", "previous"}}
    )
    pages = args.get("pages", 1)
    if type(pages) is not int or not 1 <= pages <= 10:
        raise ValueError("Choose between 1 and 10 pages.")
    if context is None:
        key = uuid.uuid4().hex
        context = WorkContext.create(
            context_id="ctx-" + key,
            run_id="run-" + key,
            correlation_id="req-" + key,
            source=WorkContextSource.CALLER,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
    req = WebRequest(
        request_id=context.correlation_id,
        run_id=context.run_id,
        mode=RequestMode.SEARCH,
        data_class=DataClass.PUBLIC,
        auth_context="app",
        profile_id="ebay-app",
        source="ebay",
        query=criteria.query,
        capture_policy="content",
        maximum_depth=pages - 1,
    )
    acquisition = AcquisitionEnvelope.create(work_context=context, request=req)
    result = AcquisitionBroker(profiles=_profile_registry(), store=history.captures).search(
        acquisition
    )
    return history.marketplace(
        result.capture, criteria, previous=args.get("previous"), run_id=context.run_id
    )
