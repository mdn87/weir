"""A single browser-observed column of the authenticated Mission Control task board."""

from __future__ import annotations

import http.client
import os
import re
import uuid
from dataclasses import dataclass
from urllib.parse import urlsplit

from weir.models import DataClass, ReaderResult, RequestMode, WebCapture, WebRequest


BOARD_PATH = "/api/lugos/review-board"
MAX_HTML = 512 * 1024
ROW_LIMIT = 200
OWNER = re.compile(r"mission-control:([1-9]\d*):([1-9]\d*):([1-9]\d*)", re.ASCII)
GRANT = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class ReviewObservation:
    url: str
    observed_at: str
    html: str
    workspace: int
    total: int
    tasks: list[dict]


def source_url() -> str:
    port = int(os.environ.get("WEIR_REVIEW_SOURCE_PORT", "3230"))
    if not 1 <= port <= 65535:
        raise ValueError("Invalid Mission Control source port.")
    return f"http://127.0.0.1:{port}{BOARD_PATH}"


def observe_board(owner: str, grant: str) -> ReviewObservation:
    from weir.browser.linux_report import read_in_browser

    url = source_url()

    def fetch():
        # Only the trusted bridge holds the grant. The renderer asks for one document.
        connection = http.client.HTTPConnection("127.0.0.1", urlsplit(url).port, timeout=12)
        try:
            connection.request("GET", BOARD_PATH, headers={
                "X-Weir-Review-Grant": grant, "X-Weir-Report-Owner": owner,
                "Accept": "text/html", "Accept-Encoding": "identity",
            })
            response = connection.getresponse()
            if response.status != 200 or response.headers.get_content_type() != "text/html":
                raise OSError("The signed-in task board could not be read.")
            body = response.read(MAX_HTML + 1)
            if not body or len(body) > MAX_HTML:
                raise OSError("Invalid task board source size.")
            return body.decode("utf-8", errors="strict")
        finally:
            connection.close()

    result, html, observed_at, _ = read_in_browser(url, fetch)
    return ReviewObservation(url, observed_at, html, result["workspace"], result["total"], result["tasks"])


def task_review_report(history, owner: str, grant: str | None, run_id: str | None):
    identity = OWNER.fullmatch(owner)
    if not identity or not isinstance(grant, str) or not GRANT.fullmatch(grant):
        raise PermissionError("A signed-in Mission Control report request is required.")
    view = observe_board(owner, grant)
    if (type(view.workspace) is not int or view.workspace != int(identity[2])
            or type(view.total) is not int or view.total < 0 or not isinstance(view.tasks, list)
            or len(view.tasks) != min(ROW_LIMIT, view.total)):
        raise OSError("The observed task list does not match the requested workspace or row count.")
    last_id = 0
    for task in view.tasks:
        if (not isinstance(task, dict) or set(task) != {"id", "title"}
                or type(task["id"]) is not int or task["id"] <= last_id
                or not isinstance(task["title"], str) or not task["title"]):
            raise OSError("The task board returned an invalid review row.")
        last_id = task["id"]
    job_run = run_id or "run-" + uuid.uuid4().hex
    request = WebRequest(request_id="req-" + uuid.uuid4().hex, run_id=job_run,
                         mode=RequestMode.OBSERVE, data_class=DataClass.PERSONAL,
                         auth_context="browser_profile", url=view.url, capture_policy="full_evidence")
    title = "Mission Control tasks in review"
    observation = ReaderResult(engine="linux-chromium", requested_url=view.url, final_url=view.url,
                               title=title, http_status=200, content=view.html)
    capture = WebCapture.from_reader_result(observation, request, captured_at=view.observed_at)
    retained = history.captures.persist(capture, request)[0]
    return history.save("task_review", {"title": title, "question": "Which tasks in my workspace are in review?",
                        "workspace": view.workspace, "total": view.total, "tasks": view.tasks,
                        "observed_at": view.observed_at, "run_id": job_run}, [retained])
