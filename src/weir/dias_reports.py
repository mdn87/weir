"""Read the two display projections used by the Dias project view."""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import subprocess
import tempfile
import uuid
from collections import Counter
from datetime import date, datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from weir.models import DataClass, ReaderResult, RequestMode, WebCapture, WebRequest
from weir.reports import ReportHistory

_PROJECT = re.compile(r"[a-z0-9][a-z0-9._:-]{0,63}")
_STAGES = {"vague", "planned", "ready", "active", "blocked", "done", "unknown"}
_MAX_BYTES = 4 * 1024 * 1024


class DiasDisplay:
    """Origin is host configuration. A request can select only a project and two GETs."""

    def __init__(
        self,
        origin: str = "http://127.0.0.1:4175",
        *,
        ssh_host: str | None = None,
        snapshot_dir: Path | None = None,
    ):
        parsed = urlsplit(origin)
        if (
            parsed.scheme not in {"https", "http"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in ("", "/")
        ):
            raise ValueError("Configure the Dias display origin without a path or credentials.")
        self.origin = origin.rstrip("/")
        self.parsed = parsed
        if ssh_host and (
            not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}", ssh_host)
            or self.origin != "http://127.0.0.1:4175"
        ):
            raise ValueError(
                "Remote Dias reads require a configured SSH alias and the local Windows display."
            )
        self.ssh_host = ssh_host
        self.snapshot_dir = snapshot_dir
        self.snapshot = None
        self.observed_at = None
        self.source_host = ssh_host or parsed.hostname

    def fetch(self, resource: str, project: str) -> tuple[str, dict]:
        if resource not in ("chip-boards", "projects") or not _PROJECT.fullmatch(project):
            raise ValueError("Invalid Dias display resource.")
        path = f"/api/v1/{resource}/{project}"
        if self.snapshot_dir is not None:
            # Read both projections from one atomic publication for this report.
            if self.snapshot is None or self.snapshot.get("project") != project:
                try:
                    with (self.snapshot_dir / _snapshot_name(project)).open("rb") as file:
                        raw = file.read(2 * _MAX_BYTES + 2049)
                    if len(raw) > 2 * _MAX_BYTES + 2048:
                        raise ValueError("Oversized snapshot.")
                    snap = json.loads(raw)
                    stamp = datetime.fromisoformat(snap["observed_at"])
                    age = (datetime.now(timezone.utc) - stamp).total_seconds()
                    if (
                        snap["project"] != project
                        or snap["origin"] != self.origin
                        or not 0 <= age <= 120
                    ):
                        raise ValueError("Expired or mismatched snapshot.")
                except (OSError, ValueError, TypeError, KeyError) as exc:
                    raise OSError(
                        "A current Dias snapshot for this project is unavailable."
                    ) from exc
                self.snapshot = snap
                self.source_host = snap["source_host"]
            self.observed_at = self.snapshot.get("view_times", {}).get(
                resource, self.snapshot["observed_at"]
            )
            value = self.snapshot["views"][resource]
        elif self.ssh_host:
            # Every remote command word is constant except the validated project slug.
            # Only the two presentation GETs are available through the host's SSH identity.
            try:
                result = subprocess.run(
                    [
                        "ssh",
                        "-T",
                        "-oBatchMode=yes",
                        "-oStrictHostKeyChecking=yes",
                        "-oForwardAgent=no",
                        "-oClearAllForwardings=yes",
                        "-oConnectTimeout=5",
                        self.ssh_host,
                        "curl.exe",
                        "-q",
                        "--fail",
                        "--silent",
                        "--max-time",
                        "8",
                        "--max-filesize",
                        str(_MAX_BYTES),
                        self.origin + path,
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    timeout=15,
                )
            except subprocess.TimeoutExpired as exc:
                raise OSError("The Dias host did not respond in time.") from exc
            if result.returncode or len(result.stdout) > _MAX_BYTES:
                raise OSError("The configured Dias host could not supply the display view.")
            value = json.loads(result.stdout)
        else:
            value = json.loads(self._get(path))
        if (
            not isinstance(value, dict)
            or value.get("schemaVersion") != 1
            or value.get("projectId") != project
        ):
            raise ValueError("Dias returned a different project or unsupported projection.")
        return self.origin + path, value

    def _get(self, path: str) -> bytes:
        transport = (
            http.client.HTTPSConnection
            if self.parsed.scheme == "https"
            else http.client.HTTPConnection
        )
        conn = transport(self.parsed.hostname, self.parsed.port, timeout=8)
        try:
            conn.request("GET", path, headers={"Accept": "application/json"})
            res = conn.getresponse()
            if res.status != 200:
                raise OSError(f"Dias display returned HTTP {res.status}.")
            if res.headers.get_content_type() != "application/json":
                raise ValueError("Dias did not return a JSON projection.")
            raw = res.read(_MAX_BYTES + 1)
            if len(raw) > _MAX_BYTES:
                raise ValueError("Dias projection exceeds the report limit.")
            return raw
        finally:
            conn.close()

    def observe_project(self, project: str) -> list[tuple[str, dict, str]]:
        """Read one fresh pair and preserve when each original view was observed."""
        self.snapshot = None
        self.observed_at = None
        views = []
        for resource in ("chip-boards", "projects"):
            url, data = self.fetch(resource, project)
            views.append((url, data, self.observed_at or datetime.now(timezone.utc).isoformat()))
        return views


def _snapshot_name(project: str) -> str:
    return hashlib.sha256(project.encode("utf-8")).hexdigest() + ".json"


def publish_snapshot(display: DiasDisplay, project: str, directory: Path) -> None:
    """Publish only the enrolled project's display views, without partial reads."""
    observations = display.observe_project(project)
    resources = ("chip-boards", "projects")
    views = {key: observation[1] for key, observation in zip(resources, observations, strict=True)}
    times = {key: observation[2] for key, observation in zip(resources, observations, strict=True)}
    payload = {
        "project": project,
        "source_host": display.source_host,
        "origin": display.origin,
        "observed_at": min(times.values()),
        "view_times": times,
        "views": views,
    }
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=directory, delete=False
    ) as out:
        json.dump(payload, out, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        out.flush()
        os.fsync(out.fileno())
    os.replace(out.name, directory / _snapshot_name(project))


def publish_main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Publish the two Dias display views used by the report service."
    )
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--ssh-host")
    parser.add_argument("project")
    args = parser.parse_args()
    publish_snapshot(DiasDisplay(ssh_host=args.ssh_host), args.project, args.directory)


def _read_chips(board: dict) -> dict[str, dict]:
    rows = board.get("chips")
    if not isinstance(rows, list) or len(rows) > 128:
        raise ValueError("Invalid chip list from Dias.")
    chips = {}
    for chip in rows:
        if (
            not isinstance(chip, dict)
            or not isinstance(chip.get("chipId"), str)
            or chip["chipId"] in chips
            or chip.get("stage") not in _STAGES
            or not isinstance(chip.get("title"), str)
            or not isinstance(chip.get("prereqs"), list)
            or not all(isinstance(p, str) for p in chip["prereqs"])
        ):
            raise ValueError("Invalid chip in the Dias board.")
        chips[chip["chipId"]] = chip
    return chips


def dias_report(
    history: ReportHistory,
    display: DiasDisplay,
    project: str,
    *,
    since: str | None = None,
    previous: str | None = None,
    run_id: str | None = None,
) -> dict:
    history.require_job("dias")
    if not isinstance(project, str) or not _PROJECT.fullmatch(project):
        raise ValueError("Choose a valid Dias project ID.")
    if since is not None:
        if not isinstance(since, str) or not re.fullmatch(r"\d{4}-\d\d-\d\d", since):
            raise ValueError("Use YYYY-MM-DD for the start of the reporting period.")
        date.fromisoformat(since)
    observations = display.observe_project(project)
    (_, board, _), (_, status, _) = observations
    chips = _read_chips(board)
    counts = dict(Counter(c["stage"] for c in chips.values()))
    problems = []
    if (
        board.get("sourceStatus") != "consistent"
        or (status.get("statusSourceEvidence") or {}).get("state") != "valid"
    ):
        problems.append(
            "Dias reports stale, incomplete or inconsistent source data. "
            "Verify the project board before starting work."
        )
    published_counts = status.get("chipCounts") or {}
    selected = status.get("nextChip") or {}
    board_chip = chips.get(selected.get("chipId"), {})
    if (
        published_counts.get("total") != len(chips)
        or any(published_counts.get(stage, 0) != n for stage, n in counts.items())
        or selected
        and (
            selected.get("stage") != board_chip.get("stage")
            or selected.get("title") != board_chip.get("title")
        )
    ):
        problems.append(
            "The two Dias views were observed at different revisions. "
            "Counts below use the captured chip board."
        )

    available, waiting, later, activity = [], [], [], []
    next_id = status.get("nextChipId")
    for key, chip in chips.items():
        prereqs = chip["prereqs"]
        missing = [p for p in prereqs if chips.get(p, {}).get("stage") != "done"]
        unlocks = [
            c["chipId"]
            for c in chips.values()
            if c["stage"] != "done"
            and key in c["prereqs"]
            and all(p == key or chips.get(p, {}).get("stage") == "done" for p in c["prereqs"])
        ]
        row = {
            "chip_id": key,
            "title": chip["title"],
            "stage": chip["stage"],
            "summary": chip.get("summary"),
            "waiting_on": missing,
            "unlocks": unlocks,
            "last_note": next(
                (e.get("message") for e in reversed(chip.get("evidence", [])) if e.get("message")),
                None,
            ),
        }
        if chip["stage"] == "blocked" or (missing and chip["stage"] != "done"):
            waiting.append(row)
        elif chip["stage"] in {"active", "ready"}:
            available.append(row)
        elif chip["stage"] != "done":
            later.append(row)
        if since:
            for event in chip.get("evidence", []):
                if event.get("at", "")[:10] >= since:
                    activity.append(
                        {"chip_id": key, "at": event["at"], "message": event.get("message")}
                    )

    def order(row):
        return (
            row["chip_id"] != next_id,
            row["stage"] != "active",
            chips[row["chip_id"]].get("sequence", 0),
            row["chip_id"],
        )

    report = {
        "title": f"{board.get('projectLabel', project)} project work report",
        "project": project,
        "question": "How can I work through this project using its chips?",
        "source_host": display.source_host,
        "milestone": status.get("currentMilestone"),
        "remaining": status.get("remainingSummary"),
        "board_revision": board.get("revision"),
        "board_as_of": board.get("generatedAt"),
        "authored_next": next_id,
        "counts": counts,
        "available": sorted(available, key=order),
        "waiting": sorted(waiting, key=order),
        "later": sorted(later, key=order),
        "warnings": problems,
        "since": since,
        "activity": sorted(activity, key=lambda x: x["at"], reverse=True),
        "stages": {key: c["stage"] for key, c in chips.items()},
    }
    if previous:
        earlier = history.open(previous)
        if earlier["job"] != "dias" or earlier["project"] != project:
            raise ValueError("Choose an earlier Dias report on the same project.")
        old, new = earlier["stages"], report["stages"]
        report["changes"] = {
            "previous_report": previous,
            "chips": [
                {"chip_id": key, "from": old.get(key), "to": new.get(key)}
                for key in sorted(old.keys() | new.keys())
                if old.get(key) != new.get(key)
            ],
        }
    run = run_id or "run-" + uuid.uuid4().hex
    captures = []
    for (url, source, observed_at), label in zip(
        observations, ("Chip board", "Project status"), strict=True
    ):
        request = WebRequest(
            request_id="req-" + uuid.uuid4().hex,
            run_id=run,
            mode=RequestMode.READ,
            data_class=DataClass.BWA_INTERNAL,
            auth_context="none",
            url=url,
            capture_policy="full_evidence",
        )
        result = ReaderResult(
            engine="dias-display",
            requested_url=url,
            final_url=url,
            title=label,
            http_status=200,
            content=source,
        )
        cap = WebCapture.from_reader_result(
            result,
            request,
            captured_at=observed_at,
        )
        captures.append(history.captures.persist(cap, request)[0])
    return history.save("dias", {**report, "run_id": run}, captures)
