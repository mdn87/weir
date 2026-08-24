from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from weir.engines.base import EngineFailure, EngineProbe, EngineUnavailable, ReaderEngine
from weir.models import ReaderResult, RequestMode, WebRequest


def _run_detached_safe(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    """Run a CLI that may spawn a persistent daemon.

    agent-browser leaves a background daemon holding inherited stdio handles,
    so PIPE capture never sees EOF and blocks far past the child's own exit.
    File redirection keeps subprocess.run waiting on process exit only.
    """
    with tempfile.TemporaryDirectory(prefix="weir-ab-", ignore_cleanup_errors=True) as tmp:
        out_path = Path(tmp) / "stdout"
        err_path = Path(tmp) / "stderr"
        with out_path.open("wb") as out, err_path.open("wb") as err:
            proc = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=timeout)
        return (
            proc.returncode,
            out_path.read_text(encoding="utf-8", errors="replace"),
            err_path.read_text(encoding="utf-8", errors="replace"),
        )


class AgentBrowserReader(ReaderEngine):
    """Read-only wrapper around `agent-browser read`.

    This adapter intentionally does not launch or control a browser session.
    Interactive `agent-browser` support belongs behind the future browser
    session and action-authority contracts.
    """

    id = "agent-browser-read"

    def __init__(self, binary: str = "agent-browser") -> None:
        self.binary = binary

    def probe(self) -> EngineProbe:
        path = shutil.which(self.binary)
        if not path:
            return EngineProbe(self.id, False, detail=f"{self.binary} not found on PATH")
        returncode, stdout, stderr = _run_detached_safe([path, "--version"], timeout=15)
        version = (stdout or stderr).strip() or None
        return EngineProbe(self.id, returncode == 0, version=version, detail=path)

    def read(self, request: WebRequest) -> ReaderResult:
        request.validate()
        if request.mode is not RequestMode.READ:
            raise EngineFailure("AgentBrowserReader supports mode=read only")
        if not request.url:
            raise EngineFailure("AgentBrowserReader requires a URL")

        binary = shutil.which(self.binary)
        if not binary:
            raise EngineUnavailable(f"{self.binary} not found on PATH")

        cmd = [binary, "read", request.url, "--json"]
        returncode, stdout, stderr = _run_detached_safe(cmd, timeout=120)
        if returncode != 0:
            raise EngineFailure(stderr.strip() or f"agent-browser exited {returncode}")

        stdout = stdout.strip()
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            payload = {"text": stdout}

        data = payload.get("data") if isinstance(payload, dict) else None
        if isinstance(payload, dict) and payload.get("success") is False:
            error = payload.get("error")
            raise EngineFailure(str(error) if error else "agent-browser reported success=false")
        if not isinstance(data, dict):
            data = payload if isinstance(payload, dict) else {}

        final_url = data.get("finalUrl") or data.get("url")
        return ReaderResult(
            engine=self.id,
            requested_url=request.url,
            final_url=final_url or request.url,
            title=data.get("title"),
            http_status=data.get("status"),
            content=payload,
        )
