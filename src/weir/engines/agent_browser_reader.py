from __future__ import annotations

import json
import shutil
import subprocess

from weir.engines.base import EngineFailure, EngineProbe, EngineUnavailable, ReaderEngine
from weir.models import ReaderResult, RequestMode, WebRequest


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
        proc = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=15)
        version = (proc.stdout or proc.stderr).strip() or None
        return EngineProbe(self.id, proc.returncode == 0, version=version, detail=path)

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
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if proc.returncode != 0:
            raise EngineFailure(proc.stderr.strip() or f"agent-browser exited {proc.returncode}")

        stdout = proc.stdout.strip()
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            payload = {"text": stdout}

        final_url = payload.get("url") if isinstance(payload, dict) else None
        title = payload.get("title") if isinstance(payload, dict) else None
        return ReaderResult(
            engine=self.id,
            requested_url=request.url,
            final_url=final_url or request.url,
            title=title,
            content=payload,
        )
