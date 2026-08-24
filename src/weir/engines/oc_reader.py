from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

from weir.engines.base import EngineCannotRead, EngineFailure, EngineProbe, EngineUnavailable, ReaderEngine
from weir.engines.shims import safe_argv
from weir.models import ReaderResult, RequestMode, WebRequest


class OcReader(ReaderEngine):
    """Read-only adapter for only-cli/oc.

    Each call gets an isolated OC_HOME so `oc` navigation state never leaks
    across unrelated WEIR requests. The returned page is copied into a WEIR
    result and the temporary session state is discarded.
    """

    id = "oc"

    def __init__(self, binary: str = "oc") -> None:
        self.binary = binary

    def probe(self) -> EngineProbe:
        path = shutil.which(self.binary)
        if not path:
            return EngineProbe(self.id, False, detail=f"{self.binary} not found on PATH")
        proc = subprocess.run(
            [path, "--help"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15
        )
        return EngineProbe(self.id, proc.returncode == 0, detail=path)

    def read(self, request: WebRequest) -> ReaderResult:
        request.validate()
        if request.mode is not RequestMode.READ:
            raise EngineFailure("OcReader supports mode=read only")
        if not request.url:
            raise EngineFailure("OcReader requires a URL")

        binary = shutil.which(self.binary)
        if not binary:
            raise EngineUnavailable(f"{self.binary} not found on PATH")

        with tempfile.TemporaryDirectory(prefix="weir-oc-") as state_dir:
            env = os.environ.copy()
            env["OC_HOME"] = state_dir
            session = f"weir-{uuid.uuid4().hex}"
            cmd = safe_argv(binary, ["open", request.url, "--json", "--session", session])
            proc = subprocess.run(
                cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, timeout=120
            )

        if proc.returncode == 2:
            raise EngineCannotRead(proc.stderr.strip() or "oc reported no readable content")
        if proc.returncode != 0:
            raise EngineFailure(proc.stderr.strip() or f"oc exited {proc.returncode}")

        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise EngineFailure(f"oc returned invalid JSON: {exc}") from exc

        if payload.get("empty"):
            raise EngineCannotRead("oc returned empty=true")

        return ReaderResult(
            engine=self.id,
            requested_url=request.url,
            final_url=payload.get("url") or request.url,
            title=payload.get("title"),
            http_status=None,
            engine_version=None,
            content=payload,
            diagnostics={"isolated_session": True},
        )
