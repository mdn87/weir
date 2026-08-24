from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


CONTRACT_VERSION = "0.1"


class RequestMode(StrEnum):
    DISCOVER = "discover"
    READ = "read"
    OBSERVE = "observe"
    INTERACT = "interact"
    COMMIT = "commit"


class DataClass(StrEnum):
    PUBLIC = "public"
    PERSONAL = "personal"
    BWA_INTERNAL = "bwa_internal"
    RESTRICTED = "restricted"


class TrustLabel(StrEnum):
    UNTRUSTED_EXTERNAL_CONTENT = "untrusted_external_content"
    TRUSTED_INTERNAL_SOURCE = "trusted_internal_source"
    UNKNOWN = "unknown"


@dataclass(slots=True)
class WebRequest:
    request_id: str
    run_id: str
    mode: RequestMode
    data_class: DataClass = DataClass.PUBLIC
    auth_context: str = "none"
    intent: str = ""
    url: str | None = None
    query: str | None = None
    profile_id: str | None = None
    allowed_domains: list[str] = field(default_factory=list)
    preferred_engine: str | None = None
    maximum_depth: int = 0
    evidence_required: bool = True
    side_effects_allowed: bool = False
    capture_policy: str = "content"
    contract_version: str = CONTRACT_VERSION

    def validate(self) -> None:
        if not self.url and not self.query:
            raise ValueError("WebRequest requires url or query")
        if self.mode in {RequestMode.DISCOVER, RequestMode.READ, RequestMode.OBSERVE} and self.side_effects_allowed:
            raise ValueError(f"{self.mode} requests cannot enable side effects")
        if self.auth_context == "none" and self.profile_id is not None:
            raise ValueError("profile_id requires a non-none auth_context")
        if self.maximum_depth < 0:
            raise ValueError("maximum_depth cannot be negative")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        value = asdict(self)
        value["mode"] = self.mode.value
        value["data_class"] = self.data_class.value
        return value


@dataclass(slots=True)
class ReaderResult:
    engine: str
    requested_url: str
    final_url: str
    content: Any
    title: str | None = None
    http_status: int | None = None
    engine_version: str | None = None
    diagnostics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _content_hash(content: Any) -> str:
    canonical = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(slots=True)
class WebCapture:
    """Contract-shaped capture emitted for every retained read.

    Mirrors contracts/web-capture.schema.json exactly; the schema declares
    additionalProperties=false, so engine diagnostics stay on ReaderResult.
    """

    capture_id: str
    request_id: str
    captured_at: str
    engine: str
    requested_url: str
    final_url: str
    trust: TrustLabel
    content_hash: str
    engine_version: str | None = None
    title: str | None = None
    http_status: int | None = None
    auth_scope: str = "none"
    content: Any = None
    raw_artifact_ref: str | None = None
    screenshot_artifact_ref: str | None = None
    contract_version: str = CONTRACT_VERSION

    @classmethod
    def from_reader_result(cls, result: ReaderResult, request: WebRequest) -> WebCapture:
        return cls(
            capture_id=f"webcap-{uuid.uuid4().hex}",
            request_id=request.request_id,
            captured_at=datetime.now(timezone.utc).isoformat(),
            engine=result.engine,
            engine_version=result.engine_version,
            requested_url=result.requested_url,
            final_url=result.final_url,
            title=result.title,
            http_status=result.http_status,
            auth_scope=request.auth_context,
            trust=TrustLabel.UNTRUSTED_EXTERNAL_CONTENT,
            content_hash=_content_hash(result.content),
            content=result.content,
        )

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["trust"] = self.trust.value
        return value
