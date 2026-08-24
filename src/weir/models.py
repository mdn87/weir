from __future__ import annotations

from dataclasses import asdict, dataclass, field
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
