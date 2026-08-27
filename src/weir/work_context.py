from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

WORK_CONTEXT_VERSION = "0.1"


class WorkContextSource(StrEnum):
    CALLER = "caller"
    OGMI = "ogmi"
    AUTOWORK = "autowork"
    LUGOS_MCP = "lugos-mcp"


def _digest(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


@dataclass(slots=True)
class WorkContext:
    """Caller-authored identity for durable work; never inferred from UI focus."""

    context_id: str
    run_id: str
    correlation_id: str
    source: WorkContextSource
    created_at: str
    objective_id: str | None = None
    assignment_id: str | None = None
    evidence_refs: list[str] | None = None
    context_hash: str = ""
    contract_version: str = WORK_CONTEXT_VERSION

    def _hash_basis(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "context_id": self.context_id,
            "objective_id": self.objective_id,
            "run_id": self.run_id,
            "assignment_id": self.assignment_id,
            "correlation_id": self.correlation_id,
            "source": self.source.value,
            "evidence_refs": list(self.evidence_refs or []),
            "created_at": self.created_at,
        }

    @classmethod
    def create(
        cls,
        *,
        context_id: str,
        run_id: str,
        correlation_id: str,
        source: WorkContextSource,
        created_at: str,
        objective_id: str | None = None,
        assignment_id: str | None = None,
        evidence_refs: list[str] | None = None,
    ) -> WorkContext:
        if not isinstance(source, WorkContextSource):
            raise ValueError("work-context source is invalid")
        context = cls(
            context_id=context_id,
            run_id=run_id,
            correlation_id=correlation_id,
            source=source,
            created_at=created_at,
            objective_id=objective_id,
            assignment_id=assignment_id,
            evidence_refs=list(evidence_refs or []),
        )
        context.context_hash = _digest(context._hash_basis())
        context.validate()
        return context

    def validate(self) -> None:
        if self.contract_version != WORK_CONTEXT_VERSION:
            raise ValueError("unsupported work-context contract version")
        for name in ("context_id", "run_id", "correlation_id"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name):
                raise ValueError(f"{name} cannot be empty")
        if self.objective_id is not None and (
            not isinstance(self.objective_id, str) or not self.objective_id
        ):
            raise ValueError("objective_id must be a non-empty string or null")
        if self.assignment_id is not None and (
            not isinstance(self.assignment_id, str) or not self.assignment_id
        ):
            raise ValueError("assignment_id must be a non-empty string or null")
        if not isinstance(self.source, WorkContextSource):
            raise ValueError("work-context source is invalid")
        if self.source is WorkContextSource.OGMI and not self.objective_id:
            raise ValueError("OGMI work contexts require objective_id")
        if self.source is WorkContextSource.AUTOWORK and not self.assignment_id:
            raise ValueError("Autowork work contexts require assignment_id")
        try:
            timestamp = datetime.fromisoformat(self.created_at.replace("Z", "+00:00"))
        except (AttributeError, ValueError) as exc:
            raise ValueError("created_at must be an RFC 3339 timestamp") from exc
        if timestamp.tzinfo is None:
            raise ValueError("created_at must include a timezone")
        if not isinstance(self.evidence_refs, list):
            raise ValueError("evidence_refs must be an array")
        if len(set(self.evidence_refs)) != len(self.evidence_refs) or any(
            not isinstance(ref, str) or not ref for ref in self.evidence_refs
        ):
            raise ValueError("evidence_refs must contain unique non-empty references")
        if self.context_hash != _digest(self._hash_basis()):
            raise ValueError("context_hash does not match the work context")

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> WorkContext:
        required = {
            "contract_version",
            "context_id",
            "objective_id",
            "run_id",
            "assignment_id",
            "correlation_id",
            "source",
            "evidence_refs",
            "created_at",
            "context_hash",
        }
        if not isinstance(value, dict) or set(value) != required:
            raise ValueError("work context has missing or unknown fields")
        if not isinstance(value["evidence_refs"], list):
            raise ValueError("evidence_refs must be an array")
        try:
            source = WorkContextSource(value["source"])
        except (TypeError, ValueError) as exc:
            raise ValueError("work-context source is invalid") from exc
        context = cls(
            context_id=value["context_id"],
            objective_id=value["objective_id"],
            run_id=value["run_id"],
            assignment_id=value["assignment_id"],
            correlation_id=value["correlation_id"],
            source=source,
            evidence_refs=list(value["evidence_refs"]),
            created_at=value["created_at"],
            context_hash=value["context_hash"],
            contract_version=value["contract_version"],
        )
        context.validate()
        return context

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {**self._hash_basis(), "context_hash": self.context_hash}


__all__ = ["WORK_CONTEXT_VERSION", "WorkContext", "WorkContextSource"]
