from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any, Sequence

from weir.contract import (
    ContractViolation,
    canonical_digest,
    parse_timestamp,
    validate_contract_size,
    validate_identifier,
)

WORK_CONTEXT_VERSION = "0.1"
MAX_WORK_CONTEXT_BYTES = 8 * 1024
MAX_INPUT_EVIDENCE_REFS = 32


class WorkContextSource(StrEnum):
    CALLER = "caller"
    OGMI = "ogmi"
    AUTOWORK = "autowork"
    LUGOS_MCP = "lugos-mcp"


@dataclass(frozen=True, slots=True)
class WorkContext:
    """Immutable caller-authored root identity; never inferred from UI focus.

    ``evidence_refs`` are inputs known when the root is created. New acquisition
    outputs bind back to ``context_hash`` through EvidenceReference and never mutate
    this tuple.
    """

    context_id: str
    run_id: str
    correlation_id: str
    source: WorkContextSource
    created_at: str
    objective_id: str | None = None
    assignment_id: str | None = None
    evidence_refs: tuple[str, ...] = ()
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
            "evidence_refs": list(self.evidence_refs),
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
        evidence_refs: Sequence[str] | None = None,
    ) -> WorkContext:
        if not isinstance(source, WorkContextSource):
            raise ValueError("work-context source is invalid")
        if evidence_refs is not None and not isinstance(evidence_refs, (list, tuple)):
            raise ValueError("evidence_refs must be an array")
        context = cls(
            context_id=context_id,
            run_id=run_id,
            correlation_id=correlation_id,
            source=source,
            created_at=created_at,
            objective_id=objective_id,
            assignment_id=assignment_id,
            evidence_refs=tuple(evidence_refs or ()),
        )
        context = replace(context, context_hash=canonical_digest(context._hash_basis()))
        context.validate()
        return context

    def validate(self) -> None:
        if self.contract_version != WORK_CONTEXT_VERSION:
            raise ValueError("unsupported work-context contract version")
        for name in ("context_id", "run_id", "correlation_id"):
            validate_identifier(getattr(self, name), name)
        if self.objective_id is not None and (
            not isinstance(self.objective_id, str) or not self.objective_id
        ):
            raise ValueError("objective_id must be a non-empty string or null")
        if self.objective_id is not None:
            validate_identifier(self.objective_id, "objective_id")
        if self.assignment_id is not None and (
            not isinstance(self.assignment_id, str) or not self.assignment_id
        ):
            raise ValueError("assignment_id must be a non-empty string or null")
        if self.assignment_id is not None:
            validate_identifier(self.assignment_id, "assignment_id")
        if not isinstance(self.source, WorkContextSource):
            raise ValueError("work-context source is invalid")
        if self.source is WorkContextSource.OGMI and not self.objective_id:
            raise ValueError("OGMI work contexts require objective_id")
        if self.source is WorkContextSource.AUTOWORK and not self.assignment_id:
            raise ValueError("Autowork work contexts require assignment_id")
        parse_timestamp(self.created_at, "created_at")
        if not isinstance(self.evidence_refs, tuple):
            raise ValueError("evidence_refs must be an immutable tuple")
        if len(self.evidence_refs) > MAX_INPUT_EVIDENCE_REFS:
            raise ValueError(
                f"evidence_refs cannot exceed {MAX_INPUT_EVIDENCE_REFS} input references"
            )
        if len(set(self.evidence_refs)) != len(self.evidence_refs) or any(
            not isinstance(ref, str) or not ref or len(ref) > 512
            for ref in self.evidence_refs
        ):
            raise ValueError("evidence_refs must contain unique non-empty references")
        if self.context_hash != canonical_digest(self._hash_basis()):
            raise ContractViolation(
                "context_hash_mismatch",
                "context_hash does not match the work context",
            )
        validate_contract_size(
            {**self._hash_basis(), "context_hash": self.context_hash},
            MAX_WORK_CONTEXT_BYTES,
            "WorkContext",
        )

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
            evidence_refs=tuple(value["evidence_refs"]),
            created_at=value["created_at"],
            context_hash=value["context_hash"],
            contract_version=value["contract_version"],
        )
        context.validate()
        return context

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {**self._hash_basis(), "context_hash": self.context_hash}


__all__ = [
    "MAX_INPUT_EVIDENCE_REFS",
    "MAX_WORK_CONTEXT_BYTES",
    "WORK_CONTEXT_VERSION",
    "WorkContext",
    "WorkContextSource",
]
