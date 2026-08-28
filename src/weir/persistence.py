from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
import uuid
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

from weir.contract import ContractViolation, canonical_json_bytes
from weir.models import DataClass, RequestMode, WebCapture, WebRequest

if TYPE_CHECKING:
    from weir.evidence import EvidenceReference

ARTIFACT_REF_PREFIX = "weir-artifact:sha256:"
BLOB_REF_PREFIX = "weir-blob:sha256:"
CAPTURE_REF_PREFIX = "weir-capture:"
EVIDENCE_REF_PREFIX = "weir-evidence:"
SAFE_CAPTURE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
SHA256_DIGEST = re.compile(r"[0-9a-f]{64}")


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _write_immutable(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            _publish_immutable(temporary, path)
        except FileExistsError:
            if path.read_bytes() != payload:
                raise OSError(f"immutable WEIR artifact collision at {path}")
    finally:
        try:
            temporary.unlink()
            if os.name != "nt":
                _fsync_directory(path.parent)
        except FileNotFoundError:
            pass


def _publish_immutable(temporary: Path, path: Path) -> None:
    if os.name == "nt":
        # MoveFileEx without REPLACE_EXISTING preserves immutable first-writer
        # semantics. WRITE_THROUGH makes Windows flush the move before return.
        import ctypes
        from ctypes import wintypes

        move_file = ctypes.WinDLL("kernel32", use_last_error=True).MoveFileExW
        move_file.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
        move_file.restype = wintypes.BOOL
        if move_file(str(temporary), str(path), 0x00000008):
            return
        error = ctypes.get_last_error()
        if error in {80, 183}:  # ERROR_FILE_EXISTS / ERROR_ALREADY_EXISTS
            raise FileExistsError(path)
        raise ctypes.WinError(error)

    # Hard-link publication is atomic and refuses to replace an immutable winner.
    os.link(temporary, path)
    _fsync_directory(path.parent)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _replace_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_bytes(_canonical_bytes(value) + b"\n")
    temporary.replace(path)


@dataclass(frozen=True, slots=True)
class RetentionDecision:
    persist_manifest: bool
    persist_content: bool
    reason: str


class ArtifactRetentionPolicy:
    """Conservative persistence defaults keyed by data classification."""

    def decide(self, request: WebRequest) -> RetentionDecision:
        if request.data_class is DataClass.RESTRICTED:
            return RetentionDecision(
                False, False, "restricted captures are never persisted by the public broker"
            )
        if request.data_class in {DataClass.PERSONAL, DataClass.BWA_INTERNAL}:
            enabled = request.capture_policy == "full_evidence"
            return RetentionDecision(
                enabled,
                enabled,
                "non-public capture persistence requires capture_policy=full_evidence",
            )
        return RetentionDecision(
            True,
            request.capture_policy in {"content", "full_evidence"},
            "public capture retention follows capture_policy",
        )


@dataclass(frozen=True, slots=True)
class PersistenceInfo:
    stored: bool
    manifest_ref: str | None
    artifact_ref: str | None
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "stored": self.stored,
            "manifest_ref": self.manifest_ref,
            "artifact_ref": self.artifact_ref,
            "reason": self.reason,
        }


class CaptureStore:
    """Local immutable manifests plus content-addressed capture bodies."""

    def __init__(self, root: Path, policy: ArtifactRetentionPolicy | None = None) -> None:
        self.root = root
        self.policy = policy or ArtifactRetentionPolicy()

    def persist(
        self, capture: WebCapture, request: WebRequest
    ) -> tuple[WebCapture, PersistenceInfo]:
        request.validate()
        _validate_capture_id(capture.capture_id)
        if capture.request_id != request.request_id:
            raise ContractViolation(
                "capture_request_mismatch",
                "WebCapture.request_id must match WebRequest.request_id",
            )
        payload = _canonical_bytes(capture.content)
        digest = hashlib.sha256(payload).hexdigest()
        expected_hash = f"sha256:{digest}"
        if expected_hash != capture.content_hash:
            raise ContractViolation(
                "artifact_hash_mismatch",
                "capture content no longer matches its content_hash",
            )
        decision = self.policy.decide(request)
        if not decision.persist_manifest:
            return capture, PersistenceInfo(False, None, None, decision.reason)

        stored_capture = capture
        artifact_ref: str | None = None
        if decision.persist_content:
            artifact_path = self.root / "artifacts" / "sha256" / digest[:2] / f"{digest}.json"
            _write_immutable(artifact_path, payload)
            artifact_ref = ARTIFACT_REF_PREFIX + digest
            stored_capture = replace(capture, raw_artifact_ref=artifact_ref)

        manifest = stored_capture.to_dict()
        # Manifests stay small; retained bodies live only in the deduplicated
        # content-addressed artifact and are rehydrated on demand.
        manifest["content"] = None
        manifest_path = self.root / "captures" / f"{capture.capture_id}.json"
        _write_immutable(manifest_path, _canonical_bytes(manifest) + b"\n")
        manifest_ref = CAPTURE_REF_PREFIX + capture.capture_id
        return stored_capture, PersistenceInfo(True, manifest_ref, artifact_ref, decision.reason)

    def load_capture(self, capture_id: str, hydrate: bool = True) -> WebCapture:
        _validate_capture_id(capture_id)
        path = self.root / "captures" / f"{capture_id}.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError(f"capture manifest {capture_id!r} is not an object")
        capture = WebCapture.from_dict(value)
        if hydrate and capture.raw_artifact_ref:
            value["content"] = self.load_artifact(capture.raw_artifact_ref)
            capture = WebCapture.from_dict(value)
        return capture

    def load_artifact(self, artifact_ref: str) -> Any:
        return json.loads(self.load_artifact_bytes(artifact_ref))

    def load_artifact_bytes(self, artifact_ref: str) -> bytes:
        """Load and hash-check the exact canonical bytes addressed by a reference."""

        if not artifact_ref.startswith(ARTIFACT_REF_PREFIX):
            raise ValueError(f"unsupported artifact reference {artifact_ref!r}")
        digest = artifact_ref.removeprefix(ARTIFACT_REF_PREFIX)
        if not SHA256_DIGEST.fullmatch(digest):
            raise ValueError(f"invalid artifact digest {digest!r}")
        path = self.root / "artifacts" / "sha256" / digest[:2] / f"{digest}.json"
        payload = path.read_bytes()
        if hashlib.sha256(payload).hexdigest() != digest:
            raise ContractViolation(
                "artifact_hash_mismatch",
                f"artifact {artifact_ref} failed its content-hash check",
            )
        return payload

    def verify_capture(self, capture: WebCapture) -> None:
        """Verify a capture against its immutable manifest and retained artifact."""

        stored = self.load_capture(capture.capture_id, hydrate=False)
        if stored.request_id != capture.request_id:
            raise ContractViolation(
                "capture_request_mismatch",
                "cached capture request_id does not match its immutable manifest",
            )
        expected = stored.to_dict()
        actual = replace(capture, content=None).to_dict()
        if expected != actual:
            raise ContractViolation(
                "artifact_hash_mismatch",
                "capture metadata does not match its immutable manifest",
            )
        if capture.raw_artifact_ref is None:
            return
        payload = self.load_artifact_bytes(capture.raw_artifact_ref)
        expected_hash = "sha256:" + hashlib.sha256(payload).hexdigest()
        if expected_hash != capture.content_hash:
            raise ContractViolation(
                "artifact_hash_mismatch",
                "capture artifact does not match content_hash",
            )
        try:
            materialized = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ContractViolation(
                "artifact_not_canonical_json",
                "capture artifact must be UTF-8 JSON",
            ) from exc
        if canonical_json_bytes(materialized) != payload:
            raise ContractViolation(
                "artifact_not_canonical_json",
                "capture artifact is not exact WEIR canonical JSON",
            )
        if capture.content is not None and canonical_json_bytes(capture.content) != payload:
            raise ContractViolation(
                "artifact_hash_mismatch",
                "capture content does not match its retained artifact",
            )

    def persist_evidence_reference(self, reference: EvidenceReference) -> str:
        """Persist a context binding immutably and return its opaque store handle."""

        from weir.evidence import EvidenceReference

        if not isinstance(reference, EvidenceReference):
            raise TypeError("reference must be an EvidenceReference")
        reference.validate()
        _validate_evidence_ref_id(reference.evidence_ref_id)
        path = self.root / "evidence-references" / f"{reference.evidence_ref_id}.json"
        _write_immutable(path, canonical_json_bytes(reference.to_dict()) + b"\n")
        loaded = self.load_evidence_reference(reference.evidence_ref_id)
        if loaded.to_dict() != reference.to_dict():
            raise ContractViolation(
                "reference_hash_mismatch",
                "persisted EvidenceReference does not match the supplied reference",
            )
        return EVIDENCE_REF_PREFIX + reference.evidence_ref_id

    def load_evidence_reference(self, reference_id: str) -> EvidenceReference:
        from weir.evidence import EvidenceReference

        if reference_id.startswith(EVIDENCE_REF_PREFIX):
            reference_id = reference_id.removeprefix(EVIDENCE_REF_PREFIX)
        _validate_evidence_ref_id(reference_id)
        path = self.root / "evidence-references" / f"{reference_id}.json"
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ContractViolation(
                "reference_hash_mismatch",
                "persisted EvidenceReference is not valid JSON",
            ) from exc
        if not isinstance(value, dict):
            raise ContractViolation(
                "reference_hash_mismatch",
                "persisted EvidenceReference is not an object",
            )
        try:
            return EvidenceReference.from_dict(value)
        except (TypeError, ValueError) as exc:
            raise ContractViolation(
                "reference_hash_mismatch",
                "persisted EvidenceReference failed validation",
            ) from exc

    def materialize_evidence(self, reference: EvidenceReference) -> Any:
        """Resolve a persisted reference and verify its exact artifact bytes."""

        stored = self.load_evidence_reference(reference.evidence_ref_id)
        if stored.to_dict() != reference.to_dict():
            raise ContractViolation(
                "reference_hash_mismatch",
                "supplied EvidenceReference does not match the persisted binding",
            )
        stored.require_materialized_content()
        return stored.verify_materialized_artifact(
            self.load_artifact_bytes(stored.artifact_ref or "")
        )

    def persist_blob(self, payload: bytes, request: WebRequest) -> str | None:
        """Persist binary evidence only when the request's retention policy allows it."""

        if not isinstance(payload, bytes):
            raise TypeError("binary evidence payload must be bytes")
        decision = self.policy.decide(request)
        if not decision.persist_content:
            return None
        digest = hashlib.sha256(payload).hexdigest()
        path = self.root / "blobs" / "sha256" / digest[:2] / f"{digest}.bin"
        _write_immutable(path, payload)
        return BLOB_REF_PREFIX + digest

    def load_blob(self, blob_ref: str) -> bytes:
        if not blob_ref.startswith(BLOB_REF_PREFIX):
            raise ValueError(f"unsupported blob reference {blob_ref!r}")
        digest = blob_ref.removeprefix(BLOB_REF_PREFIX)
        if not SHA256_DIGEST.fullmatch(digest):
            raise ValueError(f"invalid blob digest {digest!r}")
        path = self.root / "blobs" / "sha256" / digest[:2] / f"{digest}.bin"
        payload = path.read_bytes()
        if hashlib.sha256(payload).hexdigest() != digest:
            raise OSError(f"blob {blob_ref} failed its content-hash check")
        return payload


def apply_capture_policy(capture: WebCapture, request: WebRequest) -> WebCapture:
    if request.capture_policy == "metadata":
        return replace(capture, content=None)
    return capture


@dataclass(frozen=True, slots=True)
class CacheDecision:
    enabled: bool
    ttl_seconds: int
    reason: str


class CachePolicy:
    """Shared-cache eligibility; only unauthenticated public evidence qualifies."""

    def __init__(self, read_ttl_seconds: int = 300, search_ttl_seconds: int = 60) -> None:
        if read_ttl_seconds < 0 or search_ttl_seconds < 0:
            raise ValueError("cache TTL values cannot be negative")
        self.read_ttl_seconds = read_ttl_seconds
        self.search_ttl_seconds = search_ttl_seconds

    def decide(self, request: WebRequest) -> CacheDecision:
        if (
            request.mode not in {RequestMode.READ, RequestMode.SEARCH}
            or request.side_effects_allowed
        ):
            return CacheDecision(
                False, 0, "only side-effect-free read and search requests are cacheable"
            )
        if request.data_class is not DataClass.PUBLIC:
            return CacheDecision(
                False, 0, f"{request.data_class.value} evidence is not shared-cache eligible"
            )
        if request.auth_context != "none" or request.profile_id is not None:
            return CacheDecision(
                False, 0, "authenticated or profile-scoped evidence is not shared-cache eligible"
            )
        ttl = (
            self.search_ttl_seconds if request.mode is RequestMode.SEARCH else self.read_ttl_seconds
        )
        return CacheDecision(
            ttl > 0, ttl, "unauthenticated public evidence is shared-cache eligible"
        )


@dataclass(frozen=True, slots=True)
class CacheHit:
    capture: WebCapture
    age_seconds: float
    key: str


class CacheIntegrityError(OSError):
    """A cache record exists but cannot be trusted as stored evidence."""

    reason_code = "artifact_hash_mismatch"


class FileCaptureCache:
    def __init__(self, root: Path, clock: Any = time.time) -> None:
        self.root = root
        self._clock = clock

    @staticmethod
    def key_for(
        request: WebRequest,
        engine_ids: list[str],
        max_capture_bytes: int | None = None,
    ) -> str:
        basis = {
            "contract_version": request.contract_version,
            "mode": request.mode.value,
            "intent": request.intent,
            "url": request.url,
            "query": request.query,
            "source": request.source,
            "constraints": request.constraints,
            "data_class": request.data_class.value,
            "auth_context": request.auth_context,
            "profile_id": request.profile_id,
            "allowed_domains": sorted(request.allowed_domains),
            "maximum_depth": request.maximum_depth,
            "capture_policy": request.capture_policy,
            "max_capture_bytes": max_capture_bytes,
            "engines": engine_ids,
        }
        return hashlib.sha256(_canonical_bytes(basis)).hexdigest()

    def get(self, key: str, ttl_seconds: int) -> CacheHit | None:
        _validate_cache_key(key)
        path = self.root / f"{key}.json"
        try:
            serialized = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        except OSError:
            raise
        try:
            value = json.loads(serialized)
            if not isinstance(value, dict) or set(value) != {"key", "stored_at", "capture"}:
                raise ValueError("cache record has missing or unknown fields")
            stored_at = float(value["stored_at"])
            if not math.isfinite(stored_at):
                raise ValueError("cache stored_at must be finite")
            capture_value = value["capture"]
            if value["key"] != key or not isinstance(capture_value, dict):
                raise ValueError("cache record key or capture is invalid")
            capture = WebCapture.from_dict(capture_value)
            age = max(self._clock() - stored_at, 0.0)
            if age > ttl_seconds:
                return None
            return CacheHit(capture, age, key)
        except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            raise CacheIntegrityError(
                f"cache entry {key} failed its integrity check"
            ) from exc

    def put(self, key: str, capture: WebCapture) -> None:
        _validate_cache_key(key)
        value = {"key": key, "stored_at": self._clock(), "capture": capture.to_dict()}
        _replace_json(self.root / f"{key}.json", value)


def _validate_capture_id(capture_id: str) -> None:
    if not SAFE_CAPTURE_ID.fullmatch(capture_id) or capture_id in {".", ".."}:
        raise ValueError(f"invalid capture id {capture_id!r}")


def _validate_evidence_ref_id(reference_id: str) -> None:
    if not SAFE_CAPTURE_ID.fullmatch(reference_id) or reference_id in {".", ".."}:
        raise ValueError(f"invalid evidence reference id {reference_id!r}")


def _validate_cache_key(key: str) -> None:
    if not SHA256_DIGEST.fullmatch(key):
        raise ValueError("cache key must be a lowercase SHA-256 digest")
