from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
PORTABLE_KEY_PATTERN = re.compile(r"[a-z][a-z0-9_.-]{0,63}")
MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_PORTABLE_JSON_DEPTH = 8
MAX_PORTABLE_ARRAY_ITEMS = 256
MAX_PORTABLE_OBJECT_PROPERTIES = 128
MAX_PORTABLE_STRING_LENGTH = 16_384

# Fade rejects these field names recursively. WEIR-owned full-authority payloads
# keep their schema keys outside this vocabulary so the authority handoff cannot
# fail only after approval.
FADE_FORBIDDEN_KEYS = frozenset(
    {
        "api_key",
        "authorization",
        "bearer_token",
        "cookie",
        "password",
        "refresh_token",
        "secret",
        "secret_values",
        "token",
    }
)


class ContractViolation(ValueError):
    """A stable contract rejection with a machine-readable reason code."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


def canonical_json_bytes(value: Any) -> bytes:
    """Return WEIR canonical JSON: sorted keys, UTF-8, and no extra whitespace."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def is_sha256(value: object) -> bool:
    return isinstance(value, str) and SHA256_PATTERN.fullmatch(value) is not None


def parse_timestamp(value: object, name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an RFC 3339 timestamp") from exc
    if not isinstance(value, str) or parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{name} must include a timezone")
    return parsed.astimezone(timezone.utc)


def validate_identifier(value: object, name: str, *, max_length: int = 128) -> str:
    if not isinstance(value, str) or not value or len(value) > max_length:
        raise ValueError(f"{name} must be a non-empty string of at most {max_length} characters")
    return value


def validate_contract_size(value: Any, maximum: int, name: str) -> None:
    if len(canonical_json_bytes(value)) > maximum:
        raise ContractViolation(
            "contract_too_large",
            f"{name} exceeds its {maximum}-byte canonical JSON limit",
        )


def is_portable_json_value(
    value: Any,
    *,
    depth: int = 0,
    reject_fade_keys: bool = False,
) -> bool:
    """Return whether a value hashes identically in Python and JavaScript.

    Extension values deliberately exclude floats and unsafe integers. Object keys
    are ASCII and bounded, avoiding Python/JavaScript key-order edge cases.
    """

    if depth > MAX_PORTABLE_JSON_DEPTH:
        return False
    if value is None or isinstance(value, (str, bool)):
        return not isinstance(value, str) or len(value) <= MAX_PORTABLE_STRING_LENGTH
    if type(value) is int:
        return -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER
    if isinstance(value, list):
        return len(value) <= MAX_PORTABLE_ARRAY_ITEMS and all(
            is_portable_json_value(
                item,
                depth=depth + 1,
                reject_fade_keys=reject_fade_keys,
            )
            for item in value
        )
    if isinstance(value, dict):
        if len(value) > MAX_PORTABLE_OBJECT_PROPERTIES:
            return False
        for key, item in value.items():
            if not isinstance(key, str) or PORTABLE_KEY_PATTERN.fullmatch(key) is None:
                return False
            normalized = key.lower().replace("-", "_")
            if reject_fade_keys and normalized in FADE_FORBIDDEN_KEYS:
                return False
            if not is_portable_json_value(
                item,
                depth=depth + 1,
                reject_fade_keys=reject_fade_keys,
            ):
                return False
        return True
    return False


def contains_forbidden_key(value: Any) -> bool:
    stack = [value]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for key, child in node.items():
                if str(key).lower().replace("-", "_") in FADE_FORBIDDEN_KEYS:
                    return True
                stack.append(child)
        elif isinstance(node, (list, tuple)):
            stack.extend(node)
    return False


__all__ = [
    "ContractViolation",
    "FADE_FORBIDDEN_KEYS",
    "MAX_PORTABLE_ARRAY_ITEMS",
    "MAX_PORTABLE_JSON_DEPTH",
    "MAX_PORTABLE_OBJECT_PROPERTIES",
    "MAX_PORTABLE_STRING_LENGTH",
    "MAX_SAFE_INTEGER",
    "PORTABLE_KEY_PATTERN",
    "canonical_digest",
    "canonical_json_bytes",
    "contains_forbidden_key",
    "is_portable_json_value",
    "is_sha256",
    "parse_timestamp",
    "validate_contract_size",
    "validate_identifier",
]
