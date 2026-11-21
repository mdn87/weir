"""One-call bridge for trusted, local Lugos front ends with an authenticated owner."""

import json
import os
import re
import shlex
import sys
from contextlib import contextmanager
from pathlib import Path

from weir.broker import AcquisitionFailed
from weir.contract import ContractViolation
from weir.engines.base import WeirEngineError
from weir.operator_jobs import personal_root, run_job


@contextmanager
def _marketplace_profile(action, jobs):
    """Resolve only the two eBay app bindings in this one-call service process."""
    file = os.environ.get("WEIR_LODE_EBAY_ENV_FILE")
    added = []
    try:
        if action == "marketplace" and action in jobs and file:
            with Path(file).open(encoding="utf-8") as settings:
                for line in settings:
                    key, sep, value = line.strip().partition("=")
                    if not sep or key not in ("EBAY_CLIENT_ID", "EBAY_CLIENT_SECRET"):
                        continue
                    target = "WEIR_" + key
                    if target not in os.environ:
                        parts = shlex.split(value, comments=True)
                        if len(parts) != 1:
                            raise OSError("The configured marketplace profile is unavailable.")
                        os.environ[target] = parts[0]
                        added.append(target)
        yield
    finally:
        for key in added:
            os.environ.pop(key, None)


def dispatch(body: object) -> dict:
    if not isinstance(body, dict) or set(body) != {"owner", "action", "args", "permitted_jobs"}:
        raise ValueError("Invalid operator report request.")
    owner = body["owner"]
    jobs = body["permitted_jobs"]
    if (
        not isinstance(owner, str)
        or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9:._-]{0,199}", owner)
        or not isinstance(jobs, list)
        or len(jobs) > 2
        or not jobs
        or not all(isinstance(j, str) and j in {"dias", "marketplace"} for j in jobs)
    ):
        raise PermissionError("An authorized report reader is required.")
    with _marketplace_profile(body["action"], jobs):
        return run_job(
            body["action"],
            body["args"],
            owner=owner,
            root=personal_root(),
            permitted_jobs=frozenset(jobs),
        )


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(16_385)
        if len(raw) > 16_384:
            raise ValueError("Report request is too large.")
        result = dispatch(json.loads(raw))
        response = {"ok": True, "result": result}
    except PermissionError:
        response = {
            "ok": False,
            "code": "access_denied",
            "error": "This account cannot access the report.",
        }
    except FileNotFoundError:
        response = {
            "ok": False,
            "code": "not_found",
            "error": "The report or its retained evidence is missing.",
        }
    except ContractViolation:
        response = {
            "ok": False,
            "code": "integrity_error",
            "error": "Retained evidence failed verification.",
        }
    except (AcquisitionFailed, WeirEngineError, OSError):
        response = {
            "ok": False,
            "code": "source_unavailable",
            "error": "The report source is unavailable.",
        }
    except (ValueError, KeyError, TypeError):
        response = {
            "ok": False,
            "code": "invalid_request",
            "error": "The request or source projection is invalid.",
        }
    sys.stdout.buffer.write(
        json.dumps(response, ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n"
    )
    return 0 if response["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
