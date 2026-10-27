"""Independent, read-only verification of a running Windows admission deployment."""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

from weir.browser.admission import ProductionControlEvidence
from weir.browser.windows_host import read_host_snapshot, validate_host_snapshot, validate_worker_isolation
from weir.browser.windows_process import inspect_named_job, inspect_process
from weir.engines.base import EnginePolicyBlocked
from weir.windows_service import load_deployment


def verify(config_path: Path, status_path: Path) -> dict:
    config = load_deployment(config_path)
    if status_path.stat().st_size > 131072:
        raise ValueError("status exceeds the allowed size")
    status = json.loads(status_path.read_text(encoding="utf-8-sig"))
    now = datetime.now(timezone.utc)
    heartbeat = datetime.fromisoformat(status["heartbeat_at"])
    if status["state"] != "admitted" or status["action_endpoint_enabled"] is not False or heartbeat > now + timedelta(seconds=5) or now - heartbeat > timedelta(seconds=90):
        raise EnginePolicyBlocked("service has no fresh deny-only admission")
    evidence = ProductionControlEvidence.from_dict(status["evidence"])
    evidence.require_current(now, caller_id="lugos-mcp", expected_platform="windows")
    evidence.require_current(now, caller_id="fade-weir-authority", expected_platform="windows")
    pid = evidence.containment.process_id
    facts = read_host_snapshot(config, pid, supervisor_pid=evidence.process_binding.supervisor_pid)
    readback = validate_host_snapshot(config, facts, supervisor_pid=status["supervisor_pid"], worker_pid=pid)
    binding = evidence.process_binding
    if (binding.host_id != config.host_name or binding.worker_created != facts["worker"]["created"]
            or binding.supervisor_created != facts["supervisor"]["created"]
            or binding.isolation_id != config.appcontainer_sid
            or evidence.egress_policy_digest != readback.egress_digest
            or evidence.credential_protection != readback.credentials):
        raise EnginePolicyBlocked("service evidence differs from live host controls")
    job = inspect_named_job(status["job_object_name"], pid)
    if (not job["member"] or job["flags"] & 0x2208 != 0x2208 or job["flags"] & 0x1800
            or job["memory_bytes"] != config.memory_bytes or job["process_count"] != config.process_count):
        raise EnginePolicyBlocked("live Job Object differs from required controls")
    probe = status["isolation_probe"]
    for kind in ("worker", "descendant"):
        if any(probe[kind].get(field) is not True for field in ("credential_access_denied", "supervisor_access_denied", "network_attempts_complete")):
            raise EnginePolicyBlocked("isolation probe is incomplete")
    if status["positive_controls"] != 4 or status["delivered_packets"] != 0:
        raise EnginePolicyBlocked("packet enforcement did not pass")
    descendant = inspect_process(probe["sentinel_pid"])
    validate_worker_isolation(config, descendant)
    if not inspect_named_job(status["job_object_name"], descendant["pid"])["member"]:
        raise EnginePolicyBlocked("descendant is outside the worker job")
    evidence.require_current(datetime.now(timezone.utc), caller_id="lugos-mcp", expected_platform="windows")
    if (inspect_process(pid)["created"] != binding.worker_created or
            inspect_process(binding.supervisor_pid)["created"] != binding.supervisor_created):
        raise EnginePolicyBlocked("process lifetime changed during verification")
    return {"state": "verified", "checked_at": now.isoformat(), "manifest_sha256": config.runtime_manifest_sha256,
            "process_binding": binding.to_dict(), "worker_pid": pid,
            "descendant_pid": descendant["pid"], "descendant_created": descendant["created"],
            "job": job, "action_endpoint_enabled": False, "positive_controls": 4, "delivered_packets": 0}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--status", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.config, args.status), sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, EnginePolicyBlocked):
        print(json.dumps({"state": "denied", "reason_code": "independent_host_verification_failed"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
