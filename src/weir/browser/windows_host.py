"""Live Windows host evidence for the deny-only admission deployment.

Only administrator-owned deployment configuration constructs this provider. Neither
HTTP input nor a saved status/attestation document is an input to the inspector.
"""
from __future__ import annotations

import json
import ntpath
import os
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from weir.browser.admission import (
    CredentialProtectionEvidence,
    ProductionControlEvidence,
    ProductionProcessBinding,
    WorkerResourceLimits,
)
from weir.browser.process_worker import ProcessBrowserWorker
from weir.contract import canonical_digest, validate_identifier
from weir.engines.base import EnginePolicyBlocked

_ADMIN_SIDS = frozenset({"S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"})
_PRIVILEGED_GROUPS = _ADMIN_SIDS | {"S-1-5-32-551", "S-1-5-32-547", "S-1-5-32-548", "S-1-5-32-549"}
_WRITE_RIGHTS = 0x40000000 | 0x10000000 | 0x000D0156
_READ_RIGHTS = 0x80000000 | 0x10000000 | 1


def _path(value: object, *, allow_drive_root: bool = False) -> str:
    if allow_drive_root and isinstance(value, str) and re.fullmatch(r"[A-Za-z]:\\", value):
        return ntpath.normcase(value)
    if not isinstance(value, str) or not re.match(r"^[A-Za-z]:\\", value):
        raise ValueError("deployment paths must be local absolute Windows paths")
    if any(c in value for c in ('\0', '\r', '\n', '"')) or ":" in value[2:]:
        raise ValueError("deployment path contains an invalid character")
    normalized = ntpath.normpath(value)
    if normalized != value.rstrip("\\") or len(normalized) < 4:
        raise ValueError("deployment paths must be normalized")
    return ntpath.normcase(normalized)


def _within(path: str, root: str) -> bool:
    return _path(path).startswith(_path(root) + "\\")


@dataclass(frozen=True, slots=True)
class WindowsDeployment:
    host_name: str
    service_name: str
    service_sid: str
    root: str
    python_executable: str
    base_python_root: str
    firewall_rule: str
    appcontainer_name: str
    appcontainer_sid: str
    runtime_manifest_sha256: str
    memory_bytes: int
    process_count: int
    credentials: tuple[dict[str, str], ...]
    schema_version: int = 1

    @classmethod
    def from_dict(cls, value: object) -> WindowsDeployment:
        fields = set(cls.__dataclass_fields__)
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError("deployment has missing or unknown fields")
        if type(value["schema_version"]) is not int or value["schema_version"] != 1:
            raise ValueError("unsupported deployment schema")
        for name in ("host_name", "service_name", "firewall_rule", "appcontainer_name"):
            validate_identifier(value[name], name, max_length=64)
        sid = value["service_sid"]
        if not isinstance(sid, str) or not re.fullmatch(r"S-1-5-80(?:-\d+){5}", sid):
            raise ValueError("a dedicated virtual service account SID is required")
        if not isinstance(value["appcontainer_sid"], str) or not re.fullmatch(r"S-1-15-2(?:-\d+){7}", value["appcontainer_sid"]):
            raise ValueError("a worker AppContainer SID is required")
        if not isinstance(value["runtime_manifest_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["runtime_manifest_sha256"]):
            raise ValueError("runtime manifest digest is required")
        for name in ("root", "python_executable", "base_python_root"):
            _path(value[name])
        if not _within(value["python_executable"], value["root"]):
            raise ValueError("the service executable must be in its protected deployment")
        if not _within(value["base_python_root"], value["root"]):
            raise ValueError("external base Python dependencies are not permitted")
        if _path(value["python_executable"]) != _path(ntpath.join(value["base_python_root"], "python.exe")):
            raise ValueError("the interpreter must belong to the sealed runtime")
        WorkerResourceLimits(value["memory_bytes"], value["process_count"]).validate()
        sources = value["credentials"]
        if not isinstance(sources, list) or not 1 <= len(sources) <= 16:
            raise ValueError("bounded distinct caller sources are required")
        callers, ids, paths = set(), set(), set()
        for source in sources:
            if not isinstance(source, dict) or set(source) != {"caller_id", "source_id", "path"}:
                raise ValueError("invalid caller source")
            validate_identifier(source["caller_id"], "caller_id", max_length=64)
            validate_identifier(source["source_id"], "source_id")
            if not _within(source["path"], ntpath.join(value["root"], "credentials")):
                raise ValueError("credential sources must be in the protected credential directory")
            if source["caller_id"] in callers or source["source_id"] in ids or _path(source["path"]) in paths:
                raise ValueError("caller credential sources must be distinct")
            callers.add(source["caller_id"])
            ids.add(source["source_id"])
            paths.add(_path(source["path"]))
        return cls(**{**value, "host_name": value["host_name"].upper(), "credentials": tuple(dict(item) for item in sources)})

    def to_dict(self) -> dict[str, Any]:
        return {name: list(self.credentials) if name == "credentials" else getattr(self, name)
                for name in self.__dataclass_fields__}

    @property
    def command(self) -> str:
        return f'"{self.python_executable}" -I -B -m weir.windows_service --config "{ntpath.join(self.root, "deployment.json")}"'


@dataclass(frozen=True, slots=True)
class WindowsHostReadback:
    service_identity: str
    lifecycle_instance: str
    credentials: tuple[CredentialProtectionEvidence, ...]
    egress_digest: str


def _deny(condition: bool, detail: str) -> None:
    if not condition:
        raise EnginePolicyBlocked(f"Windows host control denied: {detail}")


def _check_acl(record: dict, service_sid: str, *, credential: bool) -> None:
    _deny(record.get("reparse") is False, "reparse point")
    _deny(record.get("owner") in _ADMIN_SIDS, "untrusted path owner")
    entries = record.get("aces")
    _deny(isinstance(entries, list) and bool(entries), "missing DACL")
    service_reads = False
    for ace in entries:
        _deny(isinstance(ace, dict) and type(ace.get("rights")) is int, "invalid DACL")
        _deny(type(ace.get("allow")) is bool and type(ace.get("inherit_only")) is bool, "invalid ACE")
        if ace["inherit_only"]:
            continue
        # Credential ACLs accept only allow ACEs; avoid approximating group AccessCheck.
        if not ace["allow"]:
            _deny(not credential, "credential has an unsupported deny ACE")
            _deny(ace.get("sid") not in {service_sid, "S-1-1-0", "S-1-5-11"}, "service access denied")
            continue
        sid, rights = ace.get("sid"), ace["rights"]
        if sid not in _ADMIN_SIDS:
            _deny(not rights & _WRITE_RIGHTS, "untrusted path writer")
            if credential:
                _deny(sid == service_sid or not rights & _READ_RIGHTS, "untrusted credential reader")
        if sid == service_sid and rights & _READ_RIGHTS:
            service_reads = True
    if credential:
        _deny(service_reads, "credential is unreadable to service")


def validate_host_snapshot(
    config: WindowsDeployment, facts: dict, *, supervisor_pid: int, worker_pid: int | None,
) -> WindowsHostReadback:
    """Validate live OS observations; never accept assertions from a worker/request."""
    try:
        _deny(facts["host_name"].casefold() == config.host_name.casefold(), "wrong host")
        service = facts["service"]
        _deny(service["name"] == config.service_name and service["state"] == "Running", "service stopped or replaced")
        _deny(service["pid"] == supervisor_pid and service["start_mode"] == "Manual", "wrong supervisor")
        _deny(service["account"].casefold() == ("NT SERVICE\\" + config.service_name).casefold(), "wrong service account")
        _deny(service["command"] == config.command, "wrong service command")
        for kind, expected_pid in (("supervisor", supervisor_pid), ("worker", worker_pid)):
            if expected_pid is None:
                continue
            process = facts[kind]
            _deny(type(process["pid"]) is int and process["pid"] == expected_pid, "wrong process")
            _deny(type(process["created"]) is int and process["created"] > 0, "missing process lifetime")
            _deny(process["sid"] == config.service_sid, "wrong process token")
            _deny(not set(process["groups"]) & _PRIVILEGED_GROUPS, "privileged process group")
            _deny(set(process["privileges"]) <= {"SeChangeNotifyPrivilege"}, "excess process privilege")
            _deny(_path(process["executable"]) == _path(config.python_executable), "wrong executable")
            if kind == "worker":
                validate_worker_isolation(config, process)
            else:
                # SCM gives this non-administrator virtual account high integrity.
                # SID, groups and privileges above establish its authority boundary.
                _deny(process["appcontainer_sid"] is None and process["integrity"] == "S-1-16-12288", "wrong supervisor integrity")
        if worker_pid is not None:
            _deny(facts["worker"]["parent_pid"] == supervisor_pid, "wrong worker parent")
            _deny(facts["worker"]["created"] >= facts["supervisor"]["created"], "wrong process generation")
        closure = facts["closure"]
        _deny(closure["manifest_sha256"] == config.runtime_manifest_sha256
              and type(closure["verified_files"]) is int and closure["verified_files"] > 0, "runtime closure not verified")
        paths = facts["paths"]
        _deny(isinstance(paths, list) and len(paths) >= 4, "missing protected paths")
        observed_paths = set()
        for record in paths:
            key = _path(record["path"])
            _deny(key not in observed_paths, "duplicate path")
            observed_paths.add(key)
            _check_acl(record, config.service_sid, credential=False)
        required = {config.root, ntpath.join(config.root, "deployment.json"), config.python_executable, config.base_python_root}
        intermediate = ntpath.dirname(config.base_python_root)
        while _path(intermediate) != _path(config.root):
            required.add(intermediate)
            intermediate = ntpath.dirname(intermediate)
        _deny({_path(item) for item in required} <= observed_paths, "incomplete runtime inspection")
        ancestors = facts["ancestors"]
        expected_ancestors = []
        ancestor = ntpath.dirname(config.root)
        while True:
            expected_ancestors.append(_path(ancestor, allow_drive_root=True))
            parent = ntpath.dirname(ancestor)
            if ancestor == parent:
                break
            ancestor = parent
        _deny([_path(item["path"], allow_drive_root=True) for item in ancestors] == expected_ancestors, "missing path ancestors")
        for ancestor in ancestors:
            _deny(ancestor["reparse"] is False and ancestor["owner"] in _ADMIN_SIDS, "untrusted path ancestor")
            for ace in ancestor["aces"]:
                if ace["allow"] and not ace["inherit_only"] and ace["sid"] not in _ADMIN_SIDS:
                    _deny(not ace["rights"] & 0x100D0040, "replaceable path ancestor")
        credentials = facts["credentials"]
        _deny(isinstance(credentials, list) and len(credentials) == len(config.credentials), "missing credential source")
        lookup = {_path(item["path"]): item for item in credentials}
        _deny(len(lookup) == len(credentials), "duplicate credential source")
        protected = []
        for source in config.credentials:
            record = lookup[_path(source["path"])]
            _check_acl(record, config.service_sid, credential=True)
            normalized = {"owner": record["owner"], "aces": sorted(record["aces"], key=lambda x: (x["sid"], x["rights"], x["allow"], x["inherit_only"]))}
            protected.append(CredentialProtectionEvidence(source["caller_id"], source["source_id"], canonical_digest(normalized), True))
        firewall = facts["firewall"]
        _deny(firewall["services"] == {"BFE": "Running", "MpsSvc": "Running"}, "firewall service stopped")
        _deny(firewall["profiles"] == {"Domain": True, "Private": True, "Public": True}
              and all(type(x) is bool for x in firewall["profiles"].values()), "firewall profile disabled")
        _deny(firewall["bypass_rules"] == [], "authenticated firewall bypass")
        _deny(config.appcontainer_sid not in facts["loopback_exemptions"], "AppContainer loopback exemption")
        # WMI returns an array: 1=Full, 5=InactiveProfile. Inactive profiles do not
        # weaken the exact all-profile rule; every profile must still be enabled.
        enforcement = firewall["rule"]["enforcement"]
        _deny(isinstance(enforcement, list) and 1 <= len(enforcement) <= 16 and 1 in enforcement
              and all(type(item) is int and item in (1, 5) for item in enforcement), "egress rule is not fully enforced")
        expected_rule = {
            "name": config.firewall_rule, "enabled": True, "direction": "Outbound", "action": "Block",
            "profiles": "Any", "local_user": f"D:(A;;CC;;;{config.service_sid})",
            "program": "Any", "service": "Any", "protocol": "Any",
            "local_address": ["Any"], "remote_address": ["Any"], "local_port": ["Any"], "remote_port": ["Any"],
            "interface_type": "Any", "interface_alias": ["Any"], "package": "Any",
            "remote_user": "Any", "remote_machine": "Any", "authentication": "NotRequired", "enforcement": enforcement,
        }
        _deny(firewall["rule"] == expected_rule and firewall["rule"]["enabled"] is True, "egress rule narrowed or disabled")
        instance = f"scm-{supervisor_pid}-{facts['supervisor']['created']}"
        return WindowsHostReadback(config.service_sid, instance, tuple(protected), canonical_digest(firewall))
    except EnginePolicyBlocked:
        raise
    except (KeyError, TypeError, ValueError, AttributeError):
        raise EnginePolicyBlocked("Windows host snapshot is incomplete or malformed") from None


def _inspector_script() -> Path:
    return Path(__file__).resolve().parents[1] / "data" / "windows" / "inspect-controls.ps1"


def validate_worker_isolation(config: WindowsDeployment, process: dict) -> None:
    _deny(process["sid"] == config.service_sid, "wrong worker identity")
    _deny(process["appcontainer_sid"] == config.appcontainer_sid, "worker not in its AppContainer")
    _deny(process["capabilities"] == [] and process["integrity"] == "S-1-16-4096", "worker has excess capabilities or integrity")
    _deny(set(process["privileges"]) <= {"SeChangeNotifyPrivilege"}, "excess worker privilege")


def read_host_snapshot(config: WindowsDeployment, worker_pid: int | None = None, *, supervisor_pid: int | None = None) -> dict:
    if os.name != "nt":
        raise EnginePolicyBlocked("Windows host inspection requires Windows")
    from weir.browser.windows_process import inspect_process

    supervisor_pid = os.getpid() if supervisor_pid is None else supervisor_pid
    identities = [("supervisor", supervisor_pid)] + ([] if worker_pid is None else [("worker", worker_pid)])
    before = {name: inspect_process(pid) for name, pid in identities}
    powershell = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    request = {"config": config.to_dict(), "supervisor_pid": supervisor_pid, "worker_pid": worker_pid}
    try:
        result = subprocess.run(
            [str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned", "-File", str(_inspector_script())],
            input=json.dumps(request), capture_output=True, text=True, encoding="utf-8",
            timeout=45, creationflags=subprocess.CREATE_NO_WINDOW, check=False,
        )
        if result.returncode or len(result.stdout) > 16 * 1024 * 1024:
            match = re.search(r"Windows control inspection denied: (runtime|credentials|service|firewall)\b", result.stderr)
            if match:
                raise EnginePolicyBlocked("Windows control readback failed: " + match[1])
            raise EnginePolicyBlocked("Windows control readback failed")
        facts = json.loads(result.stdout)
        for name, pid in identities:
            after = inspect_process(pid)
            _deny(before[name] == after, "process changed during inspection")
            facts[name] = {**after, "parent_pid": facts[name]["parent_pid"]}
        return facts
    except (OSError, ValueError, subprocess.SubprocessError):
        raise EnginePolicyBlocked("Windows control readback is unavailable") from None


class WindowsHostInspector:
    def __init__(self, config: WindowsDeployment, worker: ProcessBrowserWorker) -> None:
        if not isinstance(worker, ProcessBrowserWorker):
            raise TypeError("live Windows admission requires ProcessBrowserWorker")
        self.config, self.worker = config, worker

    def __call__(self) -> ProductionControlEvidence:
        worker, config = self.worker, self.config
        _deny(worker.is_alive, "worker exited")
        containment = worker.refresh_containment_evidence()
        expected = WorkerResourceLimits(config.memory_bytes, config.process_count)
        _deny(containment.resource_limits == expected, "wrong job limits")
        facts = read_host_snapshot(config, worker.process_id)
        readback = validate_host_snapshot(config, facts, supervisor_pid=os.getpid(), worker_pid=worker.process_id)
        _deny(worker.is_alive and worker.refresh_containment_evidence() == containment, "worker changed during inspection")
        now = datetime.now(timezone.utc)
        return ProductionControlEvidence.create(
            attestation_id="windows-" + uuid4().hex, platform="windows",
            service_identity=readback.service_identity, worker_identity=readback.service_identity,
            worker_id=worker.descriptor.worker_id, worker_instance_id=worker.descriptor.instance_id,
            containment=containment, process_binding=ProductionProcessBinding(config.host_name, os.getpid(), facts["supervisor"]["created"], facts["worker"]["created"], config.appcontainer_sid),
            restricted_identity=True, credential_protection=readback.credentials,
            lifecycle_supervisor="windows-service-control-manager", lifecycle_instance_id=readback.lifecycle_instance,
            lifecycle_healthy=True, egress_policy_id=config.firewall_rule,
            egress_policy_digest=readback.egress_digest, egress_enforced=True,
            verified_at=now.isoformat(), expires_at=(now + timedelta(seconds=60)).isoformat(),
        )


__all__ = ["WindowsDeployment", "WindowsHostInspector", "validate_host_snapshot"]
