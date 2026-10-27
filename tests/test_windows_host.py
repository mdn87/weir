from __future__ import annotations

import copy
import os
import threading
import unittest
from unittest import mock

from weir.browser.windows_host import WindowsDeployment, validate_host_snapshot
from weir.engines.base import EnginePolicyBlocked


SID = "S-1-5-80-123-234-345-456-567"
ROOT = r"C:\ProgramData\Lugos\WeirAdmission"
PYTHON = ROOT + r"\runtime\python.exe"
APP = "S-1-15-2-123-234-345-456-567-678-789"
SYSTEM = "S-1-5-18"
ADMINS = "S-1-5-32-544"
READ = 0x1200A9
FULL = 0x1F01FF


def deployment() -> WindowsDeployment:
    return WindowsDeployment.from_dict({
        "schema_version": 1,
        "host_name": "MATT",
        "service_name": "WeirAdmission",
        "service_sid": SID,
        "root": ROOT,
        "python_executable": PYTHON,
        "base_python_root": ROOT + r"\runtime",
        "firewall_rule": "WeirAdmission-DenyOutbound",
        "appcontainer_name": "Lugos.WeirAdmission",
        "appcontainer_sid": APP,
        "runtime_manifest_sha256": "d" * 64,
        "memory_bytes": 536870912,
        "process_count": 8,
        "credentials": [
            {"caller_id": "lugos-mcp", "source_id": "weir-mcp-v1", "path": ROOT + r"\credentials\lugos-mcp.token"},
            {"caller_id": "fade-weir-authority", "source_id": "weir-fade-v1", "path": ROOT + r"\credentials\fade-weir-authority.token"},
        ],
    })


def acl(path: str, *, credential: bool = False) -> dict:
    return {
        "path": path, "owner": ADMINS, "reparse": False,
        "aces": [
            {"sid": SYSTEM, "rights": FULL, "allow": True, "inherit_only": False},
            {"sid": ADMINS, "rights": FULL, "allow": True, "inherit_only": False},
            {"sid": SID, "rights": READ, "allow": True, "inherit_only": False},
        ],
    }


def snapshot() -> dict:
    spec = deployment()
    process = {
        "sid": SID, "groups": ["S-1-1-0", "S-1-5-6"],
        "privileges": ["SeChangeNotifyPrivilege"], "executable": PYTHON,
        "created": 133000000000000000,
        "appcontainer_sid": None, "capabilities": [], "integrity": "S-1-16-8192",
    }
    return {
        "host_name": "MATT",
        "service": {
            "name": "WeirAdmission", "state": "Running", "pid": 100,
            "account": r"NT SERVICE\WeirAdmission", "start_mode": "Manual",
            "command": spec.command,
        },
        "supervisor": {**process, "pid": 100, "parent_pid": 88},
        "worker": {**process, "pid": 101, "parent_pid": 100, "appcontainer_sid": APP, "integrity": "S-1-16-4096"},
        "paths": [acl(ROOT), acl(ROOT + r"\deployment.json"), acl(PYTHON), acl(ROOT + r"\runtime")],
        "ancestors": [acl(r"C:\ProgramData\Lugos"), acl(r"C:\ProgramData"), acl("C:\\")],
        "closure": {"manifest_sha256": "d" * 64, "verified_files": 50},
        "loopback_exemptions": [],
        "credentials": [acl(item["path"]) for item in spec.credentials],
        "firewall": {
            "services": {"BFE": "Running", "MpsSvc": "Running"},
            "profiles": {"Domain": True, "Private": True, "Public": True},
            "bypass_rules": [],
            "rule": {
                "name": "WeirAdmission-DenyOutbound", "enabled": True,
                "direction": "Outbound", "action": "Block", "profiles": "Any",
                "local_user": f"D:(A;;CC;;;{SID})", "program": "Any", "service": "Any",
                "protocol": "Any", "local_address": ["Any"], "remote_address": ["Any"],
                "local_port": ["Any"], "remote_port": ["Any"], "interface_type": "Any",
                "interface_alias": ["Any"], "package": "Any", "remote_user": "Any",
                "remote_machine": "Any", "authentication": "NotRequired", "enforcement": "Full",
            },
        },
    }


class WindowsHostTests(unittest.TestCase):
    def check(self, value: dict):
        return validate_host_snapshot(deployment(), value, supervisor_pid=100, worker_pid=101)

    def test_exact_live_host_yields_metadata_only_evidence(self):
        result = self.check(snapshot())
        self.assertEqual(len(result.credentials), 2)
        self.assertEqual(result.service_identity, SID)
        self.assertTrue(result.egress_digest.startswith("sha256:"))

    def test_wrong_identity_privilege_parent_or_service_denies(self):
        mutations = [
            ("worker", "sid", SYSTEM),
            ("worker", "groups", [ADMINS]),
            ("worker", "privileges", ["SeImpersonatePrivilege"]),
            ("worker", "appcontainer_sid", None),
            ("worker", "capabilities", ["internetClient"]),
            ("worker", "integrity", "S-1-16-8192"),
            ("worker", "parent_pid", 999),
            ("worker", "pid", 999),
            ("worker", "executable", r"C:\untrusted\python.exe"),
            ("service", "pid", 999),
            ("service", "state", "Stopped"),
            ("service", "account", "LocalSystem"),
            ("service", "command", "untrusted.exe"),
        ]
        for section, key, value in mutations:
            with self.subTest(section=section, key=key):
                facts = snapshot()
                facts[section][key] = value
                with self.assertRaises(EnginePolicyBlocked):
                    self.check(facts)

    def test_writable_runtime_and_readable_credentials_deny(self):
        for section, sid, rights in (("paths", SID, FULL), ("credentials", "S-1-1-0", READ)):
            with self.subTest(section=section):
                facts = snapshot()
                facts[section][0]["aces"].append({"sid": sid, "rights": rights, "allow": True, "inherit_only": False})
                with self.assertRaises(EnginePolicyBlocked):
                    self.check(facts)
        for section in ("paths", "credentials"):
            facts = snapshot()
            facts[section][0]["reparse"] = True
            with self.assertRaises(EnginePolicyBlocked):
                self.check(facts)

    def test_missing_path_or_duplicate_credential_does_not_attest(self):
        facts = snapshot()
        facts["paths"] = []
        with self.assertRaises(EnginePolicyBlocked):
            self.check(facts)
        facts = snapshot()
        facts["credentials"][1] = facts["credentials"][0]
        with self.assertRaises(EnginePolicyBlocked):
            self.check(facts)

    def test_firewall_must_cover_all_programs_protocols_and_addresses(self):
        changes = {
            "program": PYTHON, "protocol": "TCP", "remote_address": ["Internet"],
            "local_port": ["443"], "service": "WeirAdmission", "profiles": "Private",
            "local_user": "D:(A;;CC;;;S-1-5-18)", "enabled": False,
            "action": "Allow", "enforcement": "NotApplicable",
            "interface_alias": ["Ethernet"], "package": "different-package",
            "remote_user": "different-user", "authentication": "Required",
        }
        for key, value in changes.items():
            with self.subTest(key=key):
                facts = snapshot()
                facts["firewall"]["rule"][key] = value
                with self.assertRaises(EnginePolicyBlocked):
                    self.check(facts)

    def test_disabled_firewall_profile_or_bypass_rule_denies(self):
        for change in ("profile", "service", "bypass"):
            facts = snapshot()
            if change == "profile":
                facts["firewall"]["profiles"]["Public"] = False
            elif change == "service":
                facts["firewall"]["services"]["BFE"] = "Stopped"
            else:
                facts["firewall"]["bypass_rules"] = ["domain-bypass"]
            with self.assertRaises(EnginePolicyBlocked):
                self.check(facts)

    def test_runtime_closure_ancestor_or_loopback_exemption_denies(self):
        for change in ("closure", "ancestor", "loopback"):
            facts = snapshot()
            if change == "closure":
                facts["closure"]["manifest_sha256"] = "e" * 64
            elif change == "ancestor":
                facts["ancestors"][0]["aces"].append({"sid": SID, "rights": FULL, "allow": True, "inherit_only": False})
            else:
                facts["loopback_exemptions"] = [APP]
            with self.assertRaises(EnginePolicyBlocked):
                self.check(facts)

    def test_preflight_denial_never_constructs_a_worker(self):
        from weir.windows_service import run_supervisor

        facts = snapshot()
        facts["firewall"]["profiles"]["Public"] = False
        with mock.patch("weir.windows_service._write_status"), \
             mock.patch("weir.windows_service.os.getpid", return_value=100), \
             mock.patch("weir.windows_service.read_host_snapshot", return_value=facts), \
             mock.patch("weir.windows_service.ProcessBrowserWorker") as process, \
             mock.patch("weir.windows_service.ensure_appcontainer_profile") as profile:
            with self.assertRaises(EnginePolicyBlocked):
                run_supervisor(deployment(), threading.Event())
            process.assert_not_called()
            profile.assert_not_called()

    def test_intermediate_runtime_directories_cannot_be_omitted(self):
        data = deployment().to_dict()
        data["base_python_root"] = ROOT + r"\releases\sealed\runtime"
        data["python_executable"] = data["base_python_root"] + r"\python.exe"
        config = WindowsDeployment.from_dict(data)
        facts = snapshot()
        facts["service"]["command"] = config.command
        for kind in ("supervisor", "worker"):
            facts[kind]["executable"] = config.python_executable
        facts["paths"] = [acl(ROOT), acl(ROOT + r"\deployment.json"), acl(config.python_executable), acl(config.base_python_root)]
        with self.assertRaises(EnginePolicyBlocked):
            validate_host_snapshot(config, facts, supervisor_pid=100, worker_pid=101)

        facts["paths"].extend([acl(ROOT + r"\releases"), acl(ROOT + r"\releases\sealed")])
        validate_host_snapshot(config, facts, supervisor_pid=100, worker_pid=101)
        facts["paths"][-1]["aces"].append({"sid": SID, "rights": FULL, "allow": True, "inherit_only": False})
        with self.assertRaises(EnginePolicyBlocked):
            validate_host_snapshot(config, facts, supervisor_pid=100, worker_pid=101)

    def test_credential_group_deny_cannot_attest_service_read_access(self):
        facts = snapshot()
        facts["credentials"][0]["aces"].insert(0, {"sid": "S-1-5-6", "rights": READ, "allow": False, "inherit_only": False})
        with self.assertRaises(EnginePolicyBlocked):
            self.check(facts)

    def test_deployment_rejects_escape_and_duplicate_callers(self):
        original = deployment().to_dict()
        for field, value in (("root", r"\\server\share"), ("service_sid", SYSTEM), ("schema_version", True)):
            data = copy.deepcopy(original)
            data[field] = value
            with self.assertRaises(ValueError):
                WindowsDeployment.from_dict(data)
        data = copy.deepcopy(original)
        data["credentials"][1] = data["credentials"][0]
        with self.assertRaises(ValueError):
            WindowsDeployment.from_dict(data)

    @unittest.skipUnless(os.name == "nt", "live Windows Job Object readback")
    def test_live_job_changes_and_query_failures_deny_refresh(self):
        import ctypes
        from ctypes import wintypes
        from tests.test_process_worker import scripted_factory
        from weir.browser.admission import WorkerResourceLimits
        from weir.browser.process_worker import ProcessBrowserWorker, WorkerProcessLost

        with ProcessBrowserWorker(scripted_factory, resource_limits=WorkerResourceLimits(536870912, 8)) as worker:
            tree = worker._tree
            self.assertEqual(worker.refresh_containment_evidence().resource_limits.process_count, 8)
            with mock.patch.object(tree, "_query_information", return_value=False):
                with self.assertRaises(WorkerProcessLost):
                    worker.refresh_containment_evidence()
            original = tree._extended_type()
            self.assertTrue(tree._query_information(tree._job, 9, ctypes.byref(original), ctypes.sizeof(original), None))
            changed = tree._extended_type.from_buffer_copy(original)
            changed.BasicLimitInformation.LimitFlags &= ~0x200
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            setter = kernel.SetInformationJobObject
            setter.argtypes, setter.restype = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD], wintypes.BOOL
            try:
                self.assertTrue(setter(tree._job, 9, ctypes.byref(changed), ctypes.sizeof(changed)))
                with self.assertRaises(WorkerProcessLost):
                    worker.refresh_containment_evidence()
            finally:
                self.assertTrue(setter(tree._job, 9, ctypes.byref(original), ctypes.sizeof(original)))
            self.assertEqual(worker.refresh_containment_evidence().resource_limits.memory_bytes, 536870912)


if __name__ == "__main__":
    unittest.main()
