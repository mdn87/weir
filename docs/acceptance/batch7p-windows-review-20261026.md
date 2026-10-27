# Batch 7P Windows review and verification

Target: inventoried `4070pc` (`MATT`). Scope is deny-only admission; no production
effect adapter, browser account, relay poller or database migration is enabled.
Unprivileged local attackers and compromised workers/descendants are in scope;
Administrators, SYSTEM and the OS kernel remain trusted.

## Independent reviews

Design review `20261026-231212-266a4c829352` led to zero-capability AppContainer
isolation, preflight and pre-start checks, process creation-time binding, the full
runtime manifest/ACL closure, exact firewall filter inspection and explicit SCM
service-object and lifecycle policy.

Implementation review `20261027-001749-94f93a2a059b` inspected immutable `907a552`:

| Finding | Disposition |
| --- | --- |
| PowerShell 5.1 cannot read raw NetSecurity properties | Not reproduced. Native Windows PowerShell 5.1.26100.9711 successfully read all named raw properties under strict mode, including `LocalUsers`, `RemoteUsers`, `RemoteMachines`, `AppPath` and `ServiceName`. |
| Root creation can adopt attacker-created objects | Fixed with atomic `CreateDirectoryW` owner/DACL creation, rejection of existing unsafe child objects/reparse points, and bounded ownership changes that never walk old releases or status. |
| Group deny ACE can invalidate credential readability | Fixed by rejecting credential deny ACEs; a `SERVICE` group deny-read regression test covers the reported case. |
| Interrupted runtime copy and missing bundle break recovery | Each attempt gets a fresh release; configuration is published atomically after verification. Rollback reads the recognized installation without requiring the external bundle. |
| Acceptance consumes an SCM crash recovery | Documented explicitly. Two restarts are configured per 24-hour window; the intentional acceptance crash consumes one. No claim is made that verification resets the counter. |

The primary review also found omitted intermediate release directories and the drive
root; both now participate in live ACL validation. CI exposed a pre-existing PID-file
publication race in the parent-death test; PID markers now publish atomically.

Focused correction review `20261027-004019-37629aa583a9` examined `907a552..30ea6ba`
and reported no blocking findings. It verified protected directory creation, rejection
of unsafe existing objects, credential deny-ACE handling and recoverable installation.

Native service acceptance then identified and corrected operator/service execution
policy differences, PowerShell 7 module-path inheritance, numeric firewall enforcement
arrays, the virtual account's high-integrity supervisor token, and Session 0 bootstrap
DLL initialization. The worker probe remains headless; this does not establish GUI or
browser compatibility. Bootstrap diagnostics return only bounded exception types,
known module names and numeric codes, never exception text or credential values.

## Verification status

The real AppContainer worker and descendant passed credential-read and supervisor-
modification denial. Four reachable IPv4/IPv6 TCP/UDP controls received zero worker
packets. Independent Job Object query confirmed membership, 512 MiB memory and eight
processes; the descendant exited on worker closure. These are native sandbox proofs,
not an SCM deployment acceptance record.

The full Windows suite completed 368 tests with four platform skips. Elevated service
installation and automatic host tamper/restart acceptance are being checked separately.
