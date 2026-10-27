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

The credential denial fixture initially retained an inherited service-read ACE.
Native reproduction counted one remaining service ACE; the corrected explicit
administrator/SYSTEM-only DACL counted zero, and restoration reproduced the original
SDDL exactly. Acceptance now checks the installed denial fixture before observing the
service, so a fixture that failed to remove access cannot pass unnoticed.

All four denial checks and parent-death cleanup passed before the commissioning run
hit an exhausted SCM restart counter (event 7034 recorded 11 startup failures).
Independent recovery review `20261027-021526-e18d08e3c2a3` concurred with recreating
only the stopped, disabled, task-owned service registration. The recovery preserved
files, caller credentials, firewall and AppContainer profile, and independently
confirmed the same virtual SID, exact service policy and unchanged configuration.
The full acceptance sequence was then restarted with a fresh SCM registration.
This one-time recovery is outside the installer's automatic behavior.

## Verification status

Full elevated host acceptance passed at 2026-10-27 02:27 UTC (2026-10-26 locally).
The [native report](batch7p-windows-controls-20261026.json) records independent live
SCM/ACL/firewall/runtime readback; disabled and narrowed firewall, inaccessible
credential and writable-runtime denial with zero worker operations; worker and
descendant death on supervisor exit; and SCM restart with new process bindings.

The real AppContainer worker and descendant passed credential-read and each tested
supervisor modification-right denial. Four reachable IPv4/IPv6 TCP/UDP controls
received zero worker packets. Independent Job Object query confirmed membership,
512 MiB memory and eight processes. SCM event 7031 recorded the accepted crash as
failure 1 and restarted the service after five seconds; one configured recovery
remains in the current 24-hour window.

The full Windows suite completed 368 tests with four platform skips. Packaged CLI
checks outside the checkout and both GitHub CI jobs passed. Production effects,
GUI/browser compatibility and Linux host admission remain outside this acceptance.
