# Windows production controls (Batch 7P)

Status: source implemented; elevated host acceptance remains pending. No production website actions are authorized by
this deployment. The target is the inventoried Windows 11 workstation `4070pc`
(Windows computer name `MATT`). Linux needs a production process-binding and host provider.

## Outcome and boundary

Install an independently inspectable, deny-only admission service. It runs a real
`ProcessBrowserWorker` with Windows Job Object limits under the dedicated virtual
account `NT SERVICE\WeirAdmission`. Its worker and descendants run in a low-integrity,
zero-capability AppContainer with no supervisor handles or application environment.
The AppContainer cannot read the supervisor's caller credentials or modify its process.
A worker with no browser/action capabilities
proves the controls. It never serves the WEIR HTTP action endpoint, polls the relay,
loads a browser profile, or enables external effects.

The service runs in noninteractive Session 0. Its kernel-only denial probe does not
import the supervisor's SCM entrypoint or `ctypes`, whose DLL initialization failed
in this AppContainer during native acceptance. GUI/browser compatibility is not
claimed by this probe and remains part of a future browser/effect deployment.

The service uses the existing Windows Service Control Manager, not a new scheduler.
The account has no administrator membership. Its executable/configuration and caller
credential files live in an administrator-owned deployment directory. SYSTEM and
Administrators provision it; the service reads code/configuration/credentials and can
write only its status directory. Distinct caller sources are reserved for
`lugos-mcp` and `fade-weir-authority`; credentials never enter reports or the repo.

SCM assigns the supervisor high integrity (`S-1-16-12288`) even for this nonadministrator
virtual account. Native readback confirmed the dedicated SID, no administrator group
and only `SeChangeNotifyPrivilege`. The worker must independently have low integrity
(`S-1-16-4096`) and no AppContainer capabilities.

## Live inspection

The supervisor performs host preflight before creating a worker and verifies the child
token before its factory runs. The provider reads the live Job Object, worker process
and service on each admission.
It binds worker and supervisor process IDs and creation times to the SCM instance,
checks their token identities, rejects privileged token groups, and verifies exact
file ACLs, protected ancestors and the entire manifest-hashed Python runtime, including
standard library, native modules, dependencies and isolated import paths. It reads effective Windows Firewall
policy, requires all profiles enabled, and checks an all-protocol/all-address outbound
block for the service account SID, with no executable restriction. An unrelated
Python executable is never blocked. Enabled authenticated bypass rules and an
AppContainer loopback exemption are rejected.

The inspector reads the numeric WMI enforcement-state array: it requires full
enforcement (`1`) and permits only inactive-profile entries (`5`) alongside it.
Disabled firewall, unresolved filters and disallowed local policy states deny
admission ([Microsoft WMI contract](https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/wfascimprov/msft-netfirewallrule)).

The provider creates 60-second schema-v2 `ProductionControlEvidence` from those observations;
it never accepts a saved status report as admission evidence. A missing/failed probe,
wrong process, writable code/configuration, altered ACL, stopped supervisor, expired
record, disabled firewall/profile, or changed firewall filter denies admission.

The account-scoped firewall uses the documented `LocalUser` security filter:
[Microsoft NetSecurity reference](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule#-localuser).
Live acceptance must additionally prove that the actual worker and a descendant
cannot connect to an independently reachable test endpoint. Configuration readback
alone is not proof of packet enforcement.

The sandbox uses the documented
[AppContainer process model](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer).
Four loopback listeners remain open for the supervisor lifetime to measure TCP/UDP
delivery over IPv4/IPv6. They expose no action protocol. The trusted supervisor proves
each endpoint reachable, then independently counts packets from worker and descendant
attempts. UDP send success alone is never interpreted as successful delivery.

## Deployment and recovery

`scripts/build_windows_runtime.py --output .codex-tmp/batch7p/bundle` copies a self-contained
runtime and installs a locally built WEIR wheel plus downloaded dependency wheels.
It seals every runtime file in `runtime-manifest.json`. Run the explicit installer with
`-Mode Prepare -Bundle <absolute-bundle> -ManifestSha256 <manifest-sha256>` for read-only
validation; use `-Mode Apply` from an elevated PowerShell for host changes.

Installation and verification require PowerShell 7.3 or later with `Windows` or
`Standard` native argument passing, which preserves embedded quotes in the SCM
command and Python verifier arguments ([Microsoft reference](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_parsing#passing-arguments-that-contain-quote-characters)).
The read-only service inspector uses the built-in Windows PowerShell 5.1 with
process-scoped `RemoteSigned` for its locally installed, manifest-verified scripts.
Machine and group policies retain their normal precedence. This avoids depending on
the interactive operator's per-user execution policy when running as a service.
The inspector uses only the built-in Windows PowerShell module directory, avoiding
incompatible or user-controlled modules inherited from an operator's PowerShell 7 shell.

The installer verifies the manifest before and after copying. It creates the service disabled,
stages each new release privately until validation and AppContainer access are applied,
protects code and credentials, installs the account-scoped block, and only then starts
the service with manual start for denial-only acceptance. SCM permits two bounded
automatic crash restarts (5 and 30 seconds, reset after a day). The service token has
only `SeChangeNotifyPrivilege`; only Administrators and SYSTEM can control its service
object. It refuses an existing unrecognized service
or deployment. It never changes system-wide firewall defaults, opens inbound ports,
deletes files, rotates credentials, or migrates a database.

`-Mode Verify` performs independent readback. Apply additionally runs automatic denial
and lifecycle tests through `scripts/verify_windows_controls.ps1 -ExerciseDenials`.
`-Mode Rollback` stops/disables the service and retains its restricted files, firewall block,
and evidence. A retry reuses verified credentials and never replaces them silently.
The root is created with its protected owner/DACL in one OS call. Existing child
objects must already be protected and cannot be reparse points. Each attempt copies
to a fresh release directory and publishes configuration atomically after verification;
an interrupted copy remains inert. Rollback needs only the recognized installed
deployment and accepts `-Mode Rollback` without an external bundle.
The native acceptance tests remove service read access from a credential, disable and
narrow the firewall block, grant write access to a public nonexecuted runtime canary,
and terminate the owned supervisor. The tests require zero worker operations during
denial, new process creation times after SCM restart, and death of the old worker and
its persistent descendant. Real credential contents are never exposed by a tamper test.
The intentional supervisor crash consumes one recovery in the current 24-hour SCM
window; verification does not claim to replenish the remaining restart budget.
Unit tests additionally cover wrong process generations and evidence expiry. Restoration is required in
`finally` blocks. No test weakens protection while an action endpoint is available.

## Acceptance

1. Unit tests exercise the provider against valid and hostile host observations.
2. Windows tests query real Job Object controls and a real worker lifetime.
3. Independent elevated inspection checks SCM configuration, ACLs, effective firewall
   filters, worker identity, resource limits, fresh evidence, and denial results.
4. Missing controls cause zero worker operations. A restart gets a new instance;
   stale evidence is rejected. Worker and descendant exit with the supervisor.
5. The full repository suite and packaged-wheel checks pass. An independent review
   resolves in-scope findings before deployment is accepted.

Native development proof passed on `4070pc`: a real low-integrity AppContainer worker
and descendant could neither read a credential canary nor modify the supervisor;
four reachable endpoint controls saw zero attempted worker packets. Independent named
Job Object query confirmed 512 MiB and eight-process limits, and the descendant died
on worker closure. Full SCM/ACL/firewall acceptance is a separate elevated check.

The independent design review identified same-identity credential access, startup
ordering, PID reuse, incomplete runtime closure, narrowed firewall filters and SCM
lifecycle ambiguity. The implementation addresses these with the AppContainer,
preflight/pre-start checks, creation-time binding, full runtime manifest and ACL scan,
exact ActiveStore filter checks, and explicit manual-start/recovery/service-DACL rules.
