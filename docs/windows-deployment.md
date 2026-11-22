# Windows production controls (Batch 7P)

Status: independent native host acceptance passed on 2026-10-26. No production website actions are authorized by
this deployment. The target is the inventoried Windows 11 workstation `4070pc`
(Windows computer name `MATT`). The Linux task board reader uses a separate systemd
service and host verification. [Linux report controls](production-admission.md)

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
validation. For `-Mode Apply`, first import the two existing protected caller token
values into separate BWS entries without rotating them. Create the ignored
`config/glas.windows-install.local.json` manifest binding those entries to
`WEIR_LUGOS_MCP_CALLER_TOKEN` and `WEIR_FADE_WEIR_AUTHORITY_CALLER_TOKEN`.
From an elevated PowerShell under the account with the GLAS native profile, run:

```powershell
python scripts/with_glas.py windows-install -- -Mode Apply -Bundle <absolute-bundle> -ManifestSha256 <manifest-sha256>
```

The installer refuses missing, duplicate, or mismatched BWS tokens before changing
the service. It materializes the BWS values only in the existing protected caller
files, which the deny-only service needs to verify per-caller file access controls.
It never generates replacement tokens. `Prepare`, `Verify`, and `Rollback` remain
direct installer modes without BWS bindings.

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

Native host acceptance passed on `4070pc` at 2026-10-27 02:27 UTC (2026-10-26 locally).
The [recorded report](acceptance/batch7p-windows-controls-20261026.json) contains the
independent baseline/final readbacks, four zero-operation tamper denials, worker and
descendant death, and SCM restart with new process creation times. The low-integrity,
zero-capability AppContainer probes could not read caller credentials, obtain any of
the four tested supervisor modification rights, or deliver packets to four reachable
IPv4/IPv6 TCP/UDP endpoints. Named Job Object readback confirmed 512 MiB and eight
processes. Acceptance took about seven minutes including staging and deliberately
consumed one of the two configured crash restarts. The service remains running with
manual startup and no action endpoint.

The sealed runtime manifest SHA-256 is
`1c8c3d1147c5b2ce1e4439971ccccc8b58a2540f26c12ca8409c9823ec1883b4`.
The full Windows suite ran 368 tests with four platform skips; packaged CLI checks and
both GitHub CI jobs passed. [Review and recovery details](acceptance/batch7p-windows-review-20261026.md)
record the independent reviews and commissioning corrections.

The independent design review identified same-identity credential access, startup
ordering, PID reuse, incomplete runtime closure, narrowed firewall filters and SCM
lifecycle ambiguity. The implementation addresses these with the AppContainer,
preflight/pre-start checks, creation-time binding, full runtime manifest and ACL scan,
exact ActiveStore filter checks, and explicit manual-start/recovery/service-DACL rules.

## Chromium compatibility diagnostic

The optional Windows candidate pins Playwright 1.65.2 and its matching Chromium
159 headless shell. The builder gives the copied Python runtime container-local
asyncio pipes, reads a fixed offline field on the desktop, and hashes the Python
files, driver and browser. The default service uses its existing admission probe.

```powershell
python scripts/build_windows_runtime.py --browser-proof --output .codex-tmp/browser-proof
```

For the AppContainer trial, use a Node build with libuv's Windows child-stdio fix.
The November 21 candidate used the Node v22.23.5 source archive with SHA-256
`6cce7c58bf058700c643944903d60a325e8c9ceede1f5c2c088b435f2ada091a`.
The upstream patch file for commit `2cadaa40167050baf7c6905ac897e6fb57afb2c6`
had SHA-256 `69c9776d5d93346620e71019ad8931e949427d06d4dca1213f3f517af9027327`.
Verify both downloads before building. [Node release files](https://nodejs.org/dist/v22.23.5/) · [libuv patch](https://github.com/libuv/libuv/commit/2cadaa40167050baf7c6905ac897e6fb57afb2c6.patch)

From the extracted Node source directory, apply only the upstream pipe change and
build with the Visual Studio 2022 x64 compiler. The following commands assume the
verified patch is in the directory above the source tree.

```powershell
$env:GIT_CEILING_DIRECTORIES = (Get-Item ..).FullName
git -c core.autocrlf=false apply --directory=deps/uv --include=deps/uv/src/win/pipe.c ../libuv-2cadaa4.patch
if ($LASTEXITCODE) { throw 'libuv patch failed' }
if ((Get-FileHash deps/uv/src/win/pipe.c).Hash -ne '0739cb731a3e21eb23a7ee69ba2f1251542f34a06838cd115aa69e4a4bcc7b54') { throw 'Unexpected patched source' }
.\vcbuild.bat release x64 vs2022 openssl-no-asm
if ($LASTEXITCODE) { throw 'Node build failed' }
```

Copy `out/Release/node.exe` and the source tree's `LICENSE` into
`.codex-tmp/browser-node` in WEIR. From the WEIR checkout, package that build
for the diagnostic. The manifest covers the replacement binary and its license.

```powershell
python scripts/build_windows_runtime.py --browser-proof --browser-node-dir .codex-tmp/browser-node --output .codex-tmp/browser-proof-fixed
```

Use the preparation and deployment procedure above for the candidate. With the
candidate service stopped, an elevated operator can request one diagnostic through SCM.

```powershell
(Get-Service WeirAdmission).Start([string[]]@('chromium-field-proof'))
```

The supervisor checks the host, worker identity, Job limits, credential denials and
four loopback receivers before requesting the fixed field. The page runs offline
with JavaScript disabled. Read the fresh `status/chromium-proof.json` in the
deployment root for the observed stage. A field match keeps the processes alive
for up to 90 seconds so an independent verifier can examine them. The diagnostic
then stops. A browser-compatibility acceptance also requires live browser and
renderer inspection and cleanup checks. Restore the previous deployment and
service state after the trial. [Stock driver trial](acceptance/windows-browser-compatibility-20261121.md) · [Patched driver and Session 0 results](acceptance/windows-browser-driver-20261121.md)

### Identify a native driver initialization failure

The optional loader controls run when the packaged Node version check exits with
`0xc0000142`. Build both from the repository root in an x64 Visual Studio developer
PowerShell. Use a fresh output directory inside the project.

```powershell
$out = (New-Item -ItemType Directory .codex-tmp/loader-controls).FullName
cl /nologo /std:c17 /W4 /WX /O2 /MT /guard:cf "/Fo$out/dynamic.obj" "/Fe$out/weir-loader-probe.exe" scripts/windows_loader_probe.c /link /DYNAMICBASE /NXCOMPAT /Brepro
if ($LASTEXITCODE) { throw 'Dynamic control build failed' }
cl /nologo /std:c17 /W4 /WX /O2 /MT /guard:cf /DWEIR_STATIC_USER32 "/Fo$out/static.obj" "/Fe$out/weir-user32-startup.exe" scripts/windows_loader_probe.c user32.lib /link /DYNAMICBASE /NXCOMPAT /Brepro
if ($LASTEXITCODE) { throw 'Static control build failed' }
```

Pass `--browser-loader-probes $out` to the browser-proof build above. Before
sealing the runtime, the builder inspects both control executables with `dumpbin`,
checks coverage of the actual Node imports and runs every control on the desktop.

Each dynamic check uses a fresh child to initialize one fixed library from
System32. Exit 0 means it loaded. The intentionally absent library must return
126. Error 1114 means a DLL initialization routine failed. The static companion
imports USER32 before its program entry point and returns 37 when it reaches that
point. A native exit of `0xc0000142` means initialization failed. A timeout or a
process-start error leaves that observation incomplete. The service records the
results with the existing field diagnostic. [4070pc loader measurements](acceptance/windows-browser-loader-20261122.md) · [Windows library loading](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw)
