# Architecture

## 1. Design goal

WEIR makes web access a capability plane rather than a collection of agent-specific browser tools.

The system should remain correct if any individual engine disappears. `oc`, `agent-browser`, Playwright, Chromium, and future service connectors are replaceable implementation choices behind stable Lugos contracts.

## 2. Logical architecture

```text
                           +----------------------+
                           | user / CLI / HUD     |
                           +----------+-----------+
                                      |
                                      v
                           +----------------------+
                           | task-router/profile  |
                           +----------+-----------+
                                      |
                                      v
                           +----------------------+
                           | Autowork campaign    |
                           +----------+-----------+
                                      |
                                      v
+-------------------------------------------------------------------+
| WEIR                                                              |
|                                                                   |
| request classifier -> policy envelope -> engine router            |
|                           |                                       |
|              +------------+------------+                          |
|              |                         |                          |
|       public acquisition       authenticated operations           |
|              |                         |                          |
|       connector/readers       browser session broker              |
|              |                         |                          |
|       captures/evidence       observations/proposals              |
|              +------------+------------+                          |
|                           |                                       |
|                      verifier                                     |
+---------------------------+---------------------------------------+
                            |
             +--------------+----------------+
             |                               |
             v                               v
      read-only result                action proposal
                                             |
                                             v
                                     Fade / approval
                                             |
                                             v
                                      execution receipt
                                             |
             +-------------------------------+-------------------+
             |                    |                    |           |
             v                    v                    v           v
         Validation            Sulis                 AITU         HUD
```

## 3. Public acquisition plane

Characteristics:

- credential-free
- safe to fan out to workers
- aggressively cacheable when policy allows
- source and provenance oriented
- optimized for compact model context
- no ability to inherit authenticated browser state

Potential engines:

- direct connector/API
- Markdown or `llms.txt`
- feeds and JSON endpoints
- `oc`
- `agent-browser read`
- an eventual in-process extractor

The acquisition plane should return immutable captures. A reader's mutable navigation session is an optimization, not the evidence record.

The implemented P1 `AcquisitionBroker` is the reusable boundary for this plane. It
combines route classification, site-profile policy, target checks, engine attempts,
stable failure classes, capture construction, bounded content, optional immutable
storage/cache, and metadata-only spans. The CLI delegates to it; embedders do not need
to reproduce CLI control flow.

## 4. Authenticated operations plane

Characteristics:

- browser profile is explicit
- credentials are never embedded in the request object
- session has one controller lease
- domain policy remains active after redirects and navigation
- observations and actions are separated
- side effects require typed risk classification
- post-action state is captured and verified

Potential engines:

- `agent-browser`
- Playwright
- direct CDP
- app-specific browser integrations

A browser process is transport. It is not the orchestrator or policy authority.

The implemented session kernel is a separate `BrowserSessionBroker`; it is not folded
into `AcquisitionBroker`. Session state, work-context bindings, command idempotency,
profile reservations, controller leases, validated action receipts, and lifecycle
events live in a transactional SQLite store. Immutable observations and binary
screenshots live in the content-addressed evidence store. Evidence publication is
first-writer-wins and crash-flushed through the platform filesystem boundary before a
browser command commits its durable result.

Before a navigation or observation reaches a worker, the store atomically rotates the
automation fence and moves the session from `active` to `paused`. A second process
therefore cannot dispatch against the same revision. Successful commit returns the
session to `active` only when its target session, command attempt, reserved revision,
owning automation controller, and controller generation all match. Terminal close
consumes the same exact proof from `begin_close`; an operator or later lease cannot
bypass cleanup reservation. An uncertain worker result moves the session to `lost`.
Profile identifiers are worker-local opaque handles, and the current uniqueness rule
is scoped to `(worker_id, profile_id)`, not a global credential lock.

Manual handoff recovery is event-bound rather than state-derived. A retry may reuse a
transferred lease only when `web.controller.transferred` matches the same command,
paused revision, direction, authorization, controller identities, and target generation.
Generic lease acquisition is unavailable while a session is `paused`, preventing a
retry from consuming another command's in-flight reservation.

Every OPEN dispatch is reserved before it reaches a worker. The reservation transaction
requires the exact `opening` revision and epoch, current command attempt, and owning
automation lease/fence, so a delayed OPEN cannot reserve after close or recovery has
rotated the session. A reservation with no matching context acknowledgement remains
possible live authority, so close cannot release the profile unless that exact context
closes or the reserving worker instance attests cleanup. There is no dead-worker
retirement API yet; this deliberately favors quarantine over silent credential reuse.

When screenshot evidence is requested, the worker returns the semantic snapshot and
screenshot from one serialized observation command. The Playwright worker rejects the
result if navigation changes its document generation or URL while the bundle is being
constructed. The broker therefore never combines a structured observation with a
separately captured image from a later document.

`ProcessBrowserWorker` preserves the typed `BrowserWorker` interface while running one
worker in a spawned child process. Before the worker factory can open a browser, the
parent places the child in a Windows kill-on-close Job Object or a POSIX process group.
A POSIX watchdog kills the group if the parent disappears. A missed call or command
deadline—including time waiting for the serialized worker or framed IPC—terminates the
group, verifies that it is empty, and produces a hash-bound `WorkerDeathAttestation`.
Request and response frames have explicit byte limits. The attestation distinguishes a
clean worker-process exit from confirmed whole-tree death; it is process-death evidence,
not authority to release an authenticated profile reservation.

This local transport uses an explicit, size-bounded JSON operation/result union, with
duplicate fields, unknown fields, non-finite numbers, and invalid typed values rejected.
Decoding and typed reconstruction share the call deadline. It is not the versioned
cross-host worker-result protocol and is not a sandbox against a malicious same-account
worker process. Production admission now requires the process wrapper, explicit
resource limits, and current restricted-identity, credential-ACL, lifecycle, and OS
egress evidence. Windows applies memory/process limits in its Job Object; Linux must
prove prepared cgroup v2 containment and may not treat the process group as a resource
boundary. The direct Playwright worker's single-thread affinity and response-size
checks remain defense in depth inside that outer lifecycle boundary.

The browser contract family is version `0.2`; the established acquisition request and
capture contracts remain `0.1`.

## 4.1 Work identity is not UI focus

`WorkContext` carries explicit objective, run, assignment, correlation, provenance,
and prior-evidence identity. The browser broker binds its hash to the session at open
and requires the same context on every later call. It never infers authority from an
active desktop window, selected HUD node, current browser tab, cwd, or latest trace.

`docs/focus-and-interaction.md` maps the distinct meanings of focus across OGMI,
Autowork, HUD/Mission Control, Dias, and APU and defines the durable integration path.

## 5. Routing dimensions

Engine routing should consider at least:

```text
operation mode
URL/site profile
data classification
auth requirement
JavaScript requirement
interaction requirement
side-effect class
worker capabilities
engine health/version
run-profile cost/depth constraints
model behavior profile
benchmark evidence
```

A static priority list is acceptable for bootstrapping but is not the intended final router.

## 6. Capture model

Every meaningful observation should be capturable as immutable evidence.

A `WebCapture` binds:

- requested URL
- final/canonical URL
- capture timestamp
- engine and version
- authentication scope identifier, never credentials
- content hash
- retained artifact references
- trust label
- normalized blocks or summary

The capture ID is safe to reference later. Engine-local element IDs are not.

## 7. Session model

`BrowserSession` is live mutable state.

It should include:

- session ID
- owning run
- worker/host
- browser engine
- profile ID
- trust/data class
- allowed domains
- controller lease
- active URL/tab metadata
- creation and expiry
- state such as active, paused, lost, or closed

A session must not be silently reused between unrelated runs simply because the same browser profile is available.

The implementation adds an epoch and compare-and-swap revision. One worker/profile
pair may have one non-closed session. A same-owner recovery increments the epoch and
invalidates old leases. Manual takeover and return rotate the controller generation and
change active/paused state atomically.

## 8. Observation and semantic locators

A structured browser observation should prioritize accessibility/DOM state:

```json
{
  "url": "https://portal.example/uploads",
  "title": "Uploads",
  "elements": [
    {
      "ref": "obs-local-e17",
      "role": "button",
      "label": "Submit 12 files",
      "state": "enabled"
    }
  ]
}
```

The observation-local ref can be used immediately. Durable recipes should instead store a semantic locator:

```json
{
  "role": "button",
  "name": "Submit 12 files",
  "near": "Pending files"
}
```

The runtime re-resolves the locator against a fresh observation before acting.

The current locator contract supports role, exact/casefold name, test ID, required
state, and an explicit zero-based ordinal. Zero matches, ambiguity, and stale
session/revision/epoch produce different stable errors.

## 9. Action lifecycle

```text
observe
  -> resolve semantic target
  -> propose action
  -> classify risk
  -> check policy
  -> request approval if required
  -> reacquire/confirm state
  -> execute
  -> capture post-state
  -> verify expected result
  -> issue receipt
```

No step should infer success solely from having sent input.

## 10. Visual fallback

When structured state is insufficient:

```text
DOM/accessibility failure
  -> screenshot or targeted crop
  -> Argus/vision interpretation
  -> typed observation candidate
  -> bounded action proposal
```

Pixels can enrich an observation. They should not erase the action policy or approval boundary.

## 11. Worker placement

Public-reader workers may run on general Lugos nodes.

Authenticated browser workers should be placed according to profile and data class. Home, business, test, and restricted profiles should remain isolated. Worker inventory belongs in the Lugos capability/target registry rather than hard-coded into WEIR.

## 12. Engine-specific notes

### `oc`

Useful properties:

- compact numbered page representation
- JSON mode
- saved page state for cheap `read/find/next`
- explicit no-readable-content outcome
- browser-like request impersonation
- private/internal-target blocking

Integration rule: isolate each Lugos run with its own state directory/session name and copy useful output into immutable WEIR captures. Do not treat the `oc` session file as durable evidence.

### `agent-browser`

Useful properties:

- non-browser `read` mode
- rendered active-tab reading
- accessibility snapshots and refs
- Chromium interaction
- cookies/storage/profile state
- tabs, network inspection, screenshots, HAR, CDP, streaming

Integration rule: keep its broad feature set behind WEIR's narrower capability and authority contracts. Do not expose an unrestricted arbitrary-browser CLI to every seat merely because the backend supports it.

The contained adapter uses a unique `--session`, explicit `--allowed-domains`, content
boundaries, bounded JSON output, and only open/navigate/snapshot/get/close commands.
It rejects persistent profile IDs. Upstream intentionally rejects its domain allowlist
when combined with profile, state, restore, CDP, auto-connect, or unsafe startup args,
so this path cannot provide authenticated persistent-profile ownership.

### Playwright observer

The direct comparison worker creates one fresh nonpersistent context per session,
loads authentication only through an in-worker opaque `ProfileStateProvider` whose
verified metadata must match the selected site profile and read-only credential scope,
and runs all synchronous Playwright calls on one dedicated thread. Chromium keeps its
sandbox enabled, bypasses ambient system proxies, pins exact hosts, blocks service
workers and WebSockets, admits only GET/HEAD, and applies a bounded resource-request
budget with redacted containment errors. Evidence comes from accessibility snapshots.
The worker exposes no evaluate, click, fill, upload, persistent-context, profile-path,
or CDP attach API.

## 13. Architectural questions still open

1. Does WEIR become a Lugos submodule service, a library plus worker protocol, or both?
2. Is Fade definitively the executor for every side-effectful web action?
3. Which browser worker owns user-attached sessions and manual takeover?
4. Which production artifact service replaces the implemented local immutable store?
5. Which additional capture classes may be persisted under each data classification?
6. Which engine wins each acquisition route after repeated benchmarking?
7. How much routing intelligence belongs in WEIR versus the review-only APU/COGIN model-behavior layer?
8. What authorized, audited process can retire a reservation after the owning worker is
   provably dead without weakening profile quarantine?
