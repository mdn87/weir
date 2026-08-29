# Authenticated WEIR service boundary

Batch 2A adds the acquisition half of the persistent WEIR boundary. Batch 2B adds
observation-bound proposal registration and separates full-authority proposal reads
from pre-redacted projection reads. Batch 2D adds the authenticated dead-worker
retirement route and schema-v2 durability foundation. Batch 7 adds a source-only,
disabled-by-default action boundary for exact Fade permits and a deliberately narrow
synthetic-fixture driver. None of these source slices starts, installs, or configures a
service. No production browser-effect adapter is registered.

## One typed client contract

`WeirClient` defines `read`, `search`, `enrich`, evidence lookup, evidence
materialization, proposal registration/lookup, and command-status lookup.
`InProcessWeirClient` and
`HttpWeirClient` return the same validated `AcquisitionResponse` shape. That response
binds the full `AcquisitionEnvelope`, reusable `WebCapture`, context-specific
`EvidenceReference`, opaque reference handle, and cache provenance.

The HTTP client accepts only an `http://` loopback IP origin, disables ambient proxies,
and refuses redirects so a bearer credential cannot be forwarded to another origin.
It caps request/error/success bodies independently and revalidates every returned
contract. Evidence content travels as the exact canonical artifact bytes; the client
checks the response's content/reference hash headers and then hashes and parses the
bytes again.

## Routes and scopes

Every route requires `Authorization: Bearer ...`, `X-Weir-Client-Id`, and an RFC 3339
`X-Weir-Deadline` no more than 30 seconds ahead.

| Route | Scope | Result |
| --- | --- | --- |
| `POST /v1/acquisition/read` | `acquisition:read` | validated context-bound acquisition |
| `POST /v1/acquisition/search` | `acquisition:read` | validated context-bound acquisition |
| `POST /v1/acquisition/enrich` | `acquisition:read` | validated context-bound acquisition |
| `GET /v1/evidence/{id}` | `evidence:read` | validated `EvidenceReference` |
| `GET /v1/evidence/{id}/content` | `evidence:read` | exact canonical artifact bytes |
| `GET /v1/commands/{id}` | `command:read` | durable command status or typed not-found |
| `POST /v1/proposals` | `proposal:write` | observation-verified `ActionProposal` |
| `GET /v1/proposals/{hash}` | `proposal:read:full` | full-authority `ActionProposal` |
| `GET /v1/proposals/{hash}/projection` | `proposal:read:redacted` | prebuilt public-safe `WeirActionEvent` |
| `POST /v1/browser/profile-retirements` | `profile:retire` | exact audited dead-worker reservation retirement |
| `POST /v1/actions/execute` | `action:execute` | permit-bound action status; disabled unless a driver is injected |
| `GET /v1/actions/commands/{id}` | `action:status` | durable action status or typed not-found |

Each named client has a unique credential, scopes, and allowed `DataClass` values.
Shared credentials are rejected at registry construction. Authentication compares all
registered identities with constant-time comparisons, and the handler suppresses the
standard request log. Command status returns a result when completed and an
`error_present` marker when failed; it never returns stored adapter error text.

The two action routes additionally require the exact client identity
`fade-weir-authority`; possession of an action scope under another client identity is
insufficient. The execute body is an exact-set versioned contract containing only the
command ID, request digest, immutable proposal, and permit. Full parameters remain in
the authority channel and bounded private worker command. Action status and all public
events omit those parameters.

Full proposal registration and reads enforce both the browser session's `DataClass`
and the proposal parameter `DataClass`. A redacted read does not open the full proposal
file: it loads only a construction-time `WeirActionEvent` and nonsensitive immutable
registration metadata. The public event contract cannot contain parameters, form
values, DOM/page content, private profile IDs, credentials, cookies, or permits.

The service request limit is 256 KiB and its maximum response limit is 6 MiB. A
deployment may configure a smaller response cap. `Expect: 100-continue` requests are
rejected at the header boundary when oversized; other oversized streams are closed
without buffering. Operations check the caller deadline before and after dispatch.
Adapter-specific cancellation remains part of the later worker supervisor.

## Durable sources

The service uses the Batch 1A immutable `CaptureStore` for captures, artifacts, and
evidence references. Command lookup reads the SQLite browser command table;
proposal registration verifies its named capture against the immutable observation,
the SQLite session and `WorkContext`, the resolved semantic target, and the current
session revision. Full proposals, redacted projections, action indexes, and final
registration markers are then published immutably under a separate proposal root.

Schema v2 adds the host-global credential reservation, worker-death evidence,
operator-retirement, action-reservation, and unknown-outcome quarantine tables. Fresh
stores start directly at v2; existing v1 stores are rejected until the separately
approved offline backup/migration/readback procedure in `docs/browser-store-v2.md` is
run. Tests close and reopen the durable stores and confirm reservations, quarantine,
evidence, proposals, projections, and settled command status remain readable.
Corruption remains a typed integrity failure and never becomes a network retry.

The retirement request references already-persisted death evidence; it cannot create
that evidence. It binds the expected session epoch, worker ID and instance,
`credential_binding_id`, attestation hash, recognized disposition, and an audited
operator reference. The authenticated client identity supplies the disposition actor.

Action execution first reserves the permit, action, proposal, and command, rotates the
automation fence, and moves the session from `active` to the exclusive `paused` state in
one transaction. That nonterminal reservation prevents navigation, controller release,
session loss/close, worker cleanup attestation, and credential retirement from
interleaving. After WEIR reacquires and verifies an immutable pre-observation and
re-resolves the locator, the dispatch transaction rechecks both proposal and permit
expiry, the fence, and the exact `worker_id` + `worker_instance_id` that holds the
credential before committing `web.action.execution.dispatching`. A restart before that
marker closes the unused reservation as `cancelled` and returns the session to `active`;
a restart after it records `outcome_unknown`, creates durable operator-cleared
quarantine, and never replays the effect. The reservation table retains its coarse
schema-v2 terminal state; the immutable receipt is authoritative for `completed`,
`failed`, `blocked`, `cancelled`, or `outcome_unknown` API status.

## Disabled-by-default deployment

There is deliberately no `weir serve` command, generated credential, Windows service,
systemd unit, or background process in this batch. A deployment must inject a
`ClientRegistry` from a secret provider or a user-ACL-restricted file outside the
repository. Creating that credential material and installing a service are separate
operator-approved actions. The standalone CLI remains on its private legacy seam, and
no sibling integration is enabled merely because the server class exists.

`ProcessBrowserWorker` is now available as a drop-in broker transport. It starts the
worker factory only after OS process-tree containment is established, applies the
earlier transport/command deadline across serialized admission and bounded IPC,
terminates the full tree on timeout or parent death, and emits a hash-bound death
attestation. The current server has no browser route or production worker configuration,
so this capability is not deployed implicitly.

`BrowserActionDriver` is likewise constructor-injected and absent from the default
application. The only supplied policy accepts reversible form-state changes against one
configured synthetic HTTP loopback IP origin, requires `DataClass.PUBLIC`, and keeps
generic proposal risk at `unknown`. It does not enable click, submit, upload, external
origins, or any existing Playwright recipe path.

An injected action driver is no longer sufficient to enable execution. The service
also requires an `ActionAdmission`. The explicit local-canary admission accepts only
the synthetic fixture policy. `ProductionAdmission` reloads short-lived, hash-bound
host evidence and requires the exact process worker, resource limits, restricted
identity, per-caller protected credential source, lifecycle supervisor, and enforced
OS egress policy before it invokes the driver. Missing or stale evidence returns a
typed service-unavailable response before parsing or executing the action request.

## Remaining production work

The source admission contract and Windows Job resource limits are implemented. Live
production enablement remains disabled until deployment work provides and attests:

- restricted service identities, externally provisioned per-caller credentials, and
  lifecycle supervision plus firewall/AppContainer or cgroup/network-namespace
  controls;
- an independently reviewed production effect adapter and explicit production-host
  canary. The approved local synthetic canary does not authorize that rollout.

See `docs/production-admission.md` for the exact evidence contract and rollout
checklist. WEIR creates none of the required host identities, credentials, ACLs,
firewall rules, cgroups, namespaces, or supervisors.

Those additions must preserve per-client scope separation. In particular,
`lugos-mcp` may acquire and read evidence but cannot read command/action authority;
Fade's future client may read command/proposal authority but must not reuse another
client's credential.

## Verification

Run the focused gate:

```bash
python -m pytest -q tests/test_client_service.py tests/test_proposals.py tests/test_process_worker.py tests/test_effect_driver.py
```

The repository gate remains `python -m pytest -q`. The service tests exercise both
client implementations, all acquisition methods, exact materialization, distinct
credentials, scope and data-class denial before engine access, deadline and size
limits, fail-closed tampering, loopback-only binding, proposal-channel separation, and
evidence/proposal/status lookup after restart.
