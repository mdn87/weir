# Authenticated WEIR service boundary

Batch 2A adds the acquisition half of the persistent WEIR boundary. Batch 2B adds
observation-bound proposal registration and separates full-authority proposal reads
from pre-redacted projection reads. Neither slice starts, installs, or configures a
service, and neither enables browser effects.

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

Each named client has a unique credential, scopes, and allowed `DataClass` values.
Shared credentials are rejected at registry construction. Authentication compares all
registered identities with constant-time comparisons, and the handler suppresses the
standard request log. Command status returns a result when completed and an
`error_present` marker when failed; it never returns stored adapter error text.

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
evidence references. Command lookup reads the existing SQLite browser command table;
proposal registration verifies its named capture against the immutable observation,
the SQLite session and `WorkContext`, the resolved semantic target, and the current
session revision. Full proposals, redacted projections, action indexes, and final
registration markers are then published immutably under a separate proposal root.
This slice makes no database schema change. Tests close and reopen both durable stores
and confirm evidence, proposals, projections, and settled command status remain
readable. Corruption remains a typed integrity failure and never becomes a network
retry.

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

## Remaining Batch 2 work

Batch 2 is not complete until WEIR also has:

- disabled effect routes that later accept only Fade's exact permit/proposal binding;
- production browser admission that requires the process transport and adds OS memory
  and network-egress limits;
- host-global profile reservations and explicit cleanup attestations;
- authorized dead-worker retirement that never silently frees a profile; and
- deployment lifecycle configuration with externally provisioned credentials.

Those additions must preserve per-client scope separation. In particular,
`lugos-mcp` may acquire and read evidence but cannot read command/action authority;
Fade's future client may read command/proposal authority but must not reuse another
client's credential.

## Verification

Run the focused gate:

```bash
python -m pytest -q tests/test_client_service.py tests/test_proposals.py tests/test_process_worker.py
```

The repository gate remains `python -m pytest -q`. The service tests exercise both
client implementations, all acquisition methods, exact materialization, distinct
credentials, scope and data-class denial before engine access, deadline and size
limits, fail-closed tampering, loopback-only binding, proposal-channel separation, and
evidence/proposal/status lookup after restart.
