# Security Notes

## Threat model summary

WEIR crosses a hostile boundary by design. Web pages can contain malicious content, redirects, scripts, tracking, credential prompts, prompt injection, and UI designed to induce unintended actions.

The browser or reader engine must therefore be treated as an untrusted-input transport, not as a source of instructions.

## Core controls

### Domain policy

- Requests carry explicit allowed-domain constraints when practical.
- Redirects remain subject to policy.
- Public readers should reject private/internal network targets by default.
- Internal browsing requires a separate allowlisted route rather than globally disabling SSRF protections.
- Authenticated connectors validate every provider-supplied pagination or redirect URL
  against the configured API origin before attaching a bearer token.

The direct HTTP connector validates every redirect hop before following it. External
compact readers manage redirects inside their own process, so WEIR revalidates the
reported final URL before retaining evidence; managed deployments should also enforce
worker-level network egress controls because post-read validation cannot undo a fetch.

### Prompt injection

Page text is always data. It cannot:

- modify system or repository instructions
- grant itself new tool permissions
- expand allowed domains
- reveal credentials
- authorize an external side effect
- change retention policy

### Authentication isolation

- Profiles are identified by opaque IDs.
- Credentials are not embedded in `WebRequest`.
- Personal, business, test, and restricted profiles are isolated.
- Captures from authenticated sessions are not reused as public cache entries.
- Service connectors require an explicit profile ID and record that opaque profile scope
  on the capture; fallback public readers record `auth_scope: none`.
- Credential profile IDs and site-routing profiles remain separate: search sources and
  URL domains select site policy, never the name of a credential profile.

### Controller lease

One session has one active controller. A second agent or human takeover requires an explicit lease transition.

Leases expire and carry a monotonic generation. Worker commands bind their ID to the
session, worker session, owner, epoch, expected revision, generation, and payload
digest. Reusing an ID with changed content fails, and stale epochs/generations cannot
reach a worker. The secret fencing token remains broker/store-local and is redacted
from public session objects, receipts, and events.

Recovery of takeover and return accepts only the still-live controller named by that
command's durable transfer event. The event must match the paused revision, transfer
direction, authorization reference, controller identities, and target lease generation.
A paused navigation, close, or unrelated controller transfer cannot be adopted as a
handoff; an expired transferred lease leaves the command in doubt for explicit cleanup.

### Side effects

Side-effectful operations require typed risk classification. High-risk browser primitives such as arbitrary JS execution, file upload, purchase, account mutation, sending, deletion, and submission must not be treated as ordinary clicks.

### Artifact retention

Raw HTML, screenshots, HAR bodies, downloaded documents, and rendered DOMs may contain sensitive material. Store them under an explicit artifact/retention policy and keep ordinary telemetry metadata-only by default.

The P1 local store persists ordinary `public` content when configured. `personal` and
`bwa_internal` content requires an explicit `full_evidence` capture policy;
`restricted` captures are never written by the public broker. Only unauthenticated
public evidence enters the shared file cache. Artifact and cache lookups accept opaque
IDs or SHA-256 digests only, preventing path traversal through storage references.

P2 browser observation is stricter: the local broker requires
`capture_policy=full_evidence`, a matching site profile, an explicit credential-profile
ID, and an explicit nonempty domain allowlist. `restricted` browser placement remains
blocked until a dedicated worker and artifact boundary exist. Browser screenshots use
content-addressed binary blobs and require the exact typed site-profile policy
`screenshots: full_evidence`; missing, prohibited, or misspelled policies fail closed.
Ordinary lifecycle telemetry contains references and metadata, not page bodies,
screenshots, cookies, profile state, or fencing tokens.
Navigation events omit the full URL so query strings and fragments do not leak through
the metadata stream; the current URL remains in the access-controlled session record
and immutable evidence where it is required for recovery and provenance.

The Playwright observer launches one nonpersistent browser process per session and pins
every exact allowlisted hostname to the address WEIR validated. A catch-all Chromium
resolver rule returns `NOTFOUND` for every other hostname. Route interception remains a
second check. This avoids validating with Python DNS and then letting Chromium resolve a
different address. Subdomain suffix matching is therefore insufficient for this worker:
every reachable hostname must appear explicitly in `allowed_domains`.

Chromium runs with its sandbox enabled and ignores system proxy configuration. All
Playwright calls run on one dedicated worker thread, matching the synchronous library's
thread-affinity requirement. Route telemetry retains only a bounded count plus a
sanitized scheme/host/reason code; it never journals a resource path, query, fragment,
or page-supplied exception. A per-session request budget bounds hostile subresource
fan-out. Per-response and cumulative `Content-Length` budgets interrupt declared
oversized transfers after headers arrive. Missing lengths, compressed expansion, a
wedged browser call, and browser-process memory remain outside what an in-process thread
can safely terminate. `ProcessBrowserWorker` now supplies a spawned process boundary:
the parent propagates the earlier broker/transport deadline, terminates the Windows Job
Object or POSIX process group when it expires, and verifies that the group is empty.
The deadline covers serialized-worker admission and bounded framed IPC, not just the
browser call. Windows kill-on-close containment and a POSIX parent-liveness watchdog
also terminate the tree if the supervising process disappears. It does not yet impose
OS memory or network-egress limits, and deployments do not yet require workers to use
it. The IPC channel accepts only a strict, size-bounded JSON operation/result union;
JSON decoding and typed reconstruction run inside the transport deadline, so it does
not deserialize executable Python objects after timeout. The process wrapper remains a
lifecycle boundary, not a privilege boundary against a malicious same-account worker.

Observation contexts run with JavaScript disabled and abort every request method except
GET and HEAD. Their site profile must attest that the credential itself is read-only;
this is an operator/deployment assertion, not something a cookie blob can prove. A GET
endpoint can still be incorrectly implemented with server-side side effects, so active
JavaScript or broader credentials require a future read-only proxy/replay boundary and
are rejected by this worker.

Worker OPEN intent is journaled before dispatch, and exact context creation and closure
are journaled separately from session state. An unacknowledged OPEN dispatch therefore
counts as possibly live. If the same worker cannot attest cleanup, the session remains
nonterminal and its worker-local profile reservation stays quarantined. WEIR does not
yet provide an authorized dead-worker retirement API; direct database edits are not a
supported recovery mechanism. A `WorkerDeathAttestation` proves only the observed
process-tree outcome and cannot by itself authorize reservation release.

The OPEN reservation itself is compare-and-swap fenced by the exact `opening` revision,
epoch, current command attempt, and owning automation lease. Observation screenshots
are bundled with the semantic snapshot in one serialized worker call; Playwright checks
the document generation and URL before accepting the bundle. This prevents stale OPEN
dispatches and cross-document evidence pairs from being committed as current state.
Ordinary command completion and terminal close likewise consume the exact journaled
session revision and controller generation; a valid lease from another session, an
operator lease, or a later automation generation cannot commit an older reservation.

### Connector retries and result integrity

Retries cover transient network, throttling, and provider-server failures only, use a
small exponential bound, and never widen the API origin. Malformed marketplace entries
are omitted with diagnostics instead of being relabeled as trusted eBay records.
Structured result sets keep their schema: WEIR fails an oversized set rather than
returning an unrelated truncation shape under the marketplace contract.

### Engine supply chain

- Pin engine versions in managed deployments.
- Record engine versions in captures and benchmark results.
- Prefer managed worker images over unbounded `npx --yes` execution in production.
- Track security posture of external browser dependencies.

#### Audit snapshot (2026-08-24, benchmark host)

Both candidate engines were license- and supply-chain-reviewed before the
first benchmark; the full record (hashes, endpoints, workarounds) lives in the
host-local external-tools manifest, outside this repo.

- `@only-cli/oc` 0.4.0 (MIT): npm audit clean. The upstream repo was six days
  old at audit time with a single pseudonymous owner — pin the version and
  re-review on every upgrade. Normal reads contact only the target URL; its
  `impers` dependency reaches `api.impersonate.pro` solely on explicit
  `impers update`/`config`. Its transport spoofs browser TLS fingerprints
  (curl-impersonate), which is dual-use: domain policy must decide where
  fingerprint evasion is acceptable rather than treating it as a free default.
- `agent-browser` 0.34.0 (Apache-2.0, vercel-labs): npm audit clean, zero
  runtime npm deps, no telemetry found in the JS layer. postinstall fetches a
  platform-native binary from versioned upstream GitHub releases. Its
  persistent daemon binds 127.0.0.1 only, but outlives CLI calls and shares a
  default session across reads until the adapter passes `--session` isolation.

## `oc` integration caution

`oc` has useful private/internal-address blocking. WEIR should preserve that default for public acquisition. Internal services should use an explicit internal adapter or browser worker with its own allowlist.

## Browser profile caution

A browser profile can represent broad ambient authority even before a click occurs. Profile eligibility must therefore be part of policy and worker placement, not a convenience option exposed to arbitrary seats.

The Playwright observer accepts storage state only through an in-process provider keyed
by an opaque, worker-local profile ID. `VerifiedProfileState` must bind that ID to the
exact site-profile ID and `read_only` credential scope selected when the session opens;
the registry metadata is verified, while the actual server-side privilege remains an
operator/deployment assertion. The worker requires nonempty cookie/origin state and
creates a nonpersistent context. The contained `agent-browser` adapter is ephemeral by design:
it never passes profile, state, restore, session-name, CDP, auto-connect, or raw
startup-argument flags because those modes are incompatible with upstream domain
containment. It is consequently rejected by the authenticated browser broker rather
than mislabeled with an authenticated capture scope. Neither observer exposes arbitrary
page JavaScript or a DOM action method.

Generic `click`, `fill`, `select`, `check`, and `uncheck` proposals carry
`risk=unknown`: DOM mechanics alone cannot distinguish local staging from autosave,
network-triggered settings changes, purchases, messages, or destructive effects.
Upload and submit retain their explicit higher floors. `ActionProposal` runtime
validation binds the primary target and every condition target to the proposal's
session, observation, revision, and epoch; each target is hash-bound to its durable
semantic locator and postconditions re-resolve that locator on the newer observation.
`ExecutionReceipt` uses an ordered, unique `capture_ids` pair for before/after state and
requires `verified_capture_index=1` for verified results. Those receipt invariants are
enforced by both runtime validation and JSON Schema; proposal cross-field identity and
hash equality remain runtime checks.
