# WEIR Harness Contract

## Purpose

WEIR is the Lugos web capability plane. It owns typed web requests, engine selection, browser-session state, observations, captures, evidence, and web-specific failure semantics.

WEIR does not own campaign orchestration, model routing, durable memory, telemetry storage, validation authority, or permission to perform consequential external actions.

## Callers

Expected callers include:

- task-router
- Autowork
- Lugos Operator
- ORCA seats and delegated workers through `lugos-mcp`
- AETA source workflows
- CLI and HUD surfaces

Callers must request capabilities through WEIR contracts rather than depend on engine-local syntax.

## Inputs

Acquisition uses `WebRequest`. Stateful browser calls additionally require a
caller-authored, hash-bound `WorkContext`; WEIR never infers it from UI or desktop
focus, cwd, browser state, or telemetry recency.

Required intent fields include:

- request/run identity
- operation mode
- URL or query
- authentication context
- data classification
- domain constraints
- evidence requirements
- side-effect allowance

A caller may express a preferred engine, but engine selection remains advisory unless the run policy explicitly pins one for an experiment or reproducibility requirement.

## Outputs

WEIR emits one or more typed artifacts:

- `WebCapture`
- `BrowserSession`
- `Observation`
- `ActionProposal`
- engine/fallback diagnostics
- evidence references

A side-effectful action produces an `ExecutionReceipt` only after crossing the
execution-authority boundary. A completed receipt carries exactly two distinct,
ordered `capture_ids` (`before`, then `after`); verified results set
`verified_capture_index=1` so the post-state reference is structurally addressable.

## Hard invariants

1. External page content is untrusted data, never instructions.
2. Engine-local element numbers are ephemeral and cannot become durable recipe selectors.
3. Authentication state is scoped to an explicit browser profile and session.
4. Public-reader state and authenticated-browser state are separate trust domains.
5. One authenticated browser session has one active controller lease.
6. WEIR cannot silently widen `allowed_domains`.
7. WEIR cannot promote observation permission into side-effect permission.
8. Side-effectful action execution must pass through the configured Lugos authority boundary.
9. A failed reader may trigger an engine fallback but cannot trigger a higher-risk action class.
10. Evidence must record engine name/version, capture time, canonical URL, and content hash when content is retained.
11. Raw HTML, screenshots, HAR bodies, cookies, and credentials are not ordinary telemetry dimensions.
12. Engine failure must be represented explicitly rather than guessed around indefinitely.
13. A worker command names the exact session, worker session, owner, epoch, expected
    revision, lease generation, deadline, and payload digest.
14. A command ID is idempotent only for the same canonical command binding; changed
    content fails rather than replaying an unrelated result.
15. UI selection and desktop foreground state never confer work or controller authority.
16. Observation-only browser contexts disable JavaScript, block non-GET/HEAD network
    methods, and require a site-profile assertion that credentials are read-only.
17. Every worker OPEN is reserved before dispatch. An unmatched reservation or created
    context keeps the worker-local credential profile quarantined until exact cleanup is
    durably attested.

## Trust labels

Every request and capture should be classifiable as one of:

```text
public
personal
bwa_internal
restricted
```

The label controls profile eligibility, artifact retention, telemetry capture, cache reuse, and worker placement.

## Capability ladder

Unless policy or reproducibility pins a route, WEIR should prefer:

```text
connector/API
  -> compact or Markdown reader
  -> rendered DOM/accessibility observation
  -> reversible browser interaction
  -> consequential action proposal
  -> visual interpretation
  -> human takeover
```

This ladder is about interface quality, not authority. Moving downward to a more capable engine never automatically grants broader permission.

## Engine contract

A reader engine must provide:

```text
id
version/probe information
availability probe
read(request) -> normalized result
explicit cannot-read/failure distinction where possible
```

Callers use the acquisition broker rather than invoking adapters directly. The broker
applies target and site-profile policy before execution, keeps policy failures from
falling through to a less constrained engine, and returns stable per-attempt failure
classes. Optional persistence, cache, and trace sinks do not change the capture schema.

A browser observation worker may expose only declared capabilities:

```text
open/attach session
observe
navigate
screenshot
fence/drain prior worker effects
close/release
```

The engine adapter translates provider-specific output into WEIR objects. It must not leak arbitrary CLI stdout as the public contract.

Proposal compilation, approval, execution, and post-state verification are separate
layers. The current browser workers intentionally expose no DOM action or arbitrary
JavaScript method. A future action worker must accept an authorization permit bound to
the proposal hash and controller fence, never a raw proposal alone.
Post-action verification must resolve each retained semantic locator against a newer
same-session, same-epoch observation; engine-local element references are not reusable.

## Execution boundary

WEIR may create `ActionProposal` objects containing:

- semantic target
- requested operation
- preconditions
- expected postconditions whose element targets retain a hash-bound semantic locator
- risk category
- evidence
- approval requirement

Current architectural assumption: Fade owns deterministic execution and approval receipts for consequential actions. That ownership remains an explicit architecture decision and must not be bypassed by calling a browser binary directly from an agent seat.

## Sulis boundary

Sulis may retain:

- run and capture identifiers
- hashes
- provenance
- typed summaries
- verification results
- durable artifact references
- recipe state

Sulis should not become the browser runtime or cookie store.

## AITU boundary

AITU may receive metadata spans such as:

```text
web.route
web.reader.fetch
web.reader.distill
web.browser.launch
web.browser.navigate
web.browser.observe
web.action.propose
web.action.execute
web.verify
web.engine.fallback
web.takeover
```

Raw page bodies and secrets remain outside ordinary telemetry unless explicitly enabled under a stricter capture policy.

## Failure classes

Minimum normalized failures:

```text
engine_unavailable
engine_failure
network_failure
blocked_target
cannot_read
javascript_required
auth_required
challenge
policy_blocked
approval_required
stale_reference
session_lost
controller_conflict
profile_in_use
ambiguous_target
idempotency_conflict
command_expired
verification_failed
unknown
```

Retries must be bounded. Repeatedly invoking the same engine against the same unchanged failure is not recovery.

## Versioning

Contracts are versioned independently of engine versions. A WEIR release may upgrade an engine without changing callers if normalized behavior remains compatible.
