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

The canonical request is `WebRequest`.

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

A side-effectful action produces an `ExecutionReceipt` only after crossing the execution-authority boundary.

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

A browser engine will additionally require:

```text
open/attach session
observe
navigate
propose interaction
execute only when supplied an authorized action
verify
close/release
```

The engine adapter translates provider-specific output into WEIR objects. It must not leak arbitrary CLI stdout as the public contract.

## Execution boundary

WEIR may create `ActionProposal` objects containing:

- semantic target
- requested operation
- preconditions
- expected postconditions
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
verification_failed
unknown
```

Retries must be bounded. Repeatedly invoking the same engine against the same unchanged failure is not recovery.

## Versioning

Contracts are versioned independently of engine versions. A WEIR release may upgrade an engine without changing callers if normalized behavior remains compatible.
