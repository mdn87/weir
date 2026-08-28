# RF7 trusted `DispatchContext` provider

- Status: selected on 2026-08-28
- First provider: Autowork's local campaign dispatcher
- Exact seam: a dispatcher-owned evidence-acquisition phase after durable assignment
  compilation and before any model-provider process starts

## Decision

Autowork is the first trusted `DispatchContext` provider. More precisely, the
campaign dispatcher establishes the binding only after it has assigned a `run_id`,
compiled and persisted the exact `AgentAssignment`, and verified that the assignment's
`correlation_id` matches the accepted request. It then supplies one immutable context
to one programmatic `lugos-mcp` dispatch.

This is the only inspected boundary that owns both the assignment identity and the
provider launch. OGMI defines objective contracts but deliberately does not orchestrate
work. HUD and Mission Control present state and accept commands but do not own an
assignment. Dias focus, cwd, APU attribution, and UI selection are observational
signals. The generic MCP stdio server and the executable `lugos-tool-call` path receive
no authenticated session material.

The existing Autowork `--work-context-file` option remains a strict staging and
validation seam. Possession of a hash-valid file is not authentication, so that option
must not be used as the trusted provider by itself.

The source implementation therefore needs a two-phase local flow. It first compiles
and freezes the assignment from validated campaign intent, then acquires evidence and
constructs the exact version-5 execution request around that frozen assignment. It
must not run route, specialist, or assignment selection a second time after acquisition;
the final request is accepted only if its policy and identity fields still match the
persisted assignment.

## Binding contract

The dispatcher-owned phase must establish these values outside model-controlled tool
arguments:

| Value | Authoritative source |
| --- | --- |
| `caller_id` | fixed service identity `autowork` |
| `caller_data_class` | operator-owned acquisition policy for the campaign |
| `run_id` | the dispatcher's durable run record |
| `assignment_id` | the persisted, policy-compiled `AgentAssignment` |
| `correlation_id` | the accepted request, checked against the assignment |
| `objective_id` | an authenticated upstream objective binding when one exists; otherwise `null` |
| WEIR client and credential | an ACL-restricted `autowork` client mapping owned by the host |

The dispatcher creates or reloads one immutable WEIR `WorkContext` with
`source=autowork`; its input `evidence_refs` are frozen at creation. It constructs the
matching `lugos_mcp.DispatchContext` and captures that object in a one-call
`DispatchContextProvider`. The same call receives a `WeirClientProvider` that accepts
only the `autowork` identity and the policy-approved data class.

The provider is per dispatch, not ambient process state. The intended call shape is the
programmatic `lugos-mcp` entry point with both providers injected for that invocation.
The ordinary MCP server, command-line `lugos-tool-call`, environment variables, cwd,
window focus, and tool arguments remain unable to establish or replace the binding.

## Execution sequence

1. Autowork accepts the provider-neutral campaign intent and creates the durable run.
2. Autowork compiles and persists the exact assignment before acquisition, freezing
   route and specialist selection for the remainder of this dispatch.
3. The dispatcher creates or reloads the assignment-bound `WorkContext` and constructs
   one `DispatchContext` from the authoritative records above.
4. The dispatcher invokes only the enabled `lugos.web` action through the programmatic
   `lugos-mcp` boundary with the context and client providers injected.
5. It verifies the returned work-context and evidence-reference hashes, materializes
   the canonical evidence bytes under an Autowork-owned artifact root, and builds the
   version-5 sealed-evidence request around the persisted assignment.
6. Autowork validates the final request against that exact assignment, without
   rerunning selection, and revalidates the artifact hashes. It then starts the selected
   model provider with network access and WEIR credentials absent. The provider sees
   only the sealed evidence bytes.

Replays reload the persisted assignment and context. They do not mint a different
context for the same acquisition, and a different assignment cannot reuse the old
context or materialized evidence binding.

## Fail-closed and activation rules

Acquisition remains refused when the assignment has not been persisted, any identity
joint mismatches, the data-class policy or scoped client credential is unavailable, a
per-action flag is off, WEIR returns another context's evidence, or the request would
use the unreviewed remote relay. No fallback may derive authority from caller-supplied
JSON, environment variables, cwd, focus, or recency.

Before the first action flag is enabled, tests must prove:

- a persisted assignment produces the same context across retry and restart;
- forged identity and transport fields never reach the WEIR client;
- the generic MCP and executable CLI paths still return
  `missing_dispatch_context`;
- another assignment, correlation, data class, or evidence hash is rejected;
- materialized evidence is rebound into an exact version-5 Autowork request; and
- the launched model process receives neither network authority nor WEIR credentials.

This decision resolves RF7's provider selection. It does not enable a `lugos.web`
action, deploy WEIR credentials, implement the dispatcher-owned acquisition phase, or
authorize the Batch 8 remote relay.
