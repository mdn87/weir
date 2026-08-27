# Authority Boundaries

WEIR is intentionally positioned between agent intent and browser capability. That makes authority design more important than the choice of browser library.

## Responsibility matrix

| Component | Intended responsibility |
| --- | --- |
| task-router | classify intent and select capability family |
| run profile | set cost, depth, autonomy, evidence, and approval requirements |
| Autowork | own campaigns, assignments, delegation, and outcome gates |
| WEIR | own web transport abstraction, sessions, captures, observations, routing, and site profiles |
| Fade | own deterministic side-effect execution and approval receipts, subject to final Lugos boundary decision |
| Operator | compose target-machine workflows and supervise live runs where appropriate |
| Argus | interpret visual state when structured browser state is insufficient |
| Remotedesk | provide cooperative target-side capture/session transport |
| validation | judge whether requested outcomes are evidenced |
| Sulis | retain typed durable state, provenance, summaries, hashes, and references |
| AETA | consume source captures for source-handling workflows |
| AITU | observe traces, latency, cost, routing, failures, and interventions |
| `lugos-mcp` | expose the tool/protocol surface without becoming the browser runtime |

## Read is not act

WEIR distinguishes these modes:

```text
discover   locate candidate sources
read       acquire content
observe    inspect a rendered/authenticated state
interact   perform reversible or staged manipulation
commit     create an external side effect
```

A capability to perform one mode does not imply access to the next.

Examples:

```text
read account page            != change account setting
fill draft form              != submit form
stage upload                 != upload/commit
open checkout                != purchase
compose message              != send message
```

## Proposal versus execution

Agents should normally create an `ActionProposal`.

The proposal contains the exact requested operation and enough evidence to evaluate it. An execution authority then decides whether the action is allowed, needs approval, or is blocked.

This avoids a failure mode where a browser engine becomes a hidden policy bypass simply because its CLI exposes `click`, `fill`, `upload`, or `eval`.

## Browser JavaScript execution

Arbitrary page-context JavaScript is a high-capability primitive. It may be useful for deterministic observation and controlled automation, but it should be policy-gated separately from ordinary semantic actions.

A recipe should prefer:

```text
role/name locator -> typed action
```

over:

```text
arbitrary script string -> browser eval
```

## Credentials

WEIR requests refer to profile identifiers, never raw credentials.

Credential material belongs to a platform credential store or browser profile boundary. Page content must never be permitted to request credential disclosure or to alter the action allowlist.

## Manual takeover

Manual takeover transfers the controller lease to the operator. Automated action execution pauses until the lease is explicitly returned or the session is closed.

The handoff should be visible in HUD/event state and should not result in concurrent human and agent input.

The session store now makes this concrete: takeover validates the active automation
lease and expected session revision, rotates the fencing generation, grants an expiring
operator lease, and moves `active` to `paused` in one transaction. Return control
rotates the fence again before `paused` becomes `active`. An expired operator lease
does not silently resume automation.
Crash recovery also requires the exact durable transfer record for that command. A
`paused` state or compatible controller kind alone is not proof of ownership, and
generic lease acquisition cannot replace an expired handoff lease.

## Selection is not authority

HUD/Mission Control selection and desktop focus are operator-interface state. OGMI
objective/run identity and Autowork assignment identity are durable work authority.
WEIR accepts a caller-authored `WorkContext` and never promotes UI selection, active
window state, browser tab state, cwd, or telemetry recency into authority. See
`focus-and-interaction.md` for the cross-system mapping.
