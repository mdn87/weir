# Sibling integration plan — Fable review packet

- Status: reviewed — `contracts may freeze` with amendments A1–A9 and corrections
  C1–C6 (see the Fable review findings and decision record at the end)
- Prepared: 2026-08-27
- Reviewed: 2026-08-27 by Fable (direct WEIR inspection plus six independent
  sibling-repository verification passes)
- Scope: WEIR, `lugos-mcp`, Autowork, Fade, HUD, Mission Control, Dias, and APU

No sibling repository is changed by this document. Implementation starts only after
the decisions below are reviewed and the affected repository bases are confirmed.

## Review request

Fable, please review this as an architecture and delivery gate, not as a prose review.
Return:

1. `accept` or a concrete replacement for decisions D1–D12;
2. any missing authority, privacy, crash-recovery, or compatibility invariant;
3. any dependency that makes the proposed parallel batches unsafe; and
4. a final `contracts may freeze` or `revise before implementation` verdict.

Pay particular attention to D2 (capture versus evidence binding), D5 (Fade versus
WEIR ownership), D7 (unknown outcomes after a crash), and D12 (same-host action
canary before any remote approval relay).

## Intended outcome

This work delivers three independently useful improvements:

1. **Brokered web evidence:** callers acquire through WEIR, pass immutable typed
   evidence into Autowork, and keep provider network access disabled.
2. **Permit-bound browser actions:** Fade authenticates an approval and coordinates
   the durable run; WEIR performs the exact browser effect inside its fenced live
   session and returns verified before/after evidence.
3. **Safer ambient signals:** Dias makes focus commands durable and stale-safe, while
   APU stops attributing evidence to an unrelated recent trace.

The higher-level concept is explicit work identity and bounded authority. “Focus” is
not one global value: an OGMI objective, an Autowork assignment, a selected UI card,
a foreground window, and an APU trace match have different owners and authority.
Only an authenticated assignment or permit can authorize work. Selection, window
activation, cwd, and recency remain presentation or observational signals.

Not included in the first implementation wave:

- changing Lode's marketplace scoring, scheduling, or history logic;
- granting provider processes network access;
- exposing Fade or WEIR action endpoints beyond loopback;
- adding Sulis/AETA/AITU persistence before the event and evidence fixtures settle;
- enabling generic production browser actions; or
- allowing APU, COGIN, or Orca output to rewrite active policy automatically.

## Inspected baseline

Paths below use `repository:path` notation. They are logical paths, not assumptions
about a developer's checkout location.

| Repository or in-tree component | Reviewed revision | Relevant implementation |
| --- | --- | --- |
| WEIR | `5d125e3` on `main` | contracts, acquisition broker, browser session kernel |
| Lugos parent | `ec8366d0` on `master` | Autowork and HUD are in-tree components |
| `lugos-mcp` | `c68bafc` on `main` | router, adapters, compact tool groups |
| Fade | `b2e2772` on `main` | target-machine runtime and loopback action service |
| Mission Control | `3478e78` on `main` | typed HUD operator client and role-gated UI |
| Dias | `e3faa94` on `feat/portfolio-phase-1e` | display transport and focus broker |
| APU | `29b027a` on `main` | trace selection and minimized evidence ingestion |

The Dias baseline is not its default branch. Before Dias implementation, compare that
branch with its default branch and either land the portfolio work first or explicitly
choose it as the new base. Do not silently build durable focus on an unmerged branch.

The inspection also found unrelated local changes in the Lugos parent and untracked
runtime data in Dias/APU. Implementation must preserve them; repository cleanup is not
part of this plan.

## Current gaps confirmed in code

| Boundary | Current behavior | Consequence |
| --- | --- | --- |
| WEIR acquisition | `WebRequest` names only `run_id`; `WebCapture` has no work-context binding | public evidence can be detached from the work that requested it |
| WEIR browser | sessions bind `WorkContext`, revisions, epochs, and controller fences | this is the durable identity pattern the other paths should reuse |
| `lugos-mcp` | `Router` calls adapters; `webdata.*` performs fixed direct HTTP requests | no typed WEIR adapter or common evidence reference exists |
| Autowork | dispatch versions 1–4 support text/images but no web-evidence object | providers can receive prose or files, but not a verified capture manifest |
| Autowork policy | `NETWORK_READ` exists in vocabulary but provider safety rejects it | orchestration may acquire evidence, but providers must remain network-disabled |
| WEIR action | proposals and receipt validation exist; no permit or `execute()` exists | observation remains safe, but the action loop is intentionally incomplete |
| Fade action | the Aire-only service executes before persisting and keys replay by proposal ID | a crash can make the effect ambiguous, and a reused ID is not digest-bound |
| HUD operator API | durable command receipts and replay exist; WEIR is not a projection | the reusable operator boundary exists but cannot yet show WEIR state |
| Mission Control | mirrors HUD schemas; selection is local component state | it can display or submit a command, but selection must never grant authority |
| Dias focus | in-memory key-only receipt cache and generation-free target registry | restart, key collision, or reassociation can repeat or misdirect a command |
| APU trace choice | exact ID/cwd first, then a recent cross-project fallback | an unrelated trace can be credited with the current work |

Primary evidence anchors include:

- `weir:src/weir/models.py`, `weir:src/weir/broker.py`,
  `weir:src/weir/work_context.py`, `weir:src/weir/actions.py`, and
  `weir:src/weir/browser/broker.py`;
- `lugos-mcp:src/lugos_mcp/routing.py`,
  `lugos-mcp:src/lugos_mcp/adapters/webdata_adapter.py`, and
  `lugos-mcp:src/lugos_mcp/adapters/autowork_adapter.py`;
- `lugos:autowork/src/autowork/campaign/dispatch_contract.py`,
  `route_execution.py`, and `provider_safety.py`;
- `fade:fade/action_service.py` and `fade:fade/events.py`;
- `lugos:lugos-hud/src/operatorApi/{contract,commands,live}.mjs`;
- `mission-control:src/integrations/lugos/operator-{contract,client,state}.ts`;
- `dias:packages/focus-broker/src/{broker,target-registry}.ts` and
  `dias:packages/display-ui/src/transport/display-transport.ts`; and
- `apu:src/apu/behavior_watch.py` and `apu:src/apu/evidence.py`.

## Proposed decisions

### D1 — WEIR owns the canonical work-context schema

Keep `WorkContext` v0.1 in WEIR as the canonical cross-system identity object. Its
canonical JSON and SHA-256 rules remain unchanged. A root context is immutable;
consumers carry their own `run_id`, `assignment_id`, and `correlation_id` alongside
`work_context_hash` rather than editing the context to add downstream identifiers.
An authenticated orchestration boundary creates or resolves the context. A model/tool
argument may reference that bound context but may not supply replacement identity
fields.

Do not create a shared-contract repository yet. Cross-language consumers pin the
contract version and a schema/fixture digest in their own repository so standalone
tests do not depend on a sibling checkout. Revisit `parent_context_hash` only when a
real derived-work use case cannot be represented by root context plus local IDs.

### D2 — Bind work to an evidence reference, not to the reusable capture

Keep `WebCapture` content-addressed and context-independent so public cache entries can
be reused. Add a context-specific `EvidenceReference` v0.1 with this minimum shape:

```text
evidence_ref_id
work_context_hash
request_id
capture_id
capture_contract_version
content_hash
artifact_ref | null
data_class
trust
created_at
reference_hash
```

Add an `AcquisitionEnvelope` containing the full `WorkContext` and `WebRequest`.
`AcquisitionBroker` verifies that their run identities agree and returns the capture
plus a newly persisted `EvidenceReference`. A cache hit may reuse the same capture, but
it must produce a new evidence reference for the requesting context. Cross-system
callers may not pass a bare capture as authorized evidence.

This avoids the tempting but incorrect alternative of stamping one caller's context
onto a cacheable public capture. `artifact_ref` is an opaque WEIR reference, never a
host filesystem path; an authenticated client resolves it and materializes its own
bounded local copy. `reference_hash` binds the complete canonical reference so a
consumer can detect field substitution.

### D3 — Use one typed client and a persistent WEIR service in production

Define a `WeirClient` interface with in-process and authenticated-service
implementations. Unit tests and the standalone CLI may use the in-process client;
production sibling calls use a persistent service on the acquisition/effect host.

The service binds to loopback, authenticates named clients, caps request and response
sizes, and exposes receipt/status lookup by durable command ID. Stateful browser
workers remain on the same host as the service. Do not expose WEIR or Fade directly on
a LAN merely to connect the HUD; cross-host approval is a separate relay decision.
Give clients separate scopes: `lugos-mcp` may acquire/read evidence, while Fade alone
may submit permits/actions. Store service credentials outside contracts and logs. A
valid `work_context_hash` proves integrity, not caller authorization.

### D4 — Autowork receives evidence, not network authority

Add a validated `work_context` plus `evidence_inputs` in DispatchRequest v5. Each entry
carries the evidence reference, capture/content hashes, work-context hash, media type,
trust label, and a bounded local artifact path materialized by orchestration. Autowork
requires every entry to match the request's context, re-hashes the artifact immediately
before release, and labels its content untrusted.

`evidence` becomes an input modality, not a capability grant. Do not grant
`NETWORK_READ`, arbitrary URLs, headers, cookies, or a WEIR tool to a provider process.
The orchestrator acquires first; every candidate provider evaluates the same bytes.

### D5 — Separate authorization authority from the browser effect driver

The word “executor” currently hides two jobs:

- **Fade** authenticates the operator decision, issues the narrow permit, coordinates
  the durable action run, and resolves an ambiguous response through status lookup.
- **WEIR** is the mechanical browser effect driver because it owns the live browser
  context, semantic re-resolution, controller fence, and before/after observation.
- **HUD/Mission Control** are authenticated command ingress and presentation. They do
  not issue permits or infer authority from a selected card.

Fade's existing Playwright adapter must not create a second browser session for a WEIR
proposal. Conversely, WEIR must not decide that an action is approved.

### D6 — Add a one-use execution permit

WEIR owns the `ExecutionPermit` schema because it is the action boundary; Fade owns
issuance policy and the durable permit record. Bind the permit to at least:

```text
permit_id, proposal_hash, work_context_hash, owner_run_id,
session_id, session_epoch, action_type, risk, approval_ref,
issuer, issued_at, expires_at, use_limit=1, permit_hash
```

Do not bind it to an exact controller-lease generation: WEIR rotates that fence during
state reacquisition. The receipt records the generation actually used. The full permit
travels only over an authenticated Fade-to-WEIR channel; projections expose a harmless
reference or digest, never a reusable bearer value.

For the same-host v1, transport authentication establishes that Fade is the issuer and
the canonical permit hash detects mismatch. If a permit later crosses hosts, add a
signed assertion or mutually authenticated transport before widening the topology.

### D7 — Prefer at-most-once dispatch and an explicit unknown outcome

Fade and WEIR both reserve the permit/command and bind it to a canonical request digest
before any effect. Repeating the same identifier and digest returns the stored state;
reusing an identifier with different content fails.

No local ledger can promise exactly-once external effects across a crash. If the worker
may have acted but no durable receipt exists, do not retry automatically. Persist and
surface `outcome_unknown`, quarantine the session from further automation, and require
state reconciliation or operator disposition. Extend `ExecutionReceipt` rather than
misreporting this state as an ordinary failure.

### D8 — Dias owns local target generations, not global work authority

Dias remains a bounded foreground-window controller. Add:

- a fresh `stateInstanceId` for each host runtime;
- an opaque monotonic `targetGeneration` for each run-to-target association;
- DisplayState/RunSummary v2 fields that expose those opaque values without exposing
  the private target;
- `stateInstanceId`, `observedRevision`, and `expectedTargetGeneration` to command v2;
- a server-computed canonical request digest and durable receipt reservation; and
- reason codes for idempotency conflict, stale instance, stale target, and unknown
  outcome.

`observedRevision` is audit context, not an exact global compare-and-swap: an unrelated
run update should not invalidate a safe focus command. The broker rechecks the current
run and capability, and rejects an instance or target-generation mismatch. An optional
`work_context_hash` is correlation metadata only.

Use SQLite with WAL and a pinned stable driver for the host receipt journal unless the
Dias review identifies a proven existing durable store to reuse. Do not make the local
Node 24 `node:sqlite` API the default while that runtime still reports it as
experimental. Creating the store schema and adding its driver are implementation-time
changes that require the normal review and migration approval.

### D9 — APU trace attribution fails closed

Selection order becomes:

1. exact explicit provider/session ID; if cwd is also supplied, a mismatch rejects;
2. otherwise exact normalized cwd, bounded freshness, and exactly one candidate; or
3. no attribution.

Remove the unrelated recent cross-project fallback. Record selector provenance,
candidate count, last-event age, and confidence in the minimized evidence metadata.
Keep APU review-only: it may propose an improvement, but it may not rewrite active
behavior or become execution authority.

The source change and service lifecycle both belong to APU. WEIR must not start or
supervise the deployed `apu-watch` command. Updating a user-local executable or service
is a separate deployment step requiring permission at implementation time.

### D10 — Producers own events; HUD owns projections

Do not invent one monolithic cross-repository event schema. Each producer owns its
versioned event payload, while all participating events share a small correlation
header fixture:

```text
event_id, schema_version, occurred_at, producer,
run_id, assignment_id | null, correlation_id, work_context_hash
```

WEIR emits session/proposal/execution metadata. Fade emits approval/permit/run metadata.
HUD joins them into a redacted `weir` projection. Events and projections exclude raw
DOM, page bodies, prompt text, form values, credentials, cookies, private profile IDs,
and reusable permits.

### D11 — UI selection remains local even when an operator approves

HUD and Mission Control key rows by explicit work and proposal identifiers. An operator
may select a row to prepare an approval command, but the command contains only the
exact `proposal_hash`, `action_id`, and `work_context_hash`; the server reloads the
authoritative proposal and rejects any mismatch. The client cannot submit replacement
action parameters or mint a permit.

Viewer roles remain read-only. Operator role permits an approve/deny command through
the HUD operator API; Fade remains the authority behind that command.

### D12 — Prove same-host actions before designing the remote relay

The first action canary uses a local reversible test page with Fade and WEIR on the
same workstation. Approval is local and authenticated. Read-only HUD projections may
ship in parallel, but a remote HUD approval command stays disabled until the team
chooses and threat-models an outbound relay or existing host service path.

Do not solve that gap by binding the Fade or WEIR action service to a non-loopback
address.

## End-state call paths

### Public evidence

```text
caller WorkContext
  -> lugos-mcp `lugos.web` intent
  -> authenticated WeirClient
  -> AcquisitionBroker / selected connector or reader
  -> context-independent WebCapture
  + context-bound EvidenceReference
  -> Autowork DispatchRequest v5 sealed evidence input
  -> network-disabled provider evaluates identical bytes
```

### Browser action

```text
WEIR observation + WorkContext
  -> ActionProposal with semantic intent and proposal hash
  -> redacted HUD projection
  -> authenticated operator decision
  -> Fade approval record + one-use ExecutionPermit
  -> Fade dispatches exact permit/proposal to local WEIR service
  -> WEIR reserves command, reacquires state, re-resolves target, checks fence
  -> worker performs one effect and captures post-state
  -> WEIR ExecutionReceipt
  -> Fade final run state
  -> HUD/Mission Control projection and review-only APU evidence
```

State reacquisition and effect should be one reserved worker operation. The worker
must resolve the semantic locator against the newly acquired state; it must not reuse
the proposal's ephemeral element reference.

## Contract ownership and compatibility

| Contract | Schema owner | Runtime authority | Compatibility rule |
| --- | --- | --- | --- |
| `WorkContext` | WEIR | authenticated caller establishes authorization | keep v0.1; pin schema fixture/digest |
| `AcquisitionEnvelope`, `EvidenceReference` | WEIR | WEIR validates and persists binding | new v0.1; bare captures rejected at sibling boundary |
| `WebCapture` | WEIR | evidence content only | keep context-independent v0.1 |
| DispatchRequest v5 `work_context`/`evidence_inputs` | Autowork | assignment compiler/provider safety | accept v1–v4 during producer migration |
| `ActionProposal` v0.3 | WEIR | proposal only; no authority | add work-context hash and preserve v0.2 readers temporarily |
| `ExecutionPermit` v0.1 | WEIR | Fade issues; WEIR validates/consumes | new, one use, expiring, exact digest |
| `ExecutionReceipt` v0.3 | WEIR | WEIR records effect and verification | add permit/context IDs and unknown outcome |
| Fade approval/permit run record | Fade | Fade | retain old Aire endpoint and records unchanged |
| HUD `weir` projection/command | HUD | operator API authenticates ingress | additive projection and command versions |
| Mission Control mirror | HUD contract mirrored by Mission Control | role gate only | parity test against HUD fixtures |
| Dias command/receipt v2 | Dias | Dias host focus broker | dual-read v1/v2, v2-write, then require v2 |
| APU selector metadata | APU | observation only | additive fields; no unsafe legacy fallback |

## Implementation batches

The batches are coherent delivery units, not one-agent-per-file tasks. Batches marked
parallel share no mutable repository state once D1–D12 are accepted.

### Batch 0 — Freeze fixtures and failure semantics

Owner: WEIR with consumer review.

1. Record Fable's D1–D12 decisions in this document.
2. Add canonical positive and negative fixtures for `WorkContext`,
   `EvidenceReference`, `ActionProposal`, `ExecutionPermit`, `ExecutionReceipt`, and
   the correlation header.
3. Freeze canonical JSON, hash basis, nullability, size limits, expiry behavior,
   redaction, and reason codes.
4. Give proposal, permit, and receipt contracts independent version constants instead
   of bumping every browser contract through one shared version value.
5. Decide the retention window for evidence references, permits, receipts, and unknown
   outcomes.

Exit gate: Python and TypeScript consumers can validate the same fixtures and obtain
the same hashes. Execution remains disabled.

### Batch 1A — Bind public acquisition to work context

Owner: WEIR. May run in parallel with 1B and 1C.

Likely files:

- create `contracts/evidence-reference.schema.json` and
  `contracts/acquisition-envelope.schema.json`;
- extend `src/weir/broker.py`, `models.py`, `persistence.py`, and `telemetry.py`;
- add contract, broker, persistence, cache, and tamper tests.

Required behavior:

- every public `read`, `search`, and `enrich` receives a full valid context;
- `request.run_id != context.run_id` fails before network access;
- a cache hit creates a new context-bound evidence reference without duplicating the
  underlying capture;
- artifact/content hash mismatch fails closed; and
- telemetry contains identifiers, digests, sizes, and reason codes only.

Rollback: keep the legacy in-process API temporarily for WEIR's own CLI, but do not
enable a sibling caller without evidence binding.

### Batch 1B — Make APU attribution explicit

Owner: APU. May run in parallel with 1A and 1C.

Change `src/apu/behavior_watch.py`, `evidence.py`, `evidence_cli.py`, and their tests.
Add explicit/mismatched/ambiguous/stale cases and prove that no recent trace from a
different cwd is selected. Add health output for selector mode, last successful
attribution, ambiguity count, service heartbeat, and package/build revision without
exposing trace content. The currently deployed CLI reports enablement and
`background_service`, but no version identity.

Roll out first in report-only comparison, then strict mode. Shadow comparisons are
diagnostics and do not feed the learning loop. A rollback may require an explicit
session ID or stop automatic attribution; it must not restore cross-project recency
fallback.

After source tests pass, build/install the user-local watcher and configure its APU-owned
background lifecycle as a separate, approved deployment. Verify the running binary's
version and `background_service` health rather than assuming the source checkout is
what the host executes.

### Batch 1C — Make Dias focus replay- and stale-safe

Owner: Dias. May run in parallel with 1A and 1B.

First translate the approved portion of this plan into the phase document required by
Dias. Then change:

- `contracts/display-state.schema.json`, `run-summary.schema.json`,
  `command-request.schema.json`, `command-receipt.schema.json`, and generated contract
  types;
- `packages/focus-broker/src/target-registry.ts` and `broker.ts`;
- add `packages/focus-broker/src/receipt-store.ts`;
- wire store/configuration through `apps/host/src/runtime.ts` and servers; and
- update display and DeskThing transports to emit v2 commands.

Serve the new state and command contracts on explicit `/api/v2` routes. Keep the
existing `/api/v1` routes byte-compatible during the measured window; do not return a
schema-v2 object from a route whose current clients require v1 with no extra fields.

The store transaction reserves `idempotencyKey + requestDigest` before adapter use.
An exact settled replay returns the byte-equivalent receipt after restart. A different
digest returns an idempotency conflict. A reserved command without a receipt is
verified against current foreground state where possible; otherwise it becomes
`outcome-unknown` and is not reissued automatically.

Canary order: simulator, Surface, then Car Thing. Keep v1 routes during a measured
compatibility window; make new clients read and write v2 immediately.

### Batch 2 — Add the persistent WEIR client/service boundary

Owner: WEIR. Depends on 1A.

Create a typed client and loopback service, including:

- authenticated `read`, `search`, `enrich`, evidence lookup, and command-status routes;
- observation-bound proposal registration plus full-authority and redacted proposal
  lookup, backed by a durable proposal store;
- strict payload limits, deadlines, data-class checks, and client identities;
- the existing SQLite session/lease/command/event store plus immutable filesystem
  capture/artifact store as the durable sources of truth;
- killable browser worker processes rather than an in-process browser object;
- a host-global profile reservation and explicit cleanup attestation; and
- authorized dead-worker retirement that never frees an unconfirmed profile silently.

Keep service and in-process clients behind one contract test suite. The service must
restart without losing session revisions, evidence references, receipts, or quarantines.

Rollback: stop the service and leave its durable stores intact. Public WEIR CLI use may
fall back to the in-process client; sibling integration remains disabled.

### Batch 3 — Add the `lugos-mcp` WEIR adapter

Owner: `lugos-mcp`. Depends on Batch 2's client contract.

Create `src/lugos_mcp/adapters/weir_adapter.py` and a `lugos.web` tool group. Start with
the bounded actions `read`, `search`, `enrich`, and `capture.get`. The public schema
accepts intent, URL/query, source, constraints, and evidence policy. The authenticated
server/router context injects the already-bound WorkContext outside model-controlled
arguments. The schema does not accept replacement identity fields, an engine name,
arbitrary headers, cookies, raw credentials, or an unbounded service URL.

Wire the backend through `registry.py`, `routing.py`, server introspection, and compact
tool resolution. Add a versioned internal dispatch context from server call to router
to adapter; if a transport cannot supply an authenticated binding, `lugos.web` fails
closed instead of trusting IDs in tool arguments. Add adapter, routing, schema, server,
and negative-policy tests.

Leave `webdata.*` operational. Move one fixed action at a time behind WEIR only after
output and failure parity; keep a feature flag that returns that action to its legacy
adapter. Do not perform a big-bang alias switch.

### Batch 4 — Add sealed evidence inputs to Autowork

Owners: Autowork and the `lugos-mcp` Autowork adapter. Depends on Batches 1A and 3.

Extend DispatchRequest v5 with a validated `work_context` and bounded
`evidence_inputs`. Materialize each input under an orchestrator-owned artifact root,
reject path escape/symlinks, require the context hashes to agree, and revalidate the
content hash immediately before provider launch. Preserve v1–v4 parsing during rollout.

Update assignment compilation, dispatch storage/summary, CLI preparation, route
execution, and provider-safety projection. Evidence metadata may enter spans; raw
content may not. Provider launch remains network-disabled, and `NETWORK_READ` remains
rejected.

Canary the same task and exact evidence bundle across eligible providers. Compare
answer fidelity and citations without letting either provider reacquire the source.

Rollback: producers emit v4 and the v5 reader remains dormant. Persisted v5 requests
remain readable; do not rewrite them to v4.

### Batch 5 — Project redacted WEIR state to HUD and Mission Control

Owners: HUD first, then Mission Control. Depends on the Batch 0 event fixture; may land
before action execution.

HUD:

- create `src/weirProjection.mjs` and register a `weir` operator projection;
- ingest session, proposal, approval, permit-state, and receipt metadata;
- key rows by work-context/run/assignment/correlation/proposal identifiers; and
- test snapshots, deltas, replay, cursor reset, malformed fields, and secret redaction.

Mission Control:

- mirror the finalized HUD contract in `operator-contract.ts`;
- extend client state and rendering without changing local selection semantics; and
- test snapshot/event merge, cursor recovery, viewer/operator roles, and rejection of
  commands whose explicit identifiers do not match a projected proposal.

First rollout is read-only. The approve/deny command definition may be implemented
behind a disabled flag so it cannot outrun the Fade authority path.

Rollback: unregister the projection or hide the UI while preserving producer events
and cursor history.

### Batch 6 — Add Fade approval and permit coordination

Owner: Fade. Depends on Batch 0 contracts and Batch 2 status lookup.

Do not broaden the existing Aire `/v1/runs` request. Add a separate WEIR authority
module and endpoint with its own strict parser, durable records, and tests. It must:

1. authenticate the operator or trusted HUD command gateway;
2. load the exact proposal by hash and show a redacted but decision-useful summary;
3. store the approval decision before permit issuance;
4. issue one expiring, one-use permit and reserve the Fade run before dispatch;
5. call the local WEIR service with a Fade-specific authenticated identity;
6. query WEIR by permit/command ID after an ambiguous transport response; and
7. persist completed, blocked, denied, expired, conflict, and unknown outcomes.

Emit redacted lifecycle events with the shared correlation header. Preserve old Aire
records and endpoints byte-for-byte unless a separate compatibility change is approved.

Local console approval is the first canary. Remote HUD approval remains disabled in
this batch.

### Batch 7 — Implement permit-bound WEIR action execution

Owner: WEIR. Depends on Batches 2 and 6.

Implement the already-frozen ActionProposal v0.3, permit validator, and
ExecutionReceipt v0.3 contracts, then expose one Fade-only action endpoint. In one
durable operation:

1. validate proposal, permit, issuer identity, expiry, scope, session epoch, and hashes;
2. reserve `permit_id + request_digest` and the current controller fence;
3. reacquire a fresh observation;
4. re-resolve the semantic locator and evaluate preconditions;
5. perform exactly one typed effect through the worker;
6. acquire the post-state observation;
7. verify declared postconditions; and
8. commit the receipt before releasing the session.

Start with a small reversible action allowlist. Generic `click`, `fill`, and `submit`
remain `risk=unknown` or higher; DOM mechanics alone may not downgrade risk. Missing,
expired, replayed, mismatched, stale, or wrong-session permits fail before the effect.
The local canary excludes uploads, credentials, purchases, messages, account changes,
and production form submissions. Enabling a real external action requires a narrower
action-specific contract, redaction/retention review, and declared postconditions; the
generic DOM method does not become a blanket production capability.

If the process dies after reservation and the effect cannot be disproved, record an
unknown outcome and quarantine the session. Never infer success without two captures
and verified post-state.

Rollback: set action execution to deny-all while retaining observations, proposals,
permits, receipts, projections, and status lookup.

### Batch 8 — Add the remote approval relay only after a second review

Owners: HUD/Fade host integration. Depends on successful local action canaries.

Choose an authenticated outbound relay or an existing Lugos host service path that
keeps workstation action services on loopback. Threat-model operator identity, replay,
revocation, offline approval, queue retention, and compromised HUD behavior. Then
enable the already-versioned HUD/Mission Control approve/deny command.

This batch is intentionally not implied by the local action slice. It gets its own
review because it changes the network and authority boundary.

### Batch 9 — Cross-system acceptance and learning loop

Run a synthetic local page through observation → proposal → approval → permit → effect
→ verified receipt → projection → APU attribution. Use reversible test actions and no
production account.

Only after the deterministic path passes may APU/COGIN/Orca compare outcomes and
propose routing or policy changes. Their output is a review candidate; no component
edits active policy automatically.

## Dependency and parallelization map

```text
Fable decisions + contract fixtures (Batch 0)
  |
  +-- WEIR evidence binding (1A) -> WEIR service (2) -> lugos-mcp (3) -> Autowork (4)
  |
  +-- APU strict attribution (1B) -----------------------------------------------+
  |
  +-- Dias durable focus (1C) ---------------------------------------------------+
  |
  +-- redacted event fixture -> HUD -> Mission Control (5) ----------------------+
  |
  +-- WEIR service (2) -> Fade permit coordinator (6) -> WEIR action driver (7)
                                                        |
                                                        +-> local canary
                                                            -> relay review (8)

All paths converge in the cross-system acceptance run (9).
```

Batches 1A, 1B, and 1C are the safe first parallel wave. HUD contract work can begin
after Batch 0, but action commands remain disabled. Evidence and action work must not
share a premature “network capability” shortcut.

## Acceptance gates

### Identity and evidence

- The same root `work_context_hash` is visible in WEIR, MCP, Autowork, Fade, HUD, and
  APU records without mutating the root context.
- A model cannot replace the run, assignment, objective, or correlation identity bound
  by its authenticated orchestration context.
- A bare capture or a mismatched evidence reference is rejected at the sibling
  boundary.
- Reusing cached public content creates a new context binding and does not leak one
  caller's context into another.
- Every provider receives identical verified evidence bytes and still has no outbound
  network access.

### Authority and action

- UI selection, foreground window, browser tab, cwd, and newest trace cannot issue or
  broaden a permit.
- Only authenticated Fade may submit an execution permit to WEIR.
- Missing, expired, replayed, digest-mismatched, context-mismatched, or wrong-session
  permits cause no effect.
- A completed receipt has before/after evidence and verified post-state.
- A possibly executed command without a receipt becomes `outcome_unknown`; restart
  never blindly repeats it.

### Dias and APU

- An exact Dias replay after restart returns the original receipt without a second
  adapter call.
- Reusing a Dias key with different content returns a conflict.
- A stale host instance or target generation cannot focus a reassociated window.
- APU uses an explicit session or one fresh exact-cwd candidate; ambiguity and
  cross-project candidates produce no attribution.

### Privacy and projection

- Events and UI state contain IDs, hashes, state, risk, reason codes, timestamps, and
  bounded counts only.
- Credentials, cookies, prompt text, DOM/page bodies, form values, raw profile IDs,
  and usable permit values never appear in events or projections.
- HUD and Mission Control recover from cursor expiry/reset and cannot turn local
  selection into server-side authority.

## Verification matrix

Run targeted tests after each batch and the full repository gate once before landing.

| Repository | Targeted areas | Final gate from repository root |
| --- | --- | --- |
| WEIR | contracts, work context, broker/cache, service, browser store, actions | `python -m pytest -q` |
| `lugos-mcp` | WEIR adapter, registry, routing, server, Autowork adapter | `python -m pytest -q` |
| Autowork | dispatch contract/store, assignment, route execution, provider safety | `python -m pytest -q` |
| Fade | permit parser/store, action server, events, replay/unknown outcomes | `python -m pytest -q` |
| HUD | operator contract/events/live API/projections | `npm test` then `npm run check` |
| Mission Control | Lugos contracts/client/state/routes/UI | `pnpm test:lugos`, `pnpm lint`, `pnpm typecheck`, then `pnpm quality:gate` |
| Dias | contracts, focus broker/store, host/display integration | `npm run validate`, `npm run typecheck`, `npm test`, `npm run build` |
| APU | behavior watch, evidence, CLI, service health | `python -m pytest -q` |

Add cross-language golden-fixture tests wherever a WEIR schema is consumed. A schema
digest mismatch fails CI with an update instruction; it must not silently accept the
new producer shape.

## Platform matrix

| Lane | Required verification |
| --- | --- |
| Shared | canonical JSON/hashes, fixtures, reason codes, redaction, permit semantics, event correlation, and receipt identity match on every OS |
| Windows | Dias native focus adapter, Windows cwd normalization, installed `apu-watch` lifecycle, Playwright worker termination, global profile reservation, local Fade↔WEIR action canary |
| Linux host | `lugos-mcp`, Autowork, HUD operator API, event ingest, persistent stores, and disabled-by-default remote approval command |
| macOS/Linux clients | Unix cwd normalization, APU ambiguity tests, Mission Control contract/client behavior, and WEIR public acquisition client |

Where a component is cross-platform, keep shared contracts and tests common. Split
only process supervision, path normalization, native focus adapters, and service unit
installation into OS-specific lanes.

## Rollout and rollback

Use additive contracts and disabled-by-default feature flags. Suggested controls:

- WEIR service versus in-process acquisition;
- `lugos.web` backend enablement per action;
- Autowork v5 evidence producer enablement;
- HUD `weir` projection visibility;
- Fade permit issuance;
- WEIR action execution (`deny-all`, `local-canary`, `enabled`);
- Dias v1 acceptance/v2 requirement; and
- APU selector comparison/strict modes.

Rollback disables new producers or effect routes; it does not delete or rewrite
captures, evidence references, permits, receipts, events, Dias journals, or APU
provenance. Keep readers for already-written contract versions through the published
retention window.

Database/store creation or migration, user-local binary replacement, background
service mutation, SSH deployment, and any live account action require their normal
operator approvals when implementation reaches those steps. This review packet does
not grant them.

## Landing order

1. Land the accepted WEIR contracts and fixtures.
2. Land independent APU and Dias hardening from confirmed clean bases.
3. Land the WEIR evidence/service work.
4. Land child repositories (`lugos-mcp`, Fade, Mission Control) with features disabled
   until their dependencies exist.
5. Land Autowork and HUD as separate coherent commits in the Lugos parent.
6. Push child commits first, then update Lugos submodule pointers with the parent sync
   tooling; never leave parent pointers targeting unpushed child commits.
7. Run local evidence and action canaries, then enable one feature at a time.
8. Review the remote approval relay separately before changing a network boundary.

For substantial authority or persistence changes, use a PR and land it after the full
gate is green. Small independent safety fixes may land directly after validation. Do
not combine unrelated existing working-tree changes with these commits.

## Fable review findings (2026-08-27)

Reviewed against WEIR `main` at `955f2c4` (contracts, `work_context.py`, `models.py`,
`broker.py`, `actions.py`, `browser/broker.py` read directly). All six sibling areas
were independently re-verified by read-only inspection agents. Every baseline matches
its pin: Fade `b2e2772` (own repo, clean), `lugos-mcp` `c68bafc` (clean), Lugos parent
`ec8366d0` (8 dirty/untracked entries, none under `autowork/` or `lugos-hud/src`),
Mission Control `3478e78` (clean), Dias `e3faa94` (tracked-clean; untracked runtime
dirs preserved), APU `29b027a` (clean; untracked `.dias/`). The gap table's claims all
verified; the corrections below are where the plan's *assumptions* failed contact with
the code.

One baseline risk dissolves: Dias `feat/portfolio-phase-1e` is a strict fast-forward
of `main` (1 ahead, 0 behind, pushed). Recording it as the 1C base is low-risk.

No decision is replaced. The following amendments are contract-level and must be
resolved in Batch 0 fixtures before the freeze:

- **A1 — `WorkContext.evidence_refs` conflicts with root immutability.** The field
  participates in the hash basis, so accumulating references would change
  `context_hash` and break the "same root hash everywhere" gate. Freeze it as
  caller-supplied *input* references fixed at creation (typically empty); all
  outward evidence binding lives in `EvidenceReference`. State this in the fixture.
- **A2 — Define the artifact re-hash basis.** `content_hash` is a digest of canonical
  content JSON (post-truncation), while `artifact_ref` may point at raw bytes.
  D4's pre-launch re-hash needs an unambiguous basis: either add an explicit
  `artifact_hash` to `EvidenceReference` or define the materialized artifact as
  exactly the canonical content JSON. Also: the acquisition cache key must include
  `capture_policy` so a policy-trimmed capture never satisfies a fuller policy, and
  a reference minted from a metadata-policy capture must not satisfy an
  `evidence_inputs` entry that requires content.
- **A3 — Caller identity, not just loopback.** Any local process can reach a
  loopback port, and a single shared secret does not distinguish callers. Fade's
  existing service already has a constant-time bearer check, loopback-only binding,
  and arming flags — the packet understates it; the actual gap is that one token
  makes Aire and any future WEIR caller indistinguishable. The WEIR service must
  authenticate named clients with per-client secrets stored under user-only ACLs
  outside the repository and logs, and Fade's WEIR authority module gets its own
  token, never Aire's. Related: HUD snapshot/event reads are entirely
  unauthenticated today (only command POSTs take a bearer), so any registered
  projection is world-readable on the port — `weir` projection redaction must be
  complete at construction time; there is no later gate.
- **A4 — Permit expiry needs a clock authority.** WEIR validates `expires_at`
  against its own clock; the fixture must state the maximum tolerated skew and Fade
  must issue with margin. Without this, same-host v1 works by accident and any
  later topology change breaks silently.
- **A5 — Unknown outcome and quarantine must be first-class.** `ReceiptResult`
  currently has no unknown value, and the completed/failed validation invariants do
  not cover it. Add `outcome_unknown` with its own rules (no verification claim, no
  post-state assertion, reservation record retained) and make quarantine durable:
  it blocks new permits for the session and only operator disposition clears it —
  never a restart, retry, or timeout. Verification found Fade's current crash mode
  is worse than "ambiguous": the effect fires before any record is written and
  replay keys off the record's *absence*, so a crash-then-retry silently
  re-executes. Reserve-before-effect is non-negotiable.
- **A6 — `fill`/`select` parameters are form values.** The proposal's `parameters`
  carry the text to be filled; D10 excludes form values from events and projections.
  Resolve the tension explicitly: the full-authority proposal (Batch 2 lookup) is
  the only channel that carries parameters, Fade's authenticated approval surface
  renders them for the operator, and HUD/Mission Control projections never do.
  Classify parameters by `data_class` in the fixture. HUD's fleet projection
  already ships raw message previews through this same pipeline — that precedent
  must not be inherited by the `weir` projection.
- **A7 — Permit field names must survive Fade's payload screen.** Fade rejects any
  payload containing keys named `token`, `authorization`, `secret`, and similar at
  any depth (`FORBIDDEN_KEYS`). Freeze `ExecutionPermit`/proposal fixture field
  names to avoid that vocabulary (e.g. no `permit_token`), or the permit dies at
  Fade's own parser.
- **A8 — D4's binding joint is `correlation_id`/`assignment_id`, not `run_id`.**
  `DispatchRequest` carries no `run_id`; the orchestrator mints it at dispatch,
  after parsing. The evidence-input agreement check therefore binds at assignment
  compile time against `correlation_id`/`assignment_id`, and the orchestrator — not
  the caller — attests the run linkage. The fixture must state this so v5 does not
  invent a request-side `run_id` with nothing to check it against.
- **A9 — D9's selection rule needs three refinements.** (1) "Exactly one candidate"
  over-rejects: several sessions in one cwd is normal and today resolves via the
  `active` flag — freeze the rule as *unique active candidate among exact-cwd
  matches*. (2) Explicit ID + mismatched cwd is currently **silently ignored**, not
  merely tolerated — the trace's own cwd is recorded and later drives intervention
  in that other project's directory; the change to reject is a real behavior
  change, not a tightening of an existing check. (3) "No attribution" has no
  representation today (every caller expects a trace or a ValueError) — it needs a
  typed outcome and non-zero CLI exit handling.

### Plan corrections from sibling verification (mandatory)

These do not reopen D1–D12; they correct batch assumptions that verification showed
to be wrong.

- **C1 — Batch 5's ordering is inverted at the contract edge.** Mission Control's
  snapshot schema is a closed union of exactly five projection names with
  `.max(5)`, parsed with a throwing `.parse`: a sixth `weir` projection rejects the
  *entire* snapshot and degrades the event stream. Mission Control must tolerate
  the `weir` projection (deployed) **before** HUD registers it, or HUD's
  registration stays flag-off until then. The required HUD↔MC parity fixture test
  does not exist today — make it a Batch 5 exit gate, not an afterthought. D11's
  "viewer roles remain read-only" also overstates the present: HUD has no role
  model at all; the operator/viewer distinction is new work, and until it exists
  the unauthenticated read surface is the binding constraint (see A3).
- **C2 — Dias v2 is new machinery, not added fields.** All 16 contract schemas set
  `additionalProperties: false` with `schemaVersion` as `const: 1`, consumers
  validate with strict AJV, and the display client silently drops non-validating
  frames — a v2 frame reaching a v1 display makes it go dark, not warn. v2 means
  separate schema files plus version dispatch that does not exist on any route; the
  1C canary must explicitly detect the silent-drop mode. Reuse the in-repo
  `instanceId` + monotonic `revision` idiom from the chip-board/portfolio contracts
  rather than inventing new shapes. There is no durable store anywhere in the tree
  (every fs call is read-only), so SQLite is a genuinely new dependency — the
  plan's driver caution stands. Two behavioral notes: an existing test *asserts*
  same-key/different-command replay returns the first receipt (flip it
  deliberately, with a reason code), and the broker's capacity-pressure denial is
  currently indistinguishable from a real focus denial — give it its own reason
  code in v2.
- **C3 — Autowork v5 is not "purely additive."** Version handling is exact-set
  across ~11 enumerated edit sites in one file, `to_dict` silently drops fields of
  unhandled versions, and `__post_init__` silently downgrades newer fields — a
  missed site loses `work_context`/`evidence_inputs` without an error (a stale
  error string shows the v4 bump already missed a site). The closed modality tuple
  must widen for evidence files — a breaking validator change — and the
  Claude/Antigravity routes hard-reject non-text inputs, so v5 evidence is
  Codex-lane-only until those executors are extended; the cross-provider canary in
  Batch 4 must account for this. The inbox path parses with no
  `owned_artifact_roots`, so orchestrator-materialized evidence is unreachable
  through it without a signature change, and `rebind_execution_workspace` must be
  taught to re-fingerprint `evidence_inputs` (it only covers `visual_inputs`
  today). Reuse the existing visual-input path hardening (strict resolve,
  `..`/symlink/reparse rejection, TOCTOU fingerprints) — it is solid.
- **C4 — Batch 6 needs a second Fade server, not a second route.** The action
  service is one shared `do_POST` closure with pre-routing shared auth and an
  Aire-shaped run store (hard-coded `aire.fixed-continuation`/`kvm` fields,
  `fade_*.json` glob, shared ID namespace). Preserving Aire byte-for-byte while
  adding WEIR authority means a second `FadeActionServer` instance on its own port
  with its own token and its own runs directory (the constructor supports it; the
  CLI needs a second `--port`). Also: the action service emits zero lifecycle
  events today — `events.py` builders exist but are wired only into the recipe
  runner — so D10's Fade events are new wiring, not reuse. The Fade→Playwright
  isolation is structurally sound today (the browser adapter is reachable only via
  the recipe runner); the D5 negative test keeps it that way.
- **C5 — Batch 3's context needs an origin, and the plumbing is wider than one
  adapter.** The MCP server entry receives no session or auth material; today's
  only identity channel is ambient process env — exactly the pattern the plan
  rejects. Decide where the authenticated binding is established upstream of
  `create_server` before writing the adapter. The router passes the same three
  positional arguments to all 21 adapters, so the versioned dispatch context is a
  cross-cutting signature change, and the second dispatch path (`tool_call.py`,
  used by CLI/HUD) bypasses the server layer entirely — the fail-closed rule needs
  an explicit test there. A per-action migration seam already exists (each leaf
  ToolSpec declares its backend), but it is a static edit; the runtime feature
  flag per action is new mechanism.
- **C6 — Batch 1B is schema-breaking and APU is not review-only today.** The
  evidence validators are exact-set on read and write, so selector-provenance
  fields require an `EVIDENCE_SCHEMA_VERSION` bump (the compatibility table's
  "additive fields" row is wrong), and deployed 0.8.0 wheels cannot read v2 events.
  No test covers the cross-project fallback — removing it fails nothing — so add
  the negative coverage *first*. The likely consumer-breakage source on Windows is
  cwd normalization (case-insensitive compare without short-name resolution) plus
  the 40-line `_peek_session` scan, both of which the fallback currently masks.
  Most importantly: `intervene()` spawns `codex resume` in the *trace's* recorded
  cwd, and `apu apply` mutates files — D9's "review-only" must be scoped explicitly
  to the behavior-watch/evidence subsystem with `intervene` carved out and gated,
  and its `durable_policy_mutation: False` literal made a checked invariant.
  Wrong-cwd intervention is the live hazard strict attribution fixes; do not rely
  on `intervene` before 1B lands.

Parallelization findings:

- Batches 1A/1B/1C remain the safe first parallel wave (disjoint repositories).
  The Dias base precondition is satisfied by recording the portfolio branch as the
  base (it is a pushed fast-forward of `main`). **Batches 4 and 5 must not run
  concurrently in one Lugos parent checkout** — Autowork and HUD are in-tree
  siblings, so sequence them or use separate worktrees; the parent's unrelated
  local changes must be preserved. C1 adds a hard ordering inside Batch 5:
  Mission Control contract tolerance lands and deploys before HUD registers the
  projection.
- D5 needs a mechanical guard, not a convention: add a negative test that Fade's
  existing Playwright adapter path cannot service a WEIR proposal (wrong client
  identity at the WEIR action endpoint), landing with Batch 6.

## Fable decision record

Recorded from the 2026-08-27 manual review.

| Decision | Proposed default | Fable response |
| --- | --- | --- |
| D1 WorkContext owner/immutability | accept | accept, with A1 (freeze `evidence_refs` at creation) |
| D2 context-specific EvidenceReference | accept | accept, with A2 (explicit artifact-hash basis, cache-policy key) |
| D3 persistent authenticated WEIR service | accept | accept, with A3 (per-caller identity, not just loopback; ACL'd client secrets) |
| D4 brokered evidence; provider network disabled | accept | accept, with A8 (binding joint is correlation/assignment; orchestrator attests run linkage) and C3 |
| D5 Fade authority/coordinator; WEIR effect driver | accept | accept, plus negative test that Fade's own browser path cannot serve a WEIR proposal (isolation verified structurally sound today); C4 applies |
| D6 one-use permit; no exact lease-generation binding | accept | accept, with A4 (expiry clock authority and skew fixture) and A7 (field vocabulary); no-lease-binding confirmed against the recovery path |
| D7 explicit unknown outcome; no blind replay | accept | accept, with A5 — verification showed Fade's current crash mode silently re-executes, so reserve-before-effect is non-negotiable |
| D8 Dias instance + target generation + durable digest store | accept | accept, with C2; portfolio branch recorded as the 1C base (pushed fast-forward of `main`) |
| D9 strict APU attribution | accept | accept, with A9 (unique-active rule, cwd-mismatch reject is a behavior change, typed no-attribution) and C6 (`intervene` carve-out; schema version bump) |
| D10 producer events + HUD projection | accept | accept, with A6 and C1/C4 (redaction complete at construction — HUD reads are unauthenticated; Fade event emission is new wiring) |
| D11 explicit-ID UI commands; selection non-authoritative | accept | accept; note the role gate itself is new work (C1) — HUD has no role model today |
| D12 same-host canary before remote relay | accept | accept |

Review verdict: `contracts may freeze` for the WEIR-owned contract set — conditional
on amendments A1–A9 being folded into the Batch 0 fixtures before the freeze is
declared. Corrections C1–C6 are mandatory revisions to the implementation batches
(compatibility rows for Dias, APU, and Mission Control claimed additivity the code
does not support, and Batch 5's landing order inverts at the contract edge) but do
not reopen D1–D12. The batch dependency map is otherwise sound with the hardened
preconditions recorded above. All seven baselines were re-verified at their pins by
independent inspection before this verdict.
