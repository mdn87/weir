# Remaining sibling integration plan — Fable delivery review packet

- Status: reviewed — `implementation may proceed` with mandatory amendments RF1–RF8
  (see the Fable review findings at the end)
- Prepared: 2026-08-28
- Starting WEIR revision: `f5652f3` on `main`
- Scope: unfinished work in WEIR, APU, Dias, `lugos-mcp`, Autowork, Mission
  Control, HUD, and Fade

This packet starts after the contract freeze recorded in
`docs/sibling-integration-plan.md`. Fable already accepted decisions D1–D12,
amendments A1–A9, and corrections C1–C6. This review must not reopen those decisions
unless inspection finds a concrete contradiction. It should decide whether the
remaining implementation choices, dependency order, and rollout gates below are safe
enough to execute.

No repository other than WEIR is changed by this document. This review grants no
permission to run a database migration, replace the installed APU watcher, deploy a
service, configure credentials or firewall rules, run a Fade action canary, or enable
a remote approval relay.

## Requested verdict

Fable, inspect the cited implementation boundaries and return:

1. `accept_remaining_plan` or a numbered replacement for R1–R6;
2. any dependency that makes the proposed parallel work unsafe;
3. any missing crash-recovery, privacy, compatibility, or rollback test; and
4. `implementation may proceed` or `revise before implementation`.

Treat the six implementation choices below as the review focus. Treat the frozen
schemas and authority decisions as inputs, not open questions.

## What is already complete

| Accepted batch | Landed result | WEIR revision |
| --- | --- | --- |
| Batch 0 | Frozen Python/TypeScript fixtures for work context, evidence, proposals, permits, receipts, redaction, expiry, and failure semantics | `89f96b6` |
| Batch 1A | Context-bound acquisition, immutable evidence references, cache-policy isolation, and metadata-only telemetry | `f20910c` |
| Batch 2A | Authenticated loopback service and typed in-process/HTTP clients for acquisition and status reads | `e36c6a2` |
| Batch 2B | Durable observation-bound proposals with separate authority and redacted reads | `979db3d` |
| Batch 2C | Killable browser-worker process transport and hash-bound worker-death attestations | `f5652f3` |

These implementations passed WEIR's repository gate when landed. They are dependencies
of this plan; they are not to be rebuilt in sibling repositories.

## Reverified starting points

The relevant paths were inspected read-only on 2026-08-28. Repository heads may move
before implementation, so each batch must rebase and rerun its focused baseline check
before editing.

| Repository or component | Reverified revision | Relevant state |
| --- | --- | --- |
| WEIR | `f5652f3` on `main` | completed batches above; remaining store, effect, admission, and deployment work is absent |
| Lugos parent | local `ec8366d0`; origin `9d17844e3` | origin-only change is the Torc pointer; unrelated local state must be preserved |
| `lugos-mcp` | `c68bafc` on `main` | no trusted dispatch context or WEIR adapter |
| Fade | `b2e2772` on `main` | Aire action service unchanged; execute-before-persist crash hazard remains |
| Mission Control | local `3478e78`; origin `33b3e14` | origin-only change is README content; closed five-projection parser remains |
| Dias | `9fab0bd` on `feat/portfolio-phase-1e` | newer portfolio-only work; focus broker and contracts are unchanged |
| APU | `29b027a` on `main` | cross-project session fallback and evidence v1 remain |

The Lugos parent has unrelated changes, and Dias/APU contain untracked local runtime or
tooling state. Implementation must isolate its commits and leave that state untouched.

## Remaining work at a glance

| Area | Missing outcome | Delivery batch |
| --- | --- | --- |
| WEIR durability | host-global credential reservation, explicit store migration, authorized retirement, action reservation/quarantine ledger | 2D |
| APU | strict, typed session attribution and intervention gating | 1B |
| Dias | versioned durable focus commands and receipts | 1C |
| `lugos-mcp` | trusted dispatch context and disabled-by-default `lugos.web` adapter | 3 |
| Autowork | DispatchRequest v5 sealed evidence inputs | 4 |
| Mission Control/HUD | tolerant consumer first, then redacted `weir` projection | 5 |
| Fade | separate WEIR approval/permit coordinator | 6 |
| WEIR actions | permit-bound effect driver with verified receipts | 7 |
| Host deployment | production worker limits, service identities, credentials, and lifecycle | 7P |
| Remote approval | separately reviewed outbound relay | 8 |
| Whole system | synthetic evidence and action acceptance run | 9 |

## Residual implementation choices for Fable

### R1 — Migrate the WEIR browser store explicitly to schema v2

Use one transactional SQLite store for browser sessions, host-global credential
reservations, controller fences, action reservations, receipts, and quarantines. These
records participate in one safety decision; splitting them across stores would create
an avoidable crash boundary.

Add an opaque `credential_binding_id` supplied by the trusted profile-state registry.
It identifies the real credential state across worker adapters without storing a
cookie, token, profile path, or caller-selected label. A partial unique constraint on
active/quarantined reservations must prevent two worker IDs from using the same
binding. Keep the existing worker-local `(worker_id, profile_id)` constraint as defense
in depth.

The v1-to-v2 migration is an offline, operator-approved command. Startup must never
auto-migrate. The command must:

- require the service and workers to be stopped;
- create and verify a backup, run SQLite integrity checks, and migrate transactionally;
- require an explicit trusted binding for every non-closed session or abort;
- preserve every quarantine and existing receipt; and
- support idempotent dry-run and readback modes.

There is no downgrade that deletes v2 safety records. Rollback restores the verified
v1 backup only before any v2 writer is enabled; afterward rollback means disabling new
routes while retaining v2 data.

### R2 — Separate death evidence from authority to retire a reservation

`WorkerDeathAttestation` proves that a named worker instance and process tree died. It
does not authorize credential reuse. Add an authenticated operator retirement command
that atomically checks the current reservation, session epoch, worker ID and instance,
attestation digest, and intended disposition.

The command appends a retirement record before releasing the reservation. It rejects
stale attestations, newer workers, changed reservations, incomplete cleanup evidence,
and unrecognized dispositions. An ambiguous or failed retirement leaves the credential
quarantined. Direct SQLite edits remain unsupported.

### R3 — Inject MCP work identity through a trusted dispatch context

Add a versioned internal `DispatchContext` from the authenticated host boundary through
`create_server`, `Router.dispatch`, and every adapter call. The context carries the
already-bound `WorkContext` and caller identity; model-controlled tool arguments cannot
replace either one.

The initial host has no trusted context provider today. Land the cross-cutting plumbing
and the `lugos.web` adapter behind per-action flags first. A server or the direct
`tool_call.py` path that lacks authenticated context must reject `lugos.web` while
leaving unrelated tools unchanged. Do not fall back to environment variables, cwd,
UI selection, or tool arguments. Enable an action only after its actual orchestrator
entry point supplies and tests the binding.

### R4 — Make no-attribution a normal APU result, not an exception or fallback

Replace recency fallback with a typed selection result containing either one matched
session plus provenance or `no_attribution` plus a bounded reason code. Enforce:

- explicit session ID plus cwd mismatch returns `no_attribution`;
- automatic matching accepts exactly one active exact-cwd candidate;
- zero or multiple active candidates return `no_attribution`; and
- stale, unparsable, or cross-project traces never become candidates.

Bump the exact-set APU evidence schema to v2 and keep a deliberate reader transition;
deployed 0.8.0 readers cannot consume the new fields. Gate `intervene()` and `apu apply`
on an exact selected session/cwd binding and assert the existing
`durable_policy_mutation: False` invariant in code. Report-only comparison may measure
behavior before strict mode, but no-attribution may never trigger intervention.

### R5 — Treat strict sibling versions as migrations, not additive fields

Dias v2, Autowork v5, and APU evidence v2 each have exact-set validators and silent-loss
or silent-drop hazards. Give each version a complete producer, reader, fixture, and
rollback path. Never write a new object to an old route or silently coerce it to an old
version.

For Dias, add explicit `/api/v2` routes and a durable SQLite receipt store while keeping
v1 byte-compatible during the measured window. For Autowork, enumerate and test every
version switch, serialization path, inbox path, workspace rebind, artifact-root check,
and evidence fingerprint. DispatchRequest v5 is Codex-lane-only until other executors
can safely accept evidence files. For APU, deploy a reader capable of v2 before making
v2 the only writer.

### R6 — Separate source landing, local canaries, and production enablement

All new effect and projection features land disabled. Source changes and deterministic
tests do not imply approval to mutate a live host. A same-host synthetic Fade-to-WEIR
canary may run only after explicit operator approval and may touch only a local fixture.
No real account, purchase, message, upload, credential entry, or production form is in
scope.

Before any real external action, production workers must use mandatory process
isolation, memory/process limits, and OS-enforced egress controls. On Windows, use a Job
Object plus a dedicated restricted identity and firewall/AppContainer-equivalent
network policy. On Linux, use cgroup v2 plus a network namespace and nftables-equivalent
policy. If the host cannot prove those controls, authenticated action admission fails
closed.

## Ordered delivery batches

### Wave A — Independent safety foundations

These source branches may be developed in parallel because they are in separate
repositories. Their migrations and deployments are still separately approval-gated.

#### Batch 2D — WEIR store v2 and global reservations

1. Add explicit schema-v2 migration and backup/readback tooling.
2. Add trusted `credential_binding_id` to session admission.
3. Reserve the binding before worker construction and retain it through every
   quarantined state.
4. Add action/permit reservations and durable `outcome_unknown` quarantine records.
5. Add the authenticated, audited retirement operation from R2.
6. Test two worker IDs racing for one binding, crash at every transaction boundary,
   stale retirement, restart recovery, and migration refusal.

Exit: no code path can reuse a credential until cleanup or authorized retirement is
durably proven. Do not run the migration as part of the source-code batch.

Implementation status (2026-08-28): the Batch 2D source and deterministic tests are
complete. Fresh stores create at v2; v1 startup refuses; the offline tool provides
strict binding-map dry-run, verified backup, exclusive transactional migration, and
read-only backup comparison. `StaticProfileStateRegistry` owns the trusted binding
seam. The global partial unique constraint, exact live-holder cleanup, separately
persisted death evidence, exact authenticated operator retirement, permit reservation,
and atomic `outcome_unknown` quarantine paths are implemented and restart-tested. No
operator database was migrated, no service was deployed, and no action route or live
effect was enabled.

#### Batch 1B — APU strict attribution

1. Add failing negative tests for explicit-ID/cwd mismatch, cross-project recency,
   ambiguity, stale traces, short `_peek_session` input, and Windows path normalization.
2. Implement the typed selection result and evidence v2 provenance.
3. Apply the exact binding gate to `intervene()` and mutating `apu apply` paths.
4. Add health fields for selector mode, last successful attribution, ambiguity count,
   service heartbeat, and package/build revision without trace content.
5. Land source and tests; then request separate approval to build, replace, or invoke
   `C:\Users\Matt\.local\bin\apu-watch.exe` and to alter its background lifecycle.

Exit: wrong-project, ambiguous, or stale traces produce `no_attribution` and cannot
drive a Codex session.

#### Batch 1C — Dias durable focus

1. Write the required Dias phase document from the accepted D8/C2 decision.
2. Add separate strict v2 schemas using the existing `instanceId` plus monotonic
   `revision` idiom; retain byte-compatible v1 routes.
3. Add a transactional receipt store keyed by `idempotencyKey + requestDigest`.
4. Reserve before adapter use. After restart, return an exact settled receipt; return
   conflict for a reused key with different content; classify unresolved reservations
   as `outcome-unknown` without automatic reissue.
5. Give capacity pressure its own reason code and reject stale target generations.
6. Add explicit detection for the current client's silent invalid-frame drop.

Exit: focus replay survives restart without a second native adapter call, and a stale
host instance cannot focus a reassociated window. Creating or migrating the receipt
store requires operator approval before execution.

### Wave B — Sealed evidence path

#### Batch 3 — `lugos-mcp` dispatch context and WEIR adapter

1. Introduce `DispatchContext` across both server and direct CLI/HUD dispatch paths.
2. Update all adapter signatures without changing unrelated adapter behavior.
3. Add `lugos.web` actions `read`, `search`, `enrich`, and `capture.get` using the typed
   WEIR client; reject identity, engine, header, cookie, credential, and service-URL
   overrides in model arguments.
4. Add one disabled runtime flag per action and keep `webdata.*` operational.
5. Test missing context, forged IDs, direct `tool_call.py` bypass, caller/data-class
   authorization, timeout, and evidence-hash mismatch.

Exit: one selected action can move from `webdata.*` to WEIR without granting the model
network authority or allowing it to choose work identity.

#### Batch 4 — Autowork DispatchRequest v5

1. Add `work_context` and bounded `evidence_inputs` to every exact version branch and
   serializer; stale branches must fail loudly instead of dropping fields.
2. Reuse visual-input protections for owned roots, strict resolution,
   symlink/reparse/path escape, size bounds, and pre-launch fingerprints.
3. Extend inbox preparation and `rebind_execution_workspace` so evidence is reachable
   and re-fingerprinted after workspace movement.
4. Keep provider networking disabled and `NETWORK_READ` rejected.
5. Enable v5 only for the Codex lane initially; other executors reject it explicitly.
6. Run provider-parity evaluation only where both lanes accept the identical verified
   bytes. Record unsupported lanes rather than weakening the evidence contract.

Exit: a provider sees sealed evidence bytes bound through
`correlation_id`/`assignment_id`, cannot reacquire them, and cannot silently receive a
v4 downgrade.

### Wave C — Read-only operator projection

Batch 5 has a hard deployment order:

1. HUD authors the redacted `weir` projection fixture while registration remains off.
2. Mission Control adds and tests the sixth typed projection, removes the five-entry
   snapshot limit, and deploys that tolerance first.
3. HUD builds the projection from a construction-time allowlist. Its unauthenticated
   read endpoints must never hold form values, raw parameters, credentials, usable
   permits, page content, or raw profile IDs.
4. Add the missing HUD↔Mission Control fixture parity gate, including whole-snapshot
   parsing, deltas, cursor reset, malformed records, and redaction.
5. Register and enable the HUD projection only after the deployed Mission Control
   version proves it accepts the fixture.
6. Keep approve/deny commands absent or flag-off. The operator/viewer role model is new
   work and must exist before any command is exposed.

Exit: adding `weir` cannot make Mission Control discard the whole snapshot, and the
first rollout remains read-only.

### Wave D — Permit-bound local action path

#### Batch 6 — Fade WEIR authority service

1. Create a second `FadeActionServer` instance with its own port, token, run directory,
   strict parser, and namespace. Leave the Aire endpoint byte-compatible.
2. Authenticate the operator/gateway and Fade's WEIR client with separate identities.
3. Persist the approval decision and reserve the run before issuing or dispatching a
   permit.
4. On ambiguous transport return, query WEIR by permit/command ID; never infer absence
   from a missing Fade record and replay the effect.
5. Persist terminal and `outcome_unknown` states and emit newly wired redacted lifecycle
   events.
6. Add a structural negative test proving Fade's existing Playwright recipe path cannot
   execute a WEIR proposal.

#### Batch 7 — WEIR effect driver

1. Add one Fade-only, authenticated execution route and keep it deny-all by default.
2. Validate the immutable proposal and permit, then atomically recheck and reserve the
   request digest, context, session epoch, and controller fence in the durable store.
3. Reacquire pre-state, re-resolve the semantic locator, and check preconditions.
4. Pass full `fill`/`select` parameters only over the authority channel and bounded
   private worker protocol; exclude them from logs, events, projections, and errors.
5. Execute one typed effect, acquire post-state, verify postconditions, and commit the
   immutable receipt.
6. If execution cannot be disproved after reservation, record `outcome_unknown`,
   quarantine durably, and require an operator disposition. Never replay automatically.
7. Keep generic actions at `risk=unknown` or higher. The first allowlist contains only
   reversible effects on a local synthetic fixture.

The two source batches can use frozen fixtures and mocks in parallel after Batch 2D's
ledger shape is accepted. Their integration waits for both sides to land.

Exit: missing, stale, expired, replayed, mismatched, or wrong-session permits cause no
effect; a completed effect has verified before/after evidence; an ambiguous effect is
quarantined.

### Wave E — Approved canaries and production admission

Run these independently and only with the stated operator approval:

1. APU: build/install the user-local watcher, start its owned background lifecycle in
   report-only mode, verify the running revision, then enable strict selection.
2. Dias: create/migrate the receipt store, then canary simulator → Surface → Car Thing
   while monitoring v1/v2 silent drops and idempotent replay.
3. Fade/WEIR: run one same-host action against a synthetic local page, force ambiguous
   transport and restart cases, and prove no duplicate effect.
4. HUD/Mission Control: deploy consumer tolerance, then projection registration, with
   command handling still disabled.
5. WEIR 7P: require process transport, resource limits, restricted service identities,
   ACL-protected per-caller credentials, lifecycle supervision, and OS egress policy
   before admitting any external authenticated action.

Rollback disables producers, routes, or feature flags. It preserves evidence,
reservations, permits, receipts, quarantines, events, and receipt journals for the
published retention window.

### Wave F — Cross-system acceptance and later relay review

Batch 9 runs one synthetic chain:

```text
WorkContext
  -> WEIR evidence reference
  -> lugos-mcp DispatchContext
  -> Autowork v5 sealed evidence
  -> WEIR observation and proposal
  -> Fade decision and permit
  -> WEIR effect and verified receipt
  -> HUD/Mission Control redacted projection
  -> APU exact attribution
```

Assert the same immutable root context hash and correlation chain throughout. Also run
the negative chain: forged context, stale focus target, ambiguous APU trace, permit
replay, effect timeout, unknown outcome, and service restart. No component may turn a
UI selection, foreground window, cwd, or recent trace into authority.

Batch 8, the remote approval relay, remains outside this implementation verdict. It
needs a second review after the local canary to select an authenticated outbound path
and threat-model operator identity, replay, revocation, offline approval, queue
retention, and compromised HUD behavior. Workstation action services remain loopback.

## Dependency map

```text
Frozen D1–D12 + A1–A9 + C1–C6
  |
  +-- WEIR 2D ----------------------+-- Fade 6 ----+
  |                                 |              +-- local action canary -- WEIR 7P
  |                                 +-- WEIR 7 ----+
  |
  +-- APU 1B -------------------------------------------------------------+
  +-- Dias 1C ------------------------------------------------------------+
  +-- lugos-mcp 3 -> Autowork 4 -----------------------------------------+-- Batch 9
  +-- HUD fixture -> Mission Control tolerance (deploy) -> HUD projection +

Local Batch 9 success -> separate Batch 8 remote-relay review
```

WEIR 2D, APU 1B, Dias 1C, and the disabled Mission Control tolerance work are the first
independent source units. Autowork follows MCP context plumbing. HUD registration
follows the Mission Control deployment. The local action canary follows both Fade and
WEIR action implementations.

## Verification and landing rules

Run targeted tests after each coherent batch and the complete repository gate before
landing:

| Repository | Required final gate |
| --- | --- |
| WEIR | `python -m pytest -q` |
| APU | `python -m pytest -q` |
| Dias | `npm run validate`, `npm run typecheck`, `npm test`, `npm run build` |
| `lugos-mcp` | `python -m pytest -q` |
| Autowork | `python -m pytest -q` |
| Mission Control | `pnpm test:lugos`, `pnpm lint`, `pnpm typecheck`, `pnpm quality:gate` |
| HUD | `npm test`, then `npm run check` |
| Fade | `python -m pytest -q` |

Every cross-language schema consumer also runs the canonical fixture/hash vectors.
Every persistence batch injects crashes before reservation, after reservation, after
effect, and before receipt commit. Every feature flag has an off-path test. Tests must
observe the external effect count, not only returned status.

Land one coherent conventional commit per repository batch. For `lugos-mcp`, Fade, and
Mission Control, push child commits before changing Lugos parent pointers. Autowork and
HUD are separate commits in the shared Lugos parent and must not absorb unrelated local
changes. A held branch needs a written blocker; completed, green work lands normally.

## Approval checkpoints

Fable's verdict is technical review only. Obtain operator approval at implementation
time for:

- the WEIR v1-to-v2 SQLite migration;
- the Dias receipt-store schema/dependency and any database creation or migration;
- APU evidence schema rollout and any replacement, invocation, or lifecycle change to
  `C:\Users\Matt\.local\bin\apu-watch.exe`;
- local or remote service deployment, credential provisioning, ACL, firewall, or
  background-service changes;
- the Fade/WEIR action canary or any other live effect; and
- a future remote approval relay.

Source inspection, planning, fixtures, and disabled source implementations grant none
of these approvals.

## Fable review findings (2026-08-28)

Reviewed at WEIR `93a4527` (`f5652f3` plus this document). Baselines: every pin in
the reverified table matches its repository head; the Lugos-parent origin delta is
the Torc pointer only, the Mission Control origin delta is README-only, and the Dias
head move `e3faa94..9fab0bd` touches no focus-broker, contract, or host file. The
WEIR repository gate passes at the pin (269 passed, 1 skipped). Four independent
read-only inspection passes covered WEIR, APU + `lugos-mcp`, Autowork + Fade, and
Mission Control + HUD + Dias. Batch-0 fixture checks: `outcome_unknown` (A5) and the
permit field vocabulary (A7) are frozen as required, and the A4 clock authority is
concrete (`maximum_tolerated_skew_seconds: 5`, mirrored as
`MAX_CLOCK_SKEW_SECONDS` in `actions.py`).

No R1–R6 choice is replaced. The following amendments are mandatory and fold into
the batch specifications:

- **RF1 — R1's version machinery already exists; define creation versus migration.**
  `STORE_SCHEMA_VERSION = 1` is persisted via SQLite `user_version`
  (`store.py:27,169-248`) and unknown versions already fail closed — but a fresh
  database is auto-created at startup today. R1 must state that v2 bumps this
  existing mechanism, decide whether fresh-database creation directly at v2 remains
  a startup behavior (acceptable) while v1→v2 conversion is offline-only, and add
  coverage for the version-refusal branch, which no test exercises today.
- **RF2 — Reconcile R2 with the existing worker-asserted release path.**
  `record_worker_cleanup_attested` (`store.py:499-564`) already retires unresolved
  OPEN reservations on worker-supplied identifiers with no proof of death, and it is
  the only thing that unblocks `close_with_lease` (`store.py:1695-1701`). Batch 2D
  must enumerate the complete set of release paths for host-global credential
  reservations — live-worker cleanup attestation bound to the authenticated worker
  protocol and instance, versus R2 operator retirement — and test that a worker
  cannot attest cleanup for a binding held by another instance, or after its own
  death attestation exists. Otherwise the new partial unique constraint can be
  bypassed through the legacy path.
- **RF3 — Name the "trusted profile-state registry".** It is undefined new work, but
  a seam exists: `ProfileStateProvider`/`VerifiedProfileState`
  (`playwright_observer.py:41-74`; only the empty provider ships) plus the persisted
  `SessionProfileBinding`. R1 should implement the registry behind that protocol and
  state its owner, storage, and trust basis; `credential_binding_id` derivation
  lives behind it.
- **RF4 — Batch 4 size bounds are new work, not reuse.** The visual-input path has
  no byte or count bound at any layer (`dispatch_contract.py:1427-1434`; the
  fingerprint streams unbounded). Add explicit size and count bounds for
  `evidence_inputs` with tests, and preferably backfill `visual_inputs`. The
  exact-set hazard is confirmed at 14 version edit sites (not ~11), including the
  stale "1, 2, or 3" error string at `dispatch_contract.py:1370-1376`.
- **RF5 — Batch 5 tolerance must cover both Mission Control schemas.** The closed
  snapshot union (`operator-contract.ts:210-231`, `.max(5)`, throwing parse → 502)
  and the *narrower* `operatorEventSchema` (`:240-276`, only `autowork`/`task-loop`)
  fail independently; an unparseable event is what degrades the SSE stream. Step 2's
  tolerance deploy must widen both, and the step-4 parity gate must include
  event-schema fixtures. HUD publishes events only for `autowork` today
  (`live.mjs:94-101`), so `weir` events are new wiring and must not precede the
  Mission Control event-schema deploy.
- **RF6 — Non-blocking wording corrections.** HUD's `model-budgets` read is
  bearer-gated; the unauthenticated surface is exactly snapshot + events, and
  Mission Control's `requireRole('viewer')` proxy makes the HUD port the only
  unguarded hop — the construction-time redaction stance is unchanged. Dias's
  invalid-frame handling is not fully silent: `parseEvent` → `null` routes to a
  generic `onError` and a stuck error state (`display-transport.ts:274-277`);
  1C step 6 should target diagnosability (version mismatch is indistinguishable
  from corruption), and any new receipt reason code (capacity) is v2-only because
  the v1 enum is closed.
- **RF7 — The first trusted DispatchContext provider is an unmade, blocking
  decision.** No context channel exists, and the in-tree precedent is worse than
  ambient env: agent-mail accepts model-supplied `from_agent`/`from_session`
  arguments (`agent_mail_adapter.py:230,245,585-586`). R3's fail-closed posture is
  correct, but Batch 3's exit and Batch 4's canary are unreachable until one
  orchestrator entry point is chosen to establish the binding — record that choice
  as a named blocker before enabling any `lugos.web` action. `tool_call.py`
  constructs a fresh `Router` per invocation, so context injection must be
  per-dispatch, not per-process.
- **RF8 — Restate the dropped parallelization constraint.** Batch 4 (Autowork) and
  the HUD half of Batch 5 are in-tree siblings of one Lugos parent checkout and
  must not be edited concurrently in one working tree; sequence them or use
  separate worktrees, preserving the parent's unrelated dirty entries.

Requested-verdict answers:

1. `accept_remaining_plan` — no replacement for R1–R6; RF1–RF8 are amendments.
2. Unsafe parallelism: only RF8. Wave A parallelism is safe (disjoint repositories,
   verified).
3. Missing tests: the store version-refusal branch (RF1), cross-instance cleanup
   attestation (RF2), evidence-input size/count bounds (RF4), and Mission Control
   event-schema parity (RF5).
4. Verdict: `implementation may proceed`. This grants no migration, deployment,
   watcher, live-action, or remote-relay approval; the approval checkpoints above
   stand.

## Copy/paste prompt for Fable

> Review `docs/remaining-integration-plan.md` as the post-freeze delivery gate. The
> accepted D1–D12 decisions, A1–A9 amendments, and C1–C6 corrections in
> `docs/sibling-integration-plan.md` are fixed inputs. Inspect the current code at the
> pinned/reverified revisions, focus on R1–R6 and the batch dependency order, and return
> numbered findings followed by exactly one verdict: `implementation may proceed` or
> `revise before implementation`. This review grants no migration, deployment, watcher,
> live-action, or remote-relay approval.
