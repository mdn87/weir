# Durable Work Identity and Interaction

## The naming problem

The Lugos projects currently use **focus** for five different concepts. Treating them
as one global state would let a UI selection or foreground window accidentally become
execution authority.

| Concrete concept | Current owner | Authority meaning |
| --- | --- | --- |
| durable work objective | OGMI authority plan, run, assignment, checkpoint | says what work is authorized and should continue |
| execution assignment | Autowork dispatch and immutable assignment | says what one worker may execute |
| operator attention / selected card | HUD and Mission Control local view state | presentation only; never authority |
| desktop window activation | Dias focus broker and host-private target registry | bounded operator command to foreground one exact target |
| trace attribution | APU session/cwd/recency matching | observational provenance only |

The higher-level concept WEIR needs is **explicit work and controller identity**, not
ambient focus.

## Reusable Dias pattern

Dias already supplies the best small interaction pattern:

```text
local SelectionIntent
  -> deterministic durable run ID
  -> host-private TargetResolution
  -> expiring idempotent command
  -> verified InteractionReceipt
```

The selected display item stays local. The host resolves an opaque run ID to a private
window target, requires one exact visible match, attempts activation, and verifies the
foreground result. WEIR adopts the same separation for browser state, while adding
durable revisions and controller fencing.

## WEIR implementation

Every browser call now carries or resolves all of the following explicitly:

- a hashed `WorkContext` with `objective_id`, `run_id`, `assignment_id`,
  `correlation_id`, provenance source, and prior evidence references;
- a `BrowserSession` with one owner run, worker, opaque profile ID, data class,
  domain allowlist, epoch, and compare-and-swap revision;
- one expiring `ControllerLease`; each grant or transfer increments a monotonic
  generation used as the worker-command fence;
- a command ID bound to the operation, target session, worker session, owner, epoch,
  expected revision, lease generation, and typed payload digest;
- an immutable observation/capture or a small metadata receipt.

SQLite transactions make profile reservation, revision changes, lease rotation,
command replay, work-context binding, and the append-only event journal durable across
processes. Reusing a command ID with different content fails. Manual takeover rotates
the fence and pauses automation in one transaction; returning control rotates it again
before resuming.

Recovery is tied to the exact `web.controller.transferred` event, including command,
revision, direction, authorization, controller identities, and lease generation. A
generic `paused` session is never treated as proof that a takeover or return already
happened; this keeps unrelated command reservations from being consumed after a crash.

Each worker operation first reserves the session by rotating the automation fence and
moving `active` to `paused`; only its durable commit restores `active`. Worker methods
serialize effects through the receipt boundary, and takeover fences drain earlier
effects before acknowledging the handoff. A created worker context without a confirmed
close keeps the session and worker-local profile ID quarantined. The same applies to an
OPEN dispatch reserved before the worker response is lost; only exact worker cleanup
attestation clears it. The process transport can attest that a worker tree has died,
but that evidence cannot release a reservation; no authorized dead-worker retirement
API exists yet.

No WEIR API consults the active window, HUD selection, most recent trace, or a global
"current task." A caller must name the work context and session.

The context hash supplies integrity and replay binding; it is not authentication.
The caller-facing Lugos surface must still authenticate the caller and establish that
the named objective/run/assignment is authorized before asking WEIR to open a session.

## Observation versus action

The current Playwright worker can open, navigate, observe, capture a screenshot, and
close an isolated context. Each session gets a nonpersistent browser process whose
exact allowlisted hostnames are pinned to validated addresses. JavaScript is disabled,
only GET/HEAD transport is admitted, and the site profile must attest read-only
credentials. It has no click, fill, upload, JavaScript evaluation, persistent-profile,
ambient-Chrome, or CDP-attach method.

`ActionCompiler` can turn a fresh observation plus semantic locator into a hash-bound
proposal. Generic click and input/change primitives remain `unknown` risk because DOM
mechanics do not reveal whether a page autosaves or triggers an external consequence.
Each element postcondition retains its semantic locator and re-resolves it against the
newer observation instead of reusing an ephemeral element reference. The built-in
approval authority denies everything. `ExecutionReceipt` requires before/after evidence
and verified post-state before it can claim completion. There is deliberately no WEIR
`execute()` entry point yet.

## Cross-system call path

The durable integration shape is:

```text
caller-authored WorkContext
  -> named lugos-mcp web operation
  -> thin typed WEIR adapter
  -> immutable capture bundle
  -> Autowork providers evaluate the same evidence
  -> redacted events project to AITU/HUD
  -> review-only COGIN/Orca/APU improvement candidates
```

WEIR chooses the engine and acquisition mechanics. `lugos-mcp` should validate and
serialize intent, not accept provider/model choices. Autowork should receive a typed
evidence input instead of embedding capture JSON in a task prompt, and providers should
not receive general network access merely because orchestration acquired evidence.

## Inspection baseline

This mapping was checked on 2026-08-27 against Dias commit `e3faa94`. The concrete
implementation anchors are `packages/focus-broker/src/broker.ts`,
`packages/focus-broker/src/target-registry.ts`,
`adapters/windows-focus/src/index.ts`, and the command request/receipt schemas. They
confirm that Dias keeps target details host-private, bounds command lifetime and adapter
execution, allowlists `focus-run`, and returns a reason-coded receipt. They also confirm
that the current receipt cache is process-local and keyed only by the caller-supplied
idempotency key; it has no canonical request digest, durable journal, or run-revision
precondition. Those are the concrete gaps behind the Dias recommendation below.

## Underlying-system improvements identified

These changes belong in their owning repositories and are not silently implemented by
WEIR:

1. **APU trace attribution:** require an explicit Codex `session_id` when available.
   Otherwise require exact cwd, bounded freshness, and one unambiguous active
   candidate. Remove the fallback to an unrelated recent cross-project trace and record
   selector provenance, confidence, and candidate count.
2. **Autowork evidence input:** add a versioned capture/evidence input to the dispatch
   contract. Keep provider network disabled; orchestration acquires through WEIR first.
3. **Autowork capability policy:** reconcile the declared `NETWORK_READ` capability
   with assignment and execution policy before exposing a bounded `lugos.web` tool.
4. **Dias focus receipts:** bind idempotency keys to canonical request digests and add
   a lease/revision precondition plus append-only receipt journal. Keep target resolution
   private to the host.
5. **HUD/Mission Control:** project WEIR events by run, assignment, and correlation ID;
   keep selected-node state local and non-authoritative.

This is a review-driven learning loop. Telemetry can propose routing or policy changes,
but it must not rewrite active behavior directly.

On the inspected host, the user-local `apu-watch` installation reports the
`primary-agent-autonomy-loss` watcher enabled but `background_service=false`. That is a
review trigger, not durable execution authority. APU should run it through its owning
service lifecycle and ingest explicit `WorkContext`/session identifiers; WEIR should not
start or supervise that cross-project service.
