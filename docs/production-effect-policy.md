# First production browser action

The production allowlist is empty. A future Windows canary may request permission to
fill one empty, unsaved text field with the public marker `WEIR-CANARY`. Its effect
lasts only for the life of that browser tab. The current Windows service admits a
deny-only worker. Browser compatibility, a permit-bound adapter and approval of a
named live action are separate delivery steps.

## Enroll one page and one field

Only the deployment owner's designated human Mission Control actor may enroll, replace
or withdraw a target or approve a fill. Pin that actor's exact ID in protected host
configuration. Require a fresh user-verifying passkey decision for each of these
operations, binding each challenge to its operation and exact record digest. The same
person may enroll and approve through separate decisions.
The site owner supplies proof of control and of the deployed page version. A proposing
run, service credential, page, selected board card or acquisition profile cannot approve.

The enrollment record commits to the canary grant identity, policy revision, site
profile and its policy digest, exact HTTPS origin including port and path, the digest
of the response bytes and behavior-relevant headers, and the field's accessible name
and test ID. Its digest is SHA-256 over the canonical WEIR JSON record. Compare the
enrollment with the page the browser actually loads. Require normal TLS hostname and
certificate-chain validation against the approved trust store. Record the peer
certificate fingerprint and reject caller-supplied trust roots, proxies and TLS bypass.

Allow one top-level GET on a separately reviewed, host-enforced read path. Reject
redirects (including header and markup refresh), query strings, fragments, login,
frames and every subresource request, including same-origin resources. Require one
enabled plain-text input, initially empty, with the enrolled name and test ID and no
form owner. Scripts, autosave, telemetry, background delivery and persistent storage
disqualify the page. Start a fresh anonymous context with page JavaScript, service
workers, extensions and persistent browser state disabled. The adapter's entire
operation set is load the enrolled document, resolve the field, read its value, fill
once, read it back and close. Each uses a fixed browser protocol operation with typed
arguments. Deny arbitrary evaluation, caller selectors, click, submit, upload and
all other operations.

Before reservation, the trusted host inspector must establish a continuous block on
outbound delivery for the AppContainer and every browser descendant. Bind Windows
Filtering Platform or equivalent kernel enforcement and its protected audit records
to the AppContainer SID, Job membership and process lifetimes. Close any initial
connections, disable the read path for that context and verify the block from outside
the worker before dispatch. An inherited handle or broker must not provide a parallel
network path. Require continuous coverage through process-tree exit. A browser log or
silence in an incomplete trace cannot establish zero delivery. The adapter qualification
must exercise this boundary with an independent receiver. [Windows admission](production-admission.md)

## Bind the operator's decision to the action

1. The trusted capture producer records the enrollment digest beside the accessibility
   tree inside the retained `Observation.accessibility_snapshot`, independently of page
   content. The canonical observation hash covers this field and the URL. The canonical
   `ActionProposal` covers that hash, the exact locator and target, context, run, session,
   epoch, value and pre/postconditions. The permit covers the resulting proposal hash.
   Recompute the chain from protected records at approval, reservation and the dispatch
   marker. Reject a missing digest, a replaced enrollment or a different live document.
2. A trusted private view displays the exact destination, field, old and new values,
   discard procedure and one-use limit. The passkey decision binds the hash of the
   displayed proposal. Fade issues the one-use permit. WEIR must also independently
   verify the existing signed `RemoteDecisionCapsule` for `approve` from a protected
   local record resolved by the permit's `approval_ref`. The trusted approval ingress
   binds this reference to exactly one capsule digest. Pin the issuer, Ed25519 key,
   audience, device and enrolled human actor. Verify freshness, step-up reference,
   command, action, proposal and work-context bindings, revocation and nonce uniqueness.
   Only the same durable reservation may recheck a consumed nonce.
   The caller bearer cannot sign a decision, provision a key or change that record.
   Missing independent proof denies reservation. Preserve the relay's capsule purge and
   redacted audit rules. [Signed decision contract](remote-decision-contract.md)
3. Only authenticated `fade-weir-authority` with `action:execute` may submit. The
   version 1 request contains exactly `schema_version`, `command_id`, `request_digest`,
   `proposal` and `permit`. Recompute the request digest. The proposal must specify
   `fill`, `risk=unknown`, `requires_approval=true` and exactly
   `{"value":"WEIR-CANARY"}`. Both session data class and `parameter_data_class` must
   equal `public`. Match the permit's issuer, approval reference, proposal hash, work
   context, owner run, session, epoch, action and risk. Enforce `use_limit=1` and WEIR's
   clock, expiry and dispatch-margin rules. [Action proposal](../contracts/action-proposal.schema.json) · [Execution permit](../contracts/execution-permit.schema.json)
4. The supervisor reads separately protected caller credentials provisioned through
   GLAS. The browser receives neither service tokens nor account credentials, cookies
   or personal profiles. Its `credential_binding_id` is the trusted registry's opaque,
   host-global reservation for this anonymous canary profile. It identifies exclusive
   use of that profile and worker instance. Full proposals, observations and decisions
   stay in their protected stores. Public projections carry only redacted metadata.

## Dispatch once

The deployment has one durable grant for the entire first canary. Reserve that grant,
permit, command ID and exact request digest atomically, consuming the budget even if
the command later cancels. Re-enrollment, policy updates, a new session or epoch, a
fresh proposal or permit, restart and operator disposition cannot replenish it.
Another attempt requires a separately reviewed grant and a new explicit action approval.

Reacquire and fence the controller, capture a fresh pre-state, then resolve exactly
one enrolled textbox. Both reads of the field are network-free observations of the
same in-memory document. Bind its navigation identity to the enrolled response
digest at load. A read-only observer controlled by the supervisor must independently
read the actual document, element and value. The effect worker cannot supply or alter
that evidence. If the browser proof cannot establish this read path, deny admission.
At the durable dispatch marker compare the stored session revision
with the fresh pre-state revision, and recheck the epoch, fence, worker instance,
profile reservation, enrollment, signed decision, permit and current host evidence.
Keep that document and element pinned through the one private fill. Navigation,
replacement, manual takeover or competing input invalidates the command.

Withdrawal and authorization to dispatch must have one authoritative order. The
workstation authority serializes its final consume with withdrawal and policy removal.
A remote withdrawal is effective on acknowledgement by that authority. If ordering
or revocation freshness cannot be established, deny dispatch. If withdrawal follows
a committed dispatch, stop further admissions and reconcile the original command.

## Receipt, shutdown and rollback

| Evidence | Required decision |
| --- | --- |
| A check fails before dispatch | Invoke no fill. Deny the request. A reservation recovered without a dispatch marker is `cancelled` and spent. |
| Trusted, network-free readback shows the exact marker in the same field at a newer revision | Retain bound before/after captures. Record `completed` only after independent proof of zero delivery through shutdown and verified return to deny-only admission. A generic `filled` state or worker acknowledgement cannot establish success. |
| The caller loses a response or polls during execution | Fade uses `action:status` and the original command ID. While the command is live, report `reserved` or `executing`. Return the durable terminal result when available. A status query never dispatches. Reject a changed digest or a second permit. |
| A marked dispatch lacks a provable result, including missing post-state or incomplete egress evidence | Atomically record `outcome_unknown` with only the pre-effect capture, invalidate the lease and quarantine the session and profile reservation. Recovery never repeats the fill. |

The first reservation closes admission to further fills. On every exit, including
withdrawal, failure and crash recovery, retain available evidence and contain the
worker. For an ambiguous dispatch, persist the unknown receipt and quarantine first
when possible. Keep the egress block in force while closing the context and
terminating its descendants. Independently read back process-tree exit and restoration
of deny-only admission. Preserve an unverified shutdown as an open incident with
admission closed. A later independent, separately admitted read of the enrolled page
must find the field empty to verify discard. This check cannot resolve whether a
previous fill happened. Rollback never writes a second value to the website.

An authenticated human may keep an unresolved case quarantined, or append a cleared
quarantine record with their identity, the active record hash and a disposition
reference. Clearing requires retained evidence of the outcome or an explicit decision
to abandon it after verified containment and shutdown. Keep the historical unknown
receipt and consumed budget in both cases. A lost worker's profile can be released
only by the separate authenticated `release_after_confirmed_worker_death` operation
bound to the session epoch, worker, instance, binding and retained tree-death
attestation. Preserve permits, receipts, reservations and evidence under the existing
retention rules. [Browser store](browser-store-v2.md) · [Frozen action contracts](contract-freeze.md)

## Evidence required for implementation and rollout

First prove browser startup, observation, isolation and descendant cleanup under the
Windows service identity. Adapter qualification must then demonstrate the following.

| Case | Evidence |
| --- | --- |
| Caller bearer alone, invalid signature, wrong actor or target, expired approval, changed enrollment or withdrawal before dispatch | Zero fills for each case. Also test withdrawal after dispatch and reconciliation without replay. |
| Navigation or reload, ambiguous or nonempty field, unexpected subresource or loss of containment | Zero fills before dispatch. Exercise an existing connection and attempted outbound delivery after the read path closes. Verify denial at an independent receiver. Missing coverage after dispatch yields an unknown result. |
| Changed digest, concurrent requests, a fresh proposal or permit, cancellation before the marker and process restart | At most one durable grant reservation. A cancelled reservation stays spent. A status read and every duplicate cause zero additional fills. |
| One valid fill, lost response, lost post-state and shutdown failure | Exact-value receipt and verified discard for the successful case. Reconcile the lost response by status. Quarantine an unprovable dispatch and verify denial of further actions. |

A live canary still needs an enrolled destination, current host evidence and explicit
operator approval of the exact action. This policy enrolls zero destinations.
