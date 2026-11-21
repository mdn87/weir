# First production browser action

The production allowlist is empty. A future Windows canary may request one browser
change. It fills one empty, unsaved text field with the public marker `WEIR-CANARY`.
Its only intended effect is a change visible in that browser tab.
Selecting a destination, enabling an adapter and approving a live action each require
the evidence below. The accepted Windows service currently runs a deny-only worker.

## Eligible page and field

The site owner must nominate a dedicated page under the operator's control and supply
evidence of ownership and of the deployed page version. Enroll only an exact HTTPS
origin (including port), path, digest of the response bytes and behavior-relevant
headers, and site-profile policy digest. Use one
top-level document in a fresh, anonymous, nonpersistent browser context. Deny redirects,
alternate routes, query strings, fragments, frames, login flows and third-party content.
The approved origin must be the one actually loaded and authenticated by the browser.

The reviewed page must contain one enabled, initially empty plain-text input with a
fixed accessible name and test ID. The input has no form owner. The reviewed response
must be inert. Scripts, service workers, autosave, submission, telemetry and background
delivery each disqualify it. Keep browser scripting and persistent storage off.
After the initial read, enforce zero outbound delivery for the worker and all descendants,
including existing connections, through context disposal. A label that says “draft”
or a site's assurance about autosave is insufficient. Where the page version, network
isolation or field identity cannot be proved, WEIR must deny the fill. A production
load requires a separately reviewed read path compatible with the Windows controls.

The only eligible command is `fill` with exactly `{"value":"WEIR-CANARY"}` and public
session and parameter data. Passwords, prefilled fields and any other input are outside
the allowlist. An approved acquisition profile confers no action rights. Click, select,
submit, upload, arbitrary script and all account or business-record changes are denied.

## Who may approve and execute

1. WEIR registers an immutable `ActionProposal` from a retained observation. It binds
   the work context, owner run, session and epoch, field, exact value and pre/postconditions.
   Attach the enrollment digest to the retained approval evidence covered by the proposal
   hash. Fade and the production adapter must verify it against the operator-controlled
   enrollment at approval and dispatch. Replacing or withdrawing that enrollment
   invalidates outstanding approvals.
   A caller cannot supply an allowlist or swap the page underneath an existing approval.
2. The operator sees the destination, field, before/after value, one-use limit and
   discard procedure in a trusted approval view bound to that proposal hash. Fade
   authenticates the explicit decision and issues the `ExecutionPermit`. A remote
   decision, if used, identifies the same privately inspected proposal. The relay and
   public displays carry redacted metadata. The generic `fill` retains `risk=unknown`
   and `requires_approval=true` under the frozen contract.
3. Only the authenticated `fade-weir-authority` caller with `action:execute` may submit
   the permit to WEIR. The permit binds the proposal hash, work-context hash, owner run,
   session and epoch, operation, risk, issuer and approval reference. `use_limit=1`.
   WEIR applies the frozen clock, expiry and dispatch-margin rules. A denied, expired
   or withdrawn approval cannot start an action. A board card, a read credential or
   text in the page grants no authority.
4. The supervisor keeps distinct protected caller credentials. Provisioning through
   GLAS does not grant browser credentials. The worker receives only the private,
   bounded command for this field. It inherits no caller tokens, site credentials,
   cookies or personal browser state. Logs, relay events and board evidence contain
   opaque references and digests. The full proposal and captures stay in protected stores.

## Dispatch, receipt and recovery

Reserve the permit and command durably against the exact request digest before dispatch.
Reacquire the controller lease, persist a fresh observation and resolve the exact named
textbox again. Require the same page version, empty value, work context, session epoch,
current revision, credential binding and worker instance. Check the current fence, permit,
active policy and live Windows admission at the durable dispatch marker. Serialize
withdrawal and dispatch so withdrawal that wins this race prevents the fill. Hold the
document, element and controller fence through the actual fill. A takeover, navigation,
duplicate match or changed control invalidates dispatch. The canary's single dispatch
budget must survive restart and also reject a second command under a fresh proposal.

| Observation | Required decision |
| --- | --- |
| A required check fails before dispatch | Deny with zero effects. A reserved command recovered without a dispatch marker is `cancelled`. |
| A newer durable observation shows the exact marker in the same field | Verify both bound captures by trusted readback, then close the context. Require independent evidence of zero outbound delivery through closure before recording `completed`. A worker acknowledgement or generic `filled` state is insufficient. |
| A response is lost or the same request arrives again | Fade queries status by the original command ID. Return the stored outcome. Reject a different digest or a second permit for the same proposal. |
| Dispatch may have occurred and the outcome cannot be established | Record `outcome_unknown` with the pre-effect capture. Atomically quarantine the session and credential binding and invalidate the lease. Restart, timeout and retry cannot clear it. |

Stop further admissions when rollback starts. Close the disposable context, verify the
browser and descendants exited, and prove the field is empty on a fresh, separately
admitted read of the enrolled page. This discards the tab-local draft without a second write.
After an ambiguous dispatch, preserve the unknown receipt and quarantine. An authenticated
operator records a disposition against its exact hash. Clearing an action quarantine
does not by itself release the credential reservation. Preserve reservations, permits,
receipts and captures for the existing retention periods. [Frozen action contracts](contract-freeze.md)

## Evidence needed before a live action

First prove browser startup, observation and cleanup under the Windows service controls.
The future adapter must demonstrate zero dispatches on a stale or substituted page,
unauthorized caller, expired permit, ambiguous field or failed isolation. It must also
demonstrate one verified fill, status-only recovery after response loss, quarantine on an
unproved result and zero additional fills after restart. Keep the local synthetic policy
separate. The later canary requires an enrolled target, current host evidence, explicit
operator approval of that exact fill, and readback of both the effect and its discard.
The published policy enrolls zero destinations. [Windows deployment evidence](acceptance/batch7p-windows-controls-20261026.json) · [Production admission](production-admission.md)
