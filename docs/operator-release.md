# Finish web work from a Lugos seat

The release is ready when Matt can ask Lugos to research a question, inspect the
sources behind the answer and reopen the result days later. For work involving an account, he can also
inspect private information, decide on a specific change and see what actually
happened on the site. He should never need to choose a browser engine, start a
service or find a capture on disk to finish one of these jobs.

The product, engineering and test roundtable reached agreement on November 21,
2026. Its session ID is `weir-operator-release-20261121`. All four workflows are
part of release acceptance. The example jobs, first seat and live target are proposed
defaults. The approved retention period for each data class governs reopening.

## What the operator can do

| Job | What counts as delivered |
| --- | --- |
| Research a question across public sources | Ask for a comparison or a change since a previous run. Get a report with citations to individual captures, observation times and any gaps. Rerun with fresh observations and see what changed. |
| Compare marketplace listings | Give an item and criteria such as condition and delivered price. Get comparable rows with source links and capture times. Missing shipping stays unknown. Zero matches and a failed source give different answers. |
| Check a signed-in page | Ask for the state of an item in an authorized account. Get a private report with the observed state and time. Return to that report after signing out or restarting Lugos, subject to the reader's current access. |
| Make a useful change on a site | Inspect a proposed change, approve or decline it, and reopen its outcome. On approval, verify the saved state through a fresh read of the destination. On decline, keep the research and record the decision. |

A candidate end-to-end job is to compare listings, inspect an existing private
shortlist, and choose whether to save a listing worth following. A second public
job compares upstream release notes and shows what changed since the previous
report. These examples exercise structured data and prose. Matt still chooses the
actual site, account and permitted action for a live private workflow.

Start with Claude Code through the Lugos MCP adapter and an Autowork campaign as
the second way to request the same jobs. Both need the dispatcher's trusted
assignment context. Add run history to Mission Control. Return a run ID,
report and source-by-source outcome to the originating seat.

## What works today

Lode consumed 50 live eBay listings with WEIR provenance. The public broker can
route reads, attach observation times and retain content by hash. During planning
on November 21, WEIR's CLI fetched the public ripgrep and fd repository records.
A separate process reopened both stored captures and verified their hashes and
source identities. These checks establish acquisition and retention. Operator
acceptance still requires a request from a normal seat and retrieval through its
history. [Marketplace design and acceptance](marketplace-slice.md)

Autowork already supplies trusted assignment context to the guarded Lugos MCP
adapter. Mission Control and the HUD already show redacted action metadata.
Private evidence browsing and complete job views still need delivery.
[Dispatch contract](dispatch-context-provider.md) · [Live projection](acceptance/batch5-live-projection-20260829.md)

## Delivery order and ownership

| Dias work | Responsible components and acceptance |
| --- | --- |
| Deliver public research and comparisons from Lugos | The task router and run profile select read capabilities. Autowork binds the request to an assignment. WEIR supplies evidence, Lode handles listing comparison, and Mission Control exposes reports and run history. Sulis indexes provenance and AETA consumes source references where the job requires them. Both public jobs must work from the seat end to end. This work can ship now. |
| Prove browser isolation in the Windows service | The WEIR host owner runs the packaged browser under the intended service identity. It must read the known offline field with its sandbox enabled. An independent observer verifies resource limits, credential isolation, denied network delivery, whole-tree cleanup and restart in deny-only mode. The qualified host unlocks browser work. |
| Deliver private account reports | WEIR owns scoped observation and protected capture retention. The seat owns account selection, access checks and reopening the report. Test with fixtures during host qualification. Accept a real account-visible result only after the chosen host and account are authorized. Expired or mismatched credentials must stop the read. |
| Review the policy for a saved website change | Once Matt names the destination and action, the site and deployment owners establish the exact account, old and proposed state, allowed delivery, independent readback and undo. Review this work alongside public delivery and host qualification. Its output is a reviewed action definition that can be enrolled separately. |
| Bind production actions to reviewed permits and verify the unsaved canary | WEIR binds the operation to current state, Fade issues the single-use permit and Mission Control presents the decision. The existing canary checks the approved marker, replay denial and rollback. This is a prerequisite for the first live write on the selected Windows design. |
| Deliver a useful approved website change | Fade and WEIR enforce the reviewed definition on the enrolled target. Mission Control shows the exact change and retains the decision, receipt and before/after references. Accept by reopening an independently verified saved change. |

Public research, report history and comparison can proceed while the browser
team qualifies the host and rehearses private workflows with fixtures. On Windows
the service's Node driver exits before Playwright connects. In the desktop
AppContainer Chromium also exits before reading the field. Reinstalling Playwright
would repeat a package combination already tested. If Windows needs broader
privileges, the deployment owner can select an inventoried Linux candidate and
apply the same acceptance test there. Switching hosts requires its own reviewed
deployment decision and live checks. The existing Windows
policy covers one unsaved marker. A saved change needs its own reviewed policy,
explicit target enrollment and per-change approval. The live allowlist is empty.
[Windows measurements](acceptance/windows-browser-driver-20261121.md) · [First effect policy](production-effect-policy.md)

## Release acceptance

- Exercise both public jobs across two ordinary seat types. Run each job three
  times, varying the criteria or sources and restarting before the third run.
  Show a denied request and its reason in the seat. Open the first report from history
  after a restart and with its source offline. Each citation must open the capture
  used for that answer. Show a missing or damaged capture as an integrity error.
- Run an authorized signed-in job and compare its result with a known account
  value. Reopen it from the original authorized seat. A different unauthorized
  context must be denied. Keep private page content out of shared caches and
  telemetry, including the public HUD event stream.
- From a real job, decline one proposed change and verify the destination stayed
  the same. Approve a fresh proposal and confirm the saved result in a fresh
  session. Reopen its receipt from history. A repeat delivery or restart must
  produce at most one change. An uncertain outcome must be visible and stop
  further writes until reconciled. Reversal requires its own authority.
- Record the environment, run IDs, protected evidence references and observed
  results in the release evidence. Mark each workflow shipped on its live seat
  evidence. The overall release requires all four jobs.
