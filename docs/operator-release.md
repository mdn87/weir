# Dashboard reports and marketplace comparisons from Lugos

Matt selected two jobs for the WEIR release on November 21, 2026. From his usual
Lugos seat he wants to work through a signed-in dashboard and get a report he can
reopen, and to find and compare marketplace listings against his own criteria.
The release is ready when he can complete both jobs on real sources, repeat them
and return to the original answers and evidence from run history.

The product, engineering and testing roundtable proposed a broader set of
workflows in session `weir-operator-release-20261121`. Matt's selections set the
release criteria below. General public research and approved website changes
remain on the longer-term roadmap.

## Work through a signed-in dashboard

The operator names a dashboard, a question and the scope, such as a reporting
period. Lugos uses the authorized account, reads the relevant views and returns a
private report. Each finding identifies its period, observation time and source
view. The report shows missing or inaccessible data. An example request is
“Summarize what changed since last week and show me the exceptions.” The actual
dashboard, account and report question still need to be selected.

Accept this job on a real dashboard. Exercise the navigation or filtering needed
to answer the chosen question. Compare reported values against known account
values. Run it again for a different period, then reopen the first report from
history after a restart without visiting the source again. Enforce the reader's
current access when opening private evidence. An expired login stops acquisition,
and a different unauthorized context cannot read the stored report. Keep private
page content and credentials out of shared caches, logs and public projections.

## Find and compare marketplace listings

The operator describes the item and criteria such as condition, price including
shipping, and location. Lugos returns comparable listings with the criteria
applied, the reasons each listing qualifies, the price components, the capture
time and links to the original listing and retained evidence. Unknown shipping
stays unknown. A search with zero matches and an unavailable source produce
different answers.

Use the existing eBay connector and Lode comparison logic for the first live
marketplace. Run a real search, change a criterion, and show which candidates
enter or leave the comparison. After a restart, reopen the first comparison and
its original captures even if a listing changed or disappeared. A missing or
altered capture must be visibly identified. The operator supplies the criteria
at request time.

## Delivery and ownership

| Delivery | Who builds it and what unlocks it |
| --- | --- |
| Compare marketplace listings and reopen results in Lugos | The task router and run profile accept the operator's criteria. Autowork provides trusted assignment context to the Lugos MCP adapter. WEIR fetches and retains the evidence, Lode compares listings, and Mission Control exposes the result in run history. This is the next Dias chip. |
| Turn signed-in dashboards into reopenable reports | WEIR handles scoped acquisition, GLAS provides credential custody, and the seat handles the question, private report and access checks. Build report assembly and access checks against a fixture while the host is being qualified. A real approved dashboard and account are required for live acceptance. |
| Qualify the service browser | The WEIR host owner must show that the packaged browser reads a fixed offline field under its intended service identity with the browser sandbox enabled. An independent observer verifies resource limits, credential isolation, denied network delivery, whole-tree cleanup and restart in deny-only mode. This evidence qualifies the browser used for the live dashboard. |

Both deliveries use the same request and history experience. Return a run ID and a
report to the originating seat. A citation opens the exact capture for that run,
even when a later run used newer data. Use Sulis to index provenance and AETA
to hand off sources where a workflow needs them. Mission Control's shared event stream shows
redacted metadata. Private reports open through a context-authorized view. The
roundtable proposed Claude Code through Lugos MCP as the first interactive seat
and an Autowork campaign as a second entry point. The live release check starts
where Matt normally requests work.

## What the team can build on

- Lode already consumed 50 live eBay listings with WEIR provenance. The public
  broker also fetched the ripgrep and fd project records during planning. In a
  fresh process, both captures reopened and passed their content-hash and source
  checks. A complete comparison from the operator's seat still needs live proof.
  [Marketplace design](marketplace-slice.md)
- Autowork supplies trusted assignment context to the guarded MCP adapter. Mission
  Control and the HUD can show redacted action metadata. Complete report history
  and authorized evidence browsing still need delivery.
  [Dispatch contract](dispatch-context-provider.md) · [Live projection](acceptance/batch5-live-projection-20260829.md)
- Signed-in observation works against a local fixture. On Windows the service's
  Node driver exits before Playwright connects, and desktop AppContainer Chromium
  exits before a field read. Reinstalling the same package would repeat a tested
  configuration. If Windows needs broader privileges, an inventoried Linux
  candidate can undergo the same acceptance test after a deployment decision.
  [Windows measurements](acceptance/windows-browser-driver-20261121.md)

## Release evidence and later actions

Record both real jobs with their run IDs, environment, protected evidence references
and observed results. Each job may ship as soon as its own acceptance passes. Local
fixtures support development. The two live operator workflows establish the release.

Saving a listing back to a website is a possible later feature. Its Dias work
covers a reviewed action definition, target enrollment, per-change approval and
independent readback. The existing unsaved-field canary qualifies only that
browser operation. Both selected jobs can finish with read access and report
storage inside Lugos. The production action allowlist is empty.
[First effect policy](production-effect-policy.md)
