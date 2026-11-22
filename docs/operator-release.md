# Run and reopen web reports in Lugos

Open **Lugos → Web reports** in Mission Control. In Simple mode, choose **Switch to Full** when prompted. Sign in with an approved operator or admin account to run a report. The saved history belongs to the signed-in user, workspace and tenant. A viewer can reopen their own earlier reports. [Mission Control on the Lugos network](http://10.0.1.33:3230/lugos)

## Work through a Dias project

Choose **Dias project work**, enter `weir`, and set **Activity since**. Run the report. **Work you can do now** lists active or ready chips whose prerequisites are complete. The project's selected next chip comes first when it qualifies. **Waiting** identifies unfinished dependencies and includes the latest recorded note for blocked chips. **Later** contains work that still needs planning. Completing a chip can clear prerequisites for the work listed under **Unlocks**.

Use the chip's stated outcome to decide what to build. Mark it active on the project board, carry the work through its acceptance check, and attach that evidence when marking it done. Run the report again and select the previous report under **Compare with** to see which stages changed. **Source 1** opens the captured board. **Source 2** opens the status Dias published alongside it.

The first enrolled project on the installed service is WEIR. A separate host timer reads those two Dias display views on the Windows workstation about every 45 seconds. The report service accepts snapshots up to two minutes old and records the original observation time. Dias publishes these views without an upstream website login. Mission Control protects the report and its sources.

## Read the signed-in task board

Choose **Tasks in review** in **Lugos → Web reports**. The report lists the tasks in
the **Review** column of your current Mission Control workspace, in task ID order.
The **Review** heading on the task board opens the same read-only page. If the list
exceeds 200 tasks, the page reports the full count and displays the first 200.
**Source 1** reopens the exact document that the browser read.

Mission Control uses the operator's current browser session to issue one short-lived
read for this column. It checks the session, owner and workspace again when WEIR
redeems the read. The isolated Linux browser requests the server-rendered page with
JavaScript disabled. Only the host bridge contacts Mission Control. The saved report
contains task IDs, titles, observation time and source evidence.

## Compare marketplace listings

Choose **Marketplace comparison** and enter the item. Enter a maximum price including shipping, currency, item country or condition as needed. A listing qualifies when its recorded fields meet the criteria. Missing shipping or location remains visible. The displayed total combines item price and known shipping before tax. A search returning zero rows can still create a report. A source failure returns an error.

Run the same search with a different budget and select the earlier report under **Compare with**. The comparison shows the listings that entered and left. The live market can change between searches. **Saved reports** preserves the original listings, prices and source capture. Opening a report verifies the saved manifest and evidence hashes before displaying it.

## Command line and campaigns

The WEIR command line runs under the current operating-system account. For example.

```sh
weir report dias weir --since 2026-11-21
weir report marketplace "Keychron C2 Pro" --country US --max-delivered 65
weir report list
weir report open REPORT_ID
weir report source REPORT_ID 1
```

The eBay job uses the enrolled app profile. On a host with GLAS, the existing scoped launcher can supply it. On the deployed Lugos host the one-request worker resolves only Lode's eBay app bindings for a marketplace read. Mission Control connects to a user-only Unix socket. Its service has no access to the operator's home directory. The display publisher runs separately with a fixed project and two fixed reads. The systemd service and timer definitions are in [the host configuration](../config/lugos-host).

Autowork's trusted host can call `prepare_operator_report` with a compiled assignment and a typed web evidence plan. Its marketplace scope specifies an eBay query. Its Dias scope specifies the board and status for one project with full evidence retention. The host enables `LUGOS_WEB_REPORTS_ENABLED`. The campaign command can reopen that assignment's report in a later process.

```sh
autowork campaign web-report --config CONFIG --run-id RUN open --args '{"report_id":"REPORT_ID"}'
```

Local command-line, campaign and Mission Control histories have different owners. Each reader can reopen evidence in their own history. Matt's release selection and the team's planning discussion are recorded in the WEIR Dias board and roundtable `weir-operator-release-20261121`.

## Wider website capability

The release check exercised both forms, inspected both sources, compared two searches and reopened four reports after a restart. [Installed release evidence](acceptance/lugos-operator-reports-20261121.md)

The Linux browser supports the enrolled Mission Control Review column. Other websites need an enrolled read and account binding for their own dashboard. The Windows driver still exits before Playwright connects. Production writes require a reviewed permit and independent readback. [Windows browser qualification](acceptance/windows-browser-driver-20261121.md) · [Production effect policy](production-effect-policy.md)
