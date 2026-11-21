# Lugos web report acceptance

On November 21, 2026, the WEIR project board and eBay Browse API supplied live data to the Mission Control release installed on the inventoried Lugos host. Mission Control uses approved operator accounts to run these reports and checks the current user, tenant and workspace on every history or evidence request. The acceptance used disposable accounts and an isolated database on that host. Matt's personal production account was outside the automated test.

## Operator results

| Source | Request | Run | Saved report |
| --- | --- | --- | --- |
| Dias | Since August 1 | `run-44bb103f04de4fee8b0900b11b435c85` | `report-5c7eff42535d9b4c55eb810895ec151dea60c6f25fec1c50625149e6eb085b35` |
| Dias | Since November 21 | `run-d1f90137475643578ff9e64f7c0bab88` | `report-a03559011c0f39e881c63131a0052ce4228a990559689b68abc2a2ad280d6372` |
| eBay | US items, $65 maximum | `run-b5dfde9470dc4c50841be5f880f93da0` | `report-25338375d93ed1c582b96fd526f18ea76998ba5c9fb8c8fed9b059cea88d8bbb` |
| eBay | US items, $100 maximum | `run-243626e57e994d7a8de28f74523ad592` | `report-7347acd26590864849ebf252648c62a7610810d7a8cab416fb5821840a383b29` |

- The Dias board showed 19 chips. The stage counts matched the captured board and the designated next chip matched the separately captured project status. Filtering evidence from August 1 returned 73 events. Filtering from November 21 returned 30. The report exposed both original views with their observation times.
- Both eBay searches returned 50 listings for **Keychron C2 Pro**. A US item-location filter and a $65 limit including shipping yielded 17 matches, 11 unknowns and 22 exclusions. Raising the limit to $100 yielded 32 matches, 17 unknowns and 1 exclusion. Comparing the actual item IDs showed 17 entries and 2 departures. Prices exclude tax and describe the observation time.
- A different signed-in viewer had empty history and received 404 for the first operator's report and source. A signed-out client received 401. A logged-in viewer received 403 for a new acquisition. An unenrolled Dias source produced a source error.
- After a Mission Control restart, the first operator signed in again. All four reports reopened with their original hashes and data after disabling both sources in the reader. A separate browser test used the installed standalone build. It signed in, switched to Full mode, submitted both forms, displayed 50 listing rows, reopened a saved report and inspected both Dias citations.
- Autowork compiled a request for the live WEIR board, bound the project and two views to assignment `assignment-8da124bce2917e6269f5bebe`, and returned run `weir-dias-8e6ce4d2f8be45cfafe3739acd5c5e70`. The campaign CLI reopened the same report in a fresh process.

## Installed service

WEIR 0.5.1 records the archive owner and source observation times, checks citation fields against the verified capture, and preserves existing reports. The installed worker reopened the original November 21 eBay report and its capture without the eBay profile. Regression tests cover copied reports, missing prices, mismatched currency and shipping alone exceeding the budget.

Mission Control revision `0ccd6983e3796ec829413d3d0e1c84741d16de94` serves the Lugos panel. The installed UI returned 200 for login and 401 for an unauthenticated report request. The production systemd worker fetched both sources and reopened both reports through its owner-only Unix socket. The operator API and remote relay retained their original processes. The application schema matched the installed database before activation. Website writes remain disabled.

The UI release uses a dedicated working-directory override. For rollback, move the WEIR override aside, reload systemd and restart only Mission Control. The earlier UI release, OGMI paths and shared producer release remain available. The report worker and publisher use the scoped host definitions. [Host units](../../config/lugos-host)

The enrolled Dias display publishes board information without a website login. Other authenticated websites still require a qualified service browser. [Windows driver measurements](windows-browser-driver-20261121.md)
