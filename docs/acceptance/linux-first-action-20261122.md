# Linux rehearsal of one unsaved website action

On November 22 at 08:07 UTC, WEIR filled one empty textbox in isolated Chromium on `lugos-host`. Fade issued a single-use permit for a fixed scriptless fixture. The marker existed only in that browser. The production action allowlist remains empty. [Native run record](linux-first-action-20261122.json)

| Check | Host observation |
| --- | --- |
| Exact effect | The dispatcher called the fill once. A separate, read-only CDP session read the empty value and then `WEIR-CANARY` from the same frame, document loader and DOM node. |
| Uncertain delivery | Dropping the successful HTTP response triggered a status lookup. An identical replay returned the original receipt and a conflicting replay returned HTTP 409. A fresh WEIR process reopened the stores and returned the same receipt for the original permit after the browser had exited. |
| Ordinary service | An authenticated caller presented that exact fixture permit to the ordinary service. It denied the action because it had no production admission. |
| Host isolation | The driver, Chromium and renderers ran in the dedicated service cgroup. Renderers had a nested PID namespace and seccomp filtering. The unit had a 512 MiB memory limit and a 128-task limit. Each of the two services had eight observed processes. |
| Network | From inside each service, the startup probe could open no IPv4 or IPv6 TCP or UDP socket and could reach neither the pathname nor abstract Unix receiver. All six host receivers passed positive controls before and after the run and observed zero unexpected deliveries. |
| Discard | The host verified the first cgroup and its observed processes had disappeared. A second service with the same effective policy opened the fixture in a fresh browser and read an empty field. Its process tree also exited. |

The installed runtime was WEIR 0.6.0, Playwright 1.61.0 and Chromium 149.0.7827.55. The fixture authority used Fade source `215dd80bcbe8`, temporary caller credentials and private run stores. The host controller retained both the observation session and the fixed fill operation. A live adapter still needs independently authenticated roles, owner enrollment, a signed operator decision and a deployment-wide grant.

## Policy review

The independent Claude Opus review of the Linux policy completed in Autowork run `20261122-075227-cross-review`. The reviewed packet digest was `4e712d971be05b4b7eca0d01c50ad4a84e4c02a306d28d2769e0305757ea3e1d`. The resulting policy records these decisions. [Linux action policy](../linux-first-action-policy.md)

- Separate the rehearsal issuer, audience and stores from production. A fresh read verifies discard. Exact readback from the pinned live document verifies the fill.
- Keep the controller's observer distinct from the fixed effect operation. Live qualification must exercise cross-role denial and continuous process tracking.
- Deny network socket families and io_uring, close unrelated inherited descriptors and disable service restart. Inspect Chromium's native sandbox and bracket the run with working Internet and Unix receivers.
- Reserve and sync a single grant across hosts before dispatch. Preserve cancellation before the dispatch marker and quarantine after an ambiguous dispatch. Require a rollback fence and a rehearsal of the actual production adapter before enabling it.

## Reproduce on the inventoried host

Use a root-owned copy of these rehearsal scripts, the sealed WEIR runtime above and the trusted Fade source. Keep the driver launcher's executable bit. Run from the rehearsal checkout with a new private output directory. The trusted host inspector needs permission to inspect service namespaces and launch transient units.

```sh
/srv/lugos/runtimes/weir-operator-reports/0.6.0/bin/python -E -s \
  scripts/verify_linux_first_action.py run /var/tmp/weir-fill-qualification-new \
  --fade-source /path/to/trusted/fade-checkout
```

The command prints a redacted JSON record after both service trees exit. The private output directory contains the test ledger and captures. [Qualification entry point](../../scripts/verify_linux_first_action.py)
