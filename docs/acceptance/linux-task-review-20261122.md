# Signed-in task board report on lugos-host

In Mission Control, **Lugos → Web reports → Tasks in review** reads the Review column of the operator's current workspace. Each result includes its observation time and the original page under **Source 1**. [Open Lugos](http://10.0.1.33:3230/lugos)

## Linux service browser

WEIR 0.6.0 read a randomized page field through the dedicated systemd service. The kernel identified the worker that connected to the Unix socket. The host checked its Chromium processes, control group and network namespace before releasing the page. The renderer could not open an IPv4 or IPv6 network connection or see the operator's home and service state. Only the host bridge received the single-use read grant.

The final host check ran at 06:51 UTC on November 22. The service had a 512 MiB memory limit and a 128-task limit. The measured peak was 159 MiB with 68 observed threads. Closing the client connection reaped all nine processes. Stopping a second worker also reaped all nine. The published first qualification records a separate run of the same checks. [First host qualification](linux-review-browser-20261122.json)

## Signed-in acceptance

The test used an operator and a viewer in a disposable Mission Control workspace. It exercised the ordinary sign-in page, report form, saved history and source link. The test accounts and their task titles belong to that workspace.

| Check | Observed result |
| --- | --- |
| Empty Review column | The report showed zero tasks. |
| Two review tasks | The form showed tasks 41 and 43. The other workspace's review task, a completed task and a task in Quality Review were excluded. |
| Source evidence | The saved HTML matched the signed-in Review page byte for byte. The report and source had the same observation time. |
| Account isolation | Signed-out requests returned 401. The viewer received 403 when starting a report and 404 when opening the operator's report or source. |
| Restart and source outage | After signing in again, the operator reopened the original report and source with the reader offline. A new report returned a source error. |

## Installed release

At 07:03 UTC the live Mission Control service switched to release `078ddd2fce26` and the report bridge switched to WEIR 0.6.0. The bundle was built from `8e1f35976f85`. The only source difference in the merged revision was the SQLite driver used in one test. The live service served the login page, denied signed-out reads, rejected an invalid grant without creating a report, and answered an existing Dias report request. The migration inventory and running operator API and remote relay processes were unchanged.

At 07:04 UTC the installed Mission Control bundle, installed report bridge executable and live sandboxed Chromium service passed the signed-in checks above with an isolated database and report history. The run was `run-cd77b5c30a3144878bcbd72d2a949533`. The measurement record includes the binary package hash, source hash and saved report ID. [Installed measurements](linux-task-review-20261122.json)
