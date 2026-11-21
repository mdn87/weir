# Windows browser driver on 4070pc

The packaged browser read the fixed offline field on the Windows desktop under
the 512 MiB, eight-process Job. The same release failed under the
`NT SERVICE\WeirAdmission` account in Session 0. Windows reported
`0xc0000142` (`STATUS_DLL_INIT_FAILED`) for the Node process that the admitted
worker started. Playwright never completed its service handshake. [Windows status definitions](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)

| Test | Observation |
| --- | --- |
| Python pipes inside the desktop AppContainer | Windows denied the standard asyncio pipe with error 5. The container-local pipe opened and a child process exchanged data through it. |
| Node and Playwright in that AppContainer | Loading the sealed, link-free package directly completed the handshake. Stock Node stalled when spawning a child with piped standard I/O. The project build with the upstream libuv fix passed that check and started Chromium. |
| Chromium with only the Job applied | Chromium 149 lost its GPU process during page creation. Chromium 159 read the field with its own sandbox enabled. Job accounting recorded six processes and 220,680,192 peak committed bytes on the successful run. |
| Chromium inside the desktop AppContainer and Job | The headless shell printed its version. Browser startup exited with `0x80000003` before a field read. The full Chrome for Testing executable also exited with that code in the AppContainer. |
| Independently commissioned service in Session 0 | The worker and its Python test child were denied access to both caller credentials. Four reachable TCP/UDP receivers across IPv4 and IPv6 received zero packets. The Node process exited before Chromium started. |

The operator correlated the Session 0 process start with the worker PID in the
fresh service record, then matched the Node PID to its Windows exit event. An
independent control process returned the expected exit code 37 through the same
observer. The service diagnostic restored the previous manifest, configuration,
manual start mode and stopped state. No production action endpoint was enabled.

On a second observation of the commissioned release, Windows returned the same
exit code. Event 7 from the Windows user-mode loader recorded a fatal error
initializing `node.exe`. It did not identify the individual DLL. Both Node and
Chromium import `USER32.dll` and other Windows libraries. The next diagnostic
should identify which import fails to initialize under this service account.
Any browser design that needs additional desktop access requires a policy review.

The service field read, browser and renderer isolation, and cleanup of an
actual browser process tree still require a working service launch. The host
commissioning run separately verified cleanup of its admission worker and Python
descendant. It used the second automatic restart in the current SCM recovery window.

The tested release used a local Node v22.23.5 build with one upstream libuv
change and Playwright 1.65.2 with Chromium 159.0.8154.6. The earlier stock
driver trial and the build instructions document how to reproduce the comparison.
[Upstream libuv fix](https://github.com/libuv/libuv/pull/5181) · [Earlier service trial](windows-browser-compatibility-20261121.md) · [Windows build procedure](../windows-deployment.md#chromium-compatibility-diagnostic) · [Recorded measurements](windows-browser-driver-20261121.json)
