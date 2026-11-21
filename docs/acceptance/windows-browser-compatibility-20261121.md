# Windows Chromium compatibility trial, November 21, 2026

The Windows service could not start the Playwright driver. In Session 0 under
`NT SERVICE\WeirAdmission`, Windows returned error 5 (access denied) from
`asyncio.windows_utils.pipe` before Chromium launched. Browser compatibility
remains blocked. [Recorded host observations](windows-browser-compatibility-20261121.json)

The trial on `4070pc` used Playwright 1.61.0 and Chromium headless shell
149.0.7827.55, revision 1228. The candidate manifest covered 3,788 files.
Its SHA-256 was `bb7ec598059f826b77c038da89a3cd5651ab87d189c3dc61ba45472a97cb594f`.
The test page contained one read-only textbox named `WEIR proof` with value
`weir-observation`. It used no website, credentials or page scripts.

| Control on the same Windows host | Observation |
| --- | --- |
| Packaged browser in the operator's desktop session | Chromium read the exact field. Its process list included a browser and a renderer. |
| Desktop process worker with the 512 MiB, eight-process Job | Playwright launched Chromium, then reported `TargetClosedError` during the field-read stage. The trial produced no field match or browser cleanup measurement. |
| Desktop process worker with the Job and service AppContainer SID | Windows reported low integrity and zero capabilities. The Job readback showed eight processes, 536,870,912 bytes and kill-on-close. The Python Playwright driver failed while opening an asyncio pipe with Windows error 5. |
| SCM service in Session 0 with the same AppContainer and Job | Host admission passed. The driver again received Windows error 5 at pipe creation. The service recorded the denial at 05:46 UTC. |

The isolated worker and its Python test descendant were denied read access to both
caller credential files. Four independently reachable receivers recorded zero
TCP or UDP deliveries across IPv4 and IPv6. The independent host verifier also
confirmed that the worker and its test descendant exited on supervisor loss.
The run produced no service browser or renderer to inspect for isolation or cleanup.

At 05:46 UTC the trial restored the previous release, service command, configuration,
manual startup and stopped state. The original manifest SHA-256 was
`c8325972b151dee7849150d5275be3ea0b2ad1548fdad95ae97c6e3fecc2df2e`.
The action endpoint remained disabled.

The next compatibility test needs a browser driver that can start within the
existing Session 0 AppContainer. It must also keep the page alive within the Job
limits before browser-level credential, network and shutdown checks can proceed.
