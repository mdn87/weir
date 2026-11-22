# Windows browser loader on 4070pc

On November 22, a native comparison identified `USER32.dll` as a failing direct dependency of the packaged Node driver. Inside the Windows service sandbox, a small program linked only to `KERNEL32.dll` and `USER32.dll` exited with the same `0xc0000142` as Node. On the operator desktop it reached its entry point and returned the expected 37. Its code takes the address of a USER32 import without calling a window or desktop function.

## Native observations

The desktop and service trials used the same Node v22.23.5, Playwright 1.65.2, Chromium 159.0.8154.6 and two x64 control executables. The first trial reused the commissioned browser runtime. Only the diagnostic Python module and the two control executables differed. The dynamic probe imports only KERNEL32 and uses the System32 loader search flag. Each library ran in a fresh child. The service used the admitted worker under `NT SERVICE\WeirAdmission` in Session 0.

| Test | Desktop | Service sandbox |
| --- | --- | --- |
| Known system libraries, including a fresh load of WS2_32 | Loaded | Loaded |
| Intentionally missing library | Error 126 | Error 126 |
| GDI32, USER32, OLE32 and SHELL32 | Loaded | Error 1114 for each library |
| Static USER32 control | Reached entry, returned 37 | Native initialization failed with `0xc0000142` |
| Packaged Node and browser | Chromium read the fixed field | Node exited with `0xc0000142` before its version check or the Playwright handshake completed |

Windows reports error 1114 when a library initialization routine fails. The process-level status `0xc0000142` denotes DLL initialization failure during startup. [Win32 error codes](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--1000-1299-) · [NTSTATUS values](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)

The Node import table contains eleven direct dependencies, including USER32, OLE32 and SHELL32. USER32 in turn imports GDI32 and `win32u.dll`. The service successfully loaded `win32u.dll`, KERNEL32, WS2_32, DBGHELP, CRYPT32, ADVAPI32, IPHLPAPI, USERENV and WINMM. The tests identify a dependency sufficient to explain the driver exit. They leave the failing internal Windows call unresolved. [Earlier driver observations](windows-browser-driver-20261121.md) · [Windows library loading](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw)

## Browser qualification

The final release package reproduced the same result at 07:46 UTC. In each of the two service trials, the installer passed all eight deployment checks, four reachable network controls observed zero deliveries from the worker, and the original service configuration and runtime manifest were restored. An external observer sampled the final supervisor and worker in Session 0. Windows reported the Win32k system-call disable flag off for both. The supervisor had loaded USER32, GDI32 and win32u. The sampled worker had loaded none of the three. These observations leave the failed internal initialization call unresolved. [Both service trials and desktop control](windows-browser-loader-20261122.json)

The Windows service still needs a Chromium field read, independent inspection of the live browser and renderer, and proof that stopping the worker reaps both. The desktop field read and the cleanup of the admission worker and its test child establish separate facts. Changing desktop access requires review of the new isolation boundary. Windows creates a noninteractive window station for a service account. [Windows service desktop model](https://learn.microsoft.com/en-us/windows/win32/winstation/window-station-and-desktop-creation)
