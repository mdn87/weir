/* Native control for the fixed browser-service diagnostic. Build with /MT. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wchar.h>

#ifdef WEIR_STATIC_USER32
/* Referencing the import makes the native loader initialize USER32 before
   entry. The control never calls a window or desktop function. */
int wmain(void)
{
    int (WINAPI *volatile user32_import)(int) = GetSystemMetrics;
    return user32_import ? 37 : ERROR_INVALID_DATA;
}
#else
int wmain(int argc, wchar_t **argv)
{
    static const wchar_t *const modules[] = {
        L"kernel32.dll", L"weir-intentionally-absent.dll", L"win32u.dll",
        L"gdi32.dll", L"user32.dll", L"dbghelp.dll", L"ws2_32.dll",
        L"crypt32.dll", L"advapi32.dll", L"ole32.dll", L"iphlpapi.dll",
        L"shell32.dll", L"userenv.dll", L"winmm.dll"
    };
    if (argc != 2) return ERROR_INVALID_PARAMETER;
    for (size_t index = 0; index < ARRAYSIZE(modules); ++index) {
        if (wcscmp(argv[1], modules[index]) != 0) continue;
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
        HMODULE module = LoadLibraryExW(modules[index], NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!module) return (int)GetLastError();
        FreeLibrary(module);
        return ERROR_SUCCESS;
    }
    return ERROR_INVALID_PARAMETER;
}
#endif
