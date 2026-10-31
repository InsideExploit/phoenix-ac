#include "service.hpp"
#include "shared.hpp"
#include "pxenc.hpp"
#include "lazy_importer.hpp"
#include "brkida.hpp"
#include "../dbg.hpp"
#include "agent_stubs.hpp"
#include <stdio.h>

bool
EnableLoadDriverPrivilege(
)
{
    VIRTUALIZER_START;
    BRKIDA;
    HANDLE token = NULL;
    if (!LI_ADVAPI(OpenProcessToken)(LI_KERNEL(GetCurrentProcess)(),
                                     TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;

    LUID luid = { 0 };
    if (!LI_ADVAPI(LookupPrivilegeValueW)(NULL, pxenc(L"SeLoadDriverPrivilege"), &luid)) {
        LI_KERNEL(CloseHandle)(token);
        return false;
    }

    TOKEN_PRIVILEGES tp = { 0 };
    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Luid       = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL  ok  = LI_ADVAPI(AdjustTokenPrivileges)(token, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD err = LI_KERNEL(GetLastError)();
    LI_KERNEL(CloseHandle)(token);
    VIRTUALIZER_END;
    return ok && err == ERROR_SUCCESS;
}

bool
LocateDriverBinary(
    wchar_t Out[MAX_PATH]
)
{
    VIRTUALIZER_START;
    BRKIDA;
    wchar_t exe[MAX_PATH] = { 0 };
    if (!LI_KERNEL(GetModuleFileNameW)(NULL, exe, MAX_PATH)) return false;

    wchar_t* slash = wcsrchr(exe, L'\\');
    if (!slash) return false;
    *(slash + 1) = 0;

    auto binName = PX_WS(KG_BINARY_NAME);
    if (wcslen(exe) + wcslen(binName) + 1 >= MAX_PATH) return false;

    wcscpy_s(Out, MAX_PATH, exe);
    wcscat_s(Out, MAX_PATH, binName);
    VIRTUALIZER_END;

    return LI_KERNEL(GetFileAttributesW)(Out) != INVALID_FILE_ATTRIBUTES;
}

bool
DriverIsPresent(
)
{
    VIRTUALIZER_START;
    BRKIDA;
    SC_HANDLE scm = LI_ADVAPI(OpenSCManagerW)(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return false;

    SC_HANDLE svc = LI_ADVAPI(OpenServiceW)(scm, pxenc(KG_SERVICE_NAME), SERVICE_QUERY_STATUS);
    bool present = svc != NULL;
    if (svc) LI_ADVAPI(CloseServiceHandle)(svc);
    LI_ADVAPI(CloseServiceHandle)(scm);
    VIRTUALIZER_END;
    return present;
}

bool
DriverEnsureInstalled(
    const wchar_t* BinaryPath
)
{
    BRKIDA;
    VIRTUALIZER_START;
    SC_HANDLE scm = LI_ADVAPI(OpenSCManagerW)(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) return false;

    SC_HANDLE svc = LI_ADVAPI(OpenServiceW)(scm, pxenc(KG_SERVICE_NAME), SERVICE_ALL_ACCESS);
    if (svc) {
        DWORD need = 0;
        LI_ADVAPI(QueryServiceConfigW)(svc, NULL, 0, &need);

        QUERY_SERVICE_CONFIGW* cfg = (QUERY_SERVICE_CONFIGW*)LI_KERNEL(LocalAlloc)(LPTR, need);
        bool matches = false;
        if (cfg && LI_ADVAPI(QueryServiceConfigW)(svc, cfg, need, &need))
            matches = _wcsicmp(cfg->lpBinaryPathName, BinaryPath) == 0;
        if (cfg) LI_KERNEL(LocalFree)(cfg);

        if (!matches)
            LI_ADVAPI(ChangeServiceConfigW)(svc,
                                            SERVICE_KERNEL_DRIVER,
                                            SERVICE_DEMAND_START,
                                            SERVICE_ERROR_NORMAL,
                                            BinaryPath,
                                            NULL, NULL, NULL, NULL, NULL,
                                            pxenc(KG_DISPLAY_NAME));

        LI_ADVAPI(CloseServiceHandle)(svc);
        LI_ADVAPI(CloseServiceHandle)(scm);
        return true;
    }

    svc = LI_ADVAPI(CreateServiceW)(scm,
                                    pxenc(KG_SERVICE_NAME),
                                    pxenc(KG_DISPLAY_NAME),
                                    SERVICE_ALL_ACCESS,
                                    SERVICE_KERNEL_DRIVER,
                                    SERVICE_DEMAND_START,
                                    SERVICE_ERROR_NORMAL,
                                    BinaryPath,
                                    NULL, NULL, NULL, NULL, NULL);
    bool ok = svc != NULL;
    if (svc) LI_ADVAPI(CloseServiceHandle)(svc);
    LI_ADVAPI(CloseServiceHandle)(scm);
    VIRTUALIZER_END;
    return ok;
}

bool
DriverStart(
)
{
    VIRTUALIZER_START;
    BRKIDA;
    SC_HANDLE scm = LI_ADVAPI(OpenSCManagerW)(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return false;

    SC_HANDLE svc = LI_ADVAPI(OpenServiceW)(scm, pxenc(KG_SERVICE_NAME),
                                            SERVICE_START | SERVICE_QUERY_STATUS);
    if (!svc) { LI_ADVAPI(CloseServiceHandle)(scm); return false; }

    BOOL  ok       = LI_ADVAPI(StartServiceW)(svc, 0, NULL);
    DWORD startErr = ok ? 0 : LI_KERNEL(GetLastError)();
    if (!ok && startErr == ERROR_SERVICE_ALREADY_RUNNING) ok = TRUE;

    SERVICE_STATUS st = { 0 };
    if (ok) {
        for (int i = 0; i < 50; ++i) {
            if (!LI_ADVAPI(QueryServiceStatus)(svc, &st)) { ok = FALSE; break; }
            if (st.dwCurrentState == SERVICE_RUNNING)  break;
            if (st.dwCurrentState == SERVICE_STOPPED)  { ok = FALSE; break; }
            LI_KERNEL(Sleep)(100);
        }

        if (st.dwCurrentState != SERVICE_RUNNING) ok = FALSE;
    }

    if (!ok) {
        LI_ADVAPI(QueryServiceStatus)(svc, &st);
        KGDBG(L"[!] DriverStart: start_err=%lu state=%lu win32_exit=%lu svc_exit=0x%08lX checkpoint=%lu\n",
              startErr,
              st.dwCurrentState,
              st.dwWin32ExitCode,
              st.dwServiceSpecificExitCode,
              st.dwCheckPoint);
    }

    LI_ADVAPI(CloseServiceHandle)(svc);
    LI_ADVAPI(CloseServiceHandle)(scm);
    VIRTUALIZER_END;
    return !!ok;
}

bool
DriverStop(
)
{
    VIRTUALIZER_START;
    BRKIDA;
    SC_HANDLE scm = LI_ADVAPI(OpenSCManagerW)(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return false;

    SC_HANDLE svc = LI_ADVAPI(OpenServiceW)(scm, pxenc(KG_SERVICE_NAME),
                                            SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!svc) { LI_ADVAPI(CloseServiceHandle)(scm); return false; }

    SERVICE_STATUS st = { 0 };
    BOOL ok = LI_ADVAPI(ControlService)(svc, SERVICE_CONTROL_STOP, &st);
    if (!ok && LI_KERNEL(GetLastError)() == ERROR_SERVICE_NOT_ACTIVE) ok = TRUE;

    LI_ADVAPI(CloseServiceHandle)(svc);
    LI_ADVAPI(CloseServiceHandle)(scm);
    VIRTUALIZER_END;
    return !!ok;
}

bool
DriverUninstall(
)
{
    VIRTUALIZER_START;
    BRKIDA;
    SC_HANDLE scm = LI_ADVAPI(OpenSCManagerW)(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return false;

    SC_HANDLE svc = LI_ADVAPI(OpenServiceW)(scm, pxenc(KG_SERVICE_NAME), DELETE);
    if (!svc) { LI_ADVAPI(CloseServiceHandle)(scm); return false; }

    BOOL ok = LI_ADVAPI(DeleteService)(svc);
    LI_ADVAPI(CloseServiceHandle)(svc);
    LI_ADVAPI(CloseServiceHandle)(scm);
    VIRTUALIZER_END;
    return !!ok;
}
