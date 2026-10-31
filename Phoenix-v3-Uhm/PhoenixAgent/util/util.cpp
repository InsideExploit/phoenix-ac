#include "util.hpp"
#include <tlhelp32.h>
#include "pxstr.hpp"
#include "pxenc.hpp"
#include "lazy_importer.hpp"
#include "brkida.hpp"
#include "../dbg.hpp"
#include "agent_stubs.hpp"

int
Fail(
    const wchar_t* Msg,
    DWORD          Err
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END
    DWORD lastErr = Err ? Err : LI_KERNEL(GetLastError)();
    KGDBG(L"[!] %ls (err=%lu)\n", Msg, lastErr);
#if !KG_REQUIRE_UPDATER_GATE
    {
        wchar_t buf[512] = { 0 };
        LI_USER32(wsprintfW)(buf, PX_WS(L"PhoenixAgent stopped\n\n%ls\n\nerr=%lu"),
                             Msg ? Msg : pxenc(L"(no message)"), lastErr);
        LI_USER32(MessageBoxW)(NULL, buf, pxenc(L"PhoenixAgent (dev)"),
                               MB_ICONERROR | MB_OK | MB_SETFOREGROUND | MB_TOPMOST);
    }
#endif
    (void)Msg;
    (void)Err;
    return 1;
}

__declspec(noinline)
bool
IsElevated()
{
    BRKIDA;
    BOOL                     admin    = FALSE;
    PSID                     group    = NULL;
    SID_IDENTIFIER_AUTHORITY nt       = SECURITY_NT_AUTHORITY;
    volatile int             _vm_seal = 0;

    VIRTUALIZER_START
    if (LI_ADVAPI(AllocateAndInitializeSid)(&nt, 2,
                                            SECURITY_BUILTIN_DOMAIN_RID,
                                            DOMAIN_ALIAS_RID_ADMINS,
                                            0, 0, 0, 0, 0, 0, &group)) {
        LI_ADVAPI(CheckTokenMembership)(NULL, group, &admin);
        LI_ADVAPI(FreeSid)(group);
    }
    VIRTUALIZER_END
    _vm_seal = 1;
    (void)_vm_seal;

    return !!admin;
}

void
PreloadImports()
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END
    LI_KERNEL(LoadLibraryW)(pxenc(L"advapi32.dll"));
    LI_KERNEL(LoadLibraryW)(pxenc(L"user32.dll"));
}

__declspec(noinline)
bool
GetOwnPath(
    wchar_t Out[MAX_PATH]
)
{
    BRKIDA;
    DWORD        n        = 0;
    volatile int _vm_seal = 0;

    VIRTUALIZER_START
    n = LI_KERNEL(GetModuleFileNameW)(NULL, Out, MAX_PATH);
    VIRTUALIZER_END
    _vm_seal = 1;
    (void)_vm_seal;
    return n != 0;
}

const wchar_t*
BasenameOf(
    const wchar_t* Path
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END
    const wchar_t* p = Path + wcslen(Path);
    while (p > Path && *(p - 1) != L'\\' && *(p - 1) != L'/')
        --p;

    return p;
}

__declspec(noinline)
bool
IsSteamRunning()
{
    BRKIDA;
    VIRTUALIZER_START
    auto target = PX_WS(L"steam.exe");

    volatile int _vm_seal = 0;
    HANDLE snap = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return false;

    PROCESSENTRY32W pe    = { sizeof(pe) };
    bool            found = false;

    if (LI_KERNEL(Process32FirstW)(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, target) == 0) {
                found = true;
                break;
            }
        } while (LI_KERNEL(Process32NextW)(snap, &pe));
    }

    LI_KERNEL(CloseHandle)(snap);
    VIRTUALIZER_END
    return found;
}
