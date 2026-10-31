#include "nvintegrity.hpp"
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include "../session/session.hpp"
#include "../guard/guard.hpp"
#include "../report/report.hpp"
#include "../dbg.hpp"
#include "pxstr.hpp"
#include "pxenc.hpp"
#include "lazy_importer.hpp"
#include "brkida.hpp"
#include "agent_stubs.hpp"

#define KG_NVI_INTERVAL_MS 15000
#define KG_NVI_PROBE_BYTES 16
#define KG_NVI_SEEN_MAX    32

typedef struct _KG_NVI_CTX {
    HANDLE  Thread;
    HANDLE  StopEvent;
    HANDLE  Device;
    UINT32  Rva;
    BYTE    Baseline[KG_NVI_PROBE_BYTES];
    bool    HaveBaseline;
    DWORD   SeenPids[KG_NVI_SEEN_MAX];
    ULONG   SeenCount;
} KG_NVI_CTX;

static KG_NVI_CTX g_Nvi = { 0 };

static
bool
CaptureBaseline(
    KG_NVI_CTX* ctx
)
{
    VIRTUALIZER_START
    BRKIDA;
    HMODULE u32 = LI_KERNEL(GetModuleHandleW)(pxenc(L"user32.dll"));
    if (!u32) u32 = LI_KERNEL(LoadLibraryW)(pxenc(L"user32.dll"));
    if (!u32) return false;

    FARPROC gwda = LI_KERNEL(GetProcAddress)(u32, pxenc("GetWindowDisplayAffinity"));
    if (!gwda) return false;

    ctx->Rva = (UINT32)((ULONG_PTR)gwda - (ULONG_PTR)u32);
    memcpy(ctx->Baseline, (void*)gwda, KG_NVI_PROBE_BYTES);
    ctx->HaveBaseline = true;
    VIRTUALIZER_END
    return true;
}

static
bool
EqIgnoreCaseW(
    const wchar_t* a,
    const wchar_t* b
)
{
    while (*a && *b) {
        wchar_t x = *a;
        wchar_t y = *b;
        if (x >= L'A' && x <= L'Z') x = (wchar_t)(x + 32);
        if (y >= L'A' && y <= L'Z') y = (wchar_t)(y + 32);
        if (x != y) return false;
        ++a; ++b;
    }
    return *a == 0 && *b == 0;
}

static
bool
FindModuleBase(
    DWORD          Pid,
    const wchar_t* ModName,
    UINT64*        OutBase
)
{
    BRKIDA;
    HANDLE snap = LI_KERNEL(CreateToolhelp32Snapshot)(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, Pid);
    if (snap == INVALID_HANDLE_VALUE) return false;

    MODULEENTRY32W me = { 0 };
    me.dwSize = sizeof(me);
    bool found = false;
    if (LI_KERNEL(Module32FirstW)(snap, &me)) {
        do {
            if (EqIgnoreCaseW(me.szModule, ModName)) {
                *OutBase = (UINT64)(ULONG_PTR)me.modBaseAddr;
                found = true;
                break;
            }
        } while (LI_KERNEL(Module32NextW)(snap, &me));
    }
    LI_KERNEL(CloseHandle)(snap);
    return found;
}

static
void
BuildExtras(
    DWORD  Pid,
    UINT64 TargetAddr,
    char*  Out,
    size_t OutCap
)
{
    auto fmt = PX_A(
        "\"hookedFunction\":\"GetWindowDisplayAffinity\","
        "\"module\":\"user32.dll\","
        "\"processName\":\"nvcontainer.exe\","
        "\"pid\":%lu,"
        "\"target\":\"0x%016llX\"");
    _snprintf_s(Out, OutCap, _TRUNCATE, fmt, (unsigned long)Pid, (unsigned long long)TargetAddr);
}

static
bool
AlreadySeen(
    DWORD Pid
)
{
    for (ULONG i = 0; i < g_Nvi.SeenCount; ++i) {
        if (g_Nvi.SeenPids[i] == Pid) return true;
    }
    if (g_Nvi.SeenCount < KG_NVI_SEEN_MAX) {
        g_Nvi.SeenPids[g_Nvi.SeenCount++] = Pid;
    }
    return false;
}

static
void
CheckOnePid(
    DWORD Pid
)
{
    BRKIDA;
    UINT64 u32Base = 0;
    if (!FindModuleBase(Pid, pxenc(L"user32.dll"), &u32Base)) return;

    UINT64 target = u32Base + g_Nvi.Rva;
    BYTE   remote[KG_NVI_PROBE_BYTES] = { 0 };

    if (!ReadMem(g_Nvi.Device, (UINT32)Pid, target, remote, KG_NVI_PROBE_BYTES))
        return;

    if (memcmp(remote, g_Nvi.Baseline, KG_NVI_PROBE_BYTES) == 0)
        return;

    if (AlreadySeen(Pid)) return;

    wchar_t exePath[MAX_PATH] = { 0 };
    {
        HANDLE snap = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe = { 0 };
            pe.dwSize = sizeof(pe);
            if (LI_KERNEL(Process32FirstW)(snap, &pe)) {
                do {
                    if (pe.th32ProcessID == Pid) {
                        wcscpy_s(exePath, pe.szExeFile);
                        break;
                    }
                } while (LI_KERNEL(Process32NextW)(snap, &pe));
            }
            LI_KERNEL(CloseHandle)(snap);
        }
    }

    char extras[512];
    BuildExtras(Pid, target, extras, sizeof(extras));

    char json[2048];
    int  jlen = BuildDetectionJson(
        PX_A("nv-streamproof"),
        PX_A("user32.GetWindowDisplayAffinity hook in nvcontainer.exe"),
        exePath[0] ? exePath : pxenc(L"nvcontainer.exe"),
        NULL,
        extras,
        json, sizeof(json));

    ULONG plen  = jlen > 0 ? (ULONG)jlen : 0;
    ULONG total = 4 + plen;
    BYTE* payload = (BYTE*)HeapAlloc(GetProcessHeap(), 0, total);
    if (!payload) return;

    payload[0] = (BYTE)(plen >> 24);
    payload[1] = (BYTE)(plen >> 16);
    payload[2] = (BYTE)(plen >> 8);
    payload[3] = (BYTE)plen;
    if (plen) memcpy(payload + 4, json, plen);

    SessionSendDetection(PX_A("nv-streamproof"),
                         PX_A("user32.GetWindowDisplayAffinity hook in nvcontainer.exe"),
                         exePath[0] ? exePath : pxenc(L"nvcontainer.exe"),
                         5, payload, total);
    HeapFree(GetProcessHeap(), 0, payload);

    KGDBG(L"[nvi] hook detected pid=%lu addr=0x%016llX exe=%ls\n",
          Pid, (unsigned long long)target, exePath);
}

static
void
ScanOnce()
{
    BRKIDA;
    HANDLE snap = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe = { 0 };
    pe.dwSize = sizeof(pe);
    if (LI_KERNEL(Process32FirstW)(snap, &pe)) {
        auto needle = PX_WS(L"nvcontainer.exe");
        do {
            if (EqIgnoreCaseW(pe.szExeFile, needle)) {
                CheckOnePid(pe.th32ProcessID);
            }
        } while (LI_KERNEL(Process32NextW)(snap, &pe));
    }
    LI_KERNEL(CloseHandle)(snap);
}

static
DWORD
WINAPI
NvIntegrityThread(
    LPVOID
)
{
    BRKIDA;
    for (;;) {
        DWORD wait = LI_KERNEL(WaitForSingleObject)(g_Nvi.StopEvent, KG_NVI_INTERVAL_MS);
        if (wait == WAIT_OBJECT_0) break;

        __try {
            ScanOnce();
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            KGDBG(L"[nvi] SEH inside ScanOnce code=0x%08X\n", GetExceptionCode());
        }
    }
    return 0;
}

bool
NvIntegrityStart(
    HANDLE Device,
    HANDLE StopEvent
)
{
    BRKIDA;
    if (g_Nvi.Thread) return false;
    if (!Device || Device == INVALID_HANDLE_VALUE || !StopEvent) return false;

    g_Nvi.Device    = Device;
    g_Nvi.StopEvent = StopEvent;

    if (!CaptureBaseline(&g_Nvi)) {
        KGDBG(L"[nvi] baseline capture failed\n");
        return false;
    }
    KGDBG(L"[nvi] baseline captured rva=0x%08X\n", g_Nvi.Rva);

    g_Nvi.Thread = LI_KERNEL(CreateThread)(NULL, 0, NvIntegrityThread, NULL, 0, NULL);
    return g_Nvi.Thread != NULL;
}

void
NvIntegrityStop(
)
{
    if (!g_Nvi.Thread) return;
    LI_KERNEL(WaitForSingleObject)(g_Nvi.Thread, 3000);
    LI_KERNEL(CloseHandle)(g_Nvi.Thread);
    g_Nvi.Thread = NULL;
}
