#include "antidbg.hpp"
#include <winternl.h>
#include <intrin.h>
#include <stdio.h>
#include <string.h>
#include "../session/session.hpp"
#include "../capture/capture.hpp"
#include "../report/report.hpp"
#include "../dbg.hpp"
#include "pxstr.hpp"
#include "agent_stubs.hpp"
#include "pxenc.hpp"
#include "lazy_importer.hpp"
#include "brkida.hpp"
#include "config.hpp"

extern "C" {
	NTSYSAPI
	NTSTATUS
	NTAPI
	NtGetContextThread(
	    HANDLE   ThreadHandle,
	    PCONTEXT ThreadContext
	);
}

typedef struct _KG_ADBG_CTX {
    HANDLE StopEvent;
    HANDLE Thread;
} KG_ADBG_CTX;

static KG_ADBG_CTX g_Adbg = { 0 };

typedef LONG (WINAPI *pNtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef LONG (WINAPI *pNtQSI)(ULONG, PVOID, ULONG, PULONG);
typedef LONG (WINAPI *pNtGetContextThread)(HANDLE, PCONTEXT);

#define KG_PDP_ProcessBasicInformation  0
#define KG_PDP_ProcessDebugPort         7
#define KG_PDP_ProcessDebugObjectHandle 30
#define KG_PDP_ProcessDebugFlags        31
#define KG_SI_KernelDebuggerInformation 35

typedef struct _KG_PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PPEB     PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG     BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} KG_PROCESS_BASIC_INFORMATION;

typedef struct _KG_SYSTEM_KERNEL_DEBUGGER_INFORMATION {
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
} KG_SYSTEM_KERNEL_DEBUGGER_INFORMATION;

static
PPEB
PebSelf(
)
{
#if defined(_M_X64)
    return (PPEB)__readgsqword(0x60);
#else
    return (PPEB)__readfsdword(0x30);
#endif
}

static
bool
CheckPebBeingDebugged(
)
{
    VIRTUALIZER_START
    BRKIDA;
    PPEB peb = PebSelf();
    if (!peb)
        return false;
    VIRTUALIZER_END
    return peb->BeingDebugged != 0;
}

static
bool
CheckNtGlobalFlag(
)
{
    VIRTUALIZER_START
    BRKIDA;
    PPEB peb = PebSelf();
    if (!peb)
        return false;
#if defined(_M_X64)
    ULONG flag = *(ULONG*)((PUCHAR)peb + 0xBC);
#else
    ULONG flag = *(ULONG*)((PUCHAR)peb + 0x68);
#endif
    VIRTUALIZER_END
    return (flag & (0x10 | 0x20 | 0x40)) != 0;
}

static
bool
CheckHeapFlags(
)
{
    VIRTUALIZER_START
    BRKIDA;
    PPEB peb = PebSelf();
    if (!peb)
        return false;

    PVOID heap = peb->Reserved4[1];
    if (!heap)
        return false;
#if defined(_M_X64)
    ULONG heapFlags      = *(ULONG*)((PUCHAR)heap + 0x70);
    ULONG heapForceFlags = *(ULONG*)((PUCHAR)heap + 0x74);
#else
    ULONG heapFlags      = *(ULONG*)((PUCHAR)heap + 0x40);
    ULONG heapForceFlags = *(ULONG*)((PUCHAR)heap + 0x44);
#endif
    if ((heapFlags & ~2u) != 0)
        return true;

    if (heapForceFlags != 0)
        return true;
    VIRTUALIZER_END
    return false;
}

static
bool
CheckProcessDebugPort(
)
{
    VIRTUALIZER_START
    BRKIDA;
    pNtQIP fn = (pNtQIP)LI_NTDLL(NtQueryInformationProcess);
    if (!fn)
        return false;

    HANDLE dbgPort = NULL;
    ULONG ret = 0;
    VIRTUALIZER_END
    return fn((HANDLE)-1, KG_PDP_ProcessDebugPort, &dbgPort, sizeof(dbgPort), &ret) == 0 && dbgPort != NULL;
}

static
bool
CheckProcessDebugObject(
)
{
    VIRTUALIZER_START
    BRKIDA;
    pNtQIP fn = (pNtQIP)LI_NTDLL(NtQueryInformationProcess);
    if (!fn)
        return false;

    HANDLE dbgObj = NULL;
    ULONG ret = 0;
    VIRTUALIZER_END
    return fn((HANDLE)-1, KG_PDP_ProcessDebugObjectHandle, &dbgObj, sizeof(dbgObj), &ret) == 0 && dbgObj != NULL;
}

static
bool
CheckProcessDebugFlags(
)
{
    VIRTUALIZER_START
    BRKIDA;
    pNtQIP fn = (pNtQIP)LI_NTDLL(NtQueryInformationProcess);
    if (!fn)
        return false;

    ULONG flags = 1;
    ULONG ret = 0;
    if (fn((HANDLE)-1, KG_PDP_ProcessDebugFlags, &flags, sizeof(flags), &ret) != 0)
        return false;
    VIRTUALIZER_END
    return flags == 0;
}

static
bool
CheckRemoteDbg(
)
{
    VIRTUALIZER_START
    BRKIDA;
    BOOL present = FALSE;
    if (LI_KERNEL(CheckRemoteDebuggerPresent)((HANDLE)-1, &present) && present)
        return true;
    VIRTUALIZER_END
    return false;
}

static
bool
CheckHwBreakpoints(
)
{
    VIRTUALIZER_START
    BRKIDA;
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    pNtGetContextThread fn = (pNtGetContextThread)LI_NTDLL(NtGetContextThread);
    if (!fn)
        return false;

    if (fn((HANDLE)-2, &ctx) != 0)
        return false;
    VIRTUALIZER_END
    return ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0;
}

static
bool
CheckKernelDebugger(
)
{
    VIRTUALIZER_START
    BRKIDA;
    pNtQSI fn = (pNtQSI)LI_NTDLL(NtQuerySystemInformation);
    if (!fn)
        return false;

    KG_SYSTEM_KERNEL_DEBUGGER_INFORMATION info = { 0 };
    ULONG ret = 0;
    if (fn(KG_SI_KernelDebuggerInformation, &info, sizeof(info), &ret) != 0)
        return false;
    VIRTUALIZER_END
    return info.KernelDebuggerEnabled && !info.KernelDebuggerNotPresent;
}

static
bool
WideEqualsCI(
    const wchar_t* a,
    const wchar_t* b
)
{
    while (*a && *b) {
        wchar_t ca = *a, cb = *b;
        if (ca >= L'A' && ca <= L'Z') ca = (wchar_t)(ca + 32);
        if (cb >= L'A' && cb <= L'Z') cb = (wchar_t)(cb + 32);
        if (ca != cb)
            return false;

        a++; b++;
    }
    return *a == 0 && *b == 0;
}

static
bool
WideContainsCI(
    const wchar_t* hay,
    const wchar_t* needle
)
{
    if (!hay || !needle)
        return false;

    size_t nlen = 0; while (needle[nlen]) nlen++;
    if (nlen == 0)
        return false;

    for (size_t i = 0; hay[i]; i++) {
        size_t j = 0;
        while (j < nlen && hay[i + j]) {
            wchar_t a = hay[i + j], b = needle[j];
            if (a >= L'A' && a <= L'Z') a = (wchar_t)(a + 32);
            if (b >= L'A' && b <= L'Z') b = (wchar_t)(b + 32);
            if (a != b) break;
            j++;
        }
        if (j == nlen)
            return true;
    }
    return false;
}

typedef struct _KG_ADBG_WIN_HIT {
    HWND    Hwnd;
    DWORD   Pid;
    LONG    Style;
    LONG    ExStyle;
    RECT    Rect;
    wchar_t ClassName[128];
    wchar_t Title[256];
    wchar_t ExePath[MAX_PATH];
    char    MatchKind[16];
    char    MatchPattern[96];
} KG_ADBG_WIN_HIT;

typedef struct _KG_ADBG_WIN_ENUM {
    KG_ADBG_WIN_HIT* Hit;
    bool             Found;
    DWORD            SelfPid;
} KG_ADBG_WIN_ENUM;

static
bool
DebuggerClassMatch(
    const wchar_t*  cls,
    const wchar_t** outPattern
)
{
    if (outPattern) *outPattern = NULL;
    if (!cls || !cls[0])
        return false;

    VIRTUALIZER_START
    const wchar_t* known[] = {
        PX_W(L"OLLYDBG"),
        PX_W(L"WinDbgFrameClass"),
        PX_W(L"ID"),
        PX_W(L"IDATextEditor"),
        PX_W(L"IDAWindow"),
    };
    VIRTUALIZER_END

    for (int i = 0; i < 5; i++) {
        if (WideEqualsCI(cls, known[i])) {
            if (outPattern) *outPattern = known[i];
            return true;
        }
    }
    return false;
}

static
bool
DebuggerTitleMatch(
    const wchar_t*  title,
    const wchar_t** outPattern
)
{
    if (outPattern) *outPattern = NULL;
    if (!title || !title[0])
        return false;

    VIRTUALIZER_START
    const wchar_t* known[] = {
        PX_W(L"x64dbg"),
        PX_W(L"x32dbg"),
        PX_W(L"OllyDbg"),
        PX_W(L"WinDbg"),
        PX_W(L"IDA -"),
        PX_W(L"IDA Pro"),
        PX_W(L"Cheat Engine"),
        PX_W(L"Immunity Debugger"),
        PX_W(L"ScyllaHide"),
    };
    VIRTUALIZER_END

    for (int i = 0; i < 9; i++) {
        if (WideContainsCI(title, known[i])) {
            if (outPattern) *outPattern = known[i];
            return true;
        }
    }
    return false;
}

static
void
CopyWideBounded(
    wchar_t*       dst,
    size_t         dstCap,
    const wchar_t* src
)
{
    if (!dst || dstCap == 0)
        return;

    size_t i = 0;
    for (; src && src[i] && i + 1 < dstCap; i++) dst[i] = src[i];
    dst[i] = 0;
}

static
void
CopyAsciiBounded(
    char*       dst,
    size_t      dstCap,
    const char* src
)
{
    if (!dst || dstCap == 0)
        return;

    size_t i = 0;
    for (; src && src[i] && i + 1 < dstCap; i++) dst[i] = src[i];
    dst[i] = 0;
}

static
BOOL
CALLBACK
DbgWinEnumProc(
    HWND   hwnd,
    LPARAM lp
)
{
    KG_ADBG_WIN_ENUM* ctx = (KG_ADBG_WIN_ENUM*)lp;

    VIRTUALIZER_START
    DWORD pid = 0;
    LI_USER32(GetWindowThreadProcessId)(hwnd, &pid);
    if (pid == ctx->SelfPid)
        return TRUE;

    wchar_t cls[128] = { 0 };
    LI_USER32(GetClassNameW)(hwnd, cls, ARRAYSIZE(cls));
    wchar_t title[256] = { 0 };
    LI_USER32(GetWindowTextW)(hwnd, title, ARRAYSIZE(title));
    VIRTUALIZER_END

    const wchar_t* pattern = NULL;
    const char* matchKind = NULL;
    if (DebuggerClassMatch(cls, &pattern)) {
        matchKind = PX_A("class");
    } else if (DebuggerTitleMatch(title, &pattern)) {
        matchKind = PX_A("title");
    } else return TRUE;

    ctx->Found = true;
    if (ctx->Hit) {
        KG_ADBG_WIN_HIT* h = ctx->Hit;
        h->Hwnd = hwnd;
        h->Pid  = pid;
        CopyWideBounded(h->ClassName, ARRAYSIZE(h->ClassName), cls);
        CopyWideBounded(h->Title,     ARRAYSIZE(h->Title),     title);

        VIRTUALIZER_START
        h->Style   = (LONG)LI_USER32(GetWindowLongW)(hwnd, GWL_STYLE);
        h->ExStyle = (LONG)LI_USER32(GetWindowLongW)(hwnd, GWL_EXSTYLE);
        LI_USER32(GetWindowRect)(hwnd, &h->Rect);

        HANDLE proc = LI_KERNEL(OpenProcess)(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (proc) {
            DWORD n = ARRAYSIZE(h->ExePath);
            if (!LI_KERNEL(QueryFullProcessImageNameW)(proc, 0, h->ExePath, &n))
                h->ExePath[0] = 0;
            LI_KERNEL(CloseHandle)(proc);
        }
        VIRTUALIZER_END

        CopyAsciiBounded(h->MatchKind, sizeof(h->MatchKind), matchKind);
        if (pattern) {
            char patU[96] = { 0 };
            WideCharToMultiByte(CP_UTF8, 0, pattern, -1, patU, sizeof(patU) - 1, NULL, NULL);
            CopyAsciiBounded(h->MatchPattern, sizeof(h->MatchPattern), patU);
        }
    }

    return FALSE;
}

static
bool
CheckDebuggerWindow(
    KG_ADBG_WIN_HIT* outHit
)
{
    VIRTUALIZER_START
    LI_KERNEL(LoadLibraryW)(pxenc(L"user32.dll"));
    if (outHit) memset(outHit, 0, sizeof(*outHit));
    KG_ADBG_WIN_ENUM ctx = { outHit, false, GetCurrentProcessId() };
    LI_USER32(EnumWindows)(DbgWinEnumProc, (LPARAM)&ctx);
    VIRTUALIZER_END
    return ctx.Found;
}

static
void
JsonEscapeUtf8(
    const char* in,
    char*       out,
    size_t      outCap
)
{
    size_t o = 0;
    if (!in) {
        if (outCap) out[0] = 0;
        return;
    }
    for (size_t i = 0; in[i] && o + 8 < outCap; i++) {
        unsigned char c = (unsigned char)in[i];
        switch (c) {
        case '"':  out[o++] = '\\'; out[o++] = '"';  break;
        case '\\': out[o++] = '\\'; out[o++] = '\\'; break;
        case '\b': out[o++] = '\\'; out[o++] = 'b';  break;
        case '\f': out[o++] = '\\'; out[o++] = 'f';  break;
        case '\n': out[o++] = '\\'; out[o++] = 'n';  break;
        case '\r': out[o++] = '\\'; out[o++] = 'r';  break;
        case '\t': out[o++] = '\\'; out[o++] = 't';  break;
        default:
            if (c < 0x20) o += snprintf(out + o, outCap - o, "\\u%04x", c);
            else          out[o++] = (char)c;
        }
    }
    if (o < outCap) out[o] = 0; else out[outCap - 1] = 0;
}

static
void
WideToEscapedUtf8(
    const wchar_t* in,
    char*          out,
    size_t         outCap
)
{
    char tmp[1024] = { 0 };
    if (in && in[0]) {
        int r = WideCharToMultiByte(CP_UTF8, 0, in, -1, tmp, sizeof(tmp) - 1, NULL, NULL);
        if (r <= 0) tmp[0] = 0;
    }
    JsonEscapeUtf8(tmp, out, outCap);
}

static
void
BuildDbgWinExtras(
    const KG_ADBG_WIN_HIT* h,
    char*                  out,
    size_t                 cap
)
{
    VIRTUALIZER_START
    auto fmt = PX_A("{\"className\":\"%s\",\"title\":\"%s\",\"exePath\":\"%s\","
                           "\"pid\":%u,\"hwnd\":\"0x%llx\","
                           "\"style\":\"0x%08X\",\"exStyle\":\"0x%08X\","
                           "\"rect\":{\"l\":%ld,\"t\":%ld,\"r\":%ld,\"b\":%ld},"
                           "\"matchKind\":\"%s\",\"matchPattern\":\"%s\"}");

    char clsU[512], titleU[512], exeU[MAX_PATH * 3 + 1];
    char kindEsc[32], patEsc[192];

    WideToEscapedUtf8(h->ClassName, clsU,   sizeof(clsU));
    WideToEscapedUtf8(h->Title,     titleU, sizeof(titleU));
    WideToEscapedUtf8(h->ExePath,   exeU,   sizeof(exeU));
    JsonEscapeUtf8(h->MatchKind,    kindEsc, sizeof(kindEsc));
    JsonEscapeUtf8(h->MatchPattern, patEsc,  sizeof(patEsc));

    _snprintf_s(out, cap, _TRUNCATE, fmt,
        clsU, titleU, exeU,
        (unsigned)h->Pid, (unsigned long long)(ULONG_PTR)h->Hwnd,
        (unsigned)h->Style, (unsigned)h->ExStyle,
        h->Rect.left, h->Rect.top, h->Rect.right, h->Rect.bottom,
        kindEsc, patEsc);
    VIRTUALIZER_END
}

static
bool
DllNameMatchesDebugger(
    const UNICODE_STRING* name
)
{
    if (!name || !name->Buffer || name->Length == 0)
        return false;

    VIRTUALIZER_START
    wchar_t local[520] = { 0 };
    USHORT chars = name->Length / sizeof(wchar_t);
    if (chars >= ARRAYSIZE(local)) chars = ARRAYSIZE(local) - 1;
    for (USHORT i = 0; i < chars; i++) local[i] = name->Buffer[i];
    local[chars] = 0;

    const wchar_t* known[] = {
        PX_W(L"ScyllaHide"),
        PX_W(L"HookLibrary"),
        PX_W(L"TitanHide"),
        PX_W(L"StrongOD"),
    };
    VIRTUALIZER_END

    for (int i = 0; i < 4; i++) {
        if (WideContainsCI(local, known[i]))
            return true;
    }

    return false;
}

static
bool
CheckDebuggerModule(
)
{
    PPEB peb = PebSelf();
    if (!peb || !peb->Ldr)
        return false;

    PPEB_LDR_DATA ldr = peb->Ldr;
    PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
    PLIST_ENTRY cur = head->Flink;
    int guard = 0;
    while (cur && cur != head && guard < 1024) {
        PLDR_DATA_TABLE_ENTRY mod = CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (mod->FullDllName.Buffer && DllNameMatchesDebugger(&mod->FullDllName))
            return true;

        cur = cur->Flink;
        guard++;
    }
    return false;
}

static
bool
BasenameMatchesDebugger(
    const wchar_t* basename
)
{
    VIRTUALIZER_START
    const wchar_t* known[] = {
        PX_W(L"x64dbg.exe"),
        PX_W(L"x32dbg.exe"),
        PX_W(L"OllyDbg.exe"),
        PX_W(L"windbg.exe"),
        PX_W(L"windbgx.exe"),
        PX_W(L"ida.exe"),
        PX_W(L"ida64.exe"),
        PX_W(L"idaq.exe"),
        PX_W(L"idaq64.exe"),
        PX_W(L"idag.exe"),
        PX_W(L"idaw.exe"),
        PX_W(L"ImmunityDebugger.exe"),
        PX_W(L"ScyllaHide.exe"),
        PX_W(L"dnSpy.exe"),
        PX_W(L"dnSpyEx.exe"),
    };
    VIRTUALIZER_END

    for (int i = 0; i < 15; i++) {
        if (WideEqualsCI(basename, known[i]))
            return true;
    }

    return false;
}

static
bool
CheckParentDebugger(
)
{
    VIRTUALIZER_START
    BRKIDA;
    pNtQIP fn = (pNtQIP)LI_NTDLL(NtQueryInformationProcess);
    if (!fn)
        return false;

    KG_PROCESS_BASIC_INFORMATION pbi = { 0 };
    ULONG ret = 0;
    if (fn((HANDLE)-1, KG_PDP_ProcessBasicInformation, &pbi, sizeof(pbi), &ret) != 0)
        return false;

    DWORD ppid = (DWORD)(ULONG_PTR)pbi.InheritedFromUniqueProcessId;
    if (!ppid)
        return false;

    HANDLE hParent = LI_KERNEL(OpenProcess)(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ppid);
    if (!hParent)
        return false;

    wchar_t path[MAX_PATH] = { 0 };
    DWORD sz = MAX_PATH;
    BOOL ok = LI_KERNEL(QueryFullProcessImageNameW)(hParent, 0, path, &sz);
    LI_KERNEL(CloseHandle)(hParent);
    if (!ok)
        return false;
    VIRTUALIZER_END

    const wchar_t* basename = path;
    for (const wchar_t* p = path; *p; p++) {
        if (*p == L'\\' || *p == L'/') basename = p + 1;
    }
    return BasenameMatchesDebugger(basename);
}

static
bool
CheckRdtscTiming(
)
{
    LARGE_INTEGER f, a, b;
    LI_KERNEL(QueryPerformanceFrequency)(&f);
    LI_KERNEL(QueryPerformanceCounter)(&a);
    volatile ULONGLONG acc = 0;
    for (int i = 0; i < 200; i++) acc += __rdtsc();
    LI_KERNEL(QueryPerformanceCounter)(&b);
    ULONGLONG deltaUs = (ULONGLONG)((b.QuadPart - a.QuadPart) * 1000000ULL / f.QuadPart);
    (void)acc;
    return deltaUs > 20000;
}

static
const char*
RunAllChecks(
    char*    extras,
    size_t   extrasCap,
    wchar_t* offender,
    size_t   offenderCap
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    if (extras && extrasCap)   extras[0] = 0;
    if (offender && offenderCap) offender[0] = 0;

    if (CheckPebBeingDebugged())      return PX_A("peb-being-debugged");
    if (CheckNtGlobalFlag())          return PX_A("ntglobalflag");
    if (CheckHeapFlags())             return PX_A("heap-flags");
    if (CheckProcessDebugPort())      return PX_A("process-debug-port");
    if (CheckProcessDebugObject())    return PX_A("process-debug-object");
    if (CheckProcessDebugFlags())     return PX_A("process-debug-flags");
    if (CheckRemoteDbg())             return PX_A("remote-debugger-present");
    if (CheckHwBreakpoints())         return PX_A("hw-breakpoint");
    if (CheckKernelDebugger())        return PX_A("kernel-debugger");

    KG_ADBG_WIN_HIT winHit;
    if (CheckDebuggerWindow(&winHit)) {
        if (extras && extrasCap) BuildDbgWinExtras(&winHit, extras, extrasCap);
        if (offender && offenderCap) CopyWideBounded(offender, offenderCap, winHit.ExePath);
        return PX_A("debugger-window");
    }

    if (CheckDebuggerModule())        return PX_A("debugger-module");
    if (CheckParentDebugger())        return PX_A("parent-debugger");
    if (CheckRdtscTiming())           return PX_A("rdtsc-skew");
    return NULL;
}

static
void
FireDetection(
    const char*    hit,
    const char*    extras,
    const wchar_t* offender
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    BYTE* png = NULL; ULONG pngLen = 0;
    CaptureScreenshot(SessionGetSteamId(), hit, &png, &pngLen, NULL, 0);

    const wchar_t* off = (offender && offender[0]) ? offender : NULL;

    char json[4096];
    int jlen = BuildDetectionJson(PX_A("anti-debug"), hit, off, NULL,
                                  (extras && extras[0]) ? extras : NULL,
                                  json, sizeof(json));
    ULONG plen = jlen > 0 ? (ULONG)jlen : 0;
    ULONG effPngLen = pngLen;
    if (4 + plen + effPngLen > 32u * 1024u * 1024u - 4096u) effPngLen = 0;
    ULONG total = 4 + plen + effPngLen;
    BYTE* payload = (BYTE*)HeapAlloc(GetProcessHeap(), 0, total);
    if (payload) {
        payload[0] = (BYTE)(plen >> 24);
        payload[1] = (BYTE)(plen >> 16);
        payload[2] = (BYTE)(plen >> 8);
        payload[3] = (BYTE)plen;
        if (plen) memcpy(payload + 4, json, plen);
        if (effPngLen && png) memcpy(payload + 4 + plen, png, effPngLen);
        SessionSendDetection(PX_A("anti-debug"), hit, off, 7, payload, total);
        HeapFree(GetProcessHeap(), 0, payload);
    }
    if (png) CaptureFree(png);
}

static
DWORD
WINAPI
AdbgThread(
    LPVOID
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    KGDBG(L"[adbg] thread start\n");

    #define KG_ADBG_SEEN_MAX 32
    char    seenHit[KG_ADBG_SEEN_MAX][32]      = { 0 };
    wchar_t seenOff[KG_ADBG_SEEN_MAX][MAX_PATH] = { 0 };
    int     seenCount                           = 0;

    for (;;) {
        DWORD w = LI_KERNEL(WaitForSingleObject)(g_Adbg.StopEvent, 3000);
        if (w == WAIT_OBJECT_0)
            break;

        char    extras[2048]        = { 0 };
        wchar_t offender[MAX_PATH]  = { 0 };
        const char* hit = RunAllChecks(extras, sizeof(extras), offender, ARRAYSIZE(offender));
        if (!hit)
            continue;

        const bool isWindowHit  = (strcmp(hit, PX_A("debugger-window")) == 0);
        const bool killOnThis   = KG_ADBG_KILL && (isWindowHit ? (bool)KG_ADBG_KILL_ON_WINDOW : true);

        bool alreadySeen = false;
        for (int i = 0; i < seenCount; ++i) {
            if (strcmp(seenHit[i], hit) == 0 && lstrcmpiW(seenOff[i], offender) == 0) {
                alreadySeen = true;
                break;
            }
        }

        if (!alreadySeen) {
            if (seenCount < KG_ADBG_SEEN_MAX) {
                lstrcpynA(seenHit[seenCount], hit, ARRAYSIZE(seenHit[0]));
                lstrcpynW(seenOff[seenCount], offender, ARRAYSIZE(seenOff[0]));
                seenCount++;
            }
            KGDBG(L"[adbg] tripped: %hs\n", hit);
            FireDetection(hit, extras, offender);
        }

        if (killOnThis) {
            LI_KERNEL(SetEvent)(g_Adbg.StopEvent);
            break;
        }
    }
    KGDBG(L"[adbg] thread exit\n");
    return 0;
}

bool
AntiDbgStart(
    HANDLE StopEvent
)
{
    BRKIDA;
    if (g_Adbg.Thread)
        return false;

    g_Adbg.StopEvent = StopEvent;

    char    extras[2048]       = { 0 };
    wchar_t offender[MAX_PATH] = { 0 };
    const char* hit = RunAllChecks(extras, sizeof(extras), offender, ARRAYSIZE(offender));
    if (hit) {
        KGDBG(L"[adbg] startup trip: %hs\n", hit);
        FireDetection(hit, extras, offender);
        const bool isWindowHit = (strcmp(hit, PX_A("debugger-window")) == 0);
        const bool killOnThis  = KG_ADBG_KILL && (isWindowHit ? (bool)KG_ADBG_KILL_ON_WINDOW : true);
        if (killOnThis) {
            LI_KERNEL(SetEvent)(StopEvent);
            return false;
        }
    }

    VIRTUALIZER_START
    g_Adbg.Thread = LI_KERNEL(CreateThread)(NULL, 0, AdbgThread, NULL, 0, NULL);
    VIRTUALIZER_END

    return g_Adbg.Thread != NULL;
}

void
AntiDbgStop(
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    if (!g_Adbg.Thread)
        return;

    LI_KERNEL(WaitForSingleObject)(g_Adbg.Thread, 3000);
    LI_KERNEL(CloseHandle)(g_Adbg.Thread);
    g_Adbg.Thread = NULL;
}
