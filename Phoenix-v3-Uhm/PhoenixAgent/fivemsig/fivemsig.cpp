#include "fivemsig.hpp"
#include <windows.h>
#include <stdio.h>
#include "../dbg.hpp"
#include "../fivem/fivem.hpp"
#include "../sigcheck/sigcheck.hpp"
#include "../session/session.hpp"
#include "../report/report.hpp"
#include "../capture/capture.hpp"
#include "pxstr.hpp"
#include "pxenc.hpp"
#include "lazy_importer.hpp"
#include "brkida.hpp"
#include "agent_stubs.hpp"

#define FIVEMSIG_STARTUP_DELAY_MS 4000
#define FIVEMSIG_MAX_FILES        512
#define FIVEMSIG_SEEN_MAX         128

static HANDLE g_Thread     = NULL;
static HANDLE g_StopEvent  = NULL;
static HANDLE g_ReadyEvent = NULL;

typedef struct _SIG_SEEN {
    wchar_t Path[MAX_PATH];
} SIG_SEEN;

static SIG_SEEN g_Seen[FIVEMSIG_SEEN_MAX];
static ULONG    g_SeenCount = 0;

static
bool
IsExcludedName(
    const wchar_t* Name
)
{
    if (_wcsicmp(Name, PX_W(L"v8-9.3.345.16.dll")) == 0)
        return true;
    if (_wcsicmp(Name, PX_W(L"libuv.dll")) == 0)
        return true;
    return false;
}

static
bool
AlreadyReported(
    const wchar_t* Path
)
{
    for (ULONG i = 0; i < g_SeenCount; ++i)
        if (_wcsicmp(g_Seen[i].Path, Path) == 0) return true;
    return false;
}

static
void
MarkReported(
    const wchar_t* Path
)
{
    if (g_SeenCount >= FIVEMSIG_SEEN_MAX) {
        memmove(&g_Seen[0], &g_Seen[1], sizeof(g_Seen) - sizeof(g_Seen[0]));
        g_SeenCount = FIVEMSIG_SEEN_MAX - 1;
    }
    wcsncpy_s(g_Seen[g_SeenCount].Path, Path, _TRUNCATE);
    g_SeenCount++;
}

static
void
ReportUnsigned(
    const wchar_t* FilePath,
    LONG           TrustRc
)
{
    if (AlreadyReported(FilePath)) return;
    MarkReported(FilePath);

    char pathUtf8[MAX_PATH * 2] = { 0 };
    WideCharToMultiByte(CP_UTF8, 0, FilePath, -1, pathUtf8, sizeof(pathUtf8) - 1, NULL, NULL);

    char pathEsc[MAX_PATH * 4] = { 0 };
    size_t o = 0;
    for (size_t i = 0; pathUtf8[i] && o + 2 < sizeof(pathEsc); ++i) {
        char c = pathUtf8[i];
        if (c == '\\' || c == '"') { pathEsc[o++] = '\\'; pathEsc[o++] = c; }
        else if ((unsigned char)c < 0x20) { continue; }
        else { pathEsc[o++] = c; }
    }
    pathEsc[o] = 0;

    char extras[MAX_PATH * 4 + 128];
    _snprintf_s(extras, _TRUNCATE,
        PX_A("{\"path\":\"%s\",\"source\":\"fivem-sig\",\"wintrust\":\"0x%08lx\"}"),
        pathEsc, (unsigned long)TrustRc);

    char json[MAX_PATH * 4 + 512];
    int jlen = BuildDetectionJson(PX_A("fivem-sig"), PX_A("Unsigned FiveM Module"),
                                  FilePath, NULL, extras, json, sizeof(json));
    ULONG plen = jlen > 0 ? (ULONG)jlen : 0;
    if (!plen) return;

    BYTE* png = NULL; ULONG pngLen = 0;
    CaptureScreenshot(SessionGetSteamId(), PX_A("fivem-sig"), &png, &pngLen, NULL, 0);

    ULONG effPngLen = pngLen;
    if (4 + plen + effPngLen > 32u * 1024u * 1024u - 4096u) effPngLen = 0;
    ULONG total = 4 + plen + effPngLen;

    HANDLE heap = GetProcessHeap();
    BYTE* payload = (BYTE*)HeapAlloc(heap, 0, total);
    if (!payload) { if (png) CaptureFree(png); return; }

    payload[0] = (BYTE)(plen >> 24);
    payload[1] = (BYTE)(plen >> 16);
    payload[2] = (BYTE)(plen >> 8);
    payload[3] = (BYTE)plen;
    memcpy(payload + 4, json, plen);
    if (effPngLen && png) memcpy(payload + 4 + plen, png, effPngLen);

    (void)SessionSendDetection(PX_A("fivem-sig"), PX_A("Unsigned FiveM Module"),
                               FilePath, 6, payload, total);

    HeapFree(heap, 0, payload);
    if (png) CaptureFree(png);
}

static
void
CheckOne(
    const wchar_t* FullPath
)
{
    if (LI_KERNEL(GetFileAttributesW)(FullPath) == INVALID_FILE_ATTRIBUTES)
        return;

    LONG rc = SigVerifyTrust(FullPath);
    if (rc != ERROR_SUCCESS) {
        KGDBG(L"[fivemsig] UNSIGNED %ls rc=0x%08lx\n", FullPath, (unsigned long)rc);
        ReportUnsigned(FullPath, rc);
    }
}

static
void
ScanDirectory(
    const wchar_t* Dir,
    bool           DllsOnly,
    bool           ApplyExclusions
)
{
    wchar_t pattern[MAX_PATH];
    if (_snwprintf_s(pattern, _TRUNCATE, PX_W(L"%ls\\*"), Dir) < 0)
        return;

    WIN32_FIND_DATAW fd = { 0 };
    HANDLE h = LI_KERNEL(FindFirstFileW)(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE)
        return;

    ULONG count = 0;
    do {
        if (count >= FIVEMSIG_MAX_FILES) break;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

        const wchar_t* name = fd.cFileName;
        size_t nlen = wcslen(name);
        if (nlen < 5) continue;

        const wchar_t* ext = name + nlen - 4;
        bool isDll = (_wcsicmp(ext, PX_W(L".dll")) == 0);
        bool isExe = (_wcsicmp(ext, PX_W(L".exe")) == 0);

        if (DllsOnly && !isDll) continue;
        if (!DllsOnly && !isDll && !isExe) continue;

        if (ApplyExclusions && IsExcludedName(name)) continue;

        wchar_t full[MAX_PATH];
        if (_snwprintf_s(full, _TRUNCATE, PX_W(L"%ls\\%ls"), Dir, name) < 0)
            continue;

        CheckOne(full);
        count++;

        if (LI_KERNEL(WaitForSingleObject)(g_StopEvent, 0) == WAIT_OBJECT_0) break;
    } while (LI_KERNEL(FindNextFileW)(h, &fd));

    LI_KERNEL(FindClose)(h);
}

static
DWORD
WINAPI
FiveMSigScanThread(
    LPVOID
)
{
    BRKIDA;
    HANDLE waits[2] = { g_ReadyEvent, g_StopEvent };
    DWORD gate = LI_KERNEL(WaitForMultipleObjects)(2, waits, FALSE, INFINITE);
    if (gate != WAIT_OBJECT_0) return 0;
    LI_KERNEL(Sleep)(FIVEMSIG_STARTUP_DELAY_MS);

    if (SessionIsAllowlisted()) return 0;

    wchar_t appDir[MAX_PATH] = { 0 };
    if (!FiveMGetAppDir(appDir)) {
        KGDBG(L"[fivemsig] FiveM root unresolved, scan skipped\n");
        return 0;
    }

    wchar_t plugDir[MAX_PATH] = { 0 };
    if (_snwprintf_s(plugDir, _TRUNCATE, PX_W(L"%ls\\plugins"), appDir) < 0) return 0;

    ScanDirectory(appDir,  false, true);
    ScanDirectory(plugDir, true,  false);

    return 0;
}

bool
FiveMSigScanStart(
    HANDLE ReadyEvent
)
{
    if (!ReadyEvent) return false;
    if (g_Thread) return true;
    g_ReadyEvent = ReadyEvent;
    g_StopEvent  = LI_KERNEL(CreateEventW)(NULL, TRUE, FALSE, NULL);
    if (!g_StopEvent) return false;
    g_SeenCount = 0;
    g_Thread = LI_KERNEL(CreateThread)(NULL, 0, FiveMSigScanThread, NULL, 0, NULL);
    return g_Thread != NULL;
}

void
FiveMSigScanStop(
)
{
    if (g_StopEvent) LI_KERNEL(SetEvent)(g_StopEvent);
    if (g_Thread) {
        LI_KERNEL(WaitForSingleObject)(g_Thread, 5000);
        LI_KERNEL(CloseHandle)(g_Thread);
        g_Thread = NULL;
    }
    if (g_StopEvent) {
        LI_KERNEL(CloseHandle)(g_StopEvent);
        g_StopEvent = NULL;
    }
    g_ReadyEvent = NULL;
}
