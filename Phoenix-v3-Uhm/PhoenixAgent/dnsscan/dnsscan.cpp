#include "dnsscan.hpp"
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include "../dbg.hpp"
#include "../session/session.hpp"
#include "../report/report.hpp"
#include "../capture/capture.hpp"
#include "pxstr.hpp"
#include "pxenc.hpp"
#include "lazy_importer.hpp"
#include "brkida.hpp"
#include "agent_stubs.hpp"

#define DNSSCAN_INTERVAL_MS      60000
#define DNSSCAN_STARTUP_DELAY_MS 8000
#define DNSSCAN_MAX_REGION       (8u * 1024u * 1024u)
#define DNSSCAN_PROC_TIME_MS     15000
#define DNSSCAN_SEEN_MAX         64
#define DNSSCAN_HOST_MAX         256

static HANDLE g_Device     = INVALID_HANDLE_VALUE;
static HANDLE g_Thread     = NULL;
static HANDLE g_StopEvent  = NULL;
static HANDLE g_ReadyEvent = NULL;

typedef struct _SEEN {
    char Host[DNSSCAN_HOST_MAX];
} SEEN;

static SEEN  g_Seen[DNSSCAN_SEEN_MAX];
static ULONG g_SeenCount = 0;

static
bool
AlreadyReported(
    const char* host
)
{
    for (ULONG i = 0; i < g_SeenCount; ++i)
        if (_stricmp(g_Seen[i].Host, host) == 0) return true;
    return false;
}

static
void
MarkReported(
    const char* host
)
{
    if (g_SeenCount >= DNSSCAN_SEEN_MAX) {
        memmove(&g_Seen[0], &g_Seen[1], sizeof(g_Seen) - sizeof(g_Seen[0]));
        g_SeenCount = DNSSCAN_SEEN_MAX - 1;
    }
    strncpy_s(g_Seen[g_SeenCount].Host, host, _TRUNCATE);
    g_SeenCount++;
}

static
void
EnableDebugPrivilege(
)
{
    HANDLE tok = NULL;
    if (!LI_ADVAPI(OpenProcessToken)(LI_KERNEL(GetCurrentProcess)(),
                                     TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return;

    LUID luid = { 0 };
    if (LI_ADVAPI(LookupPrivilegeValueW)(NULL, pxenc(L"SeDebugPrivilege"), &luid)) {
        TOKEN_PRIVILEGES tp = { 0 };
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        LI_ADVAPI(AdjustTokenPrivileges)(tok, FALSE, &tp, sizeof(tp), NULL, NULL);
    }
    LI_KERNEL(CloseHandle)(tok);
}

static
DWORD
FindDnsHostPid(
)
{
    HANDLE snap = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe = { 0 };
    pe.dwSize = sizeof(pe);
    auto svcName = PX_WS(L"svchost.exe");
    auto rslvr   = PX_WS(L"dnsrslvr.dll");

    DWORD hit = 0;
    if (LI_KERNEL(Process32FirstW)(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, svcName) != 0) continue;

            HANDLE msnap = LI_KERNEL(CreateToolhelp32Snapshot)(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pe.th32ProcessID);
            if (msnap == INVALID_HANDLE_VALUE) continue;

            MODULEENTRY32W me = { 0 };
            me.dwSize = sizeof(me);
            if (LI_KERNEL(Module32FirstW)(msnap, &me)) {
                do {
                    if (_wcsicmp(me.szModule, rslvr) == 0) {
                        hit = pe.th32ProcessID;
                        break;
                    }
                } while (LI_KERNEL(Module32NextW)(msnap, &me));
            }
            LI_KERNEL(CloseHandle)(msnap);
            if (hit) break;
        } while (LI_KERNEL(Process32NextW)(snap, &pe));
    }
    LI_KERNEL(CloseHandle)(snap);
    return hit;
}

static
bool
IsHostChar(
    unsigned char c
)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '.' || c == '-';
}

static
bool
MatchEc2Pattern(
    const char* s,
    size_t      remaining
)
{
    static const char prefix[] = "ec2-3-235-182-";
    const size_t prefixLen = sizeof(prefix) - 1;
    static const char suffix[] = ".compute-1.amazonaws.com";
    const size_t suffixLen = sizeof(suffix) - 1;

    if (remaining < prefixLen + 1 + suffixLen) return false;
    for (size_t i = 0; i < prefixLen; ++i) {
        char a = s[i]; if (a >= 'A' && a <= 'Z') a += 32;
        if (a != prefix[i]) return false;
    }

    size_t p = prefixLen;
    size_t digitCount = 0;
    while (p < remaining && s[p] >= '0' && s[p] <= '9') { p++; digitCount++; }
    if (digitCount == 0 || digitCount > 3) return false;

    if (p + suffixLen > remaining) return false;
    for (size_t i = 0; i < suffixLen; ++i) {
        char a = s[p + i]; if (a >= 'A' && a <= 'Z') a += 32;
        if (a != suffix[i]) return false;
    }

    if (p + suffixLen < remaining && IsHostChar((unsigned char)s[p + suffixLen])) return false;
    return true;
}

static
size_t
MatchLiteral(
    const char* s,
    size_t      remaining,
    const char* needle,
    size_t      needleLen
)
{
    if (remaining < needleLen) return 0;
    for (size_t i = 0; i < needleLen; ++i) {
        char a = s[i]; if (a >= 'A' && a <= 'Z') a += 32;
        char b = needle[i]; if (b >= 'A' && b <= 'Z') b += 32;
        if (a != b) return 0;
    }
    if (remaining > needleLen && IsHostChar((unsigned char)s[needleLen])) return 0;
    return needleLen;
}

static
size_t
CollectHost(
    const char* s,
    size_t      remaining,
    char*       out,
    size_t      outCap
)
{
    size_t n = 0;
    while (n < remaining && IsHostChar((unsigned char)s[n])) n++;
    if (n == 0 || n >= outCap) return 0;
    memcpy(out, s, n);
    out[n] = 0;
    return n;
}

static
void
ReportHit(
    const char* brand,
    const char* host
)
{
    if (AlreadyReported(host)) return;
    MarkReported(host);

    char extras[512];
    _snprintf_s(extras, _TRUNCATE, PX_A("{\"host\":\"%s\",\"source\":\"dns-cache\",\"brand\":\"%s\"}"), host, brand);

    char json[2048];
    int jlen = BuildDetectionJson(PX_A("cheat-dns"), brand, NULL, NULL, extras, json, sizeof(json));
    ULONG plen = jlen > 0 ? (ULONG)jlen : 0;
    if (!plen) return;

    BYTE* png = NULL; ULONG pngLen = 0;
    CaptureScreenshot(SessionGetSteamId(), brand, &png, &pngLen, NULL, 0);

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

    (void)SessionSendDetection(PX_A("cheat-dns"), brand, NULL, 6, payload, total);

    HeapFree(heap, 0, payload);
    if (png) CaptureFree(png);
}

typedef struct _NEEDLE {
    const char* text;
    size_t      len;
    const char* brand;
} NEEDLE;

static
void
ScanBufferAscii(
    const char*   buf,
    size_t        len,
    const NEEDLE* needles,
    size_t        needleCount
)
{
    for (size_t i = 0; i < len; ++i) {
        if (i > 0 && IsHostChar((unsigned char)buf[i - 1])) continue;
        if (!IsHostChar((unsigned char)buf[i])) continue;

        size_t rem = len - i;
        for (size_t n = 0; n < needleCount; ++n) {
            size_t m = MatchLiteral(buf + i, rem, needles[n].text, needles[n].len);
            if (m > 0) {
                char host[DNSSCAN_HOST_MAX];
                if (CollectHost(buf + i, rem, host, sizeof(host)))
                    ReportHit(needles[n].brand, host);
                break;
            }
        }

        if (MatchEc2Pattern(buf + i, rem)) {
            char host[DNSSCAN_HOST_MAX];
            if (CollectHost(buf + i, rem, host, sizeof(host)))
                ReportHit(PX_A("Eulen Cheat"), host);
        }
    }
}

static
void
ScanBufferWide(
    const wchar_t* wbuf,
    size_t         wlen,
    const NEEDLE*  needles,
    size_t         needleCount
)
{
    size_t cap = wlen + 1;
    char* narrow = (char*)HeapAlloc(GetProcessHeap(), 0, cap);
    if (!narrow) return;
    for (size_t i = 0; i < wlen; ++i) {
        wchar_t c = wbuf[i];
        narrow[i] = (c >= 0x20 && c < 0x7F) ? (char)c : ' ';
    }
    narrow[wlen] = 0;
    ScanBufferAscii(narrow, wlen, needles, needleCount);
    HeapFree(GetProcessHeap(), 0, narrow);
}

static
void
ScanDnsProcess(
    DWORD pid
)
{
    HANDLE hProc = LI_KERNEL(OpenProcess)(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return;

    NEEDLE needles[13];
    auto sK = PX_AS("keyauth.win");
    auto sS = PX_AS("susano.gg");
    auto sE = PX_AS("eulen.gg");
    auto sH = PX_AS("hxsoftwares.com");
    auto sY = PX_AS("keyser-api.eu");
    auto sD = PX_AS("keyser-dashboard.com");
    auto sR = PX_AS("wsauth.redengine.eu");
    auto sA = PX_AS("api.redengine.net");
    auto sT = PX_AS("api.tzproject.com");
    auto sC = PX_AS("serapi.mom");
    auto sM = PX_AS("mrcheat-api.ir");
    auto sN = PX_AS("mrcheat.cc");
    auto sP = PX_AS("skript.gg");
    needles[0].text  = sK; needles[0].len  = strlen(sK); needles[0].brand  = PX_A("Generic Cheat Auth");
    needles[1].text  = sS; needles[1].len  = strlen(sS); needles[1].brand  = PX_A("Susano");
    needles[2].text  = sE; needles[2].len  = strlen(sE); needles[2].brand  = PX_A("Eulen Cheat");
    needles[3].text  = sH; needles[3].len  = strlen(sH); needles[3].brand  = PX_A("HX Software");
    needles[4].text  = sY; needles[4].len  = strlen(sY); needles[4].brand  = PX_A("Keyser Cheat");
    needles[5].text  = sD; needles[5].len  = strlen(sD); needles[5].brand  = PX_A("Keyser Cheat");
    needles[6].text  = sR; needles[6].len  = strlen(sR); needles[6].brand  = PX_A("redENGINE");
    needles[7].text  = sA; needles[7].len  = strlen(sA); needles[7].brand  = PX_A("redENGINE");
    needles[8].text  = sT; needles[8].len  = strlen(sT); needles[8].brand  = PX_A("TZ Project");
    needles[9].text  = sC; needles[9].len  = strlen(sC); needles[9].brand  = PX_A("Cumsys Bypass");
    needles[10].text = sM; needles[10].len = strlen(sM); needles[10].brand = PX_A("Mr Cheat");
    needles[11].text = sN; needles[11].len = strlen(sN); needles[11].brand = PX_A("Mr Cheat");
    needles[12].text = sP; needles[12].len = strlen(sP); needles[12].brand = PX_A("Skript Cheat");

    MEMORY_BASIC_INFORMATION mbi = { 0 };
    LPVOID addr = NULL;

    HANDLE heap = GetProcessHeap();
    BYTE*  chunk = NULL;
    SIZE_T chunkCap = 0;

    DWORD startTick = LI_KERNEL(GetTickCount)();

    __try {
        while (LI_KERNEL(VirtualQueryEx)(hProc, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            LPVOID next = (LPVOID)((ULONG_PTR)addr + mbi.RegionSize);
            if (next <= addr) break;

            if ((LI_KERNEL(GetTickCount)() - startTick) > DNSSCAN_PROC_TIME_MS) break;

            if (mbi.State != MEM_COMMIT) { addr = next; continue; }
            if (mbi.RegionSize > DNSSCAN_MAX_REGION) { addr = next; continue; }
            if (mbi.Type == MEM_IMAGE) { addr = next; continue; }

            DWORD prot = mbi.Protect & ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);
            bool readable = (prot == PAGE_READWRITE)
                         || (prot == PAGE_EXECUTE_READWRITE)
                         || (prot == PAGE_WRITECOPY)
                         || (prot == PAGE_EXECUTE_WRITECOPY)
                         || (prot == PAGE_READONLY);
            if (!readable) { addr = next; continue; }

            if (chunkCap < mbi.RegionSize) {
                if (chunk) HeapFree(heap, 0, chunk);
                chunk = (BYTE*)HeapAlloc(heap, 0, mbi.RegionSize);
                chunkCap = chunk ? mbi.RegionSize : 0;
            }
            if (!chunk) { addr = next; continue; }

            SIZE_T got = 0;
            BOOL ok = LI_KERNEL(ReadProcessMemory)(hProc, addr, chunk, mbi.RegionSize, &got);
            if (!ok || got < 16) { addr = next; continue; }

            ScanBufferAscii((const char*)chunk, got, needles, 13);
            ScanBufferWide((const wchar_t*)chunk, got / sizeof(wchar_t), needles, 13);

            addr = next;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }

    if (chunk) HeapFree(heap, 0, chunk);
    LI_KERNEL(CloseHandle)(hProc);
}

static
DWORD
WINAPI
DnsScanThread(
    LPVOID
)
{
    BRKIDA;
    HANDLE waits[2] = { g_ReadyEvent, g_StopEvent };
    DWORD gate = LI_KERNEL(WaitForMultipleObjects)(2, waits, FALSE, INFINITE);
    if (gate != WAIT_OBJECT_0) return 0;
    LI_KERNEL(Sleep)(DNSSCAN_STARTUP_DELAY_MS);

    EnableDebugPrivilege();

    for (;;) {
        if (LI_KERNEL(WaitForSingleObject)(g_StopEvent, 0) == WAIT_OBJECT_0) break;
        if (!SessionIsAllowlisted()) {
            DWORD pid = FindDnsHostPid();
            if (pid) ScanDnsProcess(pid);
        }
        if (LI_KERNEL(WaitForSingleObject)(g_StopEvent, DNSSCAN_INTERVAL_MS) != WAIT_TIMEOUT)
            break;
    }
    return 0;
}

bool
DnsScanStart(
    HANDLE ReadyEvent
)
{
    if (!ReadyEvent) return false;
    if (g_Thread) return true;
    g_ReadyEvent = ReadyEvent;
    g_StopEvent  = LI_KERNEL(CreateEventW)(NULL, TRUE, FALSE, NULL);
    if (!g_StopEvent) return false;
    g_SeenCount = 0;
    g_Thread = LI_KERNEL(CreateThread)(NULL, 0, DnsScanThread, NULL, 0, NULL);
    return g_Thread != NULL;
}

void
DnsScanStop(
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
