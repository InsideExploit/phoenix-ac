#include "overlayscan.hpp"
#include <stdio.h>
#include <string.h>
#include "../session/session.hpp"
#include "../capture/capture.hpp"
#include "../report/report.hpp"
#include "../dbg.hpp"
#include "pxstr.hpp"
#include "pxenc.hpp"
#include "lazy_importer.hpp"
#include "brkida.hpp"
#include "agent_stubs.hpp"

#define KG_OVR_INTERVAL_MS       6000
#define KG_OVR_MAX_HITS          16
#define KG_OVR_SEEN_MAX          128
#define KG_OVR_MIN_COVERAGE_PCT  50
#define KG_OVR_NEAR_FULL_PCT     95
#define KG_OVR_TRICK_MARGIN_PX   3

typedef struct _KG_OVR_CTX {
    HANDLE Thread;
    HANDLE StopEvent;
    DWORD  SelfPid;
} KG_OVR_CTX;

static KG_OVR_CTX g_Ovr = { 0 };

typedef struct _KG_OVR_HIT {
    HWND    Hwnd;
    DWORD   Pid;
    DWORD   Style;
    DWORD   ExStyle;
    RECT    Rect;
    LONG    MonitorW;
    LONG    MonitorH;
    ULONG   CoveragePct;
    wchar_t ClassName[256];
    wchar_t Title[256];
    wchar_t ExePath[MAX_PATH];
    char    Reason[64];
} KG_OVR_HIT;

typedef struct _KG_OVR_ENUM {
    KG_OVR_HIT* Hits;
    ULONG       Cap;
    ULONG       Count;
    DWORD       SelfPid;
} KG_OVR_ENUM;

static
void
JsonEscapeUtf8(
    const char* in,
    char*       out,
    size_t      outCap
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    size_t o = 0;
    if (!in) {
        if (outCap)
            out[0] = 0;
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
            if (c < 0x20)
                o += snprintf(out + o, outCap - o, "\\u%04x", c);
            else
                out[o++] = (char)c;
        }
    }

    if (o < outCap)
        out[o] = 0;
    else
        out[outCap - 1] = 0;
}

static
void
WideToEscapedUtf8(
    const wchar_t* in,
    char*          out,
    size_t         outCap
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    char tmp[1024] = { 0 };
    if (in && in[0]) {
        int r = WideCharToMultiByte(CP_UTF8, 0, in, -1, tmp, sizeof(tmp) - 1, NULL, NULL);
        if (r <= 0)
            tmp[0] = 0;
    }

    JsonEscapeUtf8(tmp, out, outCap);
}

static
bool
GetMonitorSize(
    HWND  hwnd,
    LONG* w,
    LONG* h
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    HMONITOR mon = LI_USER32(MonitorFromWindow)(hwnd, MONITOR_DEFAULTTONEAREST);
    if (!mon)
        return false;

    MONITORINFO mi = { 0 };
    mi.cbSize = sizeof(mi);
    if (!LI_USER32(GetMonitorInfoW)(mon, &mi))
        return false;

    *w = mi.rcMonitor.right  - mi.rcMonitor.left;
    *h = mi.rcMonitor.bottom - mi.rcMonitor.top;
    return true;
}

static
ULONG
CoveragePct(
    const RECT* wnd,
    LONG        monW,
    LONG        monH
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    if (monW <= 0 || monH <= 0)
        return 0;

    LONG w = wnd->right  - wnd->left;
    LONG h = wnd->bottom - wnd->top;
    if (w <= 0 || h <= 0)
        return 0;

    if (w > monW) w = monW;
    if (h > monH) h = monH;

    ULONGLONG area    = (ULONGLONG)w * (ULONGLONG)h;
    ULONGLONG monArea = (ULONGLONG)monW * (ULONGLONG)monH;
    if (monArea == 0)
        return 0;

    return (ULONG)((area * 100ULL) / monArea);
}

static
bool
PathEndsWithI(
    const wchar_t* path,
    const wchar_t* suffix
)
{
    size_t plen = wcslen(path);
    size_t slen = wcslen(suffix);
    if (plen < slen) return false;
    return _wcsicmp(path + plen - slen, suffix) == 0;
}

static
bool
PathContainsI(
    const wchar_t* path,
    const wchar_t* needle
)
{
    size_t plen = wcslen(path);
    size_t nlen = wcslen(needle);
    if (nlen == 0 || plen < nlen) return false;
    for (size_t i = 0; i + nlen <= plen; ++i) {
        if (_wcsnicmp(path + i, needle, nlen) == 0) return true;
    }
    return false;
}

static
bool
IsAllowlistedOverlay(
    const wchar_t* className,
    const wchar_t* exePath
)
{
    VIRTUALIZER_START;
    BRKIDA;

    if (!className || !exePath)
        return false;

    if (_wcsicmp(className, PX_W(L"CEF-OSC-WIDGET")) == 0 &&
        PathEndsWithI(exePath,
            PX_W(L"\\NVIDIA Corporation\\NVIDIA App\\CEF\\NVIDIA Overlay.exe"))) {
        VIRTUALIZER_END;
        return true;
    }

    if (PathEndsWithI(exePath, PX_W(L"\\msedgewebview2.exe")) &&
        PathContainsI(exePath, PX_W(L"\\Microsoft\\EdgeWebView\\Application\\"))) {
        VIRTUALIZER_END;
        return true;
    }

    VIRTUALIZER_END;
    return false;
}

static
bool
ClassifyOverlay(
    const KG_OVR_HIT* h,
    char*             outReason,
    size_t            reasonCap
)
{
    VIRTUALIZER_START;
    BRKIDA;

    bool topmost     = (h->ExStyle & WS_EX_TOPMOST) != 0;
    bool layered     = (h->ExStyle & WS_EX_LAYERED) != 0;
    bool transparent = (h->ExStyle & WS_EX_TRANSPARENT) != 0;
    bool toolwindow  = (h->ExStyle & WS_EX_TOOLWINDOW) != 0;
    bool noactivate  = (h->ExStyle & WS_EX_NOACTIVATE) != 0;

    LONG wpx = h->Rect.right  - h->Rect.left;
    LONG hpx = h->Rect.bottom - h->Rect.top;

    if (topmost && layered && transparent && h->CoveragePct >= KG_OVR_MIN_COVERAGE_PCT) {
        _snprintf_s(outReason, reasonCap, _TRUNCATE,
                    PX_A("topmost-layered-transparent-cov%lu"), h->CoveragePct);
        return true;
    }

    if (topmost && layered && h->CoveragePct >= KG_OVR_NEAR_FULL_PCT) {
        _snprintf_s(outReason, reasonCap, _TRUNCATE,
                    PX_A("topmost-layered-fullscreen-cov%lu"), h->CoveragePct);
        return true;
    }

    LONG dw = h->MonitorW - wpx;
    LONG dh = h->MonitorH - hpx;
    if (dw >= 1 && dw <= KG_OVR_TRICK_MARGIN_PX && dh >= 1 && dh <= KG_OVR_TRICK_MARGIN_PX) {
        _snprintf_s(outReason, reasonCap, _TRUNCATE,
                    PX_A("size-minus-%ldx%ld"), dw, dh);
        return true;
    }

    if (topmost && layered && toolwindow && noactivate && h->CoveragePct >= 20) {
        _snprintf_s(outReason, reasonCap, _TRUNCATE,
                    PX_A("topmost-toolwindow-noactivate-cov%lu"), h->CoveragePct);
        return true;
    }

    if (layered && noactivate && h->CoveragePct >= KG_OVR_MIN_COVERAGE_PCT) {
        _snprintf_s(outReason, reasonCap, _TRUNCATE,
                    PX_A("layered-noactivate-cov%lu"), h->CoveragePct);
        return true;
    }

    if (layered && h->CoveragePct >= KG_OVR_NEAR_FULL_PCT) {
        _snprintf_s(outReason, reasonCap, _TRUNCATE,
                    PX_A("layered-fullscreen-cov%lu"), h->CoveragePct);
        return true;
    }

    VIRTUALIZER_END;

    return false;
}

static
BOOL
CALLBACK
OvrEnumProc(
    HWND   hwnd,
    LPARAM lp
)
{
    VIRTUALIZER_START
    BRKIDA;

    KG_OVR_ENUM* ctx = (KG_OVR_ENUM*)lp;
    if (ctx->Count >= ctx->Cap)
        return FALSE;

    if (!LI_USER32(IsWindowVisible)(hwnd))
        return TRUE;

    DWORD pid = 0;
    LI_USER32(GetWindowThreadProcessId)(hwnd, &pid);
    if (pid == 0 || pid == ctx->SelfPid)
        return TRUE;

    LONG style   = (LONG)LI_USER32(GetWindowLongW)(hwnd, GWL_STYLE);
    LONG exStyle = (LONG)LI_USER32(GetWindowLongW)(hwnd, GWL_EXSTYLE);

    RECT rc = { 0 };
    if (!LI_USER32(GetWindowRect)(hwnd, &rc))
        return TRUE;

    if (rc.right - rc.left <= 0 || rc.bottom - rc.top <= 0)
        return TRUE;

    VIRTUALIZER_END

    LONG monW = 0, monH = 0;
    if (!GetMonitorSize(hwnd, &monW, &monH))
        return TRUE;

    KG_OVR_HIT probe = { 0 };
    probe.Hwnd        = hwnd;
    probe.Pid         = pid;
    probe.Style       = (DWORD)style;
    probe.ExStyle     = (DWORD)exStyle;
    probe.Rect        = rc;
    probe.MonitorW    = monW;
    probe.MonitorH    = monH;
    probe.CoveragePct = CoveragePct(&rc, monW, monH);

    char reason[64] = { 0 };
    if (!ClassifyOverlay(&probe, reason, sizeof(reason)))
        return TRUE;

    VIRTUALIZER_START;

    KG_OVR_HIT* h = &ctx->Hits[ctx->Count];
    *h = probe;
    strncpy_s(h->Reason, sizeof(h->Reason), reason, _TRUNCATE);

    LI_USER32(GetClassNameW)(hwnd, h->ClassName, ARRAYSIZE(h->ClassName));
    LI_USER32(GetWindowTextW)(hwnd, h->Title,     ARRAYSIZE(h->Title));

    HANDLE proc = LI_KERNEL(OpenProcess)(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (proc) {
        DWORD n = ARRAYSIZE(h->ExePath);
        if (!LI_KERNEL(QueryFullProcessImageNameW)(proc, 0, h->ExePath, &n))
            h->ExePath[0] = 0;
        LI_KERNEL(CloseHandle)(proc);
    }

    VIRTUALIZER_END;

    if (IsAllowlistedOverlay(h->ClassName, h->ExePath))
        return TRUE;

    ctx->Count++;
    return TRUE;
}

static
void
ReportHit(
    const KG_OVR_HIT* h
)
{
    BRKIDA;
    VIRTUALIZER_START;

    auto fmt = PX_A("{\"className\":\"%s\",\"title\":\"%s\",\"exePath\":\"%s\","
                           "\"pid\":%u,\"style\":\"0x%08X\",\"exStyle\":\"0x%08X\","
                           "\"rect\":{\"l\":%ld,\"t\":%ld,\"r\":%ld,\"b\":%ld},"
                           "\"monitor\":{\"w\":%ld,\"h\":%ld},\"coveragePct\":%lu,"
                           "\"trigger\":\"%s\"}");

    char classU[512], titleU[512], exeU[MAX_PATH * 3 + 1];
    char reasonEsc[128];
    char extras[2048];

    WideToEscapedUtf8(h->ClassName, classU, sizeof(classU));
    WideToEscapedUtf8(h->Title,     titleU, sizeof(titleU));
    WideToEscapedUtf8(h->ExePath,   exeU,   sizeof(exeU));
    JsonEscapeUtf8(h->Reason, reasonEsc, sizeof(reasonEsc));

    _snprintf_s(extras, _TRUNCATE, fmt,
        classU, titleU, exeU,
        (unsigned)h->Pid, (unsigned)h->Style, (unsigned)h->ExStyle,
        h->Rect.left, h->Rect.top, h->Rect.right, h->Rect.bottom,
        h->MonitorW, h->MonitorH, h->CoveragePct, reasonEsc);

    VIRTUALIZER_END

    BYTE* png = NULL; ULONG pngLen = 0;
    CaptureScreenshot(SessionGetSteamId(), h->Reason, &png, &pngLen, NULL, 0);

    char json[4096];
    int jlen = BuildDetectionJson(PX_A("overlay"), h->Reason,
                                  h->ExePath[0] ? h->ExePath : NULL,
                                  NULL, extras, json, sizeof(json));
    ULONG plen  = jlen > 0 ? (ULONG)jlen : 0;
    ULONG effPngLen = pngLen;
    if (4 + plen + effPngLen > 32u * 1024u * 1024u - 4096u) {
        KGDBG(L"[ovr] png too large %lu bytes, sending without screenshot\n", pngLen);
        effPngLen = 0;
    }
    ULONG total = 4 + plen + effPngLen;

    BYTE* payload = (BYTE*)HeapAlloc(GetProcessHeap(), 0, total);
    if (payload) {
        payload[0] = (BYTE)(plen >> 24);
        payload[1] = (BYTE)(plen >> 16);
        payload[2] = (BYTE)(plen >> 8);
        payload[3] = (BYTE)plen;

        if (plen)
            memcpy(payload + 4, json, plen);

        if (effPngLen && png)
            memcpy(payload + 4 + plen, png, effPngLen);

        SessionSendDetection(PX_A("overlay"), h->Reason,
                             h->ExePath[0] ? h->ExePath : NULL,
                             4, payload, total);
        HeapFree(GetProcessHeap(), 0, payload);
    }

    if (png)
        CaptureFree(png);

    KGDBG(L"[ovr] hit hwnd=%p pid=%u ex=0x%08X rect=%ldx%ld mon=%ldx%ld cov=%u%% reason=%hs cls=%ls exe=%ls\n",
          h->Hwnd, h->Pid, h->ExStyle,
          h->Rect.right - h->Rect.left, h->Rect.bottom - h->Rect.top,
          h->MonitorW, h->MonitorH, h->CoveragePct,
          h->Reason, h->ClassName, h->ExePath);
}

static
DWORD
WINAPI
OvrThread(
    LPVOID
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    LI_KERNEL(LoadLibraryW)(pxenc(L"user32.dll"));

    HWND  seen[KG_OVR_SEEN_MAX] = { 0 };
    ULONG seenCount = 0;

    for (;;) {
        DWORD w = LI_KERNEL(WaitForSingleObject)(g_Ovr.StopEvent, KG_OVR_INTERVAL_MS);
        if (w == WAIT_OBJECT_0)
            break;

        KG_OVR_HIT hits[KG_OVR_MAX_HITS];
        KG_OVR_ENUM ctx = { hits, KG_OVR_MAX_HITS, 0, g_Ovr.SelfPid };
        LI_USER32(EnumWindows)(OvrEnumProc, (LPARAM)&ctx);

        for (ULONG i = 0; i < ctx.Count; i++) {
            HWND h = hits[i].Hwnd;
            bool already = false;
            for (ULONG j = 0; j < seenCount; j++) {
                if (seen[j] == h) {
                    already = true;
                    break;
                }
            }

            if (already)
                continue;

            if (seenCount < KG_OVR_SEEN_MAX)
                seen[seenCount++] = h;

            ReportHit(&hits[i]);
        }
    }

    return 0;
}

bool
OverlayScanStart(
    HANDLE StopEvent
)
{
    VIRTUALIZER_START
    BRKIDA;

    if (g_Ovr.Thread)
        return false;

    g_Ovr.StopEvent = StopEvent;
    g_Ovr.SelfPid   = LI_KERNEL(GetCurrentProcessId)();
    g_Ovr.Thread    = LI_KERNEL(CreateThread)(NULL, 0, OvrThread, NULL, 0, NULL);

    VIRTUALIZER_END

    return g_Ovr.Thread != NULL;
}

void
OverlayScanStop(
)
{
    VIRTUALIZER_START
    BRKIDA;

    if (!g_Ovr.Thread)
        return;

    LI_KERNEL(WaitForSingleObject)(g_Ovr.Thread, 3000);
    LI_KERNEL(CloseHandle)(g_Ovr.Thread);
    g_Ovr.Thread = NULL;

    VIRTUALIZER_END
}
