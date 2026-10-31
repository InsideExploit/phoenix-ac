#include "wdainspect.hpp"
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

#ifndef WDA_NONE
#define WDA_NONE               0x00000000
#endif
#ifndef WDA_MONITOR
#define WDA_MONITOR            0x00000001
#endif
#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x00000011
#endif

#define KG_WDA_INTERVAL_MS 5000
#define KG_WDA_MAX_HITS    16
#define KG_WDA_SEEN_MAX    128

typedef struct _KG_WDA_CTX {
    HANDLE Thread;
    HANDLE StopEvent;
} KG_WDA_CTX;

static KG_WDA_CTX g_Wda = { 0 };

typedef struct _KG_WDA_HIT {
    HWND    Hwnd;
    DWORD   Affinity;
    DWORD   Pid;
    wchar_t ClassName[256];
    wchar_t Title[256];
    wchar_t ExePath[MAX_PATH];
} KG_WDA_HIT;

typedef struct _KG_WDA_ENUM {
    KG_WDA_HIT* Hits;
    ULONG       Cap;
    ULONG       Count;
} KG_WDA_ENUM;

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
BOOL
CALLBACK
WdaEnumProc(
    HWND   hwnd,
    LPARAM lp
)
{
    BRKIDA;
    KG_WDA_ENUM* ctx = (KG_WDA_ENUM*)lp;
    if (ctx->Count >= ctx->Cap)
        return FALSE;

    if (!LI_USER32(IsWindowVisible)(hwnd))
        return TRUE;

    VIRTUALIZER_START;

    DWORD aff = 0;
    if (!LI_USER32(GetWindowDisplayAffinity)(hwnd, &aff))
        return TRUE;

    if (aff != WDA_MONITOR && aff != WDA_EXCLUDEFROMCAPTURE)
        return TRUE;

    KG_WDA_HIT* h = &ctx->Hits[ctx->Count];
    memset(h, 0, sizeof(*h));
    h->Hwnd     = hwnd;
    h->Affinity = aff;

    LI_USER32(GetWindowThreadProcessId)(hwnd, &h->Pid);
    LI_USER32(GetClassNameW)(hwnd, h->ClassName, ARRAYSIZE(h->ClassName));
    LI_USER32(GetWindowTextW)(hwnd, h->Title, ARRAYSIZE(h->Title));

    if (h->Pid) {
        HANDLE proc = LI_KERNEL(OpenProcess)(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, h->Pid);
        if (proc) {
            DWORD n = ARRAYSIZE(h->ExePath);
            if (!LI_KERNEL(QueryFullProcessImageNameW)(proc, 0, h->ExePath, &n))
                h->ExePath[0] = 0;
            LI_KERNEL(CloseHandle)(proc);
        }
    }

    VIRTUALIZER_END;

    ctx->Count++;
    return TRUE;
}

static
void
ReportHit(
    const KG_WDA_HIT* h
)
{
    VIRTUALIZER_START;
    BRKIDA;

    const char* reason = (h->Affinity == WDA_EXCLUDEFROMCAPTURE)
                       ? PX_A("wda-exclude-capture")
                       : PX_A("wda-monitor");

    auto fmt = PX_A("{\"className\":\"%s\",\"title\":\"%s\",\"affinity\":%u,\"pid\":%u,\"exePath\":\"%s\"}");

    char classU[512], titleU[512], exeU[MAX_PATH * 3 + 1];
    char extras[2048];

    WideToEscapedUtf8(h->ClassName, classU, sizeof(classU));
    WideToEscapedUtf8(h->Title,     titleU, sizeof(titleU));
    WideToEscapedUtf8(h->ExePath,   exeU,   sizeof(exeU));

    _snprintf_s(extras, _TRUNCATE, fmt,
        classU, titleU, (unsigned)h->Affinity, (unsigned)h->Pid, exeU);

    VIRTUALIZER_END

    BYTE* png = NULL; ULONG pngLen = 0;
    CaptureScreenshot(SessionGetSteamId(), reason, &png, &pngLen, NULL, 0);

    char json[4096];
    int jlen = BuildDetectionJson(PX_A("display-affinity"), reason,
                                  h->ExePath[0] ? h->ExePath : NULL,
                                  NULL, extras, json, sizeof(json));
    ULONG plen  = jlen > 0 ? (ULONG)jlen : 0;
    ULONG effPngLen = pngLen;
if (4 + plen + effPngLen > 32u * 1024u * 1024u - 4096u) effPngLen = 0;
ULONG total = 4 + plen + effPngLen;

    BYTE* payload = (BYTE*)HeapAlloc(GetProcessHeap(), 0, total);
    if (payload) {
        payload[0] = (BYTE)(plen >> 24);
        payload[1] = (BYTE)(plen >> 16);
        payload[2] = (BYTE)(plen >> 8);
        payload[3] = (BYTE)plen;

        if (plen)
            memcpy(payload + 4, json, plen);

        if (effPngLen && png) memcpy(payload + 4 + plen, png, effPngLen);

        SessionSendDetection(PX_A("display-affinity"), reason,
                             h->ExePath[0] ? h->ExePath : NULL,
                             3, payload, total);
        HeapFree(GetProcessHeap(), 0, payload);
    }

    if (png)
        CaptureFree(png);

    KGDBG(L"[wda] hit hwnd=%p aff=%u pid=%u cls=%ls exe=%ls pngLen=%lu\n",
          h->Hwnd, h->Affinity, h->Pid, h->ClassName, h->ExePath, pngLen);
}

static
DWORD
WINAPI
WdaThread(
    LPVOID
)
{
    VIRTUALIZER_START
    BRKIDA;
    LI_KERNEL(LoadLibraryW)(pxenc(L"user32.dll"));

    HWND  seen[KG_WDA_SEEN_MAX] = { 0 };
    ULONG seenCount = 0;
    VIRTUALIZER_END

    for (;;) {
        DWORD w = LI_KERNEL(WaitForSingleObject)(g_Wda.StopEvent, KG_WDA_INTERVAL_MS);
        if (w == WAIT_OBJECT_0)
            break;

        KG_WDA_HIT hits[KG_WDA_MAX_HITS];
        KG_WDA_ENUM ctx = { hits, KG_WDA_MAX_HITS, 0 };
        LI_USER32(EnumWindows)(WdaEnumProc, (LPARAM)&ctx);

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

            if (seenCount < KG_WDA_SEEN_MAX)
                seen[seenCount++] = h;

            ReportHit(&hits[i]);
        }
    }

    return 0;
}

bool
WdaInspectStart(
    HANDLE StopEvent
)
{
    VIRTUALIZER_START
    BRKIDA;

    if (g_Wda.Thread)
        return false;

    g_Wda.StopEvent = StopEvent;
    g_Wda.Thread    = LI_KERNEL(CreateThread)(NULL, 0, WdaThread, NULL, 0, NULL);

    VIRTUALIZER_END

    return g_Wda.Thread != NULL;
}

void
WdaInspectStop(
)
{
    VIRTUALIZER_START
    BRKIDA;

    if (!g_Wda.Thread)
        return;

    LI_KERNEL(WaitForSingleObject)(g_Wda.Thread, 3000);
    LI_KERNEL(CloseHandle)(g_Wda.Thread);

    VIRTUALIZER_END

    g_Wda.Thread = NULL;
}
