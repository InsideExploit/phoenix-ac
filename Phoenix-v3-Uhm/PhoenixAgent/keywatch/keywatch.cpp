#include "keywatch.hpp"
#include <windows.h>
#include <string.h>
#include "../session/session.hpp"
#include "../capture/capture.hpp"
#include "../report/report.hpp"
#include "../dbg.hpp"
#include "pxstr.hpp"
#include "lazy_importer.hpp"
#include "brkida.hpp"
#include "agent_stubs.hpp"

typedef struct _KG_KW_CTX {
    HANDLE StopEvent;
    HANDLE Thread;
    HHOOK  Hook;
} KG_KW_CTX;

static KG_KW_CTX g_Kw = { 0 };

#define KG_KW_COOLDOWN_MS 5000ULL
static volatile ULONGLONG g_LastHitAt = 0;

static __declspec(noinline)
void
ReportSuspKey(
    const wchar_t* keyLabel,
    const char*    reasonAscii
)
{
    BRKIDA;
    LI_KERNEL(Sleep)(1500);

    auto type_str = PX_A("susp-key");

    BYTE* png = NULL; ULONG pngLen = 0;
    CaptureScreenshot(SessionGetSteamId(), reasonAscii, &png, &pngLen, NULL, 0);

    char json[2048];
    int jlen = BuildDetectionJson(type_str, reasonAscii,
        keyLabel, NULL, NULL,
        json, sizeof(json));

    ULONG plen    = jlen > 0 ? (ULONG)jlen : 0;
    ULONG effPngLen = pngLen;
if (4 + plen + effPngLen > 32u * 1024u * 1024u - 4096u) effPngLen = 0;
ULONG total   = 4 + plen + effPngLen;
    BYTE* payload = (BYTE*)HeapAlloc(GetProcessHeap(), 0, total);
    if (!payload) {
        if (png) CaptureFree(png);
        return;
    }

    VIRTUALIZER_START
    payload[0] = (BYTE)(plen >> 24);
    payload[1] = (BYTE)(plen >> 16);
    payload[2] = (BYTE)(plen >> 8);
    payload[3] = (BYTE)plen;
    if (plen)          memcpy(payload + 4, json, plen);
    if (effPngLen && png) memcpy(payload + 4 + plen, png, effPngLen);
    SessionSendDetection(type_str, reasonAscii, keyLabel, 3, payload, total);
    VIRTUALIZER_END

    HeapFree(GetProcessHeap(), 0, payload);
    if (png) CaptureFree(png);
}

typedef struct _KG_KW_JOB {
    const wchar_t* KeyLabel;
    const char*    Reason;
} KG_KW_JOB;

static
VOID
CALLBACK
KwWorkCallback(
    PTP_CALLBACK_INSTANCE,
    PVOID Context
)
{
    BRKIDA;
    KG_KW_JOB* job = (KG_KW_JOB*)Context;
    if (!job) return;

    ReportSuspKey(job->KeyLabel, job->Reason);
    HeapFree(GetProcessHeap(), 0, job);
}

static
LRESULT
CALLBACK
LowLevelKbdProc(
    int    nCode,
    WPARAM wParam,
    LPARAM lParam
)
{
    BRKIDA;
    if (nCode != HC_ACTION) return LI_USER32(CallNextHookEx)(NULL, nCode, wParam, lParam);
    if (wParam != WM_KEYDOWN && wParam != WM_SYSKEYDOWN)
        return LI_USER32(CallNextHookEx)(NULL, nCode, wParam, lParam);

    KBDLLHOOKSTRUCT* kb = (KBDLLHOOKSTRUCT*)lParam;

    const wchar_t* keyLabel = NULL;
    const char*    reason   = NULL;
    switch (kb->vkCode) {
    case VK_HOME:   keyLabel = PX_W(L"HOME");     reason = PX_A("susp-key-HOME");     break;
    case VK_INSERT: keyLabel = PX_W(L"INSERT");   reason = PX_A("susp-key-INSERT");   break;
    case VK_DELETE: keyLabel = PX_W(L"DELETE");   reason = PX_A("susp-key-DELETE");   break;
    case VK_PRIOR:  keyLabel = PX_W(L"PAGEUP");   reason = PX_A("susp-key-PAGEUP");   break;
    case VK_NEXT:   keyLabel = PX_W(L"PAGEDOWN"); reason = PX_A("susp-key-PAGEDOWN"); break;
    default:
        return LI_USER32(CallNextHookEx)(NULL, nCode, wParam, lParam);
    }

    ULONGLONG now  = GetTickCount64();
    ULONGLONG last = g_LastHitAt;
    if (last != 0 && now - last < KG_KW_COOLDOWN_MS)
        return LI_USER32(CallNextHookEx)(NULL, nCode, wParam, lParam);

    g_LastHitAt = now;

    KGDBG(L"[kw] hit key=%ls vk=0x%02X\n", keyLabel, kb->vkCode);

    KG_KW_JOB* job = (KG_KW_JOB*)HeapAlloc(GetProcessHeap(), 0, sizeof(KG_KW_JOB));
    if (job) {
        job->KeyLabel = keyLabel;
        job->Reason   = reason;
        if (!TrySubmitThreadpoolCallback(KwWorkCallback, job, NULL))
            HeapFree(GetProcessHeap(), 0, job);
    }

    return LI_USER32(CallNextHookEx)(NULL, nCode, wParam, lParam);
}

static
DWORD
WINAPI
KwThread(
    LPVOID
)
{
    BRKIDA;
    KGDBG(L"[kw] thread start\n");

    VIRTUALIZER_START
    HMODULE self = GetModuleHandleW(NULL);
    g_Kw.Hook = LI_USER32(SetWindowsHookExW)(WH_KEYBOARD_LL, LowLevelKbdProc, self, 0);
    if (!g_Kw.Hook) {
        KGDBG(L"[kw] SetWindowsHookExW failed err=%lu\n", GetLastError());
        return 1;
    }
    KGDBG(L"[kw] hook installed\n");
    VIRTUALIZER_END

    for (;;) {
        DWORD w = LI_USER32(MsgWaitForMultipleObjectsEx)(
            1, &g_Kw.StopEvent, INFINITE, QS_ALLINPUT, MWMO_INPUTAVAILABLE);
        if (w == WAIT_OBJECT_0) break;

        MSG msg;
        while (LI_USER32(PeekMessageW)(&msg, NULL, 0, 0, PM_REMOVE)) {
            LI_USER32(TranslateMessage)(&msg);
            LI_USER32(DispatchMessageW)(&msg);
        }
    }

    if (g_Kw.Hook) {
        LI_USER32(UnhookWindowsHookEx)(g_Kw.Hook);
        g_Kw.Hook = NULL;
    }

    KGDBG(L"[kw] thread exit\n");
    return 0;
}

bool
KeyWatchStart(
    HANDLE StopEvent
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    if (g_Kw.Thread) return false;
    g_Kw.StopEvent = StopEvent;
    g_Kw.Thread    = LI_KERNEL(CreateThread)(NULL, 0, KwThread, NULL, 0, NULL);
    return g_Kw.Thread != NULL;
}

void
KeyWatchStop(
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    if (!g_Kw.Thread) return;
    LI_KERNEL(WaitForSingleObject)(g_Kw.Thread, 3000);
    LI_KERNEL(CloseHandle)(g_Kw.Thread);
    g_Kw.Thread = NULL;
}
