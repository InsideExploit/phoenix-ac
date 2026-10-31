#include "agentui.hpp"

#include <windows.h>
#include <winhttp.h>
#include <objbase.h>
#include <shlwapi.h>
#include <wrl.h>
#include <WebView2.h>

#include <stdio.h>
#include <string.h>

#include "../resources.hpp"
#include "../util/util.hpp"
#include "../token/token.hpp"
#include "../guard/guard.hpp"
#include "../service/service.hpp"
#include "../crypto/crypto.hpp"
#include "../capture/capture.hpp"
#include "../dbg.hpp"
#include "../ciguard/ciguard.hpp"
#include "gate/gate.hpp"
#include "pxstr.hpp"
#include "pxenc.hpp"
#include "lazy_importer.hpp"
#include "brkida.hpp"
#include "agent_stubs.hpp"

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "WebView2LoaderStatic.lib")
#pragma comment(lib, "version.lib")

using namespace Microsoft::WRL;

#define KG_UI_W 880
#define KG_UI_H 600
#define WM_KG_POST   (WM_APP + 10)
#define WM_KG_DRAG   (WM_APP + 11)
#define WM_KG_RESIZE (WM_APP + 12)

#if KG_ENV_LOCAL
#define KG_UI_BACKEND_HOST   L"127.0.0.1"
#define KG_UI_BACKEND_PORT   27016
#define KG_UI_BACKEND_SECURE 0
#else
#define KG_UI_BACKEND_HOST   L"api.phoenix-ac.org"
#define KG_UI_BACKEND_PORT   443
#define KG_UI_BACKEND_SECURE 1
#endif

struct KG_UI {
    HWND                                   Hwnd            = NULL;
    ComPtr<ICoreWebView2Controller>        Controller;
    ComPtr<ICoreWebView2>                  Webview;
    EventRegistrationToken                 MsgToken        = { 0 };
    EventRegistrationToken                 ReqToken        = { 0 };

    CRITICAL_SECTION                       Lock            = { 0 };
    wchar_t*                               PendingJson     = NULL;
    HANDLE                                 JsReadyEvent    = NULL;

    HANDLE                                 SetupThread     = NULL;
    HANDLE                                 ProfileThread   = NULL;
    HANDLE                                 PlayThread      = NULL;
    HANDLE                                 WorkerProcess   = NULL;
    HANDLE                                 WorkerJob       = NULL;
    volatile LONG                          PrefetchDone    = 0;
    HANDLE                                 Device          = INVALID_HANDLE_VALUE;
    UINT64                                 SteamId         = 0;
    wchar_t                                SelfPath[MAX_PATH] = { 0 };
    BYTE                                   Token[KG_TOKEN_LEN] = { 0 };
    bool                                   TokenReady      = false;
    volatile LONG                          PlayRequested   = 0;
    volatile LONG                          CloseRequested  = 0;
    volatile LONG                          JsReady         = 0;

    BYTE*                                  LogoBytes       = NULL;
    DWORD                                  LogoLen         = 0;
};

static KG_UI g_Ui;

static
void
PostToJs(
    const wchar_t* json
);

static
wchar_t*
Utf8ToWide(
    const char* s,
    size_t      len
)
{
    VIRTUALIZER_START
    BRKIDA;

    int need = MultiByteToWideChar(CP_UTF8, 0, s, (int)len, NULL, 0);
    if (need <= 0)
        return NULL;

    wchar_t* out = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, (need + 1) * sizeof(wchar_t));
    if (!out)
        return NULL;

    MultiByteToWideChar(CP_UTF8, 0, s, (int)len, out, need);
    out[need] = 0;
    VIRTUALIZER_END

    return out;
}

static
void
EscapeJsonWide(
    const wchar_t* in,
    wchar_t*       out,
    size_t         cap
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    size_t o = 0;
    if (cap == 0)
        return;

    for (size_t i = 0; in && in[i] && o + 8 < cap; i++) {
        wchar_t c = in[i];
        switch (c) {
        case L'"':  out[o++] = L'\\'; out[o++] = L'"';  break;
        case L'\\': out[o++] = L'\\'; out[o++] = L'\\'; break;
        case L'\n': out[o++] = L'\\'; out[o++] = L'n';  break;
        case L'\r': out[o++] = L'\\'; out[o++] = L'r';  break;
        case L'\t': out[o++] = L'\\'; out[o++] = L't';  break;
        default:
            if (c < 0x20)
                o += _snwprintf_s(out + o, cap - o, _TRUNCATE, pxenc(L"\\u%04x"), c);
            else
                out[o++] = c;
        }
    }

    if (o < cap)
        out[o] = 0;
    else
        out[cap - 1] = 0;
}

static
void
UiSendPersona(
    const wchar_t* name,
    UINT64         steamId,
    const wchar_t* avatarUrl
)
{
    BRKIDA;

    wchar_t esc[512];
    wchar_t avEsc[600];
    wchar_t msg[1400];
    EscapeJsonWide(name, esc, ARRAYSIZE(esc));
    EscapeJsonWide(avatarUrl ? avatarUrl : pxenc(L""), avEsc, ARRAYSIZE(avEsc));

    VIRTUALIZER_START
    _snwprintf_s(msg, _TRUNCATE,
        PX_WS(L"{\"type\":\"persona\",\"name\":\"%ls\",\"steamId\":\"%llu\",\"avatar\":\"%ls\"}"),
        esc, (unsigned long long)steamId, avEsc);
    VIRTUALIZER_END

    PostToJs(msg);
}

static
void
UiSendSub(
    const wchar_t* text,
    bool           animated
)
{
    BRKIDA;

    wchar_t esc[256];
    wchar_t msg[400];
    EscapeJsonWide(text, esc, ARRAYSIZE(esc));

    VIRTUALIZER_START
    _snwprintf_s(msg, _TRUNCATE,
        PX_WS(L"{\"type\":\"sub\",\"text\":\"%ls\",\"animated\":%ls}"),
        esc, animated ? pxenc(L"true") : pxenc(L"false"));
    VIRTUALIZER_END

    PostToJs(msg);
}

static
void
UiSendCheck(
    const wchar_t* id,
    const wchar_t* state
)
{
    BRKIDA;

    VIRTUALIZER_START
    wchar_t msg[128];
    _snwprintf_s(msg, _TRUNCATE,
        PX_WS(L"{\"type\":\"check\",\"id\":\"%ls\",\"state\":\"%ls\"}"), id, state);
    VIRTUALIZER_END

    PostToJs(msg);
}

static
void
UiSendReady()
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    PostToJs(PX_WS(L"{\"type\":\"ready\"}"));
}

static
void
UiSendError(
    const wchar_t* msg
)
{
    BRKIDA;

    wchar_t esc[512];
    wchar_t out[600];
    EscapeJsonWide(msg, esc, ARRAYSIZE(esc));

    VIRTUALIZER_START
    _snwprintf_s(out, _TRUNCATE, PX_WS(L"{\"type\":\"error\",\"message\":\"%ls\"}"), esc);
    VIRTUALIZER_END

    PostToJs(out);
}

static
bool
WinHttpGetBuffer(
    const wchar_t* host,
    INTERNET_PORT  port,
    const wchar_t* path,
    BYTE**         outBuf,
    DWORD*         outLen
)
{
    BRKIDA;
    VIRTUALIZER_START

    *outBuf = NULL;
    *outLen = 0;

    HINTERNET s = LI_WINHTTP(WinHttpOpen)(PX_WS(L"PhoenixAgent/1.0"),
                              WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, NULL, NULL, 0);
    if (!s)
        return false;

    HINTERNET c = LI_WINHTTP(WinHttpConnect)(s, host, port, 0);
    if (!c) {
        LI_WINHTTP(WinHttpCloseHandle)(s);
        return false;
    }

    HINTERNET r = LI_WINHTTP(WinHttpOpenRequest)(c, PX_WS(L"GET"), path, NULL, WINHTTP_NO_REFERER,
                                     WINHTTP_DEFAULT_ACCEPT_TYPES,
                                     KG_UI_BACKEND_SECURE ? WINHTTP_FLAG_SECURE : 0);
    if (!r) {
        LI_WINHTTP(WinHttpCloseHandle)(c);
        LI_WINHTTP(WinHttpCloseHandle)(s);
        return false;
    }

    bool ok = false;
    if (LI_WINHTTP(WinHttpSendRequest)(r, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
        && LI_WINHTTP(WinHttpReceiveResponse)(r, NULL)) {
        DWORD status = 0;
        DWORD sz     = sizeof(status);
        LI_WINHTTP(WinHttpQueryHeaders)(r, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, WINHTTP_NO_HEADER_INDEX);
        if (status >= 200 && status < 300) {
            DWORD cap  = 0;
            DWORD used = 0;
            BYTE* buf  = NULL;
            for (;;) {
                DWORD avail = 0;
                if (!LI_WINHTTP(WinHttpQueryDataAvailable)(r, &avail) || avail == 0)
                    break;

                if (used + avail > cap) {
                    DWORD nc = cap ? cap * 2 : 4096;
                    while (nc < used + avail)
                        nc *= 2;

                    BYTE* nb = (BYTE*)(buf ? HeapReAlloc(GetProcessHeap(), 0, buf, nc)
                                           : HeapAlloc(GetProcessHeap(), 0, nc));
                    if (!nb) {
                        if (buf)
                            HeapFree(GetProcessHeap(), 0, buf);
                        buf = NULL;
                        break;
                    }
                    buf = nb;
                    cap = nc;
                }

                DWORD got = 0;
                if (!LI_WINHTTP(WinHttpReadData)(r, buf + used, avail, &got) || got == 0)
                    break;
                used += got;
            }

            if (buf && used) {
                *outBuf = buf;
                *outLen = used;
                ok      = true;
            } else if (buf) {
                HeapFree(GetProcessHeap(), 0, buf);
            }
        }
    }

    LI_WINHTTP(WinHttpCloseHandle)(r);
    LI_WINHTTP(WinHttpCloseHandle)(c);
    LI_WINHTTP(WinHttpCloseHandle)(s);
    VIRTUALIZER_END

    return ok;
}

static
__declspec(noinline)
void
ExtractStringField(
    const char* json,
    const char* key,
    wchar_t*    out,
    size_t      cap
)
{
    BRKIDA;

    if (cap == 0)
        return;

    out[0] = 0;
    auto patFmt = PX_AS("\"%s\"");
    char pat[64];
    _snprintf_s(pat, _TRUNCATE, patFmt, key);

    volatile int _vm_seal = 0;
    const char* p = NULL;
    const char* e = NULL;

    VIRTUALIZER_START
    p = strstr(json, pat);
    if (p) {
        p += strlen(pat);
        while (*p && *p != '"')
            p++;

        if (*p == '"') {
            p++;
            e = p;
            while (*e && *e != '"') {
                if (*e == '\\' && e[1])
                    e += 2;
                else
                    e++;
            }
            if (e <= p)
                e = NULL;
        } else p = NULL;
    }
    VIRTUALIZER_END
    _vm_seal = 1;
    (void)_vm_seal;

    if (!p || !e)
        return;

    int n = MultiByteToWideChar(CP_UTF8, 0, p, (int)(e - p), out, (int)cap - 1);
    if (n > 0)
        out[n] = 0;
}

enum KG_ACCOUNT_STATUS {
    KgAccountUnknown = 0,
    KgAccountActive,
    KgAccountSuspended,
    KgAccountBanned,
    KgAccountDashboard,
};

static
KG_ACCOUNT_STATUS
FetchAccountGate(
    UINT64 steamId
)
{
    BRKIDA;
    KG_ACCOUNT_STATUS result = KgAccountUnknown;

    VIRTUALIZER_START
    wchar_t path[128];
    _snwprintf_s(path, _TRUNCATE, PX_WS(L"/v1/steam/profile?steam_hex=%llx"), (unsigned long long)steamId);

    BYTE* buf = NULL;
    DWORD len = 0;
    if (!WinHttpGetBuffer(PX_WS(KG_UI_BACKEND_HOST), KG_UI_BACKEND_PORT, path, &buf, &len))
        return KgAccountUnknown;

    char* json = (char*)HeapAlloc(GetProcessHeap(), 0, len + 1);
    if (!json) {
        HeapFree(GetProcessHeap(), 0, buf);
        return KgAccountUnknown;
    }
    memcpy(json, buf, len);
    json[len] = 0;
    HeapFree(GetProcessHeap(), 0, buf);

    wchar_t status[32] = { 0 };
    ExtractStringField(json, PX_AS("status"),        status, ARRAYSIZE(status));
    if (!status[0]) ExtractStringField(json, PX_AS("state"),         status, ARRAYSIZE(status));
    if (!status[0]) ExtractStringField(json, PX_AS("accountStatus"), status, ARRAYSIZE(status));

    if      (_wcsicmp(status, PX_WS(L"banned"))    == 0) result = KgAccountBanned;
    else if (_wcsicmp(status, PX_WS(L"bannato"))   == 0) result = KgAccountBanned;
    else if (_wcsicmp(status, PX_WS(L"suspended")) == 0) result = KgAccountSuspended;
    else if (_wcsicmp(status, PX_WS(L"sospeso"))   == 0) result = KgAccountSuspended;
    else if (_wcsicmp(status, PX_WS(L"dashboard")) == 0) result = KgAccountDashboard;
    else if (_wcsicmp(status, PX_WS(L"active"))    == 0) result = KgAccountActive;
    else if (_wcsicmp(status, PX_WS(L"online"))    == 0) result = KgAccountActive;
    else if (_wcsicmp(status, PX_WS(L"offline"))   == 0) result = KgAccountActive;

    if (strstr(json, PX_AS("\"banned\":true"))    || strstr(json, PX_AS("\"banned\": true")))    result = KgAccountBanned;
    if (strstr(json, PX_AS("\"suspended\":true")) || strstr(json, PX_AS("\"suspended\": true"))) result = KgAccountSuspended;
    if (strstr(json, PX_AS("\"is_banned\":true")) || strstr(json, PX_AS("\"is_banned\": true"))) result = KgAccountBanned;
    if (strstr(json, PX_AS("\"isBanned\":true"))  || strstr(json, PX_AS("\"isBanned\": true")))  result = KgAccountBanned;

    HeapFree(GetProcessHeap(), 0, json);
    VIRTUALIZER_END

    return result;
}

static
bool
FetchProfile(
    UINT64   steamId,
    wchar_t* name,
    size_t   nameCap,
    wchar_t* avatar,
    size_t   avatarCap
)
{
    BRKIDA;

    if (name && nameCap)
        name[0] = 0;

    if (avatar && avatarCap)
        avatar[0] = 0;

    VIRTUALIZER_START
    wchar_t path[128];
    _snwprintf_s(path, _TRUNCATE, PX_WS(L"/v1/steam/profile?steam_hex=%llx"), (unsigned long long)steamId);

    BYTE* buf = NULL;
    DWORD len = 0;
    if (!WinHttpGetBuffer(PX_WS(KG_UI_BACKEND_HOST), KG_UI_BACKEND_PORT, path, &buf, &len))
        return false;

    char* json = (char*)HeapAlloc(GetProcessHeap(), 0, len + 1);
    if (!json) {
        HeapFree(GetProcessHeap(), 0, buf);
        return false;
    }
    memcpy(json, buf, len);
    json[len] = 0;
    HeapFree(GetProcessHeap(), 0, buf);

    if (name)   ExtractStringField(json, PX_AS("personaName"), name,   nameCap);
    if (avatar) ExtractStringField(json, PX_AS("avatarFull"),  avatar, avatarCap);

    HeapFree(GetProcessHeap(), 0, json);
    VIRTUALIZER_END

    return name && name[0] != 0;
}

static
__declspec(noinline)
UINT64
QuerySteamIdFromRegistry()
{
    BRKIDA;
    VIRTUALIZER_START

    auto subKey    = PX_WS(L"Software\\Valve\\Steam\\ActiveProcess");
    auto valueName = PX_WS(L"ActiveUser");

    HKEY  key        = NULL;
    DWORD activeUser = 0;
    DWORD sz         = sizeof(activeUser);
    DWORD type       = 0;
    LONG  rc         = ERROR_INVALID_HANDLE;
    volatile int _vm_seal = 0;

    if (LI_ADVAPI(RegOpenKeyExW)(HKEY_CURRENT_USER, subKey, 0, KEY_READ, &key) == ERROR_SUCCESS) {
        rc = LI_ADVAPI(RegQueryValueExW)(key, valueName, NULL, &type,
                                         (LPBYTE)&activeUser, &sz);
        LI_ADVAPI(RegCloseKey)(key);
    }

    if (rc != ERROR_SUCCESS || type != REG_DWORD || activeUser == 0)
        return 0;
    VIRTUALIZER_END

    return 76561197960265728ULL + (UINT64)activeUser;
}

static
DWORD
WINAPI
ProfileThread(
    LPVOID
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    WaitForSingleObject(g_Ui.JsReadyEvent, 10000);

    UINT64 steamId = QuerySteamIdFromRegistry();
    if (steamId == 0) {
        InterlockedExchange(&g_Ui.PrefetchDone, 1);
        return 0;
    }

    wchar_t persona[128] = { 0 };
    wchar_t avatar[600] = { 0 };
    FetchProfile(steamId, persona, ARRAYSIZE(persona), avatar, ARRAYSIZE(avatar));
    if (!persona[0])
        wcscpy_s(persona, PX_WS(L"Player"));
    UiSendPersona(persona, steamId, avatar);

    InterlockedExchange(&g_Ui.PrefetchDone, 1);
    return 0;
}

static
DWORD
WINAPI
SetupThread(
    LPVOID
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    WaitForSingleObject(g_Ui.JsReadyEvent, 10000);

    UiSendSub(PX_WS(L"Enabling privileges"), true);
    if (!EnableLoadDriverPrivilege()) {
        UiSendError(PX_WS(L"Failed to enable load-driver privilege."));
        return 1;
    }

    KG_CI_STATE ciState = CiGuardCheckState();
    if (ciState == KgCiStateEnforcement) {
        if (CiGuardSecureBootEnabled()) {
            LI_USER32(MessageBoxW)(g_Ui.Hwnd,
                PX_WS(L"Windows Driver Signing Policy is in enforcement mode and Secure Boot is enabled.\n\n"
                     L"To play PhoenixAC:\n"
                     L"1. Reboot into your BIOS/UEFI settings\n"
                     L"2. Disable Secure Boot\n"
                     L"3. Save and boot back to Windows\n"
                     L"4. Run this launcher again\n\n"
                     L"The launcher will then remove the enforcement policy automatically, "
                     L"and ask you to reboot and re-enable Secure Boot."),
                PX_WS(L"PhoenixAC: Driver Policy Blocked"),
                MB_OK | MB_ICONWARNING);
            UiSendError(PX_WS(L"Disable Secure Boot in BIOS and run the launcher again."));
            return 1;
        } else {
            UiSendSub(PX_WS(L"Removing driver enforcement policy"), true);
            CiGuardDeletePolicies();
            LI_USER32(MessageBoxW)(g_Ui.Hwnd,
                PX_WS(L"The Windows Driver enforcement policy has been removed.\n\n"
                     L"Next steps:\n"
                     L"1. Restart your PC now\n"
                     L"2. Enter your BIOS/UEFI settings\n"
                     L"3. Re-enable Secure Boot\n"
                     L"4. Boot back to Windows and run this launcher again"),
                PX_WS(L"PhoenixAC: Reboot Required"),
                MB_OK | MB_ICONINFORMATION);
            UiSendError(PX_WS(L"Reboot required. After reboot, re-enable Secure Boot and run again."));
            return 1;
        }
    }

    UiSendSub(PX_WS(L"Installing driver"), true);
    wchar_t sys[MAX_PATH] = { 0 };
    if (!LocateDriverBinary(sys)) {
        UiSendError(PX_WS(L"PhoenixDrv.sys not found next to executable."));
        return 1;
    }
    if (!DriverEnsureInstalled(sys)) {
        UiSendError(PX_WS(L"Failed to install kernel service."));
        return 1;
    }

    DriverStop();
    UiSendSub(PX_WS(L"Starting driver"), true);
    if (!DriverStart()) {
        UiSendError(PX_WS(L"Failed to start kernel service."));
        return 1;
    }

    UiSendSub(PX_WS(L"Opening device"), true);
    HANDLE device = INVALID_HANDLE_VALUE;
    for (int i = 0; i < 20; ++i) {
        device = OpenGuard();
        if (device != INVALID_HANDLE_VALUE)
            break;
        Sleep(100);
    }
    if (device == INVALID_HANDLE_VALUE) {
        UiSendError(PX_WS(L"Cannot open guard device."));
        return 1;
    }
    g_Ui.Device = device;
    UiSendCheck(PX_WS(L"dr"), PX_WS(L"ok"));

    UiSendSub(PX_WS(L"Verifying Steam identity"), true);
    UINT64 steamId = 0;
    if (!QuerySteamId(device, &steamId) || steamId == 0) {
        UiSendError(PX_WS(L"Steam is not running or you are not signed in."));
        return 1;
    }
    g_Ui.SteamId = steamId;
    UiSendCheck(PX_WS(L"st"), PX_WS(L"ok"));

    UiSendSub(PX_WS(L"Verifying system posture"), true);

    wchar_t self[MAX_PATH] = { 0 };
    if (!GetOwnPath(self)) {
        UiSendError(PX_WS(L"Cannot resolve own path."));
        return 1;
    }
    wcscpy_s(g_Ui.SelfPath, self);

    if (!SecureRandom(g_Ui.Token, KG_TOKEN_LEN)) {
        UiSendError(PX_WS(L"Token generation failed."));
        return 1;
    }
    g_Ui.TokenReady = true;

    const wchar_t* base = BasenameOf(self);
    if (!ArmRelaunch(device, base, g_Ui.Token)) {
        DWORD armErr = GetLastError();
        KG_STATUS_REPORT r = { 0 };
        if (QueryGuardStatus(device, &r)) {
            UiSendCheck(PX_WS(L"sb"), (r.SecureBoot == KgStateEnabled) ? pxenc(L"ok") : pxenc(L"fail"));
            UiSendCheck(PX_WS(L"hv"), (r.Hvci       == KgStateEnabled) ? pxenc(L"ok") : pxenc(L"fail"));
        }

        wchar_t msg[256];
        if (armErr == 5906) {
            UiSendError(PX_WS(L"Virtualized environment detected. Boot bare-metal to play."));
        } else if (armErr == 50) {
            UiSendError(PX_WS(L"Secure Boot and HVCI must both be enabled. Enable them and reboot."));
        } else if (armErr == 5) {
            UiSendError(PX_WS(L"Authentication with kernel driver failed. Restart the launcher."));
        } else {
            _snwprintf_s(msg, _TRUNCATE,
                PX_WS(L"Setup failed. Kernel driver rejected arm request (error %lu)."),
                armErr);
            UiSendError(msg);
        }
        return 1;
    }

    UiSendCheck(PX_WS(L"sb"), PX_WS(L"ok"));
    UiSendCheck(PX_WS(L"hv"), PX_WS(L"ok"));
    UiSendSub(PX_WS(L""), false);
    UiSendReady();
    return 0;
}

static
void
PostToJs(
    const wchar_t* json
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    if (!json)
        return;

    if (!InterlockedCompareExchange(&g_Ui.JsReady, 0, 0)) {
        EnterCriticalSection(&g_Ui.Lock);
        if (g_Ui.PendingJson) {
            size_t oldLen = wcslen(g_Ui.PendingJson);
            size_t addLen = wcslen(json);
            wchar_t* combined = (wchar_t*)HeapAlloc(GetProcessHeap(), 0,
                (oldLen + addLen + 2) * sizeof(wchar_t));
            if (combined) {
                wcscpy_s(combined, oldLen + addLen + 2, g_Ui.PendingJson);
                combined[oldLen] = L'\x01';
                wcscpy_s(combined + oldLen + 1, addLen + 1, json);
                HeapFree(GetProcessHeap(), 0, g_Ui.PendingJson);
                g_Ui.PendingJson = combined;
            }
        } else {
            size_t n = wcslen(json);
            g_Ui.PendingJson = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, (n + 1) * sizeof(wchar_t));
            if (g_Ui.PendingJson)
                wcscpy_s(g_Ui.PendingJson, n + 1, json);
        }
        LeaveCriticalSection(&g_Ui.Lock);
        return;
    }

    size_t n = wcslen(json);
    wchar_t* copy = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, (n + 1) * sizeof(wchar_t));
    if (!copy)
        return;
    wcscpy_s(copy, n + 1, json);

    VIRTUALIZER_START
    LI_USER32(PostMessageW)(g_Ui.Hwnd, WM_KG_POST, 0, (LPARAM)copy);
    VIRTUALIZER_END
}

static
void
FlushPending()
{
    BRKIDA;

    EnterCriticalSection(&g_Ui.Lock);
    wchar_t* p = g_Ui.PendingJson;
    g_Ui.PendingJson = NULL;
    LeaveCriticalSection(&g_Ui.Lock);

    if (!p)
        return;

    wchar_t* cur = p;
    while (*cur) {
        wchar_t* nx = cur;
        while (*nx && *nx != L'\x01')
            nx++;

        wchar_t save = *nx;
        *nx = 0;
        if (g_Ui.Webview)
            g_Ui.Webview->PostWebMessageAsJson(cur);
        if (save == 0)
            break;
        cur = nx + 1;
    }

    HeapFree(GetProcessHeap(), 0, p);
}

static
__declspec(noinline)
DWORD
WINAPI
PlayThreadProc(
    LPVOID
)
{
    BRKIDA;

    if (!g_Ui.TokenReady) {
        UiSendError(PX_WS(L"Worker token was not generated."));
        return 1;
    }

    if (g_Ui.Device != INVALID_HANDLE_VALUE) {
        LI_KERNEL(CloseHandle)(g_Ui.Device);
        g_Ui.Device = INVALID_HANDLE_VALUE;
    }

    wchar_t hex[KG_TOKEN_HEX_CHARS + 1] = { 0 };
    TokenToHex(g_Ui.Token, hex);
    SecureZeroMemory(g_Ui.Token, sizeof(g_Ui.Token));

    auto cmdFmt = PX_WS(L"\"%ls\" %ls");
    wchar_t cmd[MAX_PATH * 2] = { 0 };
    _snwprintf_s(cmd, _TRUNCATE, cmdFmt, g_Ui.SelfPath, hex);

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    DWORD flags = CREATE_NO_WINDOW | DETACHED_PROCESS | CREATE_SUSPENDED;
#ifdef KG_DEBUG
    flags = CREATE_NEW_CONSOLE | CREATE_SUSPENDED;
#endif

    BOOL ok = FALSE;
    volatile int _vm_seal = 0;

    VIRTUALIZER_START
    g_Ui.WorkerJob = LI_KERNEL(CreateJobObjectW)(NULL, NULL);
    if (g_Ui.WorkerJob) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jinfo = { 0 };
        jinfo.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
            JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        LI_KERNEL(SetInformationJobObject)(g_Ui.WorkerJob,
            JobObjectExtendedLimitInformation, &jinfo, sizeof(jinfo));
    }
    VIRTUALIZER_END

#if KG_REQUIRE_UPDATER_GATE
    UpdGateSetEnv();
#endif

    VIRTUALIZER_START
    ok = LI_KERNEL(CreateProcessW)(g_Ui.SelfPath, cmd, NULL, NULL, FALSE,
                                   flags, NULL, NULL, &si, &pi);
    SecureZeroMemory(cmd, sizeof(cmd));
    SecureZeroMemory(hex, sizeof(hex));
    if (ok) {
        if (g_Ui.WorkerJob) {
            if (!LI_KERNEL(AssignProcessToJobObject)(g_Ui.WorkerJob, pi.hProcess)) {
                LI_KERNEL(TerminateProcess)(pi.hProcess, 1);
                LI_KERNEL(CloseHandle)(pi.hProcess);
                LI_KERNEL(CloseHandle)(pi.hThread);
                LI_KERNEL(CloseHandle)(g_Ui.WorkerJob);
                g_Ui.WorkerJob = NULL;
                ok = FALSE;
            }
        }
        if (ok) {
            LI_KERNEL(ResumeThread)(pi.hThread);
            LI_KERNEL(CloseHandle)(pi.hThread);
            g_Ui.WorkerProcess = pi.hProcess;
        }
    }
    VIRTUALIZER_END

    _vm_seal = 1;
    (void)_vm_seal;

    if (!ok) {
        UiSendError(PX_WS(L"Failed to launch protected worker."));
        return 1;
    }
    PostToJs(PX_WS(L"{\"type\":\"launched\"}"));

    LI_KERNEL(WaitForSingleObject)(g_Ui.WorkerProcess, INFINITE);
    if (g_Ui.Hwnd)
        LI_USER32(PostMessageW)(g_Ui.Hwnd, WM_CLOSE, 0, 0);
    return 0;
}

static
void
HandleJsMessage(
    const wchar_t* payload
)
{
    BRKIDA;
    VIRTUALIZER_START

    if (!payload)
        return;

    if (wcsstr(payload, PX_WS(L"\"ready-for-events\""))) {
        InterlockedExchange(&g_Ui.JsReady, 1);
        SetEvent(g_Ui.JsReadyEvent);
        FlushPending();
        return;
    }

    if (wcsstr(payload, PX_WS(L"\"drag\""))) {
        LI_USER32(PostMessageW)(g_Ui.Hwnd, WM_KG_DRAG, 0, 0);
        return;
    }

    if (wcsstr(payload, PX_WS(L"\"resize\""))) {
        const wchar_t* p = wcsstr(payload, PX_WS(L"\"h\":"));
        if (p) {
            p += 4;
            while (*p == L' ')
                p++;

            int h = _wtoi(p);
            if (h >= 300 && h <= 1200)
                LI_USER32(PostMessageW)(g_Ui.Hwnd, WM_KG_RESIZE, (WPARAM)h, 0);
        }
        return;
    }

    if (wcsstr(payload, PX_WS(L"\"play\""))) {
        if (InterlockedCompareExchange(&g_Ui.PlayRequested, 1, 0) == 0)
            g_Ui.PlayThread = CreateThread(NULL, 0, PlayThreadProc, NULL, 0, NULL);

        return;
    }

    if (wcsstr(payload, PX_WS(L"\"close-now\"")) ||
        wcsstr(payload, PX_WS(L"\"close\""))) {
        InterlockedExchange(&g_Ui.CloseRequested, 1);
        LI_USER32(PostMessageW)(g_Ui.Hwnd, WM_CLOSE, 0, 0);
        return;
    }
    VIRTUALIZER_END
}

static
bool
LoadLogoBytes()
{
    BRKIDA;
    VIRTUALIZER_START

    HRSRC hr = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_LOGO_PNG), RT_RCDATA);
    if (!hr)
        return false;

    DWORD sz = SizeofResource(NULL, hr);
    HGLOBAL hg = LoadResource(NULL, hr);
    if (!hg || !sz)
        return false;

    LPVOID src = LockResource(hg);
    if (!src)
        return false;

    g_Ui.LogoBytes = (BYTE*)HeapAlloc(GetProcessHeap(), 0, sz);
    if (!g_Ui.LogoBytes)
        return false;

    memcpy(g_Ui.LogoBytes, src, sz);
    g_Ui.LogoLen = sz;
    VIRTUALIZER_END

    return true;
}

static
bool
LoadHtmlBytes(
    char** out,
    DWORD* outLen
)
{
    BRKIDA;
    VIRTUALIZER_START

    HRSRC hr = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_UI_HTML), RT_RCDATA);
    if (!hr)
        return false;

    DWORD sz = SizeofResource(NULL, hr);
    HGLOBAL hg = LoadResource(NULL, hr);
    if (!hg || !sz)
        return false;

    LPVOID src = LockResource(hg);
    if (!src)
        return false;

    char* buf = (char*)HeapAlloc(GetProcessHeap(), 0, sz + 1);
    if (!buf)
        return false;

    memcpy(buf, src, sz);
    buf[sz] = 0;
    *out    = buf;
    *outLen = sz;
    VIRTUALIZER_END

    return true;
}

class ResourceRequestHandler
    : public RuntimeClass<RuntimeClassFlags<ClassicCom>, ICoreWebView2WebResourceRequestedEventHandler>
{
public:
    HRESULT STDMETHODCALLTYPE
    Invoke(
        ICoreWebView2*                              sender,
        ICoreWebView2WebResourceRequestedEventArgs* args
    ) override
    {
        ComPtr<ICoreWebView2WebResourceRequest> req;
        if (FAILED(args->get_Request(&req)))
            return S_OK;

        LPWSTR uri = NULL;
        if (FAILED(req->get_Uri(&uri)) || !uri)
            return S_OK;

        bool hasLogo = wcsstr(uri, pxenc(L"logo.png")) != NULL;
        LI_OLE32(CoTaskMemFree)(uri);
        if (!hasLogo)
            return S_OK;

        ComPtr<ICoreWebView2Environment> env;
        ComPtr<ICoreWebView2_2> wv2;
        sender->QueryInterface(IID_PPV_ARGS(&wv2));
        if (!wv2)
            return S_OK;

        wv2->get_Environment(&env);
        if (!env)
            return S_OK;

        ComPtr<IStream> stream;
        stream.Attach(LI_SHLWAPI(SHCreateMemStream)(g_Ui.LogoBytes, g_Ui.LogoLen));
        if (!stream)
            return S_OK;

        ComPtr<ICoreWebView2WebResourceResponse> resp;
        env->CreateWebResourceResponse(stream.Get(), 200, pxenc(L"OK"),
                                       pxenc(L"Content-Type: image/png"), &resp);
        args->put_Response(resp.Get());
        return S_OK;
    }
};

class MessageReceivedHandler
    : public RuntimeClass<RuntimeClassFlags<ClassicCom>, ICoreWebView2WebMessageReceivedEventHandler>
{
public:
    HRESULT STDMETHODCALLTYPE
    Invoke(
        ICoreWebView2*,
        ICoreWebView2WebMessageReceivedEventArgs* args
    ) override
    {
        LPWSTR json = NULL;
        if (SUCCEEDED(args->get_WebMessageAsJson(&json)) && json) {
            HandleJsMessage(json);
            LI_OLE32(CoTaskMemFree)(json);
        }
        return S_OK;
    }
};

class ControllerHandler
    : public RuntimeClass<RuntimeClassFlags<ClassicCom>,
                          ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>
{
public:
    HRESULT STDMETHODCALLTYPE
    Invoke(
        HRESULT                 result,
        ICoreWebView2Controller* controller
    ) override
    {
        if (FAILED(result) || !controller)
            return S_OK;

        g_Ui.Controller = controller;
        controller->get_CoreWebView2(&g_Ui.Webview);
        if (!g_Ui.Webview)
            return S_OK;

        ComPtr<ICoreWebView2Settings> settings;
        g_Ui.Webview->get_Settings(&settings);
        if (settings) {
            settings->put_IsScriptEnabled(TRUE);
            settings->put_AreDefaultContextMenusEnabled(FALSE);
            settings->put_AreDevToolsEnabled(FALSE);
            settings->put_IsStatusBarEnabled(FALSE);
            settings->put_IsZoomControlEnabled(FALSE);
            settings->put_AreDefaultScriptDialogsEnabled(FALSE);
        }

        ComPtr<ICoreWebView2Controller2> c2;
        controller->QueryInterface(IID_PPV_ARGS(&c2));
        if (c2) {
            COREWEBVIEW2_COLOR bg = { 0, 20, 20, 30 };
            c2->put_DefaultBackgroundColor(bg);
        }

        RECT rc;
        LI_USER32(GetClientRect)(g_Ui.Hwnd, &rc);
        controller->put_Bounds(rc);

        g_Ui.Webview->AddWebResourceRequestedFilter(pxenc(L"app://*"), COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL);
        auto reqH = Make<ResourceRequestHandler>();
        g_Ui.Webview->add_WebResourceRequested(reqH.Get(), &g_Ui.ReqToken);

        auto msgH = Make<MessageReceivedHandler>();
        g_Ui.Webview->add_WebMessageReceived(msgH.Get(), &g_Ui.MsgToken);

        char* html = NULL;
        DWORD htmlLen = 0;
        if (LoadHtmlBytes(&html, &htmlLen)) {
            wchar_t* w = Utf8ToWide(html, htmlLen);
            HeapFree(GetProcessHeap(), 0, html);
            if (w) {
                g_Ui.Webview->NavigateToString(w);
                HeapFree(GetProcessHeap(), 0, w);
            }
        }
        return S_OK;
    }
};

class EnvHandler
    : public RuntimeClass<RuntimeClassFlags<ClassicCom>,
                          ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>
{
public:
    HRESULT STDMETHODCALLTYPE
    Invoke(
        HRESULT                  result,
        ICoreWebView2Environment* env
    ) override
    {
        if (FAILED(result) || !env)
            return S_OK;

        auto h = Make<ControllerHandler>();
        env->CreateCoreWebView2Controller(g_Ui.Hwnd, h.Get());
        return S_OK;
    }
};

static
LRESULT
CALLBACK
UiWndProc(
    HWND   h,
    UINT   m,
    WPARAM w,
    LPARAM l
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    switch (m) {
    case WM_SIZE:
        if (g_Ui.Controller) {
            RECT rc;
            LI_USER32(GetClientRect)(h, &rc);
            g_Ui.Controller->put_Bounds(rc);
        }
        return 0;

    case WM_KG_POST: {
        wchar_t* json = (wchar_t*)l;
        if (json) {
            if (g_Ui.Webview)
                g_Ui.Webview->PostWebMessageAsJson(json);
            HeapFree(GetProcessHeap(), 0, json);
        }
        return 0;
    }

    case WM_KG_DRAG:
        LI_USER32(ReleaseCapture)();
        LI_USER32(SendMessageW)(h, WM_NCLBUTTONDOWN, HTCAPTION, 0);
        return 0;

    case WM_KG_RESIZE: {
        int newH = (int)w;
        RECT rc;
        LI_USER32(GetWindowRect)(h, &rc);
        int curH = rc.bottom - rc.top;
        if (newH == curH)
            return 0;

        int curCenterY = rc.top + curH / 2;
        int newY = curCenterY - newH / 2;
        LI_USER32(SetWindowPos)(h, NULL, rc.left, newY, KG_UI_W, newH,
                     SWP_NOZORDER | SWP_NOACTIVATE);
        HRGN newRgn = LI_GDI32(CreateRoundRectRgn)(0, 0, KG_UI_W + 1, newH + 1, 18, 18);
        LI_USER32(SetWindowRgn)(h, newRgn, TRUE);
        return 0;
    }

    case WM_NCHITTEST: {
        LRESULT hit = LI_USER32(DefWindowProcW)(h, m, w, l);
        return hit;
    }

    case WM_CLOSE:
        LI_USER32(DestroyWindow)(h);
        return 0;

    case WM_DESTROY:
        if (g_Ui.Controller)
            g_Ui.Controller->Close();
        g_Ui.Controller = nullptr;
        g_Ui.Webview = nullptr;
        LI_USER32(PostQuitMessage)(0);
        return 0;
    }
    return LI_USER32(DefWindowProcW)(h, m, w, l);
}

enum KG_INSECURE_BOOT_STATE {
    KgBootSecure = 0,
    KgBootKernelDebug,
    KgBootTestSigning,
    KgBootNoIntegrityChecks,
};

#ifndef KG_NTSTATUS_DEFINED
#define KG_NTSTATUS_DEFINED
typedef LONG KG_NTSTATUS;
#define KG_NT_SUCCESS(s) ((KG_NTSTATUS)(s) >= 0)
#endif

typedef KG_NTSTATUS (NTAPI *KG_NtQSI_t)(ULONG, PVOID, ULONG, PULONG);

static
KG_INSECURE_BOOT_STATE
CheckInsecureBootMode()
{
    BRKIDA;
#if !KG_ENFORCE_SECURE_BOOTMODE
    return KgBootSecure;
#else
    __try {
        volatile UCHAR* kdEnabled = (volatile UCHAR*)(0x7FFE02D4);
        if (*kdEnabled != 0)
            return KgBootKernelDebug;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    HMODULE ntdll = LI_KERNEL(GetModuleHandleW)(pxenc(L"ntdll.dll"));
    if (!ntdll)
        return KgBootSecure;

    KG_NtQSI_t NtQSI = (KG_NtQSI_t)LI_KERNEL(GetProcAddress)(ntdll, pxenc("NtQuerySystemInformation"));
    if (!NtQSI)
        return KgBootSecure;

    typedef struct {
        ULONG Length;
        ULONG CodeIntegrityOptions;
    } KG_CI_INFO;

    KG_CI_INFO info = { sizeof(KG_CI_INFO), 0 };
    ULONG got = 0;
    KG_NTSTATUS s = NtQSI(103, &info, sizeof(info), &got);
    if (!KG_NT_SUCCESS(s))
        return KgBootSecure;

    if (info.CodeIntegrityOptions & 0x02)
        return KgBootTestSigning;

    if ((info.CodeIntegrityOptions & 0x01) == 0)
        return KgBootNoIntegrityChecks;

    return KgBootSecure;
#endif
}

static
const char*
InsecureBootReasonStr(
    KG_INSECURE_BOOT_STATE s
)
{
    switch (s) {
        case KgBootKernelDebug:       return PX_A("kernel-debug");
        case KgBootTestSigning:       return PX_A("test-signing");
        case KgBootNoIntegrityChecks: return PX_A("no-integrity-checks");
        default:                       return PX_A("unknown");
    }
}

static
void
Base64Encode(
    const BYTE* in,
    size_t      inLen,
    char*       out,
    size_t      outCap
)
{
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = 0;
    for (size_t i = 0; i < inLen; i += 3) {
        if (o + 5 >= outCap)
            break;

        UINT32 a = i < inLen ? in[i] : 0;
        UINT32 b = i + 1 < inLen ? in[i + 1] : 0;
        UINT32 c = i + 2 < inLen ? in[i + 2] : 0;
        UINT32 v = (a << 16) | (b << 8) | c;
        out[o++] = T[(v >> 18) & 0x3F];
        out[o++] = T[(v >> 12) & 0x3F];
        out[o++] = i + 1 < inLen ? T[(v >> 6) & 0x3F] : '=';
        out[o++] = i + 2 < inLen ? T[v & 0x3F]       : '=';
    }

    if (o < outCap)
        out[o] = 0;
    else
        out[outCap - 1] = 0;
}

static
bool
WinHttpPostBody(
    const wchar_t* host,
    INTERNET_PORT  port,
    const wchar_t* path,
    const char*    body,
    DWORD          bodyLen
)
{
    BRKIDA;
    VIRTUALIZER_START

    HINTERNET s = LI_WINHTTP(WinHttpOpen)(PX_WS(L"PhoenixAgent/1.0"),
                              WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, NULL, NULL, 0);
    if (!s)
        return false;

    HINTERNET c = LI_WINHTTP(WinHttpConnect)(s, host, port, 0);
    if (!c) {
        LI_WINHTTP(WinHttpCloseHandle)(s);
        return false;
    }

    HINTERNET r = LI_WINHTTP(WinHttpOpenRequest)(c, PX_WS(L"POST"), path, NULL, WINHTTP_NO_REFERER,
                                     WINHTTP_DEFAULT_ACCEPT_TYPES,
                                     KG_UI_BACKEND_SECURE ? WINHTTP_FLAG_SECURE : 0);
    if (!r) {
        LI_WINHTTP(WinHttpCloseHandle)(c);
        LI_WINHTTP(WinHttpCloseHandle)(s);
        return false;
    }

    auto headers = PX_WS(L"Content-Type: application/json\r\n");
    bool ok = false;
    if (LI_WINHTTP(WinHttpSendRequest)(r, headers, (DWORD)-1L, (LPVOID)body, bodyLen, bodyLen, 0)
        && LI_WINHTTP(WinHttpReceiveResponse)(r, NULL)) {
        DWORD status = 0;
        DWORD sz     = sizeof(status);
        LI_WINHTTP(WinHttpQueryHeaders)(r, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, WINHTTP_NO_HEADER_INDEX);
        ok = (status >= 200 && status < 300);
    }

    LI_WINHTTP(WinHttpCloseHandle)(r);
    LI_WINHTTP(WinHttpCloseHandle)(c);
    LI_WINHTTP(WinHttpCloseHandle)(s);
    VIRTUALIZER_END

    return ok;
}

static
void
ReportInsecureBoot(
    UINT64                 steamId,
    KG_INSECURE_BOOT_STATE state
)
{
    BRKIDA;
    const char* reason = InsecureBootReasonStr(state);

    BYTE* png    = NULL;
    ULONG pngLen = 0;
    CaptureScreenshot(steamId, reason, &png, &pngLen, NULL, 0);

    size_t b64Cap = (pngLen ? ((pngLen + 2) / 3) * 4 + 4 : 4);
    char* b64 = (char*)HeapAlloc(GetProcessHeap(), 0, b64Cap);
    if (b64) {
        if (pngLen && png)
            Base64Encode(png, pngLen, b64, b64Cap);
        else
            b64[0] = 0;
    }

    size_t bodyCap = (b64 ? b64Cap : 0) + 512;
    char* body = (char*)HeapAlloc(GetProcessHeap(), 0, bodyCap);
    if (body) {
        _snprintf_s(body, bodyCap, _TRUNCATE,
                    PX_AS("{\"steam_hex\":\"%llx\",\"reason\":\"%s\",\"screenshot_b64\":\"%s\"}"),
                    (unsigned long long)steamId, reason, b64 ? b64 : "");
        WinHttpPostBody(PX_WS(KG_UI_BACKEND_HOST), KG_UI_BACKEND_PORT,
                        PX_WS(L"/v1/detection/insecure-boot"), body, (DWORD)strlen(body));
        HeapFree(GetProcessHeap(), 0, body);
    }

    if (b64)
        HeapFree(GetProcessHeap(), 0, b64);
    if (png)
        CaptureFree(png);
}

int
AgentUiRun()
{
    BRKIDA;
    LI_KERNEL(LoadLibraryW)(pxenc(L"user32.dll"));
    LI_KERNEL(LoadLibraryW)(pxenc(L"gdi32.dll"));

    {
        KG_INSECURE_BOOT_STATE bootState = CheckInsecureBootMode();
        if (bootState != KgBootSecure) {
            UINT64 sid = QuerySteamIdFromRegistry();
            if (sid != 0)
                ReportInsecureBoot(sid, bootState);

            LI_USER32(MessageBoxW)(NULL,
                PX_WS(L"Your Windows boot configuration is insecure.\n\n"
                     L"Test mode must be turned off to continue."),
                PX_WS(L"Phoenix Anti-Cheat"), MB_OK | MB_ICONERROR);
            return 1;
        }
    }

    {
        UINT64 gateSteamId = QuerySteamIdFromRegistry();
        if (gateSteamId == 0) {
            LI_USER32(MessageBoxW)(NULL,
                PX_WS(L"Steam is not running or you are not signed in.\n\n"
                     L"Sign into Steam, then relaunch the Phoenix launcher."),
                PX_WS(L"Phoenix Anti-Cheat"), MB_OK | MB_ICONERROR);
            return 1;
        }

        KG_ACCOUNT_STATUS gate = FetchAccountGate(gateSteamId);
        if (gate == KgAccountBanned) {
            LI_USER32(MessageBoxW)(NULL,
                PX_WS(L"This account is banned.\n\n"
                     L"You are not allowed to play on ENVEART."),
                PX_WS(L"Phoenix Anti-Cheat"), MB_OK | MB_ICONERROR);
            return 1;
        }
        if (gate == KgAccountSuspended) {
            LI_USER32(MessageBoxW)(NULL,
                PX_WS(L"This account is suspended.\n\n"
                     L"The Phoenix launcher is not required while your account is under review - you can join ENVEART directly without it."),
                PX_WS(L"Phoenix Anti-Cheat"), MB_OK | MB_ICONINFORMATION);
            return 0;
        }
        if (gate == KgAccountDashboard) {
            LI_USER32(MessageBoxW)(NULL,
                PX_WS(L"This account is not enrolled for Phoenix protection.\n\n"
                     L"The Phoenix launcher is not required for this account - you can join ENVEART directly without it."),
                PX_WS(L"Phoenix Anti-Cheat"), MB_OK | MB_ICONINFORMATION);
            return 0;
        }
        if (gate != KgAccountActive) {
            LI_USER32(MessageBoxW)(NULL,
                PX_WS(L"Could not verify account status with the backend.\n\n"
                     L"Check your internet connection and try again."),
                PX_WS(L"Phoenix Anti-Cheat"), MB_OK | MB_ICONERROR);
            return 1;
        }
    }

    LI_OLE32(CoInitializeEx)(NULL, COINIT_APARTMENTTHREADED);

    InitializeCriticalSection(&g_Ui.Lock);
    g_Ui.JsReadyEvent = LI_KERNEL(CreateEventW)(NULL, TRUE, FALSE, NULL);
    g_Ui.Device = INVALID_HANDLE_VALUE;
    LoadLogoBytes();

    VIRTUALIZER_START
    HMODULE hSelf    = LI_KERNEL(GetModuleHandleW)(NULL);
    HICON   hAppIcon = LI_USER32(LoadIconW)(hSelf, MAKEINTRESOURCEW(IDI_APP_ICON));

    auto wndClassName = PX_WS(L"PhoenixAgentUI");
    WNDCLASSEXW wc = { sizeof(wc) };
    wc.lpfnWndProc   = UiWndProc;
    wc.hInstance     = hSelf;
    wc.hCursor       = LI_USER32(LoadCursorW)(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)LI_GDI32(GetStockObject)(BLACK_BRUSH);
    wc.lpszClassName = wndClassName;
    wc.hIcon         = hAppIcon;
    wc.hIconSm       = hAppIcon;
    LI_USER32(RegisterClassExW)(&wc);

    int sw = LI_USER32(GetSystemMetrics)(SM_CXSCREEN);
    int sh = LI_USER32(GetSystemMetrics)(SM_CYSCREEN);
    int x = (sw - KG_UI_W) / 2;
    int y = (sh - KG_UI_H) / 2;

    g_Ui.Hwnd = LI_USER32(CreateWindowExW)(WS_EX_APPWINDOW, PX_WS(L"PhoenixAgentUI"),
                                PX_WS(L"Phoenix Anti-Cheat"),
                                WS_POPUP | WS_VISIBLE,
                                x, y, KG_UI_W, KG_UI_H,
                                NULL, NULL, wc.hInstance, NULL);
    if (!g_Ui.Hwnd) {
        LI_OLE32(CoUninitialize)();
        return 1;
    }

    HRGN rgn = LI_GDI32(CreateRoundRectRgn)(0, 0, KG_UI_W + 1, KG_UI_H + 1, 18, 18);
    LI_USER32(SetWindowRgn)(g_Ui.Hwnd, rgn, TRUE);

    LI_USER32(ShowWindow)(g_Ui.Hwnd, SW_SHOW);
    LI_USER32(UpdateWindow)(g_Ui.Hwnd);
    VIRTUALIZER_END

    wchar_t udf[MAX_PATH] = { 0 };
    DWORD udfLen = LI_KERNEL(GetEnvironmentVariableW)(pxenc(L"LOCALAPPDATA"), udf, MAX_PATH);
    if (udfLen == 0 || udfLen >= MAX_PATH) {
        LI_USER32(DestroyWindow)(g_Ui.Hwnd);
        LI_OLE32(CoUninitialize)();
        return 1;
    }
    wcscat_s(udf, MAX_PATH, PX_WS(L"\\PhoenixAC"));
    LI_KERNEL(CreateDirectoryW)(udf, NULL);
    wcscat_s(udf, MAX_PATH, PX_WS(L"\\WebView2"));
    LI_KERNEL(CreateDirectoryW)(udf, NULL);

    auto env = Make<EnvHandler>();
    HRESULT hr = CreateCoreWebView2EnvironmentWithOptions(nullptr, udf, nullptr, env.Get());
    if (FAILED(hr)) {
        LI_USER32(MessageBoxW)(g_Ui.Hwnd,
            PX_WS(L"WebView2 Runtime is not installed on this system.\n\n"
                 L"Install Microsoft Edge WebView2 Runtime from Microsoft's website and try again."),
            PX_WS(L"Phoenix Anti-Cheat"), MB_OK | MB_ICONERROR);
        LI_USER32(DestroyWindow)(g_Ui.Hwnd);
        LI_OLE32(CoUninitialize)();
        return 1;
    }

    VIRTUALIZER_START
    g_Ui.ProfileThread = LI_KERNEL(CreateThread)(NULL, 0, ProfileThread, NULL, 0, NULL);
    g_Ui.SetupThread   = LI_KERNEL(CreateThread)(NULL, 0, SetupThread,   NULL, 0, NULL);
    VIRTUALIZER_END

    MSG msg;
    while (LI_USER32(GetMessageW)(&msg, NULL, 0, 0)) {
        LI_USER32(TranslateMessage)(&msg);
        LI_USER32(DispatchMessageW)(&msg);
    }

    VIRTUALIZER_START
    if (g_Ui.SetupThread) {
        LI_KERNEL(WaitForSingleObject)(g_Ui.SetupThread, 3000);
        LI_KERNEL(CloseHandle)(g_Ui.SetupThread);
    }
    if (g_Ui.ProfileThread) {
        LI_KERNEL(WaitForSingleObject)(g_Ui.ProfileThread, 3000);
        LI_KERNEL(CloseHandle)(g_Ui.ProfileThread);
    }
    if (g_Ui.PlayThread) {
        LI_KERNEL(WaitForSingleObject)(g_Ui.PlayThread, 5000);
        LI_KERNEL(CloseHandle)(g_Ui.PlayThread);
    }

    int rc = 0;
    if (g_Ui.WorkerProcess) {
        LI_KERNEL(WaitForSingleObject)(g_Ui.WorkerProcess, INFINITE);
        LI_KERNEL(CloseHandle)(g_Ui.WorkerProcess);
        g_Ui.WorkerProcess = NULL;
    }
    if (g_Ui.WorkerJob) {
        LI_KERNEL(CloseHandle)(g_Ui.WorkerJob);
        g_Ui.WorkerJob = NULL;
    }

    if (g_Ui.Device != INVALID_HANDLE_VALUE)
        LI_KERNEL(CloseHandle)(g_Ui.Device);
    if (g_Ui.LogoBytes)
        HeapFree(GetProcessHeap(), 0, g_Ui.LogoBytes);
    if (g_Ui.JsReadyEvent)
        LI_KERNEL(CloseHandle)(g_Ui.JsReadyEvent);
    DeleteCriticalSection(&g_Ui.Lock);
    LI_OLE32(CoUninitialize)();
    VIRTUALIZER_END

    return rc;
}
