#include "netmon.hpp"
#include <windows.h>
#include <winsock2.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <stdio.h>
#include "shared.hpp"
#include "../dbg.hpp"
#include "../session/session.hpp"
#include "../capture/capture.hpp"
#include "../report/report.hpp"
#include "pxstr.hpp"
#include "pxenc.hpp"
#include "lazy_importer.hpp"
#include "brkida.hpp"
#include "agent_stubs.hpp"

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ntdll.lib")

#if KG_NETMON_DEBUG_LOG
#define NETMON_DBG(fmt, ...) do {                                       \
    char _dbg[1600];                                                    \
    _snprintf_s(_dbg, _TRUNCATE, PX_A(fmt), ##__VA_ARGS__);             \
    OutputDebugStringA(_dbg);                                           \
} while (0)
#else
#define NETMON_DBG(fmt, ...) ((void)0)
#endif

static HANDLE      g_Device         = INVALID_HANDLE_VALUE;
static HANDLE      g_TcpThread      = NULL;
static HANDLE      g_EtwThread      = NULL;
static HANDLE      g_StopEvent      = NULL;
static TRACEHANDLE g_SessionHandle  = 0;
static TRACEHANDLE g_ConsumerHandle = INVALID_PROCESSTRACE_HANDLE;

static const GUID KG_ETW_SESSION_GUID = {
    0x8ea8bd12, 0x77b8, 0x4a83, { 0x94, 0x2d, 0x1a, 0x07, 0x66, 0xef, 0x5c, 0x11 } };

static const GUID KG_ETW_WININET_GUID = {
    0x43d1a55c, 0x76d6, 0x4f7e, { 0x99, 0x5c, 0x64, 0xc7, 0x11, 0xe5, 0xca, 0xfe } };
static const GUID KG_ETW_WINHTTP_GUID = {
    0x7d44233d, 0x3055, 0x4b9c, { 0xba, 0x64, 0x0d, 0x47, 0xca, 0x40, 0xa2, 0x32 } };
static const GUID KG_ETW_HTTPSVC_GUID = {
    0xdd5ef90a, 0x6398, 0x47a4, { 0xad, 0x34, 0x4d, 0xce, 0xcd, 0xef, 0x79, 0x5f } };
static const GUID KG_ETW_DNS_CLIENT_GUID = {
    0x1c95126e, 0x7eea, 0x49a9, { 0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d } };

static
__declspec(noinline)
const char*
HostMatchesCheat(
    const wchar_t* Host
)
{
    BRKIDA;
    volatile int _vm_seal = 0;
    VIRTUALIZER_START

    if (!Host || !*Host)
        return NULL;

    size_t hLen = wcslen(Host);

    struct { const wchar_t* suffix; const char* brand; } entries[] = {
        { PX_W(L"susano.gg"),              PX_A("Susano")             },
        { PX_W(L"susano.re"),              PX_A("Susano")             },
        { PX_W(L"ecstasy.zip"),            PX_A("Ecstasy")            },
        { PX_W(L"eulen.gg"),               PX_A("Eulen Cheat")        },
        { PX_W(L"keyauth.win"),            PX_A("Generic Cheat Auth") },
        { PX_W(L"hxsoftwares.com"),        PX_A("HX Software")        },
        { PX_W(L"keyser-api.eu"),          PX_A("Keyser Cheat")       },
        { PX_W(L"keyser-dashboard.com"),   PX_A("Keyser Cheat")       },
        { PX_W(L"mrcheat-api.ir"),         PX_A("Mr Cheat")           },
        { PX_W(L"mrcheat.cc"),             PX_A("Mr Cheat")           },
        { PX_W(L"skript.gg"),              PX_A("Skript Cheat")       },
    };

    for (size_t i = 0; i < sizeof(entries) / sizeof(entries[0]); i++) {
        const wchar_t* suffix = entries[i].suffix;
        size_t sLen = wcslen(suffix);

        if (hLen < sLen)
            continue;

        if (_wcsicmp(Host + hLen - sLen, suffix) == 0) {
            if (hLen == sLen || Host[hLen - sLen - 1] == L'.') {
                _vm_seal = 1;
                (void)_vm_seal;
                return entries[i].brand;
            }
        }
    }

    VIRTUALIZER_END

    _vm_seal = 1;
    (void)_vm_seal;
    return NULL;
}

static
__declspec(noinline)
const char*
TcpMatchesCheat(
    UINT16      Family,
    const UINT8 Addr[16],
    UINT16      Port
)
{
    BRKIDA;
    volatile int _vm_seal = 0;
    VIRTUALIZER_START

    if (Family != AF_INET)
        return NULL;

    struct { UINT8 ip[4]; UINT16 port; const char* brand; } entries[] = {
        { {3, 235, 182, 71}, 7777, PX_A("Eulen Cheat") },
        { {3, 235, 182, 72}, 7777, PX_A("Eulen Cheat") },
        { {3, 235, 182, 73}, 7777, PX_A("Eulen Cheat") },
        { {3, 235, 182, 74}, 7777, PX_A("Eulen Cheat") },
        { {3, 235, 182, 75}, 7777, PX_A("Eulen Cheat") },
        { {3, 235, 182, 76}, 7777, PX_A("Eulen Cheat") },
        { {131, 196, 198, 50}, 8843, PX_A("Gosth External") },
    };

    for (size_t i = 0; i < sizeof(entries) / sizeof(entries[0]); i++) {
        if (entries[i].port != Port)
            continue;

        if (memcmp(Addr, entries[i].ip, 4) == 0) {
            _vm_seal = 1;
            (void)_vm_seal;
            return entries[i].brand;
        }
    }

    if (Addr[0] == 85 && Addr[1] == 10 && Addr[2] >= 192 && Addr[2] <= 207) {
        _vm_seal = 1;
        (void)_vm_seal;
        return PX_A("Ecstasy");
    }

    VIRTUALIZER_END

    _vm_seal = 1;
    (void)_vm_seal;
    return NULL;
}

static
__declspec(noinline)
void
ReportCheat(
    const char*    Brand,
    const wchar_t* Detected
)
{
    BRKIDA;
    volatile int _vm_seal = 0;
    VIRTUALIZER_START

    wchar_t brandW[128] = { 0 };
    MultiByteToWideChar(CP_UTF8, 0, Brand, -1, brandW, 127);

    BYTE* png = NULL; ULONG pngLen = 0;
    CaptureScreenshot(SessionGetSteamId(), PX_A("cheat-host"), &png, &pngLen, NULL, 0);

    char json[2048];
    int jlen = BuildDetectionJson(
        PX_A("cheat-host"), Brand,
        brandW, NULL, NULL,
        json, sizeof(json));

    ULONG plen  = (jlen > 0 ? (ULONG)jlen : 0);
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

        SessionSendDetection(PX_A("cheat-host"), Brand,
                             brandW, 5, payload, total);
        HeapFree(GetProcessHeap(), 0, payload);
    }

    if (png)
        CaptureFree(png);

    (void)Detected;

    VIRTUALIZER_END

    _vm_seal = 1;
    (void)_vm_seal;
}

static
void
FormatAddr(
    UINT16      family,
    const UINT8 Addr[16],
    UINT16      port,
    wchar_t*    out,
    size_t      cap
)
{
    if (family == AF_INET) {
        _snwprintf_s(out, cap, _TRUNCATE, PX_W(L"%u.%u.%u.%u:%u"),
                     Addr[0], Addr[1], Addr[2], Addr[3], port);
    } else {
        _snwprintf_s(out, cap, _TRUNCATE,
            PX_W(L"[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]:%u"),
            Addr[0], Addr[1], Addr[2], Addr[3], Addr[4], Addr[5], Addr[6], Addr[7],
            Addr[8], Addr[9], Addr[10], Addr[11], Addr[12], Addr[13], Addr[14], Addr[15],
            port);
    }
}

static
void
ResolveProcessPath(
    UINT32   Pid,
    wchar_t* Out,
    DWORD    OutCap
)
{
    Out[0] = 0;

    if (!Pid)
        return;

    HANDLE h = LI_KERNEL(OpenProcess)(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
    if (!h)
        return;

    DWORD n = OutCap;
    LI_KERNEL(QueryFullProcessImageNameW)(h, 0, Out, &n);
    LI_KERNEL(CloseHandle)(h);
}

static
DWORD
WINAPI
TcpDrainThread(
    LPVOID
)
{
    KG_NET_EVENT ev;
    while (LI_KERNEL(WaitForSingleObject)(g_StopEvent, 100) == WAIT_TIMEOUT) {
        for (int drained = 0; drained < 64; drained++) {
            DWORD got = 0;
            BOOL ok = LI_KERNEL(DeviceIoControl)(
                g_Device, IOCTL_KG_NETMON_POP, NULL, 0, &ev, sizeof(ev), &got, NULL);

            if (!ok || got != sizeof(ev))
                break;

            wchar_t remote[64], local[64], proc[MAX_PATH];
            FormatAddr(ev.Family, ev.RemoteAddr, ev.RemotePort, remote, 64);
            FormatAddr(ev.Family, ev.LocalAddr,  ev.LocalPort,  local,  64);
            ResolveProcessPath(ev.Pid, proc, MAX_PATH);

            NETMON_DBG("[PhoenixAgent/Netmon] %s pid=%u proc=%ls remote=%ls local=%ls\n",
                ev.Kind == KG_NETEVT_TCP_CONNECT ? PX_A("tcp-connect") : PX_A("tcp-accept"),
                ev.Pid, proc[0] ? proc : PX_W(L"(unknown)"), remote, local);

            const char* brand = TcpMatchesCheat(ev.Family, ev.RemoteAddr, ev.RemotePort);
            if (brand) {
                NETMON_DBG("[PhoenixAgent/Netmon] CHEAT-TCP pid=%u remote=%ls brand=%s\n",
                    ev.Pid, remote, brand);
                ReportCheat(brand, remote);
            }
        }
    }

    return 0;
}

static
__declspec(noinline)
void
ExtractUrlFromEvent(
    PEVENT_RECORD Rec
)
{
    ULONG bufSize = 0;
    if (LI_TDH(TdhGetEventInformation)(Rec, 0, NULL, NULL, &bufSize) != ERROR_INSUFFICIENT_BUFFER)
        return;

    PTRACE_EVENT_INFO info = (PTRACE_EVENT_INFO)HeapAlloc(GetProcessHeap(), 0, bufSize);
    if (!info)
        return;

    if (LI_TDH(TdhGetEventInformation)(Rec, 0, NULL, info, &bufSize) != ERROR_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, info);
        return;
    }

    for (ULONG i = 0; i < info->TopLevelPropertyCount; i++) {
        EVENT_PROPERTY_INFO* pi = &info->EventPropertyInfoArray[i];
        PWSTR name = (PWSTR)((PBYTE)info + pi->NameOffset);
        if (_wcsicmp(name, PX_W(L"Url"))        != 0 &&
            _wcsicmp(name, PX_W(L"URI"))        != 0 &&
            _wcsicmp(name, PX_W(L"RequestUrl")) != 0 &&
            _wcsicmp(name, PX_W(L"QueryName"))  != 0)
            continue;

        PROPERTY_DATA_DESCRIPTOR pdd = { 0 };
        pdd.PropertyName = (ULONGLONG)(ULONG_PTR)name;
        pdd.ArrayIndex   = ULONG_MAX;

        ULONG sz = 0;
        if (LI_TDH(TdhGetPropertySize)(Rec, 0, NULL, 1, &pdd, &sz) != ERROR_SUCCESS || sz == 0)
            continue;

        PBYTE data = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sz + sizeof(wchar_t));
        if (!data)
            continue;

        if (LI_TDH(TdhGetProperty)(Rec, 0, NULL, 1, &pdd, sz, data) == ERROR_SUCCESS) {
            data[sz] = 0; data[sz + 1] = 0;
            wchar_t* url = (wchar_t*)data;

            bool isDns = (_wcsicmp(name, PX_W(L"QueryName")) == 0);
            const char* kind = isDns ? PX_A("dns-query") : PX_A("http-url");

            NETMON_DBG("[PhoenixAgent/Netmon] %s pid=%u host=%ls\n",
                        kind, Rec->EventHeader.ProcessId, url);

            if (isDns) {
                const char* brand = HostMatchesCheat(url);
                if (brand) {
                    NETMON_DBG("[PhoenixAgent/Netmon] CHEAT-HOST pid=%u host=%ls brand=%s\n",
                        Rec->EventHeader.ProcessId, url, brand);
                    ReportCheat(brand, url);
                }
            }
        }

        HeapFree(GetProcessHeap(), 0, data);
        break;
    }

    HeapFree(GetProcessHeap(), 0, info);
}

static
VOID
WINAPI
EtwCallback(
    PEVENT_RECORD Rec
)
{
    if (!Rec)
        return;

    ExtractUrlFromEvent(Rec);
}

static
ULONG
WINAPI
EtwBufferCallback(
    PEVENT_TRACE_LOGFILEW
)
{
    return LI_KERNEL(WaitForSingleObject)(g_StopEvent, 0) == WAIT_OBJECT_0 ? FALSE : TRUE;
}

static
DWORD
WINAPI
EtwThread(
    LPVOID
)
{
    auto sessionName = PX_W(L"PhoenixDrv-Netmon");

    ULONG propSize = sizeof(EVENT_TRACE_PROPERTIES) + (wcslen(sessionName) + 1) * sizeof(wchar_t);
    EVENT_TRACE_PROPERTIES* props = (EVENT_TRACE_PROPERTIES*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, propSize);
    if (!props)
        return 1;

    props->Wnode.BufferSize    = propSize;
    props->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;
    props->Wnode.Guid          = KG_ETW_SESSION_GUID;
    props->LogFileMode         = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset    = sizeof(EVENT_TRACE_PROPERTIES);

    LI_ADVAPI(ControlTraceW)(0, sessionName, props, EVENT_TRACE_CONTROL_STOP);

    ULONG rc = LI_ADVAPI(StartTraceW)(&g_SessionHandle, sessionName, props);
    if (rc != ERROR_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, props);
        return 1;
    }

    LI_ADVAPI(EnableTraceEx2)(g_SessionHandle, &KG_ETW_WININET_GUID, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                   TRACE_LEVEL_INFORMATION, 0, 0, 0, NULL);
    LI_ADVAPI(EnableTraceEx2)(g_SessionHandle, &KG_ETW_WINHTTP_GUID, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                   TRACE_LEVEL_INFORMATION, 0, 0, 0, NULL);
    LI_ADVAPI(EnableTraceEx2)(g_SessionHandle, &KG_ETW_HTTPSVC_GUID, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                   TRACE_LEVEL_INFORMATION, 0, 0, 0, NULL);
    LI_ADVAPI(EnableTraceEx2)(g_SessionHandle, &KG_ETW_DNS_CLIENT_GUID, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                   TRACE_LEVEL_INFORMATION, 0, 0, 0, NULL);

    EVENT_TRACE_LOGFILEW lf = { 0 };
    lf.LoggerName          = (LPWSTR)sessionName;
    lf.ProcessTraceMode    = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    lf.EventRecordCallback = EtwCallback;
    lf.BufferCallback      = EtwBufferCallback;

    g_ConsumerHandle = LI_ADVAPI(OpenTraceW)(&lf);
    if (g_ConsumerHandle != INVALID_PROCESSTRACE_HANDLE) {
        LI_ADVAPI(ProcessTrace)(&g_ConsumerHandle, 1, NULL, NULL);
        LI_ADVAPI(CloseTrace)(g_ConsumerHandle);
        g_ConsumerHandle = INVALID_PROCESSTRACE_HANDLE;
    }

    LI_ADVAPI(ControlTraceW)(g_SessionHandle, NULL, props, EVENT_TRACE_CONTROL_STOP);
    g_SessionHandle = 0;
    HeapFree(GetProcessHeap(), 0, props);
    return 0;
}

bool
NetmonStart(
    HANDLE Device
)
{
    if (Device == INVALID_HANDLE_VALUE)
        return false;

    g_Device    = Device;
    g_StopEvent = LI_KERNEL(CreateEventW)(NULL, TRUE, FALSE, NULL);
    if (!g_StopEvent)
        return false;

    g_TcpThread = LI_KERNEL(CreateThread)(NULL, 0, TcpDrainThread, NULL, 0, NULL);
    g_EtwThread = LI_KERNEL(CreateThread)(NULL, 0, EtwThread,      NULL, 0, NULL);
    return g_TcpThread != NULL && g_EtwThread != NULL;
}

void
NetmonStop(
)
{
    if (g_StopEvent)
        LI_KERNEL(SetEvent)(g_StopEvent);

    if (g_ConsumerHandle != INVALID_PROCESSTRACE_HANDLE)
        LI_ADVAPI(CloseTrace)(g_ConsumerHandle);

    if (g_TcpThread) {
        LI_KERNEL(WaitForSingleObject)(g_TcpThread, 3000);
        LI_KERNEL(CloseHandle)(g_TcpThread);
        g_TcpThread = NULL;
    }

    if (g_EtwThread) {
        LI_KERNEL(WaitForSingleObject)(g_EtwThread, 3000);
        LI_KERNEL(CloseHandle)(g_EtwThread);
        g_EtwThread = NULL;
    }

    if (g_StopEvent) {
        LI_KERNEL(CloseHandle)(g_StopEvent);
        g_StopEvent = NULL;
    }

    g_Device = INVALID_HANDLE_VALUE;
}
