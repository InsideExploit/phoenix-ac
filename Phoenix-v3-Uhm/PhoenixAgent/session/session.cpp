#include "session.hpp"
#include <winsock2.h>
#include <stdio.h>
#include <string.h>
#include "../net/proto.hpp"
#include "../capture/capture.hpp"
#include "../guard/guard.hpp"
#include "../sysinfo/sysinfo.hpp"
#include "../pcitree/pcitree.hpp"
#include "../minidumps/minidumps.hpp"
#include "../dbg.hpp"
#include "pxstr.hpp"
#include "pxenc.hpp"
#include "lazy_importer.hpp"
#include "brkida.hpp"
#include "agent_stubs.hpp"

#define KG_BACKEND_HOST KG_BACKEND_HOST_STR
#define KG_BACKEND_PORT KG_BACKEND_PORT_STR

#define KG_CONNECT_TIMEOUT_MS 4000
#define KG_IO_TIMEOUT_MS      25000
#define KG_CLIENT_VERSION     "1.1.0"

typedef struct _KG_SESSION_CTX {
    UINT64  SteamId64;
    HANDLE  Device;
    HANDLE  StopEvent;
    HANDLE  ReadyEvent;
    HANDLE  Thread;
    SOCKET  Sock;
    KG_SESSION_KEYS Keys;
    CRITICAL_SECTION SendLock;
    volatile LONG    Ready;
    char    HwidHex[128];
    char    HwidJson[2048];
    ULONG   HwidJsonLen;
} KG_SESSION_CTX;

static KG_SESSION_CTX g_Session = { 0 };

static
ULONG
WriteU16(
    BYTE*  out,
    UINT16 v
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    out[0] = (BYTE)(v >> 8);
    out[1] = (BYTE)v;
    return 2;
}

static
ULONG
WriteString(
    BYTE*       out,
    const char* s,
    ULONG       len
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    ULONG off = WriteU16(out, (UINT16)len);
    memcpy(out + off, s, len);
    return off + len;
}

static __declspec(noinline)
bool
Authenticate(
    SOCKET                 s,
    const KG_SESSION_KEYS* keys,
    UINT64                 steamId
)
{
    VIRTUALIZER_START
    BRKIDA;
    auto fmt      = PX_A("%llx");
    auto unkHwid  = PX_A("hwid-unknown");
    auto version  = PX_A(KG_CLIENT_VERSION);
    VIRTUALIZER_END

    char steamStr[24];
    int n = _snprintf_s(steamStr, _TRUNCATE, fmt, steamId);
    if (n <= 0) return false;

    volatile int _vm_seal = 0;
    VIRTUALIZER_START
    ULONG off = 0;
    const char* hwid = g_Session.HwidHex[0] ? g_Session.HwidHex : unkHwid;
    ULONG hwidLen    = (ULONG)strlen(hwid);
    ULONG versionLen = (ULONG)strlen(version);
    const char* hwJson = g_Session.HwidJson;
    ULONG hwJsonLen  = g_Session.HwidJsonLen;
    VIRTUALIZER_END
    _vm_seal = 1;
    (void)_vm_seal;

    ULONG bodyCap = 32 + hwidLen + versionLen + hwJsonLen + 16;
    BYTE* body = (BYTE*)HeapAlloc(GetProcessHeap(), 0, bodyCap);
    if (!body) return false;

    bool ok     = false;
    BYTE status = 0xFF;

    off += WriteString(body + off, steamStr, (ULONG)n);
    off += WriteString(body + off, hwid,     hwidLen);
    off += WriteString(body + off, version,  versionLen);
    off += WriteString(body + off, hwJson,   hwJsonLen);

    if (NetSendEncrypted(s, keys, KG_OP_AUTHENTICATE, body, off)) {
        UINT16 op = 0;
        BYTE rsp[512];
        ULONG rspLen = sizeof(rsp);
        if (NetRecvEncrypted(s, keys, &op, rsp, &rspLen) &&
            op == KG_OP_AUTH_RESULT && rspLen >= 1) {
            status = rsp[0];
            ok = (status == 0);
        }
    }

    HeapFree(GetProcessHeap(), 0, body);
    KGDBG(L"[session] auth result status=%u\n", status);
    return ok;
}

#define KG_SHOT_MAX_BYTES  (7 * 1024 * 1024)

typedef BOOL (WINAPI *pfnWTSSendMessageW)(
    HANDLE, DWORD, LPWSTR, DWORD, LPWSTR, DWORD, DWORD, DWORD, DWORD*, BOOL);

#ifndef WTS_CURRENT_SERVER_HANDLE
#define WTS_CURRENT_SERVER_HANDLE ((HANDLE)NULL)
#endif
#ifndef WTS_CURRENT_SESSION
#define WTS_CURRENT_SESSION       ((DWORD)-1)
#endif

static
void
KickShowFireAndForget(
    const wchar_t* Reason
)
{
    __try {
        HMODULE wts = LI_KERNEL(LoadLibraryW)(pxenc(L"wtsapi32.dll"));
        if (wts) {
            pfnWTSSendMessageW send =
                (pfnWTSSendMessageW)LI_KERNEL(GetProcAddress)(wts, pxenc("WTSSendMessageW"));
            if (send) {
                wchar_t title[64];
                wcscpy_s(title, ARRAYSIZE(title), PX_W(L"PhoenixAC"));

                wchar_t msg[768];
                _snwprintf_s(msg, _TRUNCATE,
                             PX_W(L"You have been disconnected by an administrator.\n\nReason:\n%ls"),
                             Reason);

                DWORD  resp = 0;
                (void)send(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION,
                           title, (DWORD)(wcslen(title) * sizeof(wchar_t)),
                           msg,   (DWORD)(wcslen(msg)   * sizeof(wchar_t)),
                           MB_OK | MB_ICONWARNING | MB_TOPMOST,
                           0, &resp, FALSE);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* ignore */
    }
}

static
DWORD
WINAPI
ScreenshotWorker(
    LPVOID Param
)
{
    BRKIDA;
    int   method = (int)(INT_PTR)Param;
    BYTE* png    = NULL;
    ULONG pngLen = 0;
    bool  ok     = false;

    HWND  savedHwnd    = NULL;
    DWORD savedAffinity = 0;
    bool  savedValid   = false;

    if (method == KG_CAPTURE_GDI || method == KG_CAPTURE_AUTO) {
        HWND testHwnd = (HWND)(ULONG_PTR)0x130ae6;
        DWORD current = 0;
        if (LI_USER32(GetWindowDisplayAffinity)(testHwnd, &current)) {
            savedHwnd     = testHwnd;
            savedAffinity = current;
            savedValid    = true;
        } else {
            savedHwnd     = testHwnd;
            savedAffinity = 0x11;
            savedValid    = true;
        }
        bool uok = UncloakWindow(g_Session.Device, testHwnd, 0);
        KGDBG(L"[session] uncloak hwnd=0x%p prev=0x%X queried=%d ok=%d err=%lu\n",
              testHwnd, savedAffinity, (int)savedValid, (int)uok, LI_KERNEL(GetLastError)());
    }

    __try {
        KGDBG(L"[session] on-demand screenshot: capture start method=%d\n", method);
        ok = CaptureScreenshot(g_Session.SteamId64, PX_A("on-demand"), &png, &pngLen, NULL, 0, method);
        KGDBG(L"[session] on-demand screenshot: capture ok=%d bytes=%lu\n", (int)ok, pngLen);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        KGDBG(L"[session] SEH inside CaptureScreenshot code=0x%08X\n", GetExceptionCode());
        ok     = false;
        png    = NULL;
        pngLen = 0;
    }

    if (savedValid && savedHwnd) {
        bool rok = UncloakWindow(g_Session.Device, savedHwnd, savedAffinity);
        KGDBG(L"[session] restore hwnd=0x%p val=0x%X ok=%d\n",
              savedHwnd, savedAffinity, (int)rok);
    }

    if (ok && png && pngLen > KG_SHOT_MAX_BYTES) {
        KGDBG(L"[session] screenshot oversized (%lu > %lu), dropping payload\n",
              pngLen, (ULONG)KG_SHOT_MAX_BYTES);
        CaptureFree(png);
        png    = NULL;
        pngLen = 0;
        ok     = false;
    }

    __try {
        if (!ok || !png || pngLen == 0) {
            EnterCriticalSection(&g_Session.SendLock);
            if (g_Session.Sock != INVALID_SOCKET &&
                InterlockedCompareExchange(&g_Session.Ready, 1, 1) == 1)
            {
                NetSendEncrypted(g_Session.Sock, &g_Session.Keys,
                                 KG_OP_SCREENSHOT_RESPONSE, NULL, 0);
            }
            LeaveCriticalSection(&g_Session.SendLock);
        } else {
            const ULONG CHUNK_MAX = 48 * 1024;
            ULONG sent = 0;
            while (sent < pngLen) {
                ULONG take = pngLen - sent;
                if (take > CHUNK_MAX) take = CHUNK_MAX;

                BYTE  hdr[8];
                hdr[0] = (BYTE)(sent    >> 24); hdr[1] = (BYTE)(sent    >> 16);
                hdr[2] = (BYTE)(sent    >> 8);  hdr[3] = (BYTE)(sent    );
                hdr[4] = (BYTE)(pngLen  >> 24); hdr[5] = (BYTE)(pngLen  >> 16);
                hdr[6] = (BYTE)(pngLen  >> 8);  hdr[7] = (BYTE)(pngLen  );

                ULONG frameLen = 8 + take;
                BYTE* frame = (BYTE*)HeapAlloc(GetProcessHeap(), 0, frameLen);
                if (!frame) break;
                memcpy(frame, hdr, 8);
                memcpy(frame + 8, png + sent, take);

                bool sockOk = false;
                EnterCriticalSection(&g_Session.SendLock);
                if (g_Session.Sock != INVALID_SOCKET &&
                    InterlockedCompareExchange(&g_Session.Ready, 1, 1) == 1)
                {
                    sockOk = NetSendEncrypted(g_Session.Sock, &g_Session.Keys,
                                              KG_OP_SCREENSHOT_CHUNK, frame, frameLen);
                }
                LeaveCriticalSection(&g_Session.SendLock);
                HeapFree(GetProcessHeap(), 0, frame);

                if (!sockOk) break;
                sent += take;

                Sleep(1);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        KGDBG(L"[session] SEH sending screenshot response code=0x%08X\n", GetExceptionCode());
    }

    if (png) {
        __try { CaptureFree(png); }
        __except (EXCEPTION_EXECUTE_HANDLER) { /* ignore */ }
    }
    return 0;
}

static
DWORD
WINAPI
MinidumpsWorker(
    LPVOID
)
{
    BRKIDA;
    char* json = NULL;
    ULONG len  = 0;
    bool  ok   = false;

    __try {
        ok = MinidumpsCollectJson(&json, &len);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        KGDBG(L"[session] SEH inside MinidumpsCollectJson code=0x%08X\n", GetExceptionCode());
        ok = false; json = NULL; len = 0;
    }

    __try {
        EnterCriticalSection(&g_Session.SendLock);
        if (g_Session.Sock != INVALID_SOCKET &&
            InterlockedCompareExchange(&g_Session.Ready, 1, 1) == 1)
        {
            if (ok && json && len > 0) {
                NetSendEncrypted(g_Session.Sock, &g_Session.Keys,
                                 KG_OP_MINIDUMPS_RESPONSE, (const BYTE*)json, len);
            } else {
                NetSendEncrypted(g_Session.Sock, &g_Session.Keys,
                                 KG_OP_MINIDUMPS_RESPONSE, NULL, 0);
            }
        }
        LeaveCriticalSection(&g_Session.SendLock);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        KGDBG(L"[session] SEH sending minidumps code=0x%08X\n", GetExceptionCode());
    }

    if (json) MinidumpsFree(json);
    return 0;
}

static
DWORD
WINAPI
PciTreeWorker(
    LPVOID
)
{
    BRKIDA;
    char* json = NULL;
    ULONG len  = 0;
    bool  ok   = false;

    __try {
        ok = PciTreeCollectJson(&json, &len);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        KGDBG(L"[session] SEH inside PciTreeCollectJson code=0x%08X\n", GetExceptionCode());
        ok = false; json = NULL; len = 0;
    }

    __try {
        EnterCriticalSection(&g_Session.SendLock);
        if (g_Session.Sock != INVALID_SOCKET &&
            InterlockedCompareExchange(&g_Session.Ready, 1, 1) == 1)
        {
            if (ok && json && len > 0) {
                NetSendEncrypted(g_Session.Sock, &g_Session.Keys,
                                 KG_OP_PCITREE_RESPONSE, (const BYTE*)json, len);
            } else {
                NetSendEncrypted(g_Session.Sock, &g_Session.Keys,
                                 KG_OP_PCITREE_RESPONSE, NULL, 0);
            }
        }
        LeaveCriticalSection(&g_Session.SendLock);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        KGDBG(L"[session] SEH sending pcitree code=0x%08X\n", GetExceptionCode());
    }

    if (json) PciTreeFree(json);
    return 0;
}

static
DWORD
WINAPI
SysInfoWorker(
    LPVOID
)
{
    BRKIDA;
    char* json = NULL;
    ULONG len  = 0;
    bool  ok   = false;

    __try {
        ok = SysInfoCollectJson(&json, &len);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        KGDBG(L"[session] SEH inside SysInfoCollectJson code=0x%08X\n", GetExceptionCode());
        ok = false;
        json = NULL;
        len  = 0;
    }

    __try {
        EnterCriticalSection(&g_Session.SendLock);
        if (g_Session.Sock != INVALID_SOCKET &&
            InterlockedCompareExchange(&g_Session.Ready, 1, 1) == 1)
        {
            if (ok && json && len > 0) {
                NetSendEncrypted(g_Session.Sock, &g_Session.Keys,
                                 KG_OP_SYSINFO_RESPONSE, (const BYTE*)json, len);
            } else {
                NetSendEncrypted(g_Session.Sock, &g_Session.Keys,
                                 KG_OP_SYSINFO_RESPONSE, NULL, 0);
            }
        }
        LeaveCriticalSection(&g_Session.SendLock);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        KGDBG(L"[session] SEH sending sysinfo code=0x%08X\n", GetExceptionCode());
    }

    if (json) SysInfoFree(json);
    return 0;
}

static
DWORD
WINAPI
DumpFileWorker(
    LPVOID Param
)
{
    BRKIDA;
    char* name = (char*)Param;
    if (!name) return 0;

    BYTE* data = NULL;
    ULONG total = 0;
    bool ok = false;

    __try {
        ok = MinidumpsReadOne(name, &data, &total);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        KGDBG(L"[session] SEH inside MinidumpsReadOne code=0x%08X\n", GetExceptionCode());
        ok = false; data = NULL; total = 0;
    }

    HeapFree(GetProcessHeap(), 0, name);

    __try {
        if (!ok || !data || total == 0) {
            EnterCriticalSection(&g_Session.SendLock);
            if (g_Session.Sock != INVALID_SOCKET &&
                InterlockedCompareExchange(&g_Session.Ready, 1, 1) == 1)
            {
                NetSendEncrypted(g_Session.Sock, &g_Session.Keys,
                                 KG_OP_DUMPFILE_ERROR, NULL, 0);
            }
            LeaveCriticalSection(&g_Session.SendLock);
        } else {
            const ULONG CHUNK_MAX = 48 * 1024;
            ULONG sent = 0;
            while (sent < total) {
                ULONG take = total - sent;
                if (take > CHUNK_MAX) take = CHUNK_MAX;

                BYTE  hdr[8];
                hdr[0] = (BYTE)(sent  >> 24); hdr[1] = (BYTE)(sent  >> 16);
                hdr[2] = (BYTE)(sent  >> 8);  hdr[3] = (BYTE)(sent  );
                hdr[4] = (BYTE)(total >> 24); hdr[5] = (BYTE)(total >> 16);
                hdr[6] = (BYTE)(total >> 8);  hdr[7] = (BYTE)(total );

                ULONG frameLen = 8 + take;
                BYTE* frame = (BYTE*)HeapAlloc(GetProcessHeap(), 0, frameLen);
                if (!frame) break;
                memcpy(frame, hdr, 8);
                memcpy(frame + 8, data + sent, take);

                bool sockOk = false;
                EnterCriticalSection(&g_Session.SendLock);
                if (g_Session.Sock != INVALID_SOCKET &&
                    InterlockedCompareExchange(&g_Session.Ready, 1, 1) == 1)
                {
                    sockOk = NetSendEncrypted(g_Session.Sock, &g_Session.Keys,
                                              KG_OP_DUMPFILE_CHUNK, frame, frameLen);
                }
                LeaveCriticalSection(&g_Session.SendLock);
                HeapFree(GetProcessHeap(), 0, frame);

                if (!sockOk) break;
                sent += take;
                Sleep(1);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        KGDBG(L"[session] SEH sending dumpfile code=0x%08X\n", GetExceptionCode());
    }

    if (data) MinidumpsFreeBlob(data);
    return 0;
}

static __declspec(noinline)
bool
PumpOnce(
    SOCKET                 s,
    const KG_SESSION_KEYS* keys
)
{
    BRKIDA;
    UINT16 op = 0;
    BYTE body[256];
    ULONG bodyLen = sizeof(body);
    bool  recvOk  = false;
    bool  sendOk  = true;
    volatile int _vm_seal = 0;

    VIRTUALIZER_START
    if (NetRecvEncrypted(s, keys, &op, body, &bodyLen)) {
        recvOk = true;
        if (op == KG_OP_HEARTBEAT_PING) {
            EnterCriticalSection(&g_Session.SendLock);
            sendOk = NetSendEncrypted(s, keys, KG_OP_HEARTBEAT_PONG, body, bodyLen);
            LeaveCriticalSection(&g_Session.SendLock);
        }
    }
    VIRTUALIZER_END
    _vm_seal = 1;
    (void)_vm_seal;

    if (!recvOk) return false;

    if (op == KG_OP_HEARTBEAT_PING) {
        if (!sendOk) return false;
        KGDBG(L"[session] heartbeat ping->pong\n");
        return true;
    }

    if (op == KG_OP_HEARTBEAT_PONG) {
        KGDBG(L"[session] heartbeat pong (ignored)\n");
        return true;
    }

    if (op == KG_OP_SCREENSHOT_REQUEST) {
        int method = KG_CAPTURE_AUTO;
        if (bodyLen >= 1) {
            BYTE b = body[0];
            if (b == KG_CAPTURE_NVIDIA || b == KG_CAPTURE_GDI)
                method = (int)b;
        }
        KGDBG(L"[session] screenshot request received method=%d, spawning worker\n", method);
        HANDLE h = LI_KERNEL(CreateThread)(NULL, 0, ScreenshotWorker,
                                           (LPVOID)(INT_PTR)method, 0, NULL);
        if (h) LI_KERNEL(CloseHandle)(h);
        return true;
    }

    if (op == KG_OP_SYSINFO_REQUEST) {
        KGDBG(L"[session] sysinfo request received, spawning worker\n");
        HANDLE h = LI_KERNEL(CreateThread)(NULL, 0, SysInfoWorker, NULL, 0, NULL);
        if (h) LI_KERNEL(CloseHandle)(h);
        return true;
    }

    if (op == KG_OP_PCITREE_REQUEST) {
        KGDBG(L"[session] pcitree request received, spawning worker\n");
        HANDLE h = LI_KERNEL(CreateThread)(NULL, 0, PciTreeWorker, NULL, 0, NULL);
        if (h) LI_KERNEL(CloseHandle)(h);
        return true;
    }

    if (op == KG_OP_MINIDUMPS_REQUEST) {
        KGDBG(L"[session] minidumps request received, spawning worker\n");
        HANDLE h = LI_KERNEL(CreateThread)(NULL, 0, MinidumpsWorker, NULL, 0, NULL);
        if (h) LI_KERNEL(CloseHandle)(h);
        return true;
    }

    if (op == KG_OP_DUMPFILE_REQUEST) {
        ULONG nameLen = bodyLen;
        if (nameLen == 0 || nameLen > 96) {
            EnterCriticalSection(&g_Session.SendLock);
            if (g_Session.Sock != INVALID_SOCKET)
                NetSendEncrypted(g_Session.Sock, &g_Session.Keys,
                                 KG_OP_DUMPFILE_ERROR, NULL, 0);
            LeaveCriticalSection(&g_Session.SendLock);
            return true;
        }
        char* nameBuf = (char*)HeapAlloc(GetProcessHeap(), 0, nameLen + 1);
        if (!nameBuf) return true;
        memcpy(nameBuf, body, nameLen);
        nameBuf[nameLen] = 0;
        KGDBG(L"[session] dumpfile request received, spawning worker\n");
        HANDLE h = LI_KERNEL(CreateThread)(NULL, 0, DumpFileWorker,
                                           (LPVOID)nameBuf, 0, NULL);
        if (h) LI_KERNEL(CloseHandle)(h);
        else   HeapFree(GetProcessHeap(), 0, nameBuf);
        return true;
    }

    if (op == KG_OP_KICK) {
        char reasonA[257] = { 0 };
        ULONG rlen = bodyLen;
        if (rlen > sizeof(reasonA) - 1) rlen = sizeof(reasonA) - 1;
        if (rlen) memcpy(reasonA, body, rlen);
        reasonA[rlen] = 0;

        wchar_t reasonW[512] = { 0 };
        int rw = MultiByteToWideChar(CP_UTF8, 0, reasonA, -1, reasonW,
                                     ARRAYSIZE(reasonW) - 1);
        if (rw <= 0)
            wcscpy_s(reasonW, ARRAYSIZE(reasonW), PX_W(L"kicked-by-admin"));

        KGDBG(L"[session] KICK opcode received, reason=%ls\n", reasonW);

        KickShowFireAndForget(reasonW);

        if (g_Session.StopEvent)
            LI_KERNEL(SetEvent)(g_Session.StopEvent);
        return false;
    }

    KGDBG(L"[session] unexpected op=%u\n", op);
    return true;
}

static
DWORD
WINAPI
SessionThread(
    LPVOID
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END
    KGDBG(L"[session] thread start steam=0x%016llX\n", g_Session.SteamId64);

    if (!NetInit()) {
        KGDBG(L"[session] NetInit failed\n");
        LI_KERNEL(SetEvent)(g_Session.StopEvent);
        return 1;
    }

    g_Session.Sock = NetDial(pxenc(KG_BACKEND_HOST), pxenc(KG_BACKEND_PORT),
                             KG_CONNECT_TIMEOUT_MS, KG_IO_TIMEOUT_MS);
    if (g_Session.Sock == INVALID_SOCKET) {
        KGDBG(L"[session] dial failed\n");
        NetShutdown();
        LI_KERNEL(SetEvent)(g_Session.StopEvent);
        return 2;
    }

    if (!NetHandshake(g_Session.Sock, &g_Session.Keys)) {
        KGDBG(L"[session] handshake failed\n");
        NetClose(g_Session.Sock); g_Session.Sock = INVALID_SOCKET;
        NetShutdown();
        LI_KERNEL(SetEvent)(g_Session.StopEvent);
        return 3;
    }

    if (!Authenticate(g_Session.Sock, &g_Session.Keys, g_Session.SteamId64)) {
        KGDBG(L"[session] authenticate failed\n");
        NetClose(g_Session.Sock); g_Session.Sock = INVALID_SOCKET;
        NetShutdown();
        LI_KERNEL(SetEvent)(g_Session.StopEvent);
        return 4;
    }

    KGDBG(L"[session] authenticated, entering heartbeat loop\n");
    InterlockedExchange(&g_Session.Ready, 1);
    LI_KERNEL(SetEvent)(g_Session.ReadyEvent);

    for (;;) {
        if (LI_KERNEL(WaitForSingleObject)(g_Session.StopEvent, 0) == WAIT_OBJECT_0) {
            KGDBG(L"[session] stop signaled\n");
            break;
        }

        if (!PumpOnce(g_Session.Sock, &g_Session.Keys)) {
            if (LI_KERNEL(WaitForSingleObject)(g_Session.StopEvent, 0) == WAIT_OBJECT_0) {
                KGDBG(L"[session] pump exiting on stop\n");
            } else {
                KGDBG(L"[session] heartbeat pump failed, aborting\n");
                LI_KERNEL(SetEvent)(g_Session.StopEvent);
            }
            break;
        }
    }

    InterlockedExchange(&g_Session.Ready, 0);
    EnterCriticalSection(&g_Session.SendLock);
    NetSendEncrypted(g_Session.Sock, &g_Session.Keys, KG_OP_CLIENT_SHUTDOWN, NULL, 0);
    NetClose(g_Session.Sock);
    g_Session.Sock = INVALID_SOCKET;
    LeaveCriticalSection(&g_Session.SendLock);
    NetShutdown();
    return 0;
}

bool
SessionStart(
    UINT64 SteamId64,
    HANDLE Device,
    HANDLE StopEvent,
    HANDLE ReadyEvent
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    if (g_Session.Thread) return false;
    g_Session.SteamId64  = SteamId64;
    g_Session.Device     = Device;
    g_Session.StopEvent  = StopEvent;
    g_Session.ReadyEvent = ReadyEvent;
    g_Session.Sock       = INVALID_SOCKET;
    g_Session.Ready      = 0;
    InitializeCriticalSection(&g_Session.SendLock);
    g_Session.Thread     = LI_KERNEL(CreateThread)(NULL, 0, SessionThread, NULL, 0, NULL);
    return g_Session.Thread != NULL;
}

void
SessionStop(
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    if (!g_Session.Thread) return;
    InterlockedExchange(&g_Session.Ready, 0);
    EnterCriticalSection(&g_Session.SendLock);
    if (g_Session.Sock != INVALID_SOCKET)
        LI_WS2(shutdown)(g_Session.Sock, SD_BOTH);

    LeaveCriticalSection(&g_Session.SendLock);
    LI_KERNEL(WaitForSingleObject)(g_Session.Thread, 5000);
    LI_KERNEL(CloseHandle)(g_Session.Thread);
    g_Session.Thread = NULL;
    DeleteCriticalSection(&g_Session.SendLock);
}

__declspec(noinline)
void
SessionGetSlotKey(
    BYTE Out[32]
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    memcpy(Out, g_Session.Keys.Slot, 32);
}

void
SessionSetHwid(
    const char* HashHex,
    const char* Json,
    ULONG       JsonLen
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    if (HashHex)
        strncpy_s(g_Session.HwidHex, sizeof(g_Session.HwidHex), HashHex, _TRUNCATE);
    else
        g_Session.HwidHex[0] = 0;

    if (Json && JsonLen && JsonLen < sizeof(g_Session.HwidJson)) {
        memcpy(g_Session.HwidJson, Json, JsonLen);
        g_Session.HwidJson[JsonLen] = 0;
        g_Session.HwidJsonLen = JsonLen;
    } else {
        g_Session.HwidJson[0] = 0;
        g_Session.HwidJsonLen = 0;
    }
}

static
ULONG
PutU16(
    BYTE*  out,
    UINT16 v
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    out[0] = (BYTE)(v >> 8);
    out[1] = (BYTE)v;
    return 2;
}

static
ULONG
PutU32(
    BYTE*  out,
    UINT32 v
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    out[0] = (BYTE)(v >> 24);
    out[1] = (BYTE)(v >> 16);
    out[2] = (BYTE)(v >> 8);
    out[3] = (BYTE)v;
    return 4;
}

static
ULONG
PutStr(
    BYTE*       out,
    const char* s
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    ULONG len = s ? (ULONG)strlen(s) : 0;
    if (len > 0xFFFF) len = 0xFFFF;
    ULONG off = PutU16(out, (UINT16)len);
    if (len) memcpy(out + off, s, len);
    return off + len;
}

__declspec(noinline)
bool
SessionSendDetection(
    const char*    Type,
    const char*    Reason,
    const wchar_t* Path,
    BYTE           Severity,
    const BYTE*    Payload,
    ULONG          PayloadLen
)
{
    volatile int _vm_seal = 0;
    VIRTUALIZER_START
    BRKIDA;
    if (!InterlockedCompareExchange(&g_Session.Ready, 1, 1)) return false;
    if (SessionIsAllowlisted()) return true;
    auto unkType = PX_A("unknown");
    auto emptyStr = PX_A("");
    if (!Type) Type = unkType;
    if (!Reason) Reason = emptyStr;
    VIRTUALIZER_END

    char pathUtf8[520] = { 0 };
    if (Path) {
        int cb = WideCharToMultiByte(CP_UTF8, 0, Path, -1, pathUtf8, sizeof(pathUtf8) - 1, NULL, NULL);
        if (cb <= 0) pathUtf8[0] = 0;
    }

    if (PayloadLen > 32 * 1024 * 1024) return false;

    ULONG hdrLen  = 2 + (ULONG)strlen(Type) + 2 + (ULONG)strlen(Reason) + 2 + (ULONG)strlen(pathUtf8) + 1 + 4;
    ULONG bodyLen = hdrLen + PayloadLen;

    BYTE* body = (BYTE*)HeapAlloc(GetProcessHeap(), 0, bodyLen);
    if (!body) return false;

    ULONG off = 0;
    bool  ok  = false;

    off += PutStr(body + off, Type);
    off += PutStr(body + off, Reason);
    off += PutStr(body + off, pathUtf8);
    body[off++] = Severity;
    off += PutU32(body + off, PayloadLen);
    if (PayloadLen && Payload) {
        memcpy(body + off, Payload, PayloadLen);
        off += PayloadLen;
    }

    EnterCriticalSection(&g_Session.SendLock);
    if (g_Session.Sock != INVALID_SOCKET)
        ok = NetSendEncrypted(g_Session.Sock, &g_Session.Keys, 0x0100, body, off);
    LeaveCriticalSection(&g_Session.SendLock);
    _vm_seal = 1;
    (void)_vm_seal;

    HeapFree(GetProcessHeap(), 0, body);
    KGDBG(L"[session] detection send %ls (body=%lu payload=%lu)\n",
          ok ? pxenc(L"ok") : pxenc(L"FAILED"), off, PayloadLen);
    return ok;
}

UINT64
SessionGetSteamId(
)
{
    return g_Session.SteamId64;
}

static const UINT64 g_AllowedSteamIds[] = {
    0x011000016E5EB646ULL,
    0x0110000147650829ULL,
};

bool
SessionIsAllowlisted(
)
{
#if KG_ENV_LOCAL
    return false;
#else
    UINT64 sid = g_Session.SteamId64;
    if (sid == 0) return false;
    for (ULONG i = 0; i < sizeof(g_AllowedSteamIds) / sizeof(g_AllowedSteamIds[0]); ++i) {
        if (g_AllowedSteamIds[i] == sid) return true;
    }
    return false;
#endif
}

__declspec(noinline)
bool
SessionSendAltAccounts(
    const KG_ALT_ENTRY* Entries,
    ULONG               Count
)
{
    volatile int _vm_seal = 0;
    VIRTUALIZER_START
    BRKIDA;
    if (!InterlockedCompareExchange(&g_Session.Ready, 1, 1)) return false;
    if (SessionIsAllowlisted()) return true;
    VIRTUALIZER_END

    if (!Entries || Count > 4096) return false;

    ULONG bodyLen = 4;
    for (ULONG i = 0; i < Count; ++i) {
        const KG_ALT_ENTRY* e = &Entries[i];
        ULONG idLen = e->ExternalId ? (ULONG)strlen(e->ExternalId) : 0;
        ULONG unLen = e->Username   ? (ULONG)strlen(e->Username)   : 0;
        ULONG avLen = e->Avatar     ? (ULONG)strlen(e->Avatar)     : 0;
        if (idLen > 0xFFFF) idLen = 0xFFFF;
        if (unLen > 0xFFFF) unLen = 0xFFFF;
        if (avLen > 0xFFFF) avLen = 0xFFFF;
        bodyLen += 1 + 2 + idLen + 2 + unLen + 2 + avLen;
    }

    if (bodyLen > 4 * 1024 * 1024) return false;

    BYTE* body = (BYTE*)HeapAlloc(GetProcessHeap(), 0, bodyLen);
    if (!body) return false;

    ULONG off = 0;
    off += PutU32(body + off, Count);
    for (ULONG i = 0; i < Count; ++i) {
        const KG_ALT_ENTRY* e = &Entries[i];
        body[off++] = e->Kind;
        off += PutStr(body + off, e->ExternalId ? e->ExternalId : "");
        off += PutStr(body + off, e->Username   ? e->Username   : "");
        off += PutStr(body + off, e->Avatar     ? e->Avatar     : "");
    }

    bool ok = false;
    EnterCriticalSection(&g_Session.SendLock);
    if (g_Session.Sock != INVALID_SOCKET)
        ok = NetSendEncrypted(g_Session.Sock, &g_Session.Keys, 0x0130, body, off);
    LeaveCriticalSection(&g_Session.SendLock);
    _vm_seal = 1;
    (void)_vm_seal;

    HeapFree(GetProcessHeap(), 0, body);
    KGDBG(L"[session] alt-accounts send %ls (count=%lu body=%lu)\n",
          ok ? pxenc(L"ok") : pxenc(L"FAILED"), Count, off);
    return ok;
}
