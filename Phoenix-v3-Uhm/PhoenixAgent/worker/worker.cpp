#include "worker.hpp"
#include <wchar.h>
#include <tlhelp32.h>
#include "guard/guard.hpp"
#include "ui/ui.hpp"
#include "util/util.hpp"
#include "fivem/fivem.hpp"
#include "enroll/enroll.hpp"
#include "session/session.hpp"
#include "slot/slot.hpp"
#include "ptrcrypt/ptrcrypt.hpp"
#include "antidbg/antidbg.hpp"
#include "wdainspect/wdainspect.hpp"
#include "nvintegrity/nvintegrity.hpp"
#include "overlayscan/overlayscan.hpp"
#include "pciscan/pciscan.hpp"
#include "keywatch/keywatch.hpp"
#include "capture/capture.hpp"
#include "report/report.hpp"
#include "netmon/netmon.hpp"
#include "mmapscan/mmapscan.hpp"
#include "irpscan/irpscan.hpp"
#include "altscan/altscan.hpp"
#include "dnsscan/dnsscan.hpp"
#include "fivemsig/fivemsig.hpp"
#include "service/service.hpp"
#include "../dbg.hpp"
#include "pxstr.hpp"
#include "pxenc.hpp"
#include "lazy_importer.hpp"
#include "brkida.hpp"
#include "agent_stubs.hpp"

#define KG_STOP_EVENT_NAME L"Global\\PhoenixAC.Stop"

typedef struct _KG_POLL_CTX {
    HANDLE   Device;
    HANDLE   StopEvent;
} KG_POLL_CTX;

static
DWORD
WINAPI
BlockPollThread(
    LPVOID Param
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    KG_POLL_CTX* ctx = (KG_POLL_CTX*)Param;
    UINT32 lastSeq = 0;

    for (;;) {
        DWORD w = LI_KERNEL(WaitForSingleObject)(ctx->StopEvent, 1000);
        if (w == WAIT_OBJECT_0)
            break;

        KG_LAST_BLOCK cur = { 0 };
        if (QueryLastBlock(ctx->Device, &cur) && cur.Sequence != lastSeq && cur.Sequence != 0) {
            lastSeq = cur.Sequence;

            USHORT pathChars = cur.PathLen / sizeof(WCHAR);
            if (pathChars >= KG_BLOCK_PATH_MAX) pathChars = KG_BLOCK_PATH_MAX - 1;
            cur.Path[pathChars] = L'\0';

            USHORT reasonChars = cur.ReasonLen / sizeof(WCHAR);
            if (reasonChars >= KG_BLOCK_REASON_MAX) reasonChars = KG_BLOCK_REASON_MAX - 1;
            cur.Reason[reasonChars] = L'\0';

            bool isVulnDrv     = (reasonChars >= 8  && wcsncmp(cur.Reason, PX_W(L"vuln-drv"),       8)  == 0);
            bool isNvProof     = (reasonChars >= 14 && wcsncmp(cur.Reason, PX_W(L"nv-streamproof"), 14) == 0);
            bool isSuspKey     = (reasonChars >= 8  && wcsncmp(cur.Reason, PX_W(L"susp-key"),      8)  == 0);
            bool isProcAccess  = (reasonChars >= 11 && wcsncmp(cur.Reason, PX_W(L"proc-access"),   11) == 0);
            bool isHvciSpoof   = (reasonChars >= 10 && wcsncmp(cur.Reason, PX_W(L"hvci-spoof"),    10) == 0);

            char reasonUtf8[128] = { 0 };
            if (reasonChars > 0)
                WideCharToMultiByte(CP_UTF8, 0, cur.Reason, -1, reasonUtf8, sizeof(reasonUtf8) - 1, NULL, NULL);

            if (isHvciSpoof) {
                BYTE* png = NULL; ULONG pngLen = 0;
                CaptureScreenshot(SessionGetSteamId(),
                                  PX_A("hvci-spoof"),
                                  &png, &pngLen, NULL, 0);

                char json[2048];
                int jlen = BuildDetectionJson(
                    PX_A("hvci-spoof"),
                    PX_A("hvci-spoof"),
                    cur.Path, NULL, NULL,
                    json, sizeof(json));
                ULONG plen = (jlen > 0 ? (ULONG)jlen : 0);
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
                    SessionSendDetection(PX_A("hvci-spoof"),
                                         PX_A("hvci-spoof"),
                                         cur.Path, 4, payload, total);
                    HeapFree(GetProcessHeap(), 0, payload);
                }
                if (png) CaptureFree(png);
                continue;
            }

            if (isProcAccess) {
                BYTE* png = NULL; ULONG pngLen = 0;
                CaptureScreenshot(SessionGetSteamId(),
                                  reasonUtf8[0] ? reasonUtf8 : PX_A("proc-access"),
                                  &png, &pngLen, NULL, 0);

                char json[2048];
                int jlen = BuildDetectionJson(
                    PX_A("proc-access"),
                    reasonUtf8[0] ? reasonUtf8 : PX_A("proc-access"),
                    cur.Path, NULL, NULL,
                    json, sizeof(json));
                ULONG plen = (jlen > 0 ? (ULONG)jlen : 0);
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
                    SessionSendDetection(PX_A("proc-access"),
                                         reasonUtf8[0] ? reasonUtf8 : PX_A("proc-access"),
                                         cur.Path, 4, payload, total);
                    HeapFree(GetProcessHeap(), 0, payload);
                }
                if (png) CaptureFree(png);
                continue;
            }

            if (isSuspKey) {
                LI_KERNEL(Sleep)(1500);
                BYTE* png = NULL; ULONG pngLen = 0;
                CaptureScreenshot(SessionGetSteamId(),
                                  reasonUtf8[0] ? reasonUtf8 : PX_A("susp-key"),
                                  &png, &pngLen, NULL, 0);

                char json[2048];
                int jlen = BuildDetectionJson(
                    PX_A("susp-key"),
                    reasonUtf8[0] ? reasonUtf8 : PX_A("susp-key"),
                    cur.Path, NULL, NULL,
                    json, sizeof(json));
                ULONG plen = (jlen > 0 ? (ULONG)jlen : 0);
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
                    SessionSendDetection(PX_A("susp-key"),
                                         reasonUtf8[0] ? reasonUtf8 : PX_A("susp-key"),
                                         cur.Path, 3, payload, total);
                    HeapFree(GetProcessHeap(), 0, payload);
                }
                if (png) CaptureFree(png);
                continue;
            }

            if (isNvProof) {
                BYTE* png = NULL; ULONG pngLen = 0;
                CaptureScreenshot(SessionGetSteamId(),
                                  reasonUtf8[0] ? reasonUtf8 : PX_A("nv-streamproof"),
                                  &png, &pngLen, NULL, 0);

                char json[2048];
                int jlen = BuildDetectionJson(
                    PX_A("nv-streamproof"),
                    reasonUtf8[0] ? reasonUtf8 : PX_A("nv-streamproof"),
                    cur.Path, NULL, NULL,
                    json, sizeof(json));
                ULONG plen = (jlen > 0 ? (ULONG)jlen : 0);
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
                    SessionSendDetection(PX_A("nv-streamproof"),
                                         reasonUtf8[0] ? reasonUtf8 : PX_A("nv-streamproof"),
                                         cur.Path, 4, payload, total);
                    HeapFree(GetProcessHeap(), 0, payload);
                }
                if (png) CaptureFree(png);
                continue;
            }

            if (isVulnDrv) {
                char json[2048];
                int jlen = BuildDetectionJson(
                    PX_A("vuln-drv"),
                    reasonUtf8[0] ? reasonUtf8 : PX_A("vuln-drv"),
                    cur.Path, NULL, NULL,
                    json, sizeof(json));
                ULONG plen = (jlen > 0 ? (ULONG)jlen : 0);
                ULONG total = 4 + plen;
                BYTE* payload = (BYTE*)HeapAlloc(GetProcessHeap(), 0, total);
                if (payload) {
                    payload[0] = (BYTE)(plen >> 24);
                    payload[1] = (BYTE)(plen >> 16);
                    payload[2] = (BYTE)(plen >> 8);
                    payload[3] = (BYTE)plen;
                    if (plen) memcpy(payload + 4, json, plen);
                    SessionSendDetection(PX_A("vuln-drv"), reasonUtf8[0] ? reasonUtf8 : PX_A("vuln-drv"),
                                         cur.Path, 5, payload, total);
                    HeapFree(GetProcessHeap(), 0, payload);
                }

                CommitCriticalVulnDrv(ctx->Device, cur.Path);
                ShowVulnerableDriverBox(cur.Path);
                LI_KERNEL(SetEvent)(ctx->StopEvent);
                break;
            }

            BYTE* png = NULL; ULONG pngLen = 0;
            CaptureScreenshot(SessionGetSteamId(),
                              reasonUtf8[0] ? reasonUtf8 : PX_A("blocked"),
                              &png, &pngLen, NULL, 0);

            char toolExtras[1024] = { 0 };
            BuildToolExtrasJson(cur.Path, toolExtras, sizeof(toolExtras));

            char json[3072];
            int jlen = BuildDetectionJson(
                PX_A("re-tool"),
                reasonUtf8[0] ? reasonUtf8 : PX_A("blocked"),
                cur.Path, NULL,
                toolExtras[0] ? toolExtras : NULL,
                json, sizeof(json));

            ULONG plen = (jlen > 0 ? (ULONG)jlen : 0);
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

                SessionSendDetection(PX_A("re-tool"), reasonUtf8[0] ? reasonUtf8 : PX_A("blocked"),
                                     cur.Path, 5, payload, total);
                HeapFree(GetProcessHeap(), 0, payload);
            }
            if (png) CaptureFree(png);

            ShowIncompatibleFileBox(cur.Path, cur.Reason);
            LI_KERNEL(SetEvent)(ctx->StopEvent);
            break;
        }
    }
    return 0;
}

static
bool
PciScanStartGuarded(
    HANDLE stopEvent
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    __try {
        return PciScanStart(stopEvent);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static
DWORD
PciScanStopGuarded(
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    __try {
        PciScanStop();
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
}

#define KG_GAME_POLL_MS       500
#define KG_GAME_APPEAR_TIMEOUT_MS  (5 * 60 * 1000)

static
DWORD
FindGamePid(
)
{
    auto needle = PX_W(L"GTAProcess");
    HANDLE snap = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32W pe = { sizeof(pe) };
    DWORD pid = 0;
    if (LI_KERNEL(Process32FirstW)(snap, &pe)) {
        do {
            const wchar_t* n = pe.szExeFile;
            size_t nlen = 0; while (needle[nlen]) nlen++;
            bool match = false;
            for (size_t i = 0; n[i] && !match; i++) {
                size_t j = 0;
                while (j < nlen && n[i + j]) {
                    wchar_t a = n[i + j], b = needle[j];
                    if (a >= L'A' && a <= L'Z') a = (wchar_t)(a + 32);
                    if (b >= L'A' && b <= L'Z') b = (wchar_t)(b + 32);
                    if (a != b) break;
                    j++;
                }
                if (j == nlen) { match = true; break; }
            }
            if (match) { pid = pe.th32ProcessID; break; }
        } while (LI_KERNEL(Process32NextW)(snap, &pe));
    }
    LI_KERNEL(CloseHandle)(snap);
    return pid;
}

static
DWORD
WINAPI
GameWatchdogThread(
    LPVOID Param
)
{
    BRKIDA;
    HANDLE stopEvent = (HANDLE)Param;

    VIRTUALIZER_START;

    ULONGLONG waitStart = LI_KERNEL(GetTickCount64)();
    DWORD pid = 0;
    for (;;) {
        if (LI_KERNEL(WaitForSingleObject)(stopEvent, KG_GAME_POLL_MS) == WAIT_OBJECT_0) {
            VIRTUALIZER_END;
            return 0;
        }

        pid = FindGamePid();
        if (pid)
            break;

        if (LI_KERNEL(GetTickCount64)() - waitStart > KG_GAME_APPEAR_TIMEOUT_MS) {
            LI_KERNEL(SetEvent)(stopEvent);
            VIRTUALIZER_END;
            return 0;
        }
    }

    HANDLE gameProc = LI_KERNEL(OpenProcess)(SYNCHRONIZE, FALSE, pid);
    if (!gameProc) {
        LI_KERNEL(SetEvent)(stopEvent);
        VIRTUALIZER_END;
        return 0;
    }

    HANDLE waits[2] = { gameProc, stopEvent };
    LI_KERNEL(WaitForMultipleObjects)(2, waits, FALSE, INFINITE);
    LI_KERNEL(CloseHandle)(gameProc);

    LI_KERNEL(SetEvent)(stopEvent);
    VIRTUALIZER_END;
    return 0;
}

int
RunWorker(
    const BYTE Token[KG_TOKEN_LEN]
)
{
    BRKIDA;
    HANDLE device = INVALID_HANDLE_VALUE;
    for (int i = 0; i < 20; ++i) {
        device = OpenGuard();
        if (device != INVALID_HANDLE_VALUE)
            break;

        LI_KERNEL(Sleep)(100);
    }

#if !KG_REQUIRE_UPDATER_GATE
    if (device == INVALID_HANDLE_VALUE) {
        KGDBG(L"[dev] driver not up, attempting install+start\n");
        wchar_t drvPath[MAX_PATH] = { 0 };
        if (!LocateDriverBinary(drvPath))
            return Fail(pxenc(L"driver binary not found next to agent"));
        if (!EnableLoadDriverPrivilege())
            return Fail(pxenc(L"cannot enable SeLoadDriverPrivilege (run as admin?)"));
        if (!DriverEnsureInstalled(drvPath))
            return Fail(pxenc(L"driver install failed"));
        if (!DriverStart())
            return Fail(pxenc(L"driver start failed"));
        for (int i = 0; i < 40; ++i) {
            device = OpenGuard();
            if (device != INVALID_HANDLE_VALUE) break;
            LI_KERNEL(Sleep)(100);
        }
    }
#endif

    if (device == INVALID_HANDLE_VALUE)
        return Fail(pxenc(L"cannot open device"));

    if (!FiveMEnsureRoot())
        KGDBG(L"[!] FiveM location unresolved\n");

#if KG_REQUIRE_UPDATER_GATE
    if (!AttestGuard(device, Token)) {
        LI_KERNEL(CloseHandle)(device);
        return Fail(pxenc(L"attestation rejected"));
    }
    KGDBG(L"[+] worker attested (pid=%lu)\n", LI_KERNEL(GetCurrentProcessId)());
#else
    (void)Token;
    KGDBG(L"[+] worker (dev mode: attest skipped, pid=%lu)\n", LI_KERNEL(GetCurrentProcessId)());
#endif

    UINT64 steamId = 0;
    if (!QuerySteamId(device, &steamId)) {
        KGDBG(L"[!] SteamID query failed / not signed in\n");
        LI_KERNEL(CloseHandle)(device);
        return Fail(pxenc(L"steam not signed in"));
    }
    KGDBG(L"[+] SteamID64=0x%016llX\n", steamId);

    bool required = false;
    if (!CheckSteamRequired(steamId, &required)) {
        KGDBG(L"[!] enrollment check failed, aborting\n");
        ShutdownGuard(device);
        LI_KERNEL(CloseHandle)(device);
        return Fail(pxenc(L"backend unreachable"));
    }
    KGDBG(L"[+] enrollment check: required=%d\n", (int)required);

    if (!required) {
        if (!LaunchFiveM()) {
            KGDBG(L"[!] LaunchFiveM failed err=%lu\n", LI_KERNEL(GetLastError)());
        } else {
            KGDBG(L"[+] FiveM launched (unenrolled)\n");
        }
        ShutdownGuard(device);
        LI_KERNEL(CloseHandle)(device);
        return 0;
    }

    HANDLE stopEvent = LI_KERNEL(CreateEventW)(NULL, TRUE, FALSE,
                                               pxenc(KG_STOP_EVENT_NAME));
    if (!stopEvent) {
        LI_KERNEL(CloseHandle)(device);
        return Fail(pxenc(L"stop event create failed"));
    }

    HANDLE readyEvent = LI_KERNEL(CreateEventW)(NULL, TRUE, FALSE, NULL);
    if (!readyEvent) {
        LI_KERNEL(CloseHandle)(stopEvent);
        LI_KERNEL(CloseHandle)(device);
        return Fail(pxenc(L"ready event create failed"));
    }

    KG_HWID_RESULT hwid = { 0 };
    if (QueryHwid(device, &hwid)) {
        KGDBG(L"[+] HWID hash=%hs\n", hwid.HashHex);
        SessionSetHwid(hwid.HashHex, hwid.Json, hwid.JsonLen);
    } else {
        KGDBG(L"[!] QueryHwid failed\n");
        SessionSetHwid(NULL, NULL, 0);
    }
    SecureZeroMemory(&hwid, sizeof(hwid));

    if (!SessionStart(steamId, device, stopEvent, readyEvent)) {
        LI_KERNEL(CloseHandle)(readyEvent);
        LI_KERNEL(CloseHandle)(stopEvent);
        LI_KERNEL(CloseHandle)(device);
        return Fail(pxenc(L"session start failed"));
    }

    HANDLE waitHandles[2] = { readyEvent, stopEvent };
    DWORD w = LI_KERNEL(WaitForMultipleObjects)(2, waitHandles, FALSE, 15000);
    if (w != WAIT_OBJECT_0) {
        KGDBG(L"[!] session did not authenticate (w=%lu)\n", w);
        LI_KERNEL(SetEvent)(stopEvent);
        SessionStop();
        LI_KERNEL(CloseHandle)(readyEvent);
        LI_KERNEL(CloseHandle)(stopEvent);
        ShutdownGuard(device);
        LI_KERNEL(CloseHandle)(device);
        return Fail(pxenc(L"session authentication failed"));
    }
    KGDBG(L"[+] session ready, launching FiveM\n");

    BYTE slotKey[32] = { 0 };
    SessionGetSlotKey(slotKey);
    if (!SlotStart(device, slotKey, stopEvent)) {
        KGDBG(L"[!] slot writer start failed\n");
    } else {
        KGDBG(L"[+] slot writer armed\n");
    }
    SecureZeroMemory(slotKey, sizeof(slotKey));

#if KG_PTRCRYPT_ENABLE
    if (!PtrCryptStart(device, stopEvent)) {
        KGDBG(L"[!] ptrcrypt start failed\n");
    } else {
        KGDBG(L"[+] ptrcrypt armed\n");
    }
#else
    KGDBG(L"[i] ptrcrypt disabled via KG_PTRCRYPT_ENABLE=0\n");
#endif

    if (!AntiDbgStart(stopEvent)) {
        KGDBG(L"[!] anti-debug start returned false\n");
    } else {
        KGDBG(L"[+] anti-debug armed\n");
    }

    if (!WdaInspectStart(stopEvent)) {
        KGDBG(L"[!] wda inspect start returned false\n");
    } else {
        KGDBG(L"[+] wda inspect armed\n");
    }

    if (!NvIntegrityStart(device, stopEvent)) {
        KGDBG(L"[!] nvcontainer integrity start returned false\n");
    } else {
        KGDBG(L"[+] nvcontainer integrity armed\n");
    }

    if (!OverlayScanStart(stopEvent)) {
        KGDBG(L"[!] overlay scan start returned false\n");
    } else {
        KGDBG(L"[+] overlay scan armed\n");
    }

    KGDBG(L"[+] pci scan DISABLED\n");

    if (!KeyWatchStart(stopEvent)) {
        KGDBG(L"[!] key watch start returned false\n");
    } else {
        KGDBG(L"[+] key watch armed\n");
    }

    NetmonStart(device);
    MmapScanStart(device, readyEvent);
    IrpScanStart(device, readyEvent);
    AltScanStart(readyEvent);
    DnsScanStart(readyEvent);
    FiveMSigScanStart(readyEvent);

    if (!LaunchFiveM()) {
        KGDBG(L"[!] LaunchFiveM failed err=%lu\n", LI_KERNEL(GetLastError)());
        LI_KERNEL(SetEvent)(stopEvent);
        FiveMSigScanStop();
        DnsScanStop();
        AltScanStop();
        IrpScanStop();
        MmapScanStop();
        NetmonStop();
        SessionStop();
        LI_KERNEL(CloseHandle)(readyEvent);
        LI_KERNEL(CloseHandle)(stopEvent);
        ShutdownGuard(device);
        LI_KERNEL(CloseHandle)(device);
        return Fail(pxenc(L"fivem launch failed"));
    }
    KGDBG(L"[+] FiveM launched\n");

    KG_POLL_CTX ctx = { device, stopEvent };
#if KG_BLOCKLIST_ENABLE
    HANDLE pollThread     = LI_KERNEL(CreateThread)(NULL, 0, BlockPollThread,    &ctx,      0, NULL);
#else
    HANDLE pollThread     = NULL;
#endif
    HANDLE watchdogThread = LI_KERNEL(CreateThread)(NULL, 0, GameWatchdogThread, stopEvent, 0, NULL);

    LI_KERNEL(WaitForSingleObject)(stopEvent, INFINITE);

    PciScanStopGuarded();
    KeyWatchStop();
    OverlayScanStop();
    WdaInspectStop();
    AntiDbgStop();
#if KG_PTRCRYPT_ENABLE
    PtrCryptStop();
#endif
    SlotStop();
    FiveMSigScanStop();
    DnsScanStop();
    AltScanStop();
    IrpScanStop();
    MmapScanStop();
    NetmonStop();
    SessionStop();

    if (pollThread) {
        LI_KERNEL(WaitForSingleObject)(pollThread, 3000);
        LI_KERNEL(CloseHandle)(pollThread);
    }
    if (watchdogThread) {
        LI_KERNEL(WaitForSingleObject)(watchdogThread, 3000);
        LI_KERNEL(CloseHandle)(watchdogThread);
    }

    KillTrustedGuard(device);
    ShutdownGuard(device);

    LI_KERNEL(CloseHandle)(readyEvent);
    LI_KERNEL(CloseHandle)(stopEvent);
    LI_KERNEL(CloseHandle)(device);
    return 0;
}
