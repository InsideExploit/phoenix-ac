#include "mmapscan.hpp"
#include <windows.h>
#include <stdio.h>
#include "shared.hpp"
#include "../dbg.hpp"
#include "../session/session.hpp"
#include "../report/report.hpp"
#include "../capture/capture.hpp"
#include "pxstr.hpp"
#include "pxenc.hpp"
#include "lazy_importer.hpp"
#include "brkida.hpp"
#include "agent_stubs.hpp"

#define KG_MMAP_POLL_INTERVAL_MS 30000
#define KG_MMAP_DRAIN_MAX        32

static HANDLE g_Device     = INVALID_HANDLE_VALUE;
static HANDLE g_Thread     = NULL;
static HANDLE g_StopEvent  = NULL;
static HANDLE g_ReadyEvent = NULL;

static
void
HexBytesToJson(
    const UINT8* Bytes,
    UINT32       Len,
    char*        Out,
    size_t       OutCap
)
{
    static const char hd[] = "0123456789abcdef";
    size_t o = 0;
    for (UINT32 i = 0; i < Len && o + 2 < OutCap; ++i) {
        Out[o++] = hd[(Bytes[i] >> 4) & 0xf];
        Out[o++] = hd[Bytes[i] & 0xf];
    }
    if (o < OutCap) Out[o] = 0;
    else if (OutCap > 0) Out[OutCap - 1] = 0;
}

static
void
JsonEscapeAsciiName(
    const char* In,
    char*       Out,
    size_t      OutCap
)
{
    size_t o = 0;
    for (size_t i = 0; In[i] && o + 1 < OutCap; ++i) {
        unsigned c = (unsigned char)In[i];
        if (c == '"' || c == '\\') {
            if (o + 2 >= OutCap) break;
            Out[o++] = '\\';
            Out[o++] = (char)c;
        } else if (c < 0x20) {
            continue;
        } else {
            Out[o++] = (char)c;
        }
    }
    Out[o] = 0;
}

static
void
ReportOne(
    const KG_MMAP_EVENT* Ev
)
{
    BRKIDA;

    char dumpHex[KG_MMAP_DUMP_BYTES * 2 + 1];
    HexBytesToJson(Ev->Dump, Ev->DumpLen, dumpHex, sizeof(dumpHex));

    char nearestName[KG_MMAP_MOD_NAME_MAX * 2 + 1];
    JsonEscapeAsciiName(Ev->NearestModule, nearestName, sizeof(nearestName));

    char extras[KG_MMAP_DUMP_BYTES * 2 + 512];
    _snprintf_s(extras, _TRUNCATE,
        PX_A("{\"address\":\"0x%016llX\","
             "\"tid\":%u,"
             "\"nearestModule\":\"%s\","
             "\"nearestOffset\":%u,"
             "\"dumpBytes\":%u,"
             "\"dumpHex\":\"%s\"}"),
        (unsigned long long)Ev->StartAddress,
        (unsigned)Ev->Tid,
        nearestName,
        (unsigned)Ev->NearestModuleOffset,
        (unsigned)Ev->DumpLen,
        dumpHex);

    char reason[128];
    _snprintf_s(reason, _TRUNCATE,
        PX_A("mapped-thread-0x%016llX"),
        (unsigned long long)Ev->StartAddress);

    char json[KG_MMAP_DUMP_BYTES * 2 + 2048];
    int jlen = BuildDetectionJson(PX_A("manual-mapped-driver"), reason,
                                  NULL, NULL, extras, json, sizeof(json));
    ULONG plen = jlen > 0 ? (ULONG)jlen : 0;
    if (!plen) return;

    BYTE* png = NULL; ULONG pngLen = 0;
    CaptureScreenshot(SessionGetSteamId(), reason, &png, &pngLen, NULL, 0);

    ULONG effPngLen = pngLen;
    if (4 + plen + effPngLen > 32u * 1024u * 1024u - 4096u) {
        effPngLen = 0;
    }
    ULONG total = 4 + plen + effPngLen;

    HANDLE heap = GetProcessHeap();
    BYTE* payload = (BYTE*)HeapAlloc(heap, 0, total);
    if (!payload) {
        if (png) CaptureFree(png);
        return;
    }

    payload[0] = (BYTE)(plen >> 24);
    payload[1] = (BYTE)(plen >> 16);
    payload[2] = (BYTE)(plen >> 8);
    payload[3] = (BYTE)plen;
    memcpy(payload + 4, json, plen);
    if (effPngLen && png) memcpy(payload + 4 + plen, png, effPngLen);

    (void)SessionSendDetection(PX_A("manual-mapped-driver"), reason, NULL, 6, payload, total);

    HeapFree(heap, 0, payload);
    if (png) CaptureFree(png);
}

static
DWORD
WINAPI
MmapDrainThread(
    LPVOID
)
{
    BRKIDA;
    KG_MMAP_EVENT ev;

    HANDLE waits[2] = { g_ReadyEvent, g_StopEvent };
    DWORD  gateWait = LI_KERNEL(WaitForMultipleObjects)(2, waits, FALSE, INFINITE);
    if (gateWait != WAIT_OBJECT_0) return 0;
    LI_KERNEL(Sleep)(1000);
    for (;;) {
        if (!SessionIsAllowlisted()) {
            for (int drained = 0; drained < KG_MMAP_DRAIN_MAX; ++drained) {
                DWORD got = 0;
                BOOL ok = LI_KERNEL(DeviceIoControl)(
                    g_Device, IOCTL_KG_MMAP_POP, NULL, 0, &ev, sizeof(ev), &got, NULL);
                if (!ok) break;
                if (got != sizeof(ev)) break;
                ReportOne(&ev);
            }
        }

        if (LI_KERNEL(WaitForSingleObject)(g_StopEvent, KG_MMAP_POLL_INTERVAL_MS) != WAIT_TIMEOUT)
            break;
    }
    return 0;
}

bool
MmapScanStart(
    HANDLE Device,
    HANDLE ReadyEvent
)
{
    if (Device == INVALID_HANDLE_VALUE) return false;
    if (!ReadyEvent) return false;
    if (g_Thread) return true;

    g_Device     = Device;
    g_ReadyEvent = ReadyEvent;
    g_StopEvent  = LI_KERNEL(CreateEventW)(NULL, TRUE, FALSE, NULL);
    if (!g_StopEvent) return false;

    g_Thread = LI_KERNEL(CreateThread)(NULL, 0, MmapDrainThread, NULL, 0, NULL);
    return g_Thread != NULL;
}

void
MmapScanStop(
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
    g_Device = INVALID_HANDLE_VALUE;
}
