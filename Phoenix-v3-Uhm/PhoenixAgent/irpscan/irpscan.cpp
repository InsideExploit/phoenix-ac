#include "irpscan.hpp"
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

#define KG_IRP_POLL_INTERVAL_MS 30000
#define KG_IRP_DRAIN_MAX        16

static HANDLE g_Device     = INVALID_HANDLE_VALUE;
static HANDLE g_Thread     = NULL;
static HANDLE g_StopEvent  = NULL;
static HANDLE g_ReadyEvent = NULL;

static
const char*
MjName(
    UINT32 Mj
)
{
    switch (Mj) {
        case 0:  return PX_A("IRP_MJ_CREATE");
        case 1:  return PX_A("IRP_MJ_CREATE_NAMED_PIPE");
        case 2:  return PX_A("IRP_MJ_CLOSE");
        case 3:  return PX_A("IRP_MJ_READ");
        case 4:  return PX_A("IRP_MJ_WRITE");
        case 5:  return PX_A("IRP_MJ_QUERY_INFORMATION");
        case 6:  return PX_A("IRP_MJ_SET_INFORMATION");
        case 7:  return PX_A("IRP_MJ_QUERY_EA");
        case 8:  return PX_A("IRP_MJ_SET_EA");
        case 9:  return PX_A("IRP_MJ_FLUSH_BUFFERS");
        case 10: return PX_A("IRP_MJ_QUERY_VOLUME_INFORMATION");
        case 11: return PX_A("IRP_MJ_SET_VOLUME_INFORMATION");
        case 12: return PX_A("IRP_MJ_DIRECTORY_CONTROL");
        case 13: return PX_A("IRP_MJ_FILE_SYSTEM_CONTROL");
        case 14: return PX_A("IRP_MJ_DEVICE_CONTROL");
        case 15: return PX_A("IRP_MJ_INTERNAL_DEVICE_CONTROL");
        case 16: return PX_A("IRP_MJ_SHUTDOWN");
        case 17: return PX_A("IRP_MJ_LOCK_CONTROL");
        case 18: return PX_A("IRP_MJ_CLEANUP");
        case 19: return PX_A("IRP_MJ_CREATE_MAILSLOT");
        case 20: return PX_A("IRP_MJ_QUERY_SECURITY");
        case 21: return PX_A("IRP_MJ_SET_SECURITY");
        case 22: return PX_A("IRP_MJ_POWER");
        case 23: return PX_A("IRP_MJ_SYSTEM_CONTROL");
        case 24: return PX_A("IRP_MJ_DEVICE_CHANGE");
        case 25: return PX_A("IRP_MJ_QUERY_QUOTA");
        case 26: return PX_A("IRP_MJ_SET_QUOTA");
        case 27: return PX_A("IRP_MJ_PNP");
        default: return PX_A("IRP_MJ_UNKNOWN");
    }
}

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
WideToJsonUtf8(
    const wchar_t* In,
    char*          Out,
    size_t         OutCap
)
{
    if (!In || !In[0] || OutCap == 0) { if (OutCap) Out[0] = 0; return; }
    int cb = WideCharToMultiByte(CP_UTF8, 0, In, -1, NULL, 0, NULL, NULL);
    if (cb <= 0 || (size_t)cb > OutCap) { Out[0] = 0; return; }
    WideCharToMultiByte(CP_UTF8, 0, In, -1, Out, (int)OutCap, NULL, NULL);
    size_t o = 0, r = 0;
    while (Out[r]) {
        unsigned c = (unsigned char)Out[r++];
        if (c == '"' || c == '\\') {
            if (o + 2 >= OutCap) break;
            Out[o++] = '\\';
            Out[o++] = (char)c;
        } else if (c < 0x20) {
            continue;
        } else {
            if (o + 1 >= OutCap) break;
            Out[o++] = (char)c;
        }
    }
    Out[o] = 0;
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
    const KG_IRP_EVENT* Ev
)
{
    BRKIDA;

    char dumpHex[KG_MMAP_DUMP_BYTES * 2 + 1];
    HexBytesToJson(Ev->Dump, Ev->DumpLen, dumpHex, sizeof(dumpHex));

    char nearestName[KG_MMAP_MOD_NAME_MAX * 2 + 1];
    JsonEscapeAsciiName(Ev->NearestModule, nearestName, sizeof(nearestName));

    char drvU[KG_IRP_NAME_MAX * 3 + 1];
    char devU[KG_IRP_NAME_MAX * 3 + 1];
    char lnkU[KG_IRP_NAME_MAX * 3 + 1];
    WideToJsonUtf8(Ev->DriverName,  drvU, sizeof(drvU));
    WideToJsonUtf8(Ev->DeviceName,  devU, sizeof(devU));
    WideToJsonUtf8(Ev->SymlinkName, lnkU, sizeof(lnkU));

    const char* mjStr = MjName(Ev->MajorFunction);

    char extras[KG_MMAP_DUMP_BYTES * 2 + 1024];
    _snprintf_s(extras, _TRUNCATE,
        PX_A("{\"address\":\"0x%016llX\","
             "\"majorFunction\":\"%s\","
             "\"majorIndex\":%u,"
             "\"driverName\":\"%s\","
             "\"deviceName\":\"%s\","
             "\"symlinkName\":\"%s\","
             "\"nearestModule\":\"%s\","
             "\"nearestOffset\":%u,"
             "\"dumpBytes\":%u,"
             "\"dumpHex\":\"%s\"}"),
        (unsigned long long)Ev->OffendingAddress,
        mjStr, (unsigned)Ev->MajorFunction,
        drvU, devU, lnkU,
        nearestName,
        (unsigned)Ev->NearestModuleOffset,
        (unsigned)Ev->DumpLen,
        dumpHex);

    char reason[128];
    _snprintf_s(reason, _TRUNCATE,
        PX_A("mapped-irp-0x%016llX"),
        (unsigned long long)Ev->OffendingAddress);

    char json[KG_MMAP_DUMP_BYTES * 2 + 4096];
    int jlen = BuildDetectionJson(PX_A("manual-mapped-irp"), reason,
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

    (void)SessionSendDetection(PX_A("manual-mapped-irp"), reason, NULL, 6, payload, total);

    HeapFree(heap, 0, payload);
    if (png) CaptureFree(png);
}

static
DWORD
WINAPI
IrpDrainThread(
    LPVOID
)
{
    BRKIDA;
    KG_IRP_EVENT ev;

    HANDLE waits[2] = { g_ReadyEvent, g_StopEvent };
    DWORD  gateWait = LI_KERNEL(WaitForMultipleObjects)(2, waits, FALSE, INFINITE);
    if (gateWait != WAIT_OBJECT_0) return 0;
    LI_KERNEL(Sleep)(1000);
    for (;;) {
        if (!SessionIsAllowlisted()) {
            for (int drained = 0; drained < KG_IRP_DRAIN_MAX; ++drained) {
                DWORD got = 0;
                BOOL ok = LI_KERNEL(DeviceIoControl)(
                    g_Device, IOCTL_KG_IRP_POP, NULL, 0, &ev, sizeof(ev), &got, NULL);
                if (!ok) break;
                if (got != sizeof(ev)) break;
                ReportOne(&ev);
            }
        }

        if (LI_KERNEL(WaitForSingleObject)(g_StopEvent, KG_IRP_POLL_INTERVAL_MS) != WAIT_TIMEOUT)
            break;
    }
    return 0;
}

bool
IrpScanStart(
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

    g_Thread = LI_KERNEL(CreateThread)(NULL, 0, IrpDrainThread, NULL, 0, NULL);
    return g_Thread != NULL;
}

void
IrpScanStop(
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
