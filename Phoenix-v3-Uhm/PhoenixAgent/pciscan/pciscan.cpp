#include "pciscan.hpp"
#include <windows.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <stdio.h>
#include <wchar.h>
#include "../session/session.hpp"
#include "../report/report.hpp"
#include "../dbg.hpp"
#include "pxstr.hpp"
#include "agent_stubs.hpp"
#include "pxenc.hpp"
#include "lazy_importer.hpp"
#include "brkida.hpp"

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")

typedef struct _KG_PCI_DEV {
    wchar_t Instance[MAX_DEVICE_ID_LEN];
    wchar_t Desc[256];
    wchar_t ClassName[64];
    wchar_t Mfg[128];
    wchar_t Location[256];
    ULONG   Vid;
    ULONG   Did;
    ULONG   Subsys;
    ULONG   Rev;
    BOOLEAN InUse;
} KG_PCI_DEV;

#define KG_PCI_CACHE_MAX 512

static KG_PCI_DEV       g_Cache[KG_PCI_CACHE_MAX];
static CRITICAL_SECTION g_CacheLock;
static HCMNOTIFICATION  g_HNotify = NULL;
static BOOLEAN          g_Inited  = FALSE;

static
const wchar_t*
VendorName(
    ULONG vid
)
{
    BRKIDA;
    switch (vid) {
    case 0x8086: return PX_W(L"Intel");
    case 0x1022: return PX_W(L"AMD");
    case 0x10DE: return PX_W(L"NVIDIA");
    case 0x1002: return PX_W(L"AMD/ATI");
    case 0x10EC: return PX_W(L"Realtek");
    case 0x14E4: return PX_W(L"Broadcom");
    case 0x168C: return PX_W(L"Qualcomm Atheros");
    case 0x17CB: return PX_W(L"Qualcomm");
    case 0x1969: return PX_W(L"Attansic");
    case 0x1AE0: return PX_W(L"Google");
    case 0x1B4B: return PX_W(L"Marvell");
    case 0x1B6F: return PX_W(L"Etron");
    case 0x1B21: return PX_W(L"ASMedia");
    case 0x144D: return PX_W(L"Samsung");
    case 0x1987: return PX_W(L"Phison");
    case 0x15B7: return PX_W(L"SanDisk");
    case 0x1179: return PX_W(L"Toshiba");
    case 0x1CC1: return PX_W(L"ADATA");
    case 0x1C5C: return PX_W(L"SK hynix");
    case 0x1E4B: return PX_W(L"MAXIO");
    case 0x1D79: return PX_W(L"Silicon Motion");
    case 0x1DEE: return PX_W(L"Kingston");
    case 0x1B36: return PX_W(L"Red Hat (virtio)");
    case 0x15AD: return PX_W(L"VMware");
    case 0x1414: return PX_W(L"Microsoft (Hyper-V)");
    case 0x10EE: return PX_W(L"Xilinx (FPGA)");
    case 0x1172: return PX_W(L"Altera/Intel FPGA");
    case 0x12BA: return PX_W(L"PLX/DMA-family");
    case 0x1AFC: return PX_W(L"Lattice");
    case 0x1957: return PX_W(L"Freescale");
    case 0x1D0F: return PX_W(L"Amazon");
    default:     return PX_W(L"Unknown");
    }
}

static
bool
ParseVenDev(
    const wchar_t* hwid,
    ULONG*         pVid,
    ULONG*         pDid,
    ULONG*         pSubsys,
    ULONG*         pRev
)
{
    BRKIDA;

    if (!hwid)
        return false;

    const wchar_t* ven = wcsstr(hwid, PX_W(L"VEN_"));
    const wchar_t* dev = wcsstr(hwid, PX_W(L"DEV_"));
    if (!ven || !dev)
        return false;

    unsigned vid = 0, did = 0, sub = 0, rev = 0;
    swscanf_s(ven + 4, PX_W(L"%4x"), &vid);
    swscanf_s(dev + 4, PX_W(L"%4x"), &did);

    const wchar_t* subs = wcsstr(hwid, PX_W(L"SUBSYS_"));
    if (subs)
        swscanf_s(subs + 7, PX_W(L"%8x"), &sub);

    const wchar_t* r = wcsstr(hwid, PX_W(L"REV_"));
    if (r)
        swscanf_s(r + 4, PX_W(L"%2x"), &rev);

    if (pVid)    *pVid    = vid;
    if (pDid)    *pDid    = did;
    if (pSubsys) *pSubsys = sub;
    if (pRev)    *pRev    = rev;
    return true;
}

static
void
SymLinkToInstance(
    const wchar_t* sl,
    wchar_t*       out,
    size_t         cap
)
{
    BRKIDA;

    if (!sl || !out || cap == 0) {
        if (cap)
            out[0] = 0;
        return;
    }

    const wchar_t* p = sl;
    if (p[0] == L'\\' && p[1] == L'\\' && p[2] == L'?' && p[3] == L'\\')
        p += 4;

    size_t o = 0;
    while (*p && *p != L'{' && o + 1 < cap) {
        out[o++] = (*p == L'#') ? L'\\' : *p;
        p++;
    }

    while (o > 0 && (out[o-1] == L'\\' || out[o-1] == L' '))
        o--;

    out[o] = 0;
}

static
bool
IsPciSymLink(
    const wchar_t* sl
)
{
    BRKIDA;

    if (!sl)
        return false;

    for (const wchar_t* p = sl; *p; p++) {
        wchar_t a = p[0], b = p[1], c = p[2], d = p[3];
        if ((a == L'P' || a == L'p') &&
            (b == L'C' || b == L'c') &&
            (c == L'I' || c == L'i') &&
             d == L'#')
            return true;
    }

    return false;
}

static
void
PopulateDevice(
    HDEVINFO         set,
    PSP_DEVINFO_DATA di,
    KG_PCI_DEV*      out
)
{
    BRKIDA;
    RtlZeroMemory(out, sizeof(*out));
    LI_CFGMGR32(CM_Get_Device_IDW)(di->DevInst, out->Instance, ARRAYSIZE(out->Instance), 0);
    LI_SETUPAPI(SetupDiGetDeviceRegistryPropertyW)(set, di, SPDRP_DEVICEDESC,          NULL, (PBYTE)out->Desc,      sizeof(out->Desc),      NULL);
    LI_SETUPAPI(SetupDiGetDeviceRegistryPropertyW)(set, di, SPDRP_CLASS,               NULL, (PBYTE)out->ClassName, sizeof(out->ClassName), NULL);
    LI_SETUPAPI(SetupDiGetDeviceRegistryPropertyW)(set, di, SPDRP_MFG,                 NULL, (PBYTE)out->Mfg,       sizeof(out->Mfg),       NULL);
    LI_SETUPAPI(SetupDiGetDeviceRegistryPropertyW)(set, di, SPDRP_LOCATION_INFORMATION,NULL, (PBYTE)out->Location,  sizeof(out->Location),  NULL);

    wchar_t hwid[1024] = { 0 };
    LI_SETUPAPI(SetupDiGetDeviceRegistryPropertyW)(set, di, SPDRP_HARDWAREID, NULL, (PBYTE)hwid, sizeof(hwid), NULL);
    ParseVenDev(hwid, &out->Vid, &out->Did, &out->Subsys, &out->Rev);

    out->InUse = TRUE;
}

static
void
CachePut(
    const KG_PCI_DEV* dev
)
{
    BRKIDA;
    EnterCriticalSection(&g_CacheLock);

    for (ULONG i = 0; i < KG_PCI_CACHE_MAX; i++) {
        if (g_Cache[i].InUse && _wcsicmp(g_Cache[i].Instance, dev->Instance) == 0) {
            g_Cache[i] = *dev;
            LeaveCriticalSection(&g_CacheLock);
            return;
        }
    }

    for (ULONG i = 0; i < KG_PCI_CACHE_MAX; i++) {
        if (!g_Cache[i].InUse) {
            g_Cache[i] = *dev;
            LeaveCriticalSection(&g_CacheLock);
            return;
        }
    }

    LeaveCriticalSection(&g_CacheLock);
}

static
BOOLEAN
CacheTakeByInstance(
    const wchar_t* instance,
    KG_PCI_DEV*    out
)
{
    BRKIDA;
    EnterCriticalSection(&g_CacheLock);

    for (ULONG i = 0; i < KG_PCI_CACHE_MAX; i++) {
        if (g_Cache[i].InUse && _wcsicmp(g_Cache[i].Instance, instance) == 0) {
            *out = g_Cache[i];
            g_Cache[i].InUse = FALSE;
            LeaveCriticalSection(&g_CacheLock);
            return TRUE;
        }
    }

    LeaveCriticalSection(&g_CacheLock);
    return FALSE;
}

static
void
EnumeratePciSilent(
)
{
    BRKIDA;
    HDEVINFO set = LI_SETUPAPI(SetupDiGetClassDevsW)(NULL, pxenc(L"PCI"), NULL,
                                                     DIGCF_ALLCLASSES | DIGCF_PRESENT);
    if (set == INVALID_HANDLE_VALUE)
        return;

    SP_DEVINFO_DATA di = { 0 };
    di.cbSize = sizeof(di);
    for (DWORD i = 0; LI_SETUPAPI(SetupDiEnumDeviceInfo)(set, i, &di); i++) {
        KG_PCI_DEV dev;
        PopulateDevice(set, &di, &dev);
        CachePut(&dev);
    }

    LI_SETUPAPI(SetupDiDestroyDeviceInfoList)(set);
}

static
void
RefreshOneByInstance(
    const wchar_t* instance
)
{
    BRKIDA;
    HDEVINFO set = LI_SETUPAPI(SetupDiGetClassDevsW)(NULL, instance, NULL, DIGCF_ALLCLASSES);
    if (set == INVALID_HANDLE_VALUE)
        return;

    SP_DEVINFO_DATA di = { 0 };
    di.cbSize = sizeof(di);
    if (LI_SETUPAPI(SetupDiEnumDeviceInfo)(set, 0, &di)) {
        KG_PCI_DEV dev;
        PopulateDevice(set, &di, &dev);
        if (dev.Vid != 0 || dev.Did != 0)
            CachePut(&dev);
    }

    LI_SETUPAPI(SetupDiDestroyDeviceInfoList)(set);
}

static
void
EscapeUtf8(
    const char* in,
    char*       out,
    size_t      cap
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    size_t o = 0;
    if (!in) {
        if (cap)
            out[0] = 0;
        return;
    }

    for (size_t i = 0; in[i] && o + 8 < cap; i++) {
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
                o += _snprintf_s(out + o, cap - o, _TRUNCATE, "\\u%04x", c);
            else
                out[o++] = (char)c;
        }
    }

    if (o < cap)
        out[o] = 0;
    else
        out[cap - 1] = 0;
}

static
void
WideToEsc(
    const wchar_t* in,
    char*          out,
    size_t         cap
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

    EscapeUtf8(tmp, out, cap);
}

static
void
ReportRemoval(
    const KG_PCI_DEV* dev
)
{
    BRKIDA;
    VIRTUALIZER_START;

    auto fmt_extras = PX_A("{\"vendor\":\"%s\",\"vid\":\"0x%04X\",\"did\":\"0x%04X\","
                                  "\"subsys\":\"0x%08X\",\"rev\":\"0x%02X\","
                                  "\"description\":\"%s\",\"className\":\"%s\","
                                  "\"manufacturer\":\"%s\",\"location\":\"%s\","
                                  "\"instance\":\"%s\"}");
    auto fmt_reason = PX_A("%s device unplugged (VID=%04X DID=%04X)");

    char descU[512], classU[256], mfgU[384], locU[512], instU[600];
    char vendorU[128];
    char extras[2048];
    char reason[256];

    WideToEsc(dev->Desc,     descU,  sizeof(descU));
    WideToEsc(dev->ClassName,classU, sizeof(classU));
    WideToEsc(dev->Mfg,      mfgU,   sizeof(mfgU));
    WideToEsc(dev->Location, locU,   sizeof(locU));
    WideToEsc(dev->Instance, instU,  sizeof(instU));

    {
        char tmp[128] = { 0 };
        WideCharToMultiByte(CP_UTF8, 0, VendorName(dev->Vid), -1,
                                       tmp, sizeof(tmp) - 1, NULL, NULL);
        EscapeUtf8(tmp, vendorU, sizeof(vendorU));
    }

    _snprintf_s(extras, _TRUNCATE, fmt_extras,
        vendorU, dev->Vid, dev->Did, dev->Subsys, dev->Rev,
        descU, classU, mfgU, locU, instU);

    _snprintf_s(reason, _TRUNCATE, fmt_reason,
                mfgU[0] ? mfgU : vendorU, dev->Vid, dev->Did);

    VIRTUALIZER_END

    char json[3072];
    int jlen = BuildDetectionJson(PX_A("pci-removed"), reason, NULL, NULL, extras,
                                  json, sizeof(json));
    if (jlen <= 0)
        return;

    ULONG plen  = (ULONG)jlen;
    ULONG total = 4 + plen;
    BYTE* payload = (BYTE*)HeapAlloc(GetProcessHeap(), 0, total);
    if (!payload)
        return;

    payload[0] = (BYTE)(plen >> 24);
    payload[1] = (BYTE)(plen >> 16);
    payload[2] = (BYTE)(plen >> 8);
    payload[3] = (BYTE)plen;
    memcpy(payload + 4, json, plen);

    SessionSendDetection(PX_A("pci-removed"), reason, NULL, 3, payload, total);
    HeapFree(GetProcessHeap(), 0, payload);
}

static
DWORD
CALLBACK
OnDeviceEvent(
    HCMNOTIFICATION       hNotify,
    PVOID                 Context,
    CM_NOTIFY_ACTION      Action,
    PCM_NOTIFY_EVENT_DATA EventData,
    DWORD                 EventDataSize
)
{
    BRKIDA;
    UNREFERENCED_PARAMETER(hNotify);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(EventDataSize);

    if (!EventData || EventData->FilterType != CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE)
        return ERROR_SUCCESS;

    const wchar_t* sl = EventData->u.DeviceInterface.SymbolicLink;
    if (!IsPciSymLink(sl))
        return ERROR_SUCCESS;

    wchar_t instance[MAX_DEVICE_ID_LEN] = { 0 };
    SymLinkToInstance(sl, instance, ARRAYSIZE(instance));
    if (!instance[0])
        return ERROR_SUCCESS;

    if (Action == CM_NOTIFY_ACTION_DEVICEINTERFACEARRIVAL) {
        RefreshOneByInstance(instance);
    } else if (Action == CM_NOTIFY_ACTION_DEVICEINTERFACEREMOVAL) {
        KG_PCI_DEV dev;
        if (CacheTakeByInstance(instance, &dev))
            ReportRemoval(&dev);
    }

    return ERROR_SUCCESS;
}

bool
PciScanStart(
    HANDLE StopEvent
)
{
    BRKIDA;
    UNREFERENCED_PARAMETER(StopEvent);

    if (g_Inited)
        return false;

    KGDBG(L"[pci] init-cs\n");
    InitializeCriticalSection(&g_CacheLock);
    RtlZeroMemory(g_Cache, sizeof(g_Cache));

    KGDBG(L"[pci] enum-start\n");
    EnumeratePciSilent();
    KGDBG(L"[pci] enum-done\n");

    CM_NOTIFY_FILTER filter = { 0 };
    filter.cbSize     = sizeof(filter);
    filter.Flags      = CM_NOTIFY_FILTER_FLAG_ALL_INTERFACE_CLASSES;
    filter.FilterType = CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE;

    CONFIGRET cr = LI_CFGMGR32(CM_Register_Notification)(&filter, NULL, OnDeviceEvent, &g_HNotify);
    KGDBG(L"[pci] register cr=%u\n", cr);
    if (cr != CR_SUCCESS) {
        DeleteCriticalSection(&g_CacheLock);
        return false;
    }

    g_Inited = TRUE;
    return true;
}

void
PciScanStop(
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    if (!g_Inited)
        return;

    if (g_HNotify) {
        LI_CFGMGR32(CM_Unregister_Notification)(g_HNotify);
        g_HNotify = NULL;
    }

    DeleteCriticalSection(&g_CacheLock);
    g_Inited = FALSE;
}
