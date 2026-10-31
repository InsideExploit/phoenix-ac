#include "pcitree.hpp"
#include <setupapi.h>
#include <cfgmgr32.h>
#include <devguid.h>
#include <devpropdef.h>

EXTERN_C const DEVPROPKEY DECLSPEC_SELECTANY KG_DEVPKEY_InstallDate =
    { { 0x83da6326, 0x97a6, 0x4088, { 0x94, 0x53, 0xa1, 0x92, 0x3f, 0x57, 0x3b, 0x29 } }, 100 };
EXTERN_C const DEVPROPKEY DECLSPEC_SELECTANY KG_DEVPKEY_FirstInstallDate =
    { { 0x83da6326, 0x97a6, 0x4088, { 0x94, 0x53, 0xa1, 0x92, 0x3f, 0x57, 0x3b, 0x29 } }, 101 };
EXTERN_C const DEVPROPKEY DECLSPEC_SELECTANY KG_DEVPKEY_LastArrivalDate =
    { { 0x83da6326, 0x97a6, 0x4088, { 0x94, 0x53, 0xa1, 0x92, 0x3f, 0x57, 0x3b, 0x29 } }, 102 };
EXTERN_C const DEVPROPKEY DECLSPEC_SELECTANY KG_DEVPKEY_LastRemovalDate =
    { { 0x83da6326, 0x97a6, 0x4088, { 0x94, 0x53, 0xa1, 0x92, 0x3f, 0x57, 0x3b, 0x29 } }, 103 };

EXTERN_C const DEVPROPKEY DECLSPEC_SELECTANY KG_DEVPKEY_PciMaxLinkSpeed =
    { { 0x3ab22e31, 0x8264, 0x4b4e, { 0x9a, 0xf5, 0xa8, 0xd2, 0xd8, 0xe3, 0x3e, 0x62 } }, 11 };
EXTERN_C const DEVPROPKEY DECLSPEC_SELECTANY KG_DEVPKEY_PciMaxLinkWidth =
    { { 0x3ab22e31, 0x8264, 0x4b4e, { 0x9a, 0xf5, 0xa8, 0xd2, 0xd8, 0xe3, 0x3e, 0x62 } }, 12 };
EXTERN_C const DEVPROPKEY DECLSPEC_SELECTANY KG_DEVPKEY_PciCurrentLinkSpeed =
    { { 0x3ab22e31, 0x8264, 0x4b4e, { 0x9a, 0xf5, 0xa8, 0xd2, 0xd8, 0xe3, 0x3e, 0x62 } }, 9 };
EXTERN_C const DEVPROPKEY DECLSPEC_SELECTANY KG_DEVPKEY_PciCurrentLinkWidth =
    { { 0x3ab22e31, 0x8264, 0x4b4e, { 0x9a, 0xf5, 0xa8, 0xd2, 0xd8, 0xe3, 0x3e, 0x62 } }, 10 };
#include <stdio.h>
#include <string.h>
#include "../dbg.hpp"
#include "pxenc.hpp"
#include "lazy_importer.hpp"
#include "brkida.hpp"
#include "agent_stubs.hpp"

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")
#pragma comment(lib, "advapi32.lib")

#define JB_INIT_CAP (32 * 1024)

typedef struct _JB {
    char*  Buf;
    ULONG  Len;
    ULONG  Cap;
} JB;

static bool JbGrow(JB* b, ULONG need) {
    if (b->Len + need + 1 <= b->Cap) return true;
    ULONG cap = b->Cap ? b->Cap : JB_INIT_CAP;
    while (cap < b->Len + need + 1) cap *= 2;
    char* nb = (char*)HeapReAlloc(GetProcessHeap(), 0, b->Buf, cap);
    if (!nb) return false;
    b->Buf = nb; b->Cap = cap; return true;
}
static bool JbInit(JB* b) {
    b->Buf = (char*)HeapAlloc(GetProcessHeap(), 0, JB_INIT_CAP);
    b->Len = 0; b->Cap = JB_INIT_CAP;
    if (!b->Buf) return false;
    b->Buf[0] = 0;
    return true;
}
static bool JbRaw(JB* b, const char* s, ULONG n) {
    if (!JbGrow(b, n)) return false;
    memcpy(b->Buf + b->Len, s, n);
    b->Len += n; b->Buf[b->Len] = 0;
    return true;
}
static bool JbStr(JB* b, const char* s) { return JbRaw(b, s, (ULONG)strlen(s)); }
static bool JbFmt(JB* b, const char* fmt, ...) {
    char tmp[1024];
    va_list ap; va_start(ap, fmt);
    int n = _vsnprintf_s(tmp, _TRUNCATE, fmt, ap);
    va_end(ap);
    if (n <= 0) return true;
    return JbRaw(b, tmp, (ULONG)n);
}
static bool JbEscUtf8(JB* b, const char* s) {
    if (!s) return JbStr(b, PX_A("\"\""));
    if (!JbStr(b, PX_A("\""))) return false;
    for (const unsigned char* p = (const unsigned char*)s; *p; ++p) {
        unsigned c = *p;
        switch (c) {
        case '"':  if (!JbStr(b, PX_A("\\\""))) return false; break;
        case '\\': if (!JbStr(b, PX_A("\\\\"))) return false; break;
        case '\b': if (!JbStr(b, PX_A("\\b")))  return false; break;
        case '\f': if (!JbStr(b, PX_A("\\f")))  return false; break;
        case '\n': if (!JbStr(b, PX_A("\\n")))  return false; break;
        case '\r': if (!JbStr(b, PX_A("\\r")))  return false; break;
        case '\t': if (!JbStr(b, PX_A("\\t")))  return false; break;
        default:
            if (c < 0x20) { if (!JbFmt(b, PX_A("\\u%04x"), c)) return false; }
            else          { char t[2] = { (char)c, 0 }; if (!JbStr(b, t)) return false; }
            break;
        }
    }
    return JbStr(b, PX_A("\""));
}
static bool JbEscW(JB* b, const wchar_t* w) {
    if (!w || !*w) return JbStr(b, PX_A("\"\""));
    int need = LI_KERNEL(WideCharToMultiByte)(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    if (need <= 0) return JbStr(b, PX_A("\"\""));
    char* tmp = (char*)HeapAlloc(GetProcessHeap(), 0, need);
    if (!tmp) return JbStr(b, PX_A("\"\""));
    LI_KERNEL(WideCharToMultiByte)(CP_UTF8, 0, w, -1, tmp, need, NULL, NULL);
    bool r = JbEscUtf8(b, tmp);
    HeapFree(GetProcessHeap(), 0, tmp);
    return r;
}

static bool
ReadRegSz(
    HDEVINFO         di,
    SP_DEVINFO_DATA* dd,
    DWORD            prop,
    wchar_t*         out,
    DWORD            outBytes
)
{
    if (!out || outBytes < sizeof(wchar_t)) return false;
    out[0] = 0;
    DWORD regType = 0;
    return LI_SETUPAPI(SetupDiGetDeviceRegistryPropertyW)(
        di, dd, prop, &regType, (PBYTE)out, outBytes, NULL) ? true : false;
}

static bool
ReadRegMultiSz(
    HDEVINFO         di,
    SP_DEVINFO_DATA* dd,
    DWORD            prop,
    wchar_t*         out,
    DWORD            outBytes
)
{
    if (!out || outBytes < sizeof(wchar_t) * 2) return false;
    out[0] = 0; out[1] = 0;
    DWORD regType = 0;
    return LI_SETUPAPI(SetupDiGetDeviceRegistryPropertyW)(
        di, dd, prop, &regType, (PBYTE)out, outBytes, NULL) ? true : false;
}

static bool
ReadRegDword(
    HDEVINFO         di,
    SP_DEVINFO_DATA* dd,
    DWORD            prop,
    DWORD*           out
)
{
    DWORD regType = 0;
    return LI_SETUPAPI(SetupDiGetDeviceRegistryPropertyW)(
        di, dd, prop, &regType, (PBYTE)out, sizeof(DWORD), NULL) ? true : false;
}

static void
ParseVenDev(
    const wchar_t* hwid,
    wchar_t*       venOut,
    wchar_t*       devOut,
    wchar_t*       subsysOut,
    wchar_t*       revOut
)
{
    venOut[0] = 0; devOut[0] = 0; subsysOut[0] = 0; revOut[0] = 0;
    if (!hwid) return;
    const wchar_t* p = hwid;
    while (*p) {
        if ((p[0] == L'V' || p[0] == L'v') &&
            (p[1] == L'E' || p[1] == L'e') &&
            (p[2] == L'N' || p[2] == L'n') &&
            p[3] == L'_') {
            for (int i = 0; i < 4 && p[4 + i]; ++i) venOut[i] = p[4 + i];
            venOut[4] = 0;
        } else if ((p[0] == L'D' || p[0] == L'd') &&
                   (p[1] == L'E' || p[1] == L'e') &&
                   (p[2] == L'V' || p[2] == L'v') &&
                   p[3] == L'_') {
            for (int i = 0; i < 4 && p[4 + i]; ++i) devOut[i] = p[4 + i];
            devOut[4] = 0;
        } else if ((p[0] == L'S' || p[0] == L's') &&
                   (p[1] == L'U' || p[1] == L'u') &&
                   (p[2] == L'B' || p[2] == L'b') &&
                   (p[3] == L'S' || p[3] == L's') &&
                   (p[4] == L'Y' || p[4] == L'y') &&
                   (p[5] == L'S' || p[5] == L's') &&
                   p[6] == L'_') {
            for (int i = 0; i < 8 && p[7 + i]; ++i) subsysOut[i] = p[7 + i];
            subsysOut[8] = 0;
        } else if ((p[0] == L'R' || p[0] == L'r') &&
                   (p[1] == L'E' || p[1] == L'e') &&
                   (p[2] == L'V' || p[2] == L'v') &&
                   p[3] == L'_') {
            for (int i = 0; i < 2 && p[4 + i]; ++i) revOut[i] = p[4 + i];
            revOut[2] = 0;
        }
        ++p;
    }
}

static void
FileTimeToIso(
    const FILETIME* ft,
    wchar_t*        out,
    size_t          outCap
)
{
    SYSTEMTIME st = { 0 };
    if (!ft || (ft->dwLowDateTime == 0 && ft->dwHighDateTime == 0)) { out[0] = 0; return; }
    FILETIME lft = *ft;
    if (!LI_KERNEL(FileTimeToSystemTime)(&lft, &st)) { out[0] = 0; return; }
    _snwprintf_s(out, outCap, _TRUNCATE, pxenc(L"%04u-%02u-%02uT%02u:%02u:%02uZ"),
                 st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}

static bool
GetDeviceUint32(
    HDEVINFO          di,
    SP_DEVINFO_DATA*  dd,
    const DEVPROPKEY* key,
    ULONG*            out
)
{
    if (out) *out = 0;
    DEVPROPTYPE type = 0;
    ULONG value = 0;
    DWORD required = 0;
    if (!LI_SETUPAPI(SetupDiGetDevicePropertyW)(di, dd, key,
        &type, (PBYTE)&value, sizeof(value), &required, 0))
        return false;
    if (type != DEVPROP_TYPE_UINT32) return false;
    if (out) *out = value;
    return true;
}

static bool
GetDeviceDate(
    HDEVINFO         di,
    SP_DEVINFO_DATA* dd,
    const DEVPROPKEY* key,
    wchar_t*         out,
    size_t           outCap
)
{
    out[0] = 0;
    DEVPROPTYPE type = 0;
    FILETIME ft = { 0 };
    DWORD required = 0;
    if (!LI_SETUPAPI(SetupDiGetDevicePropertyW)(di, dd, key,
        &type, (PBYTE)&ft, sizeof(ft), &required, 0))
        return false;
    if (type != DEVPROP_TYPE_FILETIME) return false;
    FileTimeToIso(&ft, out, outCap);
    return out[0] != 0;
}

static void
GetSystemRootW(
    wchar_t* out,
    size_t   cap
)
{
    out[0] = 0;
    UINT n = LI_KERNEL(GetSystemWindowsDirectoryW)(out, (UINT)cap);
    if (n == 0 || n >= cap) {
        wcscpy_s(out, cap, pxenc(L"C:\\Windows"));
    }
}

static void
NormalizeDriverPath(
    wchar_t* io,
    size_t   cap
)
{
    if (!io || !*io) return;

    if ((io[0] == L'\\' && io[1] == L'?' && io[2] == L'?' && io[3] == L'\\') ||
        (io[0] == L'\\' && io[1] == L'\\' && io[2] == L'?' && io[3] == L'\\')) {
        size_t rem = wcslen(io + 4) + 1;
        memmove(io, io + 4, rem * sizeof(wchar_t));
    }

    auto systemRootTag = PX_W(L"\\SystemRoot\\");
    size_t tagLen = 12;
    if (_wcsnicmp(io, systemRootTag, tagLen) == 0) {
        wchar_t sysroot[MAX_PATH] = { 0 };
        GetSystemRootW(sysroot, ARRAYSIZE(sysroot));
        wchar_t merged[1024] = { 0 };
        _snwprintf_s(merged, _TRUNCATE, pxenc(L"%ls\\%ls"), sysroot, io + tagLen);
        wcscpy_s(io, cap, merged);
        return;
    }

    if (io[0] == L'\\' && (io[1] < L'0' || io[1] > L'9')) {
        wchar_t sysroot[MAX_PATH] = { 0 };
        GetSystemRootW(sysroot, ARRAYSIZE(sysroot));
        wchar_t merged[1024] = { 0 };
        _snwprintf_s(merged, _TRUNCATE, pxenc(L"%ls%ls"), sysroot, io);
        wcscpy_s(io, cap, merged);
        return;
    }

    if ((io[0] >= L'a' && io[0] <= L'z') || (io[0] >= L'A' && io[0] <= L'Z')) {
        if (io[1] == L':') return;
    }

    if (io[0] && io[1]) {
        wchar_t sysroot[MAX_PATH] = { 0 };
        GetSystemRootW(sysroot, ARRAYSIZE(sysroot));
        wchar_t merged[1024] = { 0 };
        _snwprintf_s(merged, _TRUNCATE, pxenc(L"%ls\\%ls"), sysroot, io);
        wcscpy_s(io, cap, merged);
    }
}

static void
ResolveDriverPath(
    const wchar_t* service,
    wchar_t*       outPath,
    size_t         outCap
)
{
    outPath[0] = 0;
    if (!service || !*service) return;

    wchar_t keyPath[512];
    _snwprintf_s(keyPath, _TRUNCATE, pxenc(L"SYSTEM\\CurrentControlSet\\Services\\%ls"),
                 service);

    HKEY key = NULL;
    if (LI_ADVAPI(RegOpenKeyExW)(HKEY_LOCAL_MACHINE, keyPath,
                                 0, KEY_READ, &key) != ERROR_SUCCESS)
        return;

    wchar_t raw[1024] = { 0 };
    DWORD type = 0, cb = sizeof(raw) - sizeof(wchar_t);
    LONG r = LI_ADVAPI(RegQueryValueExW)(key, pxenc(L"ImagePath"), NULL, &type,
                                         (LPBYTE)raw, &cb);
    LI_ADVAPI(RegCloseKey)(key);

    if (r != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ) || cb < sizeof(wchar_t))
        return;
    DWORD chars = cb / sizeof(wchar_t);
    if (chars > 0) raw[chars - 1] = 0;

    if (type == REG_EXPAND_SZ) {
        wchar_t expanded[1024] = { 0 };
        if (LI_KERNEL(ExpandEnvironmentStringsW)(raw, expanded, ARRAYSIZE(expanded)) > 0) {
            wcscpy_s(raw, ARRAYSIZE(raw), expanded);
        }
    }

    NormalizeDriverPath(raw, ARRAYSIZE(raw));
    wcscpy_s(outPath, outCap, raw);
}

static void
EmitMemoryRanges(
    JB*      b,
    DEVINST  devInst,
    bool*    outHasResources,
    bool*    outHasMem
)
{
    *outHasResources = false;
    *outHasMem = false;
    JbStr(b, PX_A("["));

    LOG_CONF logConf = 0;
    CONFIGRET cr = LI_CFGMGR32(CM_Get_First_Log_Conf)(&logConf, devInst, ALLOC_LOG_CONF);
    if (cr != CR_SUCCESS)
        cr = LI_CFGMGR32(CM_Get_First_Log_Conf)(&logConf, devInst, BOOT_LOG_CONF);
    if (cr != CR_SUCCESS) { JbStr(b, PX_A("]")); return; }

    bool firstMem = true;
    RES_DES prev = (RES_DES)logConf;
    for (;;) {
        RES_DES resDes = 0;
        RESOURCEID resType = 0;
        cr = LI_CFGMGR32(CM_Get_Next_Res_Des)(&resDes, prev, ResType_All, &resType, 0);
        if (cr != CR_SUCCESS) break;

        *outHasResources = true;

        if (resType == ResType_Mem) {
            ULONG size = 0;
            LI_CFGMGR32(CM_Get_Res_Des_Data_Size)(&size, resDes, 0);
            if (size >= sizeof(MEM_RESOURCE)) {
                MEM_RESOURCE* mem = (MEM_RESOURCE*)HeapAlloc(GetProcessHeap(), 0, size);
                if (mem) {
                    if (LI_CFGMGR32(CM_Get_Res_Des_Data)(resDes, (PVOID)mem, size, 0) == CR_SUCCESS) {
                        if (!firstMem) JbStr(b, PX_A(","));
                        firstMem = false;
                        JbFmt(b, PX_A("{\"start\":%llu,\"end\":%llu}"),
                              (unsigned long long)mem->MEM_Header.MD_Alloc_Base,
                              (unsigned long long)mem->MEM_Header.MD_Alloc_End);
                        *outHasMem = true;
                    }
                    HeapFree(GetProcessHeap(), 0, mem);
                }
            }
        }

        if (prev != (RES_DES)logConf)
            LI_CFGMGR32(CM_Free_Res_Des_Handle)(prev);
        prev = resDes;
    }
    if (prev != (RES_DES)logConf)
        LI_CFGMGR32(CM_Free_Res_Des_Handle)(prev);
    LI_CFGMGR32(CM_Free_Log_Conf_Handle)(logConf);
    JbStr(b, PX_A("]"));
}

static void
EmitHardwareIdArray(
    JB*            b,
    const wchar_t* multiSz
)
{
    JbStr(b, PX_A("["));
    if (!multiSz) { JbStr(b, PX_A("]")); return; }
    bool first = true;
    const wchar_t* p = multiSz;
    while (*p) {
        if (!first) JbStr(b, PX_A(","));
        first = false;
        JbEscW(b, p);
        while (*p) ++p;
        ++p;
    }
    JbStr(b, PX_A("]"));
}

static void
EmitOneDevice(
    JB*              b,
    HDEVINFO         di,
    SP_DEVINFO_DATA* dd,
    bool             isFirst
)
{
    wchar_t instanceId[512] = { 0 };
    LI_SETUPAPI(SetupDiGetDeviceInstanceIdW)(di, dd, instanceId,
                                             ARRAYSIZE(instanceId) - 1, NULL);

    wchar_t desc[512]         = { 0 };
    wchar_t friendly[256]     = { 0 };
    wchar_t className[128]    = { 0 };
    wchar_t classGuid[64]     = { 0 };
    wchar_t manufacturer[256] = { 0 };
    wchar_t hwids[4096]       = { 0 };
    wchar_t service[128]      = { 0 };
    wchar_t location[256]     = { 0 };
    wchar_t driverKey[128]    = { 0 };

    ReadRegSz     (di, dd, SPDRP_DEVICEDESC,          desc,         sizeof(desc));
    ReadRegSz     (di, dd, SPDRP_FRIENDLYNAME,        friendly,     sizeof(friendly));
    ReadRegSz     (di, dd, SPDRP_CLASS,               className,    sizeof(className));
    ReadRegSz     (di, dd, SPDRP_CLASSGUID,           classGuid,    sizeof(classGuid));
    ReadRegSz     (di, dd, SPDRP_MFG,                 manufacturer, sizeof(manufacturer));
    ReadRegSz     (di, dd, SPDRP_SERVICE,             service,      sizeof(service));
    ReadRegSz     (di, dd, SPDRP_LOCATION_INFORMATION,location,     sizeof(location));
    ReadRegSz     (di, dd, SPDRP_DRIVER,              driverKey,    sizeof(driverKey));
    ReadRegMultiSz(di, dd, SPDRP_HARDWAREID,          hwids,        sizeof(hwids));

    DWORD bus = (DWORD)-1;
    DWORD address = 0;
    ReadRegDword(di, dd, SPDRP_BUSNUMBER, &bus);
    ReadRegDword(di, dd, SPDRP_ADDRESS,   &address);
    UINT devNum  = (address >> 16) & 0xFFFF;
    UINT funNum  = address & 0xFFFF;

    wchar_t ven[8] = { 0 }, dev[8] = { 0 }, sub[16] = { 0 }, rev[4] = { 0 };
    ParseVenDev(hwids, ven, dev, sub, rev);

    wchar_t driverPath[512] = { 0 };
    ResolveDriverPath(service, driverPath, ARRAYSIZE(driverPath));

    ULONG devStatus = 0, problemCode = 0;
    bool present = true;
    if (LI_CFGMGR32(CM_Get_DevNode_Status)(&devStatus, &problemCode, dd->DevInst, 0) == CR_SUCCESS) {
        present = (devStatus & DN_HAS_PROBLEM) == 0 || problemCode != CM_PROB_PHANTOM;
        if (problemCode == CM_PROB_PHANTOM) present = false;
    }

    wchar_t installDate[32]      = { 0 };
    wchar_t firstInstallDate[32] = { 0 };
    wchar_t lastArrivalDate[32]  = { 0 };
    wchar_t lastRemovalDate[32]  = { 0 };
    GetDeviceDate(di, dd, &KG_DEVPKEY_InstallDate,      installDate,      ARRAYSIZE(installDate));
    GetDeviceDate(di, dd, &KG_DEVPKEY_FirstInstallDate, firstInstallDate, ARRAYSIZE(firstInstallDate));
    GetDeviceDate(di, dd, &KG_DEVPKEY_LastArrivalDate,  lastArrivalDate,  ARRAYSIZE(lastArrivalDate));
    GetDeviceDate(di, dd, &KG_DEVPKEY_LastRemovalDate,  lastRemovalDate,  ARRAYSIZE(lastRemovalDate));

    ULONG currentLinkSpeed = 0, currentLinkWidth = 0, maxLinkSpeed = 0, maxLinkWidth = 0;
    GetDeviceUint32(di, dd, &KG_DEVPKEY_PciCurrentLinkSpeed, &currentLinkSpeed);
    GetDeviceUint32(di, dd, &KG_DEVPKEY_PciCurrentLinkWidth, &currentLinkWidth);
    GetDeviceUint32(di, dd, &KG_DEVPKEY_PciMaxLinkSpeed,     &maxLinkSpeed);
    GetDeviceUint32(di, dd, &KG_DEVPKEY_PciMaxLinkWidth,     &maxLinkWidth);

    if (!isFirst) JbStr(b, PX_A(","));
    JbStr(b, PX_A("{"));
    JbStr(b, PX_A("\"instanceId\":"));   JbEscW(b, instanceId);
    JbStr(b, PX_A(",\"description\":")); JbEscW(b, desc);
    JbStr(b, PX_A(",\"friendlyName\":"));JbEscW(b, friendly);
    JbStr(b, PX_A(",\"className\":"));   JbEscW(b, className);
    JbStr(b, PX_A(",\"classGuid\":"));   JbEscW(b, classGuid);
    JbStr(b, PX_A(",\"manufacturer\":"));JbEscW(b, manufacturer);
    JbStr(b, PX_A(",\"service\":"));     JbEscW(b, service);
    JbStr(b, PX_A(",\"driverPath\":"));  JbEscW(b, driverPath);
    JbStr(b, PX_A(",\"driverKey\":"));   JbEscW(b, driverKey);
    JbStr(b, PX_A(",\"location\":"));    JbEscW(b, location);
    JbStr(b, PX_A(",\"vendorId\":"));    JbEscW(b, ven);
    JbStr(b, PX_A(",\"deviceId\":"));    JbEscW(b, dev);
    JbStr(b, PX_A(",\"subsysId\":"));    JbEscW(b, sub);
    JbStr(b, PX_A(",\"revision\":"));    JbEscW(b, rev);
    JbStr(b, PX_A(",\"bus\":"));
    if (bus == (DWORD)-1) JbStr(b, PX_A("null")); else JbFmt(b, PX_A("%lu"), bus);
    JbFmt(b, PX_A(",\"device\":%u"), devNum);
    JbFmt(b, PX_A(",\"function\":%u"), funNum);
    JbFmt(b, PX_A(",\"present\":%s"),  present ? "true" : "false");
    JbFmt(b, PX_A(",\"status\":%lu"),  devStatus);
    JbFmt(b, PX_A(",\"problem\":%lu"), problemCode);
    JbStr(b, PX_A(",\"hardwareIds\":")); EmitHardwareIdArray(b, hwids);

    bool hasRes = false, hasMem = false;
    JbStr(b, PX_A(",\"memoryRanges\":"));
    EmitMemoryRanges(b, dd->DevInst, &hasRes, &hasMem);

    bool hasDriver = service[0] != 0;
    bool driverProblem = false;
    if (problemCode == CM_PROB_NOT_CONFIGURED    ||
        problemCode == CM_PROB_FAILED_START      ||
        problemCode == CM_PROB_NORMAL_CONFLICT   ||
        problemCode == CM_PROB_NEED_RESTART      ||
        problemCode == CM_PROB_REINSTALL         ||
        problemCode == CM_PROB_FAILED_INSTALL    ||
        problemCode == CM_PROB_FAILED_ADD        ||
        problemCode == CM_PROB_HELD_FOR_EJECT) {
        driverProblem = true;
    }

    bool isPci     = (instanceId[0] == L'P' && instanceId[1] == L'C' && instanceId[2] == L'I' && instanceId[3] == L'\\');
    bool isPciBus0 = isPci && (bus == 0);
    bool fpgaCapable = (maxLinkSpeed == 0) || (maxLinkSpeed <= 2);
    bool dmaEligible = isPci && !isPciBus0 && fpgaCapable;
    bool suspicious = dmaEligible && (!hasRes || !hasMem || !hasDriver || driverProblem);

    JbFmt(b, PX_A(",\"hasResources\":%s"), hasRes ? "true" : "false");
    JbFmt(b, PX_A(",\"hasMemoryRange\":%s"), hasMem ? "true" : "false");
    JbFmt(b, PX_A(",\"hasDriver\":%s"), hasDriver ? "true" : "false");
    JbFmt(b, PX_A(",\"isPci\":%s"), isPci ? "true" : "false");
    JbFmt(b, PX_A(",\"isPciBus0\":%s"), isPciBus0 ? "true" : "false");
    JbFmt(b, PX_A(",\"fpgaCapable\":%s"), fpgaCapable ? "true" : "false");
    JbFmt(b, PX_A(",\"suspiciousDma\":%s"), suspicious ? "true" : "false");

    JbStr(b, PX_A(",\"suspiciousReasons\":["));
    if (dmaEligible) {
        bool firstReason = true;
        if (!hasDriver)     { if (!firstReason) JbStr(b, PX_A(",")); JbStr(b, PX_A("\"driver-missing\""));   firstReason = false; }
        if (driverProblem)  { if (!firstReason) JbStr(b, PX_A(",")); JbStr(b, PX_A("\"driver-problem\""));   firstReason = false; }
        if (!hasRes)        { if (!firstReason) JbStr(b, PX_A(",")); JbStr(b, PX_A("\"no-resources\""));     firstReason = false; }
        else if (!hasMem)   { if (!firstReason) JbStr(b, PX_A(",")); JbStr(b, PX_A("\"no-memory-range\"")); firstReason = false; }
    }
    JbStr(b, PX_A("]"));

    JbStr(b, PX_A(",\"dates\":{"));
    JbStr(b, PX_A("\"install\":"));       JbEscW(b, installDate);
    JbStr(b, PX_A(",\"firstInstall\":")); JbEscW(b, firstInstallDate);
    JbStr(b, PX_A(",\"lastArrival\":"));  JbEscW(b, lastArrivalDate);
    JbStr(b, PX_A(",\"lastRemoval\":"));  JbEscW(b, lastRemovalDate);
    JbStr(b, PX_A("}"));

    JbStr(b, PX_A(",\"link\":{"));
    JbFmt(b, PX_A("\"currentSpeed\":%lu"),  currentLinkSpeed);
    JbFmt(b, PX_A(",\"currentWidth\":%lu"), currentLinkWidth);
    JbFmt(b, PX_A(",\"maxSpeed\":%lu"),     maxLinkSpeed);
    JbFmt(b, PX_A(",\"maxWidth\":%lu"),     maxLinkWidth);
    JbStr(b, PX_A("}"));

    JbStr(b, PX_A("}"));
}

bool
PciTreeCollectJson(
    char** OutJson,
    ULONG* OutLen
)
{
    BRKIDA;
    if (!OutJson || !OutLen) return false;
    *OutJson = NULL; *OutLen = 0;

    JB b = { 0 };
    if (!JbInit(&b)) return false;

    __try {
        JbStr(&b, PX_A("{\"devices\":["));

        HDEVINFO di = LI_SETUPAPI(SetupDiGetClassDevsW)(
            NULL, pxenc(L"PCI"), NULL, DIGCF_ALLCLASSES | DIGCF_PRESENT);
        if (di == INVALID_HANDLE_VALUE) {
            JbStr(&b, PX_A("]}"));
        } else {
            SP_DEVINFO_DATA dd = { 0 };
            dd.cbSize = sizeof(dd);
            bool first = true;
            for (DWORD i = 0; LI_SETUPAPI(SetupDiEnumDeviceInfo)(di, i, &dd); ++i) {
                __try {
                    EmitOneDevice(&b, di, &dd, first);
                    first = false;
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                }
            }
            LI_SETUPAPI(SetupDiDestroyDeviceInfoList)(di);
            JbStr(&b, PX_A("]}"));
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        HeapFree(GetProcessHeap(), 0, b.Buf);
        return false;
    }

    *OutJson = b.Buf;
    *OutLen  = b.Len;
    return true;
}

void
PciTreeFree(
    char* Json
)
{
    if (Json) HeapFree(GetProcessHeap(), 0, Json);
}
