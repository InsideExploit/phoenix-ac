#include "hwid.hpp"

#include <ntstrsafe.h>
#include <intrin.h>
#include <bcrypt.h>

#include "pxstr.hpp"
#include "klazy.hpp"

extern "C" {
	NTSTATUS
	NTAPI
	ZwQuerySystemInformation(
	    _In_      ULONG   SystemInformationClass,
	    _Inout_   PVOID   SystemInformation,
	    _In_      ULONG   SystemInformationLength,
	    _Out_opt_ PULONG  ReturnLength
	);
}

#define KG_SYSINFO_FIRMWARE_TABLE 76
#define KG_SMBIOS_SIGNATURE       0x52534D42u

typedef struct _KG_FW_INFO {
    ULONG ProviderSignature;
    ULONG Action;
    ULONG TableID;
    ULONG TableBufferLength;
    UCHAR TableBuffer[1];
} KG_FW_INFO, *PKG_FW_INFO;

typedef struct _KG_SMBIOS_HEADER {
    UCHAR  Type;
    UCHAR  Length;
    USHORT Handle;
} KG_SMBIOS_HEADER, *PKG_SMBIOS_HEADER;

static SIZE_T SafeStrLenA(const CHAR* s, SIZE_T cap)
{
    SIZE_T n = 0;
    while (n < cap && s[n])
        n++;

    return n;
}

static const CHAR* GetSmbiosString(const UCHAR* structEnd, const UCHAR* bufEnd, UCHAR index)
{
    if (index == 0)
        return "";

    const CHAR* p = (const CHAR*)structEnd;
    UCHAR n = 1;

    while ((const UCHAR*)p < bufEnd && *p != 0) {
        SIZE_T len = SafeStrLenA(p, (SIZE_T)(bufEnd - (const UCHAR*)p));
        if (n == index)
            return p;

        p += len + 1;
        n++;
    }

    return "";
}

static const UCHAR* NextSmbios(const UCHAR* cur, const UCHAR* bufEnd)
{
    const KG_SMBIOS_HEADER* h = (const KG_SMBIOS_HEADER*)cur;
    const UCHAR* strStart = cur + h->Length;
    const UCHAR* p = strStart;

    while (p + 1 < bufEnd) {
        if (p[0] == 0 && p[1] == 0)
            return p + 2;

        p++;
    }

    return bufEnd;
}

static void AppendJson(CHAR* out, SIZE_T cap, SIZE_T* off, const CHAR* key, const CHAR* value)
{
    if (!value)
        value = "";

    SIZE_T remain = (cap > *off) ? cap - *off - 1 : 0;
    if (remain == 0)
        return;

    CHAR esc[512];
    SIZE_T eo = 0;

    for (SIZE_T i = 0; value[i] && eo + 6 < sizeof(esc); i++) {
        CHAR c = value[i];

        if (c == '"' || c == '\\') {
            esc[eo++] = '\\';
            esc[eo++] = c;
        } else if ((UCHAR)c < 0x20)
            esc[eo++] = '_';
        else
            esc[eo++] = c;
    }
    esc[eo] = 0;

    NTSTATUS s = RtlStringCchPrintfA(out + *off, remain,
        PX_A("%s\"%s\":\"%s\""), *off > 1 ? PX_A(",") : PX_A(""), key, esc);

    if (NT_SUCCESS(s)) {
        SIZE_T len = 0;
        RtlStringCchLengthA(out + *off, remain, &len);
        *off += len;
    }
}

static void CpuBrandString(CHAR out[49])
{
    int r[4] = { 0 };
    __cpuid(r, 0x80000000);
    RtlZeroMemory(out, 49);

    if ((unsigned)r[0] < 0x80000004u)
        return;

    __cpuid((int*)out,        0x80000002);
    __cpuid((int*)(out + 16), 0x80000003);
    __cpuid((int*)(out + 32), 0x80000004);
    out[48] = 0;

    for (SIZE_T i = 0; i < 48; i++) {
        if ((UCHAR)out[i] < 0x20)
            out[i] = ' ';
    }
}

static void CpuVendorSignature(CHAR outVendor[13], UINT32* outSig)
{
    int r[4] = { 0 };
    __cpuid(r, 0);
    RtlZeroMemory(outVendor, 13);
    RtlCopyMemory(outVendor + 0, &r[1], 4);
    RtlCopyMemory(outVendor + 4, &r[3], 4);
    RtlCopyMemory(outVendor + 8, &r[2], 4);
    __cpuid(r, 1);
    *outSig = (UINT32)r[0];
}

static void UuidToHex(const UCHAR* uuid, CHAR out[37])
{
    static const CHAR hex[] = "0123456789abcdef";

    for (int i = 0; i < 16; i++) {
        out[i * 2]     = hex[(uuid[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[ uuid[i]       & 0xF];
    }
    out[32] = 0;
}

static void HashHex(const UCHAR* mac, CHAR out[65])
{
    static const CHAR hex[] = "0123456789abcdef";

    for (int i = 0; i < 32; i++) {
        out[i * 2]     = hex[(mac[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[ mac[i]       & 0xF];
    }
    out[64] = 0;
}

static NTSTATUS Sha256(const UCHAR* data, ULONG len, UCHAR out[32])
{
    BCRYPT_ALG_HANDLE  alg = NULL;
    BCRYPT_HASH_HANDLE h   = NULL;

    NTSTATUS s = KL_KSECDD(BCryptOpenAlgorithmProvider)(&alg, PX_W(BCRYPT_SHA256_ALGORITHM), NULL, 0);
    if (!NT_SUCCESS(s))
        return s;

    s = KL_KSECDD(BCryptCreateHash)(alg, &h, NULL, 0, NULL, 0, 0);
    if (!NT_SUCCESS(s)) {
        KL_KSECDD(BCryptCloseAlgorithmProvider)(alg, 0);
        return s;
    }

    s = KL_KSECDD(BCryptHashData)(h, (PUCHAR)data, len, 0);
    if (NT_SUCCESS(s))
        s = KL_KSECDD(BCryptFinishHash)(h, out, 32, 0);

    KL_KSECDD(BCryptDestroyHash)(h);
    KL_KSECDD(BCryptCloseAlgorithmProvider)(alg, 0);
    return s;
}

static NTSTATUS ReadSmbios(PVOID* Out, ULONG* OutLen)
{
    ULONG needed = 0;
    KG_FW_INFO probe = { KG_SMBIOS_SIGNATURE, 1, 0, 0 };

    NTSTATUS s = KL_NT(ZwQuerySystemInformation)(KG_SYSINFO_FIRMWARE_TABLE,
                                                 &probe, sizeof(probe), &needed);
    if (s != STATUS_BUFFER_TOO_SMALL && s != STATUS_INFO_LENGTH_MISMATCH)
        return s;

    if (needed < sizeof(KG_FW_INFO))
        return STATUS_UNSUCCESSFUL;

    PVOID buf = KL_NT(ExAllocatePool2)(POOL_FLAG_PAGED, needed, 'DwHk');
    if (!buf)
        return STATUS_INSUFFICIENT_RESOURCES;

    KG_FW_INFO* req = (KG_FW_INFO*)buf;
    req->ProviderSignature = KG_SMBIOS_SIGNATURE;
    req->Action            = 1;
    req->TableID           = 0;
    req->TableBufferLength = needed - FIELD_OFFSET(KG_FW_INFO, TableBuffer);

    ULONG got = 0;
    s = KL_NT(ZwQuerySystemInformation)(KG_SYSINFO_FIRMWARE_TABLE, buf, needed, &got);
    if (!NT_SUCCESS(s)) {
        g_KH.ExFreePoolWithTag(buf, 0);
        return s;
    }

    *Out    = buf;
    *OutLen = got;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
HwidCollect(
    KG_HWID_RESULT* Out
)
{
    if (!Out)
        return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(Out, sizeof(*Out));

    CHAR   sysManuf[128]      = { 0 };
    CHAR   sysProduct[128]    = { 0 };
    CHAR   sysSerial[128]     = { 0 };
    CHAR   sysUuid[37]        = { 0 };
    CHAR   boardManuf[128]    = { 0 };
    CHAR   boardProduct[128]  = { 0 };
    CHAR   boardSerial[128]   = { 0 };
    CHAR   chassisSerial[128] = { 0 };
    CHAR   biosVendor[128]    = { 0 };
    CHAR   biosVersion[128]   = { 0 };
    CHAR   cpuBrand[49]       = { 0 };
    CHAR   cpuVendor[13]      = { 0 };
    UINT32 cpuSig             = 0;

    CpuBrandString(cpuBrand);
    CpuVendorSignature(cpuVendor, &cpuSig);

    PVOID fw = NULL;
    ULONG fwLen = 0;
    NTSTATUS s = ReadSmbios(&fw, &fwLen);
    if (NT_SUCCESS(s) && fw) {
        KG_FW_INFO*  info     = (KG_FW_INFO*)fw;
        const UCHAR* table    = info->TableBuffer;
        ULONG        tableLen = info->TableBufferLength;

        if (tableLen >= 8 && FIELD_OFFSET(KG_FW_INFO, TableBuffer) + tableLen <= fwLen) {
            ULONG        rawOff = 8;
            const UCHAR* p      = table + rawOff;
            const UCHAR* end    = table + tableLen;

            while (p + sizeof(KG_SMBIOS_HEADER) <= end) {
                const KG_SMBIOS_HEADER* h = (const KG_SMBIOS_HEADER*)p;
                if (h->Length < sizeof(KG_SMBIOS_HEADER))
                    break;

                const UCHAR* structEnd = p + h->Length;
                if (structEnd > end)
                    break;

                switch (h->Type) {
                case 0: {
                    UCHAR viIdx = p[0x04], vsIdx = p[0x05];
                    RtlStringCbCopyA(biosVendor,  sizeof(biosVendor),  GetSmbiosString(structEnd, end, viIdx));
                    RtlStringCbCopyA(biosVersion, sizeof(biosVersion), GetSmbiosString(structEnd, end, vsIdx));
                    break;
                }
                case 1: {
                    if (h->Length >= 0x19) {
                        UCHAR mi = p[0x04], pi = p[0x05], si = p[0x07];
                        RtlStringCbCopyA(sysManuf,   sizeof(sysManuf),   GetSmbiosString(structEnd, end, mi));
                        RtlStringCbCopyA(sysProduct, sizeof(sysProduct), GetSmbiosString(structEnd, end, pi));
                        RtlStringCbCopyA(sysSerial,  sizeof(sysSerial),  GetSmbiosString(structEnd, end, si));
                        UuidToHex(p + 0x08, sysUuid);
                    }
                    break;
                }
                case 2: {
                    if (h->Length >= 0x08) {
                        UCHAR mi = p[0x04], pi = p[0x05], si = p[0x07];
                        RtlStringCbCopyA(boardManuf,   sizeof(boardManuf),   GetSmbiosString(structEnd, end, mi));
                        RtlStringCbCopyA(boardProduct, sizeof(boardProduct), GetSmbiosString(structEnd, end, pi));
                        RtlStringCbCopyA(boardSerial,  sizeof(boardSerial),  GetSmbiosString(structEnd, end, si));
                    }
                    break;
                }
                case 3: {
                    if (h->Length >= 0x08) {
                        UCHAR si = p[0x07];
                        RtlStringCbCopyA(chassisSerial, sizeof(chassisSerial), GetSmbiosString(structEnd, end, si));
                    }
                    break;
                }
                }

                p = NextSmbios(p, end);
                if (p == NULL || p >= end)
                    break;

                if (h->Type == 127)
                    break;
            }
        }

        g_KH.ExFreePoolWithTag(fw, 0);
    }

    SIZE_T off = 0;
    Out->Json[0] = '{';
    off = 1;

    AppendJson(Out->Json, sizeof(Out->Json), &off, PX_A("sysManufacturer"),   sysManuf);
    AppendJson(Out->Json, sizeof(Out->Json), &off, PX_A("sysProduct"),        sysProduct);
    AppendJson(Out->Json, sizeof(Out->Json), &off, PX_A("sysSerial"),         sysSerial);
    AppendJson(Out->Json, sizeof(Out->Json), &off, PX_A("sysUuid"),           sysUuid);
    AppendJson(Out->Json, sizeof(Out->Json), &off, PX_A("boardManufacturer"), boardManuf);
    AppendJson(Out->Json, sizeof(Out->Json), &off, PX_A("boardProduct"),      boardProduct);
    AppendJson(Out->Json, sizeof(Out->Json), &off, PX_A("boardSerial"),       boardSerial);
    AppendJson(Out->Json, sizeof(Out->Json), &off, PX_A("chassisSerial"),     chassisSerial);
    AppendJson(Out->Json, sizeof(Out->Json), &off, PX_A("biosVendor"),        biosVendor);
    AppendJson(Out->Json, sizeof(Out->Json), &off, PX_A("biosVersion"),       biosVersion);
    AppendJson(Out->Json, sizeof(Out->Json), &off, PX_A("cpuBrand"),          cpuBrand);
    AppendJson(Out->Json, sizeof(Out->Json), &off, PX_A("cpuVendor"),         cpuVendor);

    CHAR cpuSigStr[16] = { 0 };
    RtlStringCbPrintfA(cpuSigStr, sizeof(cpuSigStr), PX_A("0x%08x"), cpuSig);
    AppendJson(Out->Json, sizeof(Out->Json), &off, PX_A("cpuSig"), cpuSigStr);

    if (off + 1 < sizeof(Out->Json))
        Out->Json[off++] = '}';

    Out->Json[off] = 0;
    Out->JsonLen   = (UINT32)off;

    CHAR canonical[1024];
    RtlStringCbPrintfA(canonical, sizeof(canonical),
        PX_A("sysUuid=%s|sysSerial=%s|boardSerial=%s|chassisSerial=%s|cpuVendor=%s|cpuSig=0x%08x"),
        sysUuid, sysSerial, boardSerial, chassisSerial, cpuVendor, cpuSig);

    SIZE_T canLen = 0;
    RtlStringCbLengthA(canonical, sizeof(canonical), &canLen);
    Sha256((const UCHAR*)canonical, (ULONG)canLen, Out->Hash);
    HashHex(Out->Hash, Out->HashHex);
    return STATUS_SUCCESS;
}
