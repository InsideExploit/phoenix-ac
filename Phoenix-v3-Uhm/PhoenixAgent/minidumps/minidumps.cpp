#include "minidumps.hpp"
#include <dbghelp.h>
#include <stdio.h>
#include <string.h>
#include "../dbg.hpp"
#include "pxenc.hpp"
#include "lazy_importer.hpp"
#include "brkida.hpp"
#include "agent_stubs.hpp"

#pragma comment(lib, "dbghelp.lib")

#define JB_INIT_CAP (32 * 1024)
#define KG_MAX_DUMPS 50
#define KG_MAX_MODULES_PER_DUMP 12

#define KG_KDUMP_SIG_PAGE   0x45474150
#define KG_KDUMP_VALID_DU64 0x34365544
#define KG_KDUMP_VALID_DUMP 0x504D5544

#pragma pack(push, 4)
typedef struct _KG_DUMP_HEADER64 {
    ULONG   Signature;
    ULONG   ValidDump;
    ULONG   MajorVersion;
    ULONG   MinorVersion;
    ULONG64 DirectoryTableBase;
    ULONG64 PfnDataBase;
    ULONG64 PsLoadedModuleList;
    ULONG64 PsActiveProcessHead;
    ULONG   MachineImageType;
    ULONG   NumberOfProcessors;
    ULONG   BugCheckCode;
    ULONG   Padding;
    ULONG64 BugCheckParameter1;
    ULONG64 BugCheckParameter2;
    ULONG64 BugCheckParameter3;
    ULONG64 BugCheckParameter4;
} KG_DUMP_HEADER64;

typedef struct _KG_TRIAGE_DUMP_HEADER64 {
    ULONG   ServicePackBuild;
    ULONG   SizeOfDump;
    ULONG   ValidOffset;
    ULONG   ContextOffset;
    ULONG   ExceptionOffset;
    ULONG   MmOffset;
    ULONG   UnloadedDriversOffset;
    ULONG   PrcbOffset;
    ULONG   ProcessOffset;
    ULONG   ThreadOffset;
    ULONG   CallStackOffset;
    ULONG   SizeOfCallStack;
    ULONG   DriverListOffset;
    ULONG   DriverCount;
    ULONG   StringPoolOffset;
    ULONG   StringPoolSize;
    ULONG   BrokenDriverOffset;
    ULONG   TriageOptions;
    ULONG64 TopOfStack;
    ULONG   BugCheckCode;
    ULONG   _padding;
    ULONG64 BugCheckParameter1;
    ULONG64 BugCheckParameter2;
    ULONG64 BugCheckParameter3;
    ULONG64 BugCheckParameter4;
} KG_TRIAGE_DUMP_HEADER64;
#pragma pack(pop)

#define KG_TRIAGE_HDR_FILE_OFFSET 0x2000

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

static void
FileTimeToIso(
    const FILETIME* ft,
    char*           out,
    size_t          cap
)
{
    if (!out || cap == 0) return;
    out[0] = 0;
    if (!ft) return;
    if (ft->dwLowDateTime == 0 && ft->dwHighDateTime == 0) return;
    SYSTEMTIME st = { 0 };
    if (!LI_KERNEL(FileTimeToSystemTime)(ft, &st)) return;
    _snprintf_s(out, cap, _TRUNCATE, PX_A("%04u-%02u-%02uT%02u:%02u:%02uZ"),
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}

static bool
ScanForNeedleA(
    const void*  data,
    size_t       size,
    const char*  needle
)
{
    size_t nlen = strlen(needle);
    if (nlen == 0 || size < nlen) return false;
    const unsigned char* p = (const unsigned char*)data;
    for (size_t i = 0; i + nlen <= size; ++i) {
        if (p[i] == (unsigned char)needle[0] && memcmp(p + i, needle, nlen) == 0)
            return true;
    }
    return false;
}

static bool
GetStream(
    PVOID       Base,
    ULONG       StreamType,
    PVOID*      OutData,
    ULONG*      OutSize
)
{
    PMINIDUMP_DIRECTORY dir = NULL;
    PVOID data = NULL;
    ULONG size = 0;
    if (!LI_DBGHELP(MiniDumpReadDumpStream)(Base, StreamType, &dir, &data, &size))
        return false;
    if (OutData) *OutData = data;
    if (OutSize) *OutSize = size;
    return true;
}

static bool
IsNameChar(
    unsigned char c
)
{
    return (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') ||
           c == '_' || c == '-' || c == '.' || c == ' ' || c == '+';
}

static bool
ExtractProcessName(
    const BYTE* base,
    size_t      mapSize,
    char*       out,
    size_t      outCap
)
{
    if (!base || !out || outCap == 0) return false;
    out[0] = 0;
    if (mapSize < 16) return false;

    for (size_t i = 0; i + 15 <= mapSize; ++i) {
        const unsigned char* p = base + i;

        if (!((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z'))) continue;

        size_t k = 0;
        bool bad = false;
        while (k < 15 && p[k] != 0) {
            if (!IsNameChar(p[k])) { bad = true; break; }
            ++k;
        }
        if (bad) continue;
        if (k < 5 || k > 15) continue;

        bool paddingOk = true;
        for (size_t j = k; j < 15; ++j) {
            if (p[j] != 0) { paddingOk = false; break; }
        }
        if (!paddingOk) continue;

        size_t dotPos = 0;
        bool hasDot = false;
        for (size_t j = 0; j < k; ++j) {
            if (p[j] == '.') { dotPos = j; hasDot = true; }
        }
        if (!hasDot) continue;
        if (dotPos < 3) continue;

        size_t extLen = k - dotPos - 1;
        if (extLen == 0 || extLen > 3) continue;

        char ext[4] = { 0 };
        for (size_t j = 0; j < extLen; ++j) {
            unsigned char c = p[dotPos + 1 + j];
            if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + 32);
            ext[j] = (char)c;
        }
        if (strcmp(ext, "e") != 0 && strcmp(ext, "ex") != 0 && strcmp(ext, "exe") != 0) continue;

        char cand[16] = { 0 };
        memcpy(cand, p, k);
        cand[k] = 0;

        strcpy_s(out, outCap, cand);
        return true;
    }
    return false;
}

typedef struct _KG_DUMP_MODULE {
    ULONG64 Base;
    ULONG64 End;
    char    Name[64];
} KG_DUMP_MODULE;

static bool
MatchExtWide(
    const wchar_t* w,
    size_t         remaining,
    size_t*        outExtLen
)
{
    if (remaining < 5) return false;
    if (w[0] != L'.') return false;

    wchar_t a = w[1], b = w[2], c = w[3], d = w[4];
    wchar_t la = (a >= L'A' && a <= L'Z') ? (wchar_t)(a + 32) : a;
    wchar_t lb = (b >= L'A' && b <= L'Z') ? (wchar_t)(b + 32) : b;
    wchar_t lc = (c >= L'A' && c <= L'Z') ? (wchar_t)(c + 32) : c;

    bool sys = (la == L's' && lb == L'y' && lc == L's');
    bool dll = (la == L'd' && lb == L'l' && lc == L'l');
    bool exe = (la == L'e' && lb == L'x' && lc == L'e');
    if (!sys && !dll && !exe) return false;

    if (d != 0 && !(d >= L'0' && d <= L'9') &&
        !((d >= L'A' && d <= L'Z') || (d >= L'a' && d <= L'z')) &&
        d != L'.' && d != L'_' && d != L'-')
    {
        *outExtLen = 3;
        return true;
    }
    if (d == 0) { *outExtLen = 3; return true; }
    return false;
}

static ULONG
CollectKernelModules(
    const BYTE*      base,
    size_t           mapSize,
    KG_DUMP_MODULE*  out,
    ULONG            maxOut
)
{
    if (!base || !out || maxOut == 0) return 0;
    ULONG count = 0;

    for (size_t i = 0; i + 12 < mapSize && count < maxOut; i += 2) {
        const wchar_t* w = (const wchar_t*)(base + i);
        size_t extLen = 0;
        size_t remWChars = (mapSize - i) / 2;
        if (!MatchExtWide(w, remWChars, &extLen)) continue;

        size_t nameStart = i;
        while (nameStart >= 2) {
            wchar_t cc = *(const wchar_t*)(base + nameStart - 2);
            if (cc == 0) break;
            if (cc < 0x20 || cc > 0x7E) break;
            if (cc == L'\\' || cc == L'/' || cc == L':') break;
            nameStart -= 2;
        }
        size_t chars = ((i + 8) - nameStart) / 2;
        if (chars < 5 || chars > 60) continue;

        char nameA[64] = { 0 };
        size_t ao = 0;
        for (size_t k = 0; k < chars && ao + 1 < sizeof(nameA); ++k) {
            wchar_t wc = *(const wchar_t*)(base + nameStart + k * 2);
            if (wc >= 0x20 && wc <= 0x7E) nameA[ao++] = (char)wc;
        }
        nameA[ao] = 0;
        if (ao < 5) continue;

        bool dupName = false;
        for (ULONG m = 0; m < count; ++m) {
            if (_stricmp(out[m].Name, nameA) == 0) { dupName = true; break; }
        }
        if (dupName) continue;

        size_t nameEnd = i + 8;
        size_t searchEnd = nameEnd + 256;
        if (searchEnd > mapSize) searchEnd = mapSize;
        ULONG64 baseAddr = 0;

        for (size_t j = nameEnd; j + 8 <= searchEnd; j += 2) {
            ULONG64 v = *(const ULONG64*)(base + j);
            if (v < 0xFFFF800000000000ULL) continue;
            if (v >= 0xFFFFFFFFFFFFFFFEULL) continue;
            if ((v & 0xFFF) != 0) continue;
            baseAddr = v;
            break;
        }
        if (baseAddr == 0) continue;

        ULONG size = 0x400000;
        for (size_t j = nameEnd; j + 4 <= searchEnd; j += 4) {
            ULONG v = *(const ULONG*)(base + j);
            if (v >= 0x1000 && v <= 0x8000000 && (v & 0xFFF) == 0) { size = v; break; }
        }

        out[count].Base = baseAddr;
        out[count].End  = baseAddr + size;
        strcpy_s(out[count].Name, sizeof(out[count].Name), nameA);
        ++count;
        i += 8;
    }
    return count;
}

static const KG_DUMP_MODULE*
FindContainingModule(
    ULONG64                addr,
    const KG_DUMP_MODULE*  mods,
    ULONG                  count
)
{
    for (ULONG i = 0; i < count; ++i) {
        if (addr >= mods[i].Base && addr < mods[i].End) return &mods[i];
    }
    return NULL;
}

static void
EmitKernelStack(
    JB*                    b,
    const BYTE*            stackBase,
    size_t                 stackLen,
    ULONG64                topOfStack,
    const KG_DUMP_MODULE*  mods,
    ULONG                  modCount
)
{
    JbStr(b, PX_A("["));
    if (!stackBase || stackLen == 0) { JbStr(b, PX_A("]")); return; }

    ULONG limit = 64;
    ULONG emitted = 0;
    size_t bytes = stackLen;
    if (bytes > 0x2000) bytes = 0x2000;

    ULONG64 minKernel = 0xFFFF800000000000ULL;
    ULONG64 maxKernel = 0xFFFFFFFFFFFFFFFFULL - 0x1000;

    ULONG64 sp = topOfStack;

    for (size_t i = 0; i + 8 <= bytes && emitted < limit; i += 8) {
        ULONG64 val = *(const ULONG64*)(stackBase + i);
        if (val < minKernel || val > maxKernel) continue;
        if ((val & 0xFFF) == 0) continue;

        if (emitted) JbStr(b, PX_A(","));
        JbStr(b, PX_A("{"));
        JbFmt(b, PX_A("\"sp\":\"0x%016llX\""), (unsigned long long)(sp + i));
        JbFmt(b, PX_A(",\"ret\":\"0x%016llX\""), (unsigned long long)val);

        const KG_DUMP_MODULE* m = FindContainingModule(val, mods, modCount);
        if (m) {
            JbStr(b, PX_A(",\"mod\":"));
            JbEscUtf8(b, m->Name);
            JbFmt(b, PX_A(",\"off\":\"0x%llX\""), (unsigned long long)(val - m->Base));
        } else {
            JbStr(b, PX_A(",\"mod\":\"\",\"off\":\"\""));
        }

        JbStr(b, PX_A("}"));
        ++emitted;
    }
    JbStr(b, PX_A("]"));
}

static const wchar_t*
ModuleBasename(
    const wchar_t* path
)
{
    if (!path) return L"";
    const wchar_t* base = path;
    for (const wchar_t* p = path; *p; ++p) {
        if (*p == L'\\' || *p == L'/') base = p + 1;
    }
    return base;
}

static void
ProcessOneDump(
    JB*            b,
    const wchar_t* fullPath,
    const wchar_t* basename,
    ULONGLONG      fileSize,
    const FILETIME* fileTime,
    bool           isFirst
)
{
    if (!isFirst) JbStr(b, PX_A(","));
    JbStr(b, PX_A("{"));

    JbStr(b, PX_A("\"name\":"));    JbEscW(b, basename);
    JbStr(b, PX_A(",\"path\":"));   JbEscW(b, fullPath);
    JbFmt(b, PX_A(",\"size\":%llu"), (unsigned long long)fileSize);

    char isoTime[32] = { 0 };
    FileTimeToIso(fileTime, isoTime, sizeof(isoTime));
    JbStr(b, PX_A(",\"modifiedAt\":")); JbEscUtf8(b, isoTime);

    HANDLE hFile = LI_KERNEL(CreateFileW)(fullPath, GENERIC_READ, FILE_SHARE_READ,
                                          NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        JbStr(b, PX_A(",\"error\":\"cannot open\""));
        JbStr(b, PX_A("}"));
        return;
    }

    HANDLE hMap = LI_KERNEL(CreateFileMappingW)(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) {
        LI_KERNEL(CloseHandle)(hFile);
        JbStr(b, PX_A(",\"error\":\"cannot map\""));
        JbStr(b, PX_A("}"));
        return;
    }

    PVOID base = LI_KERNEL(MapViewOfFile)(hMap, FILE_MAP_READ, 0, 0, 0);
    LI_KERNEL(CloseHandle)(hMap);
    if (!base) {
        LI_KERNEL(CloseHandle)(hFile);
        JbStr(b, PX_A(",\"error\":\"cannot view\""));
        JbStr(b, PX_A("}"));
        return;
    }

    LARGE_INTEGER sz = { 0 };
    LI_KERNEL(GetFileSizeEx)(hFile, &sz);
    size_t mapSize = (size_t)sz.QuadPart;

    __try {
        MINIDUMP_HEADER* hdr = (MINIDUMP_HEADER*)base;
        KG_DUMP_HEADER64* kh = (KG_DUMP_HEADER64*)base;
        if (mapSize >= sizeof(KG_DUMP_HEADER64) &&
            kh->Signature == KG_KDUMP_SIG_PAGE &&
            (kh->ValidDump == KG_KDUMP_VALID_DU64 || kh->ValidDump == KG_KDUMP_VALID_DUMP)) {
            JbFmt(b, PX_A(",\"bugcheck\":%lu"), kh->BugCheckCode);
            JbStr(b, PX_A(",\"args\":["));
            JbFmt(b, PX_A("\"0x%016llX\",\"0x%016llX\",\"0x%016llX\",\"0x%016llX\""),
                  (unsigned long long)kh->BugCheckParameter1,
                  (unsigned long long)kh->BugCheckParameter2,
                  (unsigned long long)kh->BugCheckParameter3,
                  (unsigned long long)kh->BugCheckParameter4);
            JbStr(b, PX_A("]"));
            JbStr(b, PX_A(",\"exceptionAddress\":\"\""));
            const char* arch =
                kh->MachineImageType == 0x8664 ? PX_A("x64") :
                kh->MachineImageType == 0x014C ? PX_A("x86") :
                kh->MachineImageType == 0xAA64 ? PX_A("ARM64") : PX_A("unknown");
            JbFmt(b, PX_A(",\"os\":{\"major\":%lu,\"minor\":%lu,\"build\":0,\"processorArch\":%u,\"numberOfProcessors\":%u}"),
                  (unsigned long)kh->MajorVersion, (unsigned long)kh->MinorVersion,
                  kh->MachineImageType == 0x8664 ? 9 :
                  kh->MachineImageType == 0x014C ? 0 :
                  kh->MachineImageType == 0xAA64 ? 12 : 0,
                  kh->NumberOfProcessors);
            (void)arch;

            const BYTE* kBase = (const BYTE*)base;

            static KG_DUMP_MODULE kmods[256];
            ULONG kmodCount = CollectKernelModules(kBase, mapSize, kmods, ARRAYSIZE(kmods));

            ULONG64 ctxRip = 0, ctxRsp = 0;
            if (mapSize >= KG_TRIAGE_HDR_FILE_OFFSET + sizeof(KG_TRIAGE_DUMP_HEADER64)) {
                KG_TRIAGE_DUMP_HEADER64* triEarly =
                    (KG_TRIAGE_DUMP_HEADER64*)(kBase + KG_TRIAGE_HDR_FILE_OFFSET);
                if (triEarly->ContextOffset) {
                    ULONG64 ctxOff = (ULONG64)KG_TRIAGE_HDR_FILE_OFFSET + triEarly->ContextOffset;
                    if (ctxOff + 0x100 <= mapSize) {
                        ctxRsp = *(const ULONG64*)(kBase + ctxOff + 0x98);
                        ctxRip = *(const ULONG64*)(kBase + ctxOff + 0xF8);
                    }
                }
            }

            const KG_DUMP_MODULE* crashedMod = NULL;
            if (ctxRip >= 0xFFFF800000000000ULL)
                crashedMod = FindContainingModule(ctxRip, kmods, kmodCount);
            if (!crashedMod &&
                (kh->BugCheckCode == 0x1E || kh->BugCheckCode == 0x3B || kh->BugCheckCode == 0x50 ||
                 kh->BugCheckCode == 0x7E || kh->BugCheckCode == 0xC4 || kh->BugCheckCode == 0xD1 ||
                 kh->BugCheckCode == 0x139))
            {
                crashedMod = FindContainingModule(kh->BugCheckParameter3, kmods, kmodCount);
                if (!crashedMod)
                    crashedMod = FindContainingModule(kh->BugCheckParameter2, kmods, kmodCount);
                if (!crashedMod)
                    crashedMod = FindContainingModule(kh->BugCheckParameter1, kmods, kmodCount);
            }

            JbFmt(b, PX_A(",\"moduleCount\":%lu"), (unsigned long)kmodCount);
            JbStr(b, PX_A(",\"modules\":["));
            ULONG kmLimit = kmodCount < KG_MAX_MODULES_PER_DUMP ? kmodCount : KG_MAX_MODULES_PER_DUMP;
            for (ULONG i = 0; i < kmLimit; ++i) {
                if (i) JbStr(b, PX_A(","));
                JbStr(b, PX_A("{"));
                JbStr(b, PX_A("\"name\":")); JbEscUtf8(b, kmods[i].Name);
                JbFmt(b, PX_A(",\"base\":\"0x%016llX\""), (unsigned long long)kmods[i].Base);
                JbFmt(b, PX_A(",\"size\":%llu"), (unsigned long long)(kmods[i].End - kmods[i].Base));
                JbStr(b, PX_A(",\"timestamp\":0,\"versionMS\":0,\"versionLS\":0"));
                JbStr(b, PX_A("}"));
            }
            JbStr(b, PX_A("]"));

            JbStr(b, PX_A(",\"crashedModule\":"));
            if (crashedMod) JbEscUtf8(b, crashedMod->Name);
            else            JbStr(b, PX_A("\"\""));
            JbStr(b, PX_A(",\"dumpKind\":\"kernel\""));

            char processName[32] = { 0 };
            ExtractProcessName(kBase, mapSize, processName, sizeof(processName));

            JbStr(b, PX_A(",\"processName\":"));
            JbEscUtf8(b, processName);

            if (mapSize >= KG_TRIAGE_HDR_FILE_OFFSET + sizeof(KG_TRIAGE_DUMP_HEADER64)) {
                KG_TRIAGE_DUMP_HEADER64* tri =
                    (KG_TRIAGE_DUMP_HEADER64*)(kBase + KG_TRIAGE_HDR_FILE_OFFSET);

                JbStr(b, PX_A(",\"stackFrames\":["));
                bool wroteAny = false;

                if (ctxRip >= 0xFFFF800000000000ULL) {
                    JbStr(b, PX_A("{"));
                    JbFmt(b, PX_A("\"sp\":\"0x%016llX\""), (unsigned long long)ctxRsp);
                    JbFmt(b, PX_A(",\"ret\":\"0x%016llX\""), (unsigned long long)ctxRip);
                    const KG_DUMP_MODULE* mm = FindContainingModule(ctxRip, kmods, kmodCount);
                    if (mm) {
                        JbStr(b, PX_A(",\"mod\":")); JbEscUtf8(b, mm->Name);
                        JbFmt(b, PX_A(",\"off\":\"0x%llX\""), (unsigned long long)(ctxRip - mm->Base));
                    } else {
                        JbStr(b, PX_A(",\"mod\":\"\",\"off\":\"\""));
                    }
                    JbStr(b, PX_A("}"));
                    wroteAny = true;
                }

                if (tri->CallStackOffset && tri->SizeOfCallStack) {
                    ULONG64 stackFileOff = (ULONG64)KG_TRIAGE_HDR_FILE_OFFSET + tri->CallStackOffset;
                    if (stackFileOff + tri->SizeOfCallStack <= mapSize) {
                        const BYTE* stackBase = kBase + stackFileOff;
                        size_t bytes = tri->SizeOfCallStack;
                        if (bytes > 0x2000) bytes = 0x2000;
                        ULONG64 sp0 = tri->TopOfStack;
                        ULONG emitted = 0;
                        ULONG limit = 32;

                        for (size_t k = 0; k + 8 <= bytes && emitted < limit; k += 8) {
                            ULONG64 val = *(const ULONG64*)(stackBase + k);
                            if (val < 0xFFFF800000000000ULL) continue;
                            if (val == 0xFFFFFFFFFFFFFFFFULL) continue;
                            if ((val & 0xFFF) == 0) continue;
                            const KG_DUMP_MODULE* m = FindContainingModule(val, kmods, kmodCount);
                            if (!m) continue;

                            if (wroteAny) JbStr(b, PX_A(","));
                            JbStr(b, PX_A("{"));
                            JbFmt(b, PX_A("\"sp\":\"0x%016llX\""), (unsigned long long)(sp0 + k));
                            JbFmt(b, PX_A(",\"ret\":\"0x%016llX\""), (unsigned long long)val);
                            JbStr(b, PX_A(",\"mod\":")); JbEscUtf8(b, m->Name);
                            JbFmt(b, PX_A(",\"off\":\"0x%llX\""), (unsigned long long)(val - m->Base));
                            JbStr(b, PX_A("}"));
                            wroteAny = true;
                            ++emitted;
                        }
                    }
                }
                JbStr(b, PX_A("]"));
            } else {
                JbStr(b, PX_A(",\"stackFrames\":[]"));
            }

            bool hasMmCopy = ScanForNeedleA(base, mapSize, PX_A("MmCopyVirtualMemory"));
            JbFmt(b, PX_A(",\"mmCopyVirtualMemory\":%s"), hasMmCopy ? PX_A("true") : PX_A("false"));
        } else if (mapSize >= sizeof(MINIDUMP_HEADER) && hdr->Signature != MINIDUMP_SIGNATURE) {
            JbStr(b, PX_A(",\"error\":\"bad signature\""));
        } else {
            PVOID exStreamPtr = NULL;
            ULONG exStreamSize = 0;
            ULONGLONG exAddr = 0;
            if (GetStream(base, ExceptionStream, &exStreamPtr, &exStreamSize) &&
                exStreamSize >= sizeof(MINIDUMP_EXCEPTION_STREAM)) {
                MINIDUMP_EXCEPTION_STREAM* ex = (MINIDUMP_EXCEPTION_STREAM*)exStreamPtr;
                ULONG code = (ULONG)ex->ExceptionRecord.ExceptionCode;
                JbFmt(b, PX_A(",\"bugcheck\":%lu"), code);
                JbStr(b, PX_A(",\"args\":["));
                ULONG nparam = ex->ExceptionRecord.NumberParameters;
                if (nparam > 15) nparam = 15;
                for (ULONG i = 0; i < nparam; ++i) {
                    if (i) JbStr(b, PX_A(","));
                    JbFmt(b, PX_A("\"0x%016llX\""),
                          (unsigned long long)ex->ExceptionRecord.ExceptionInformation[i]);
                }
                JbStr(b, PX_A("]"));
                exAddr = ex->ExceptionRecord.ExceptionAddress;
                JbFmt(b, PX_A(",\"exceptionAddress\":\"0x%016llX\""),
                      (unsigned long long)exAddr);
            }

            PVOID sysPtr = NULL;
            ULONG sysSize = 0;
            if (GetStream(base, SystemInfoStream, &sysPtr, &sysSize) &&
                sysSize >= sizeof(MINIDUMP_SYSTEM_INFO)) {
                MINIDUMP_SYSTEM_INFO* si = (MINIDUMP_SYSTEM_INFO*)sysPtr;
                JbFmt(b, PX_A(",\"os\":{\"major\":%u,\"minor\":%u,\"build\":%u,\"processorArch\":%u,\"numberOfProcessors\":%u}"),
                      si->MajorVersion, si->MinorVersion, si->BuildNumber,
                      si->ProcessorArchitecture, si->NumberOfProcessors);
            }

            PVOID modPtr = NULL;
            ULONG modSize = 0;
            const wchar_t* crashedModule = NULL;
            if (GetStream(base, ModuleListStream, &modPtr, &modSize) &&
                modSize >= sizeof(MINIDUMP_MODULE_LIST)) {
                MINIDUMP_MODULE_LIST* mods = (MINIDUMP_MODULE_LIST*)modPtr;
                ULONG32 count = mods->NumberOfModules;
                JbFmt(b, PX_A(",\"moduleCount\":%lu"), (unsigned long)count);
                JbStr(b, PX_A(",\"modules\":["));
                ULONG32 limit = count < KG_MAX_MODULES_PER_DUMP ? count : KG_MAX_MODULES_PER_DUMP;
                for (ULONG32 i = 0; i < limit; ++i) {
                    if (i) JbStr(b, PX_A(","));
                    MINIDUMP_MODULE* m = &mods->Modules[i];
                    const wchar_t* namePtr = L"";
                    if (m->ModuleNameRva) {
                        MINIDUMP_STRING* ms = (MINIDUMP_STRING*)((BYTE*)base + m->ModuleNameRva);
                        namePtr = ms->Buffer;
                    }
                    JbStr(b, PX_A("{"));
                    JbStr(b, PX_A("\"name\":")); JbEscW(b, ModuleBasename(namePtr));
                    JbFmt(b, PX_A(",\"base\":\"0x%016llX\""), (unsigned long long)m->BaseOfImage);
                    JbFmt(b, PX_A(",\"size\":%lu"), m->SizeOfImage);
                    JbFmt(b, PX_A(",\"timestamp\":%lu"), m->TimeDateStamp);
                    JbFmt(b, PX_A(",\"versionMS\":%lu,\"versionLS\":%lu"),
                          m->VersionInfo.dwFileVersionMS, m->VersionInfo.dwFileVersionLS);
                    JbStr(b, PX_A("}"));
                }
                JbStr(b, PX_A("]"));

                for (ULONG32 i = 0; i < count; ++i) {
                    MINIDUMP_MODULE* m = &mods->Modules[i];
                    if (exAddr >= m->BaseOfImage &&
                        exAddr <  m->BaseOfImage + m->SizeOfImage) {
                        MINIDUMP_STRING* ms = (MINIDUMP_STRING*)((BYTE*)base + m->ModuleNameRva);
                        crashedModule = ms->Buffer;
                        break;
                    }
                }
            }
            if (crashedModule) {
                JbStr(b, PX_A(",\"crashedModule\":"));
                JbEscW(b, ModuleBasename(crashedModule));
            } else {
                JbStr(b, PX_A(",\"crashedModule\":\"\""));
            }

            JbStr(b, PX_A(",\"processName\":\"\""));
            JbStr(b, PX_A(",\"stackFrames\":[]"));
            JbStr(b, PX_A(",\"dumpKind\":\"user\""));

            bool hasMmCopy = ScanForNeedleA(base, mapSize, PX_A("MmCopyVirtualMemory"));
            JbFmt(b, PX_A(",\"mmCopyVirtualMemory\":%s"), hasMmCopy ? PX_A("true") : PX_A("false"));
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        JbStr(b, PX_A(",\"error\":\"parse-exception\""));
    }

    LI_KERNEL(UnmapViewOfFile)(base);
    LI_KERNEL(CloseHandle)(hFile);

    JbStr(b, PX_A("}"));
}

bool
MinidumpsCollectJson(
    char** OutJson,
    ULONG* OutLen
)
{
    BRKIDA;
    if (!OutJson || !OutLen) return false;
    *OutJson = NULL; *OutLen = 0;

    JB b = { 0 };
    if (!JbInit(&b)) return false;

    wchar_t sysroot[MAX_PATH] = { 0 };
    UINT sysrootLen = LI_KERNEL(GetSystemWindowsDirectoryW)(sysroot, ARRAYSIZE(sysroot));
    if (sysrootLen == 0) wcscpy_s(sysroot, ARRAYSIZE(sysroot), pxenc(L"C:\\Windows"));

    wchar_t folder[MAX_PATH];
    _snwprintf_s(folder, _TRUNCATE, pxenc(L"%ls\\Minidump"), sysroot);
    JbStr(&b, PX_A("{\"folder\":"));
    JbEscW(&b, folder);
    JbStr(&b, PX_A(",\"dumps\":["));

    wchar_t pattern[MAX_PATH];
    _snwprintf_s(pattern, _TRUNCATE, pxenc(L"%ls\\Minidump\\*.dmp"), sysroot);

    WIN32_FIND_DATAW fd = { 0 };
    HANDLE h = LI_KERNEL(FindFirstFileW)(pattern, &fd);
    bool first = true;
    ULONG count = 0;
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            if (count >= KG_MAX_DUMPS) break;

            wchar_t fullPath[MAX_PATH];
            _snwprintf_s(fullPath, _TRUNCATE, pxenc(L"%ls\\Minidump\\%ls"), sysroot, fd.cFileName);

            ULONGLONG fileSize =
                ((ULONGLONG)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;

            __try {
                ProcessOneDump(&b, fullPath, fd.cFileName, fileSize,
                               &fd.ftLastWriteTime, first);
                first = false;
                ++count;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
            }
        } while (LI_KERNEL(FindNextFileW)(h, &fd));
        LI_KERNEL(FindClose)(h);
    }
    JbStr(&b, PX_A("]}"));

    *OutJson = b.Buf;
    *OutLen  = b.Len;
    return true;
}

void
MinidumpsFree(
    char* Json
)
{
    if (Json) HeapFree(GetProcessHeap(), 0, Json);
}

#define KG_MAX_DUMP_BYTES (32u * 1024u * 1024u)

static bool
IsSafeDumpName(
    const char* name
)
{
    if (!name || !*name) return false;
    size_t n = strlen(name);
    if (n == 0 || n > 96) return false;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)name[i];
        bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
        if (!ok) return false;
    }
    if (n < 5) return false;
    const char* dot = name + n - 4;
    if (dot[0] != '.' ||
        (dot[1] != 'd' && dot[1] != 'D') ||
        (dot[2] != 'm' && dot[2] != 'M') ||
        (dot[3] != 'p' && dot[3] != 'P'))
        return false;
    if (name[0] == '.') return false;
    for (size_t i = 0; i + 1 < n; ++i)
        if (name[i] == '.' && name[i + 1] == '.') return false;
    return true;
}

bool
MinidumpsReadOne(
    const char*  RequestedName,
    BYTE**       OutData,
    ULONG*       OutLen
)
{
    BRKIDA;
    if (!OutData || !OutLen) return false;
    *OutData = NULL; *OutLen = 0;

    if (!IsSafeDumpName(RequestedName)) return false;

    wchar_t wname[128] = { 0 };
    int wn = LI_KERNEL(MultiByteToWideChar)(CP_UTF8, 0, RequestedName, -1,
                                            wname, ARRAYSIZE(wname));
    if (wn <= 0) return false;

    wchar_t sysroot[MAX_PATH] = { 0 };
    UINT sysrootLen = LI_KERNEL(GetSystemWindowsDirectoryW)(sysroot, ARRAYSIZE(sysroot));
    if (sysrootLen == 0) wcscpy_s(sysroot, ARRAYSIZE(sysroot), pxenc(L"C:\\Windows"));

    wchar_t fullPath[MAX_PATH];
    _snwprintf_s(fullPath, _TRUNCATE, pxenc(L"%ls\\Minidump\\%ls"), sysroot, wname);

    HANDLE hFile = LI_KERNEL(CreateFileW)(fullPath, GENERIC_READ, FILE_SHARE_READ,
                                          NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER sz = { 0 };
    if (!LI_KERNEL(GetFileSizeEx)(hFile, &sz) ||
        sz.QuadPart <= 0 || sz.QuadPart > (LONGLONG)KG_MAX_DUMP_BYTES)
    {
        LI_KERNEL(CloseHandle)(hFile);
        return false;
    }

    ULONG total = (ULONG)sz.QuadPart;
    BYTE* buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, total);
    if (!buf) {
        LI_KERNEL(CloseHandle)(hFile);
        return false;
    }

    ULONG readTotal = 0;
    while (readTotal < total) {
        DWORD got = 0;
        if (!LI_KERNEL(ReadFile)(hFile, buf + readTotal, total - readTotal, &got, NULL) ||
            got == 0)
        {
            HeapFree(GetProcessHeap(), 0, buf);
            LI_KERNEL(CloseHandle)(hFile);
            return false;
        }
        readTotal += got;
    }
    LI_KERNEL(CloseHandle)(hFile);

    *OutData = buf;
    *OutLen  = total;
    return true;
}

void
MinidumpsFreeBlob(
    BYTE* Data
)
{
    if (Data) HeapFree(GetProcessHeap(), 0, Data);
}
