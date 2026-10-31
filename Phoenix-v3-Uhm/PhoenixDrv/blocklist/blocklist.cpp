#include "blocklist.hpp"

#include <ntstrsafe.h>

#include "pxstr.hpp"
#include "klazy.hpp"

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif

extern "C" {
	NTSTATUS
	SeLocateProcessImageName(
	    _In_  PEPROCESS         Process,
	    _Out_ PUNICODE_STRING*  pImageFileName
	);

	NTSTATUS
	NTAPI
	ZwQuerySystemInformation(
	    _In_      ULONG   SystemInformationClass,
	    _Inout_   PVOID   SystemInformation,
	    _In_      ULONG   SystemInformationLength,
	    _Out_opt_ PULONG  ReturnLength
	);
}

#ifndef SystemProcessInformation
#define SystemProcessInformation 5
#endif

typedef struct _KG_SPI {
    ULONG          NextEntryOffset;
    ULONG          NumberOfThreads;
    UCHAR          Reserved1[48];
    UNICODE_STRING ImageName;
    LONG           BasePriority;
    HANDLE         UniqueProcessId;
    HANDLE         InheritedFromUniqueProcessId;
} KG_SPI, *PKG_SPI;

extern "C"
VOID
BlocklistRecordFromKernel(
    _In_ PCUNICODE_STRING Path,
    _In_ const WCHAR*     Reason
);

extern "C"
VOID
BlocklistKillProtectedFromKernel(
    VOID
);

#define KG_STR_MAX      64
#define KG_XOR_KEY_LO   0x5A
#define KG_XOR_KEY_HI   0x2C

typedef struct _KG_BLOCK_ENTRY {
    wchar_t Basename[KG_STR_MAX];
    wchar_t Company[KG_STR_MAX];
    wchar_t Original[KG_STR_MAX];
    wchar_t Reason[KG_STR_MAX];
} KG_BLOCK_ENTRY, *PKG_BLOCK_ENTRY;

static constexpr wchar_t KobPlaceholder()
{
    return (wchar_t)((KG_XOR_KEY_HI << 8) | KG_XOR_KEY_LO);
}

static constexpr wchar_t KobRound(wchar_t plain, size_t idx)
{
    wchar_t key = (wchar_t)(((KG_XOR_KEY_HI + (idx * 7)) << 8) | ((KG_XOR_KEY_LO ^ (idx * 3)) & 0xFF));
    return (wchar_t)(plain ^ key);
}

static constexpr KG_BLOCK_ENTRY KobMake(const wchar_t* base, const wchar_t* company,
                                         const wchar_t* orig, const wchar_t* reason)
{
    KG_BLOCK_ENTRY e{};

    for (size_t i = 0; i < KG_STR_MAX; i++) {
        e.Basename[i] = KobRound((wchar_t)0, i);
        e.Company[i]  = KobRound((wchar_t)0, i);
        e.Original[i] = KobRound((wchar_t)0, i);
        e.Reason[i]   = KobRound((wchar_t)0, i);
    }

    if (base) {
        for (size_t i = 0; base[i] && i < KG_STR_MAX - 1; i++)
            e.Basename[i] = KobRound(base[i], i);
    }

    if (company) {
        for (size_t i = 0; company[i] && i < KG_STR_MAX - 1; i++)
            e.Company[i] = KobRound(company[i], i);
    }

    if (orig) {
        for (size_t i = 0; orig[i] && i < KG_STR_MAX - 1; i++)
            e.Original[i] = KobRound(orig[i], i);
    }

    if (reason) {
        for (size_t i = 0; reason[i] && i < KG_STR_MAX - 1; i++)
            e.Reason[i] = KobRound(reason[i], i);
    }

    return e;
}

static void KobDecode(const wchar_t* enc, wchar_t* out)
{
    for (size_t i = 0; i < KG_STR_MAX; i++) {
        out[i] = KobRound(enc[i], i);

        if (out[i] == 0) {
            for (size_t j = i + 1; j < KG_STR_MAX; j++)
                out[j] = 0;

            return;
        }
    }

    out[KG_STR_MAX - 1] = 0;
}

static const KG_BLOCK_ENTRY g_Blocklist[] = {
    KobMake(L"x64dbg.exe",                        L"x64dbg",                          nullptr,                L"x64dbg"),
    KobMake(L"x32dbg.exe",                        L"x64dbg",                          nullptr,                L"x64dbg"),
    KobMake(L"cheatengine.exe",                   L"Cheat Engine",                    nullptr,                L"Cheat Engine"),
    KobMake(L"cheatengine-i386.exe",              L"Cheat Engine",                    nullptr,                L"Cheat Engine"),
    KobMake(L"cheatengine-x86_64.exe",            L"Cheat Engine",                    nullptr,                L"Cheat Engine"),
    KobMake(L"cheatengine-x86_64-SSE4-AVX2.exe",  L"Cheat Engine",                    nullptr,                L"Cheat Engine"),
    KobMake(L"ida.exe",                           L"Hex-Rays",                        nullptr,                L"IDA"),
    KobMake(L"ida64.exe",                         L"Hex-Rays",                        nullptr,                L"IDA"),
    KobMake(L"ida32.exe",                         L"Hex-Rays",                        nullptr,                L"IDA"),
    KobMake(L"idag.exe",                          L"Hex-Rays",                        nullptr,                L"IDA"),
    KobMake(L"idaq.exe",                          L"Hex-Rays",                        nullptr,                L"IDA"),
    KobMake(L"idaw.exe",                          L"Hex-Rays",                        nullptr,                L"IDA"),
    KobMake(L"HxD.exe",                           nullptr,                            nullptr,                L"HxD"),
    KobMake(L"die.exe",                           nullptr,                            nullptr,                L"Detect It Easy"),
    KobMake(L"diec.exe",                          nullptr,                            nullptr,                L"Detect It Easy"),
    KobMake(L"ProcessHacker.exe",                 nullptr,                            nullptr,                L"Process Hacker"),
    KobMake(L"SystemInformer.exe",                nullptr,                            nullptr,                L"System Informer"),
    KobMake(L"OllyDbg.exe",                       nullptr,                            nullptr,                L"OllyDbg"),
    KobMake(L"ollyice.exe",                       nullptr,                            nullptr,                L"OllyICE"),
    KobMake(L"windbg.exe",                        nullptr,                            nullptr,                L"WinDbg"),
    KobMake(L"windbgx.exe",                       nullptr,                            nullptr,                L"WinDbg Preview"),
    KobMake(L"binaryninja.exe",                   L"Vector 35",                       nullptr,                L"Binary Ninja"),
    KobMake(L"ReClass.exe",                       nullptr,                            nullptr,                L"ReClass"),
    KobMake(L"ReClass.NET.exe",                   nullptr,                            nullptr,                L"ReClass.NET"),
    KobMake(L"ReClass64.exe",                     nullptr,                            nullptr,                L"ReClass"),
    KobMake(L"ScyllaHide.exe",                    nullptr,                            nullptr,                L"ScyllaHide"),
    KobMake(L"Scylla.exe",                        nullptr,                            nullptr,                L"Scylla"),
    KobMake(L"CFF Explorer.exe",                  nullptr,                            nullptr,                L"CFF Explorer"),
    KobMake(L"PE-bear.exe",                       nullptr,                            nullptr,                L"PE-bear"),
    KobMake(L"PEview.exe",                        nullptr,                            nullptr,                L"PEview"),
    KobMake(L"Wireshark.exe",                     nullptr,                            nullptr,                L"Wireshark"),
    KobMake(L"Fiddler.exe",                       nullptr,                            nullptr,                L"Fiddler"),
    KobMake(L"httpdebuggerui.exe",                nullptr,                            nullptr,                L"HTTP Debugger"),
    KobMake(L"frida.exe",                         nullptr,                            nullptr,                L"Frida"),
    KobMake(L"frida-server.exe",                  nullptr,                            nullptr,                L"Frida"),
    KobMake(L"dnSpy.exe",                         nullptr,                            nullptr,                L"dnSpy"),
    KobMake(L"dnSpyEx.exe",                       nullptr,                            nullptr,                L"dnSpyEx"),
    KobMake(L"ImHex.exe",                         nullptr,                            nullptr,                L"ImHex"),
    KobMake(L"cutter.exe",                        nullptr,                            nullptr,                L"Cutter"),
    KobMake(L"iaito.exe",                         nullptr,                            nullptr,                L"iaito"),
    KobMake(L"radare2.exe",                       nullptr,                            nullptr,                L"radare2"),
    KobMake(L"r2.exe",                            nullptr,                            nullptr,                L"radare2"),
    KobMake(L"ImmunityDebugger.exe",              nullptr,                            nullptr,                L"Immunity Debugger"),
    KobMake(L"lordpe.exe",                        nullptr,                            nullptr,                L"LordPE"),
    KobMake(L"exeinfope.exe",                     nullptr,                            nullptr,                L"Exeinfo PE"),
    KobMake(L"apimonitor-x64.exe",                nullptr,                            nullptr,                L"API Monitor"),
    KobMake(L"apimonitor-x86.exe",                nullptr,                            nullptr,                L"API Monitor"),
    KobMake(L"procexp64.exe",                     nullptr,                            nullptr,                L"Process Explorer"),
    KobMake(L"procexp.exe",                       nullptr,                            nullptr,                L"Process Explorer"),
    KobMake(L"procmon64.exe",                     nullptr,                            nullptr,                L"Process Monitor"),
    KobMake(L"procmon.exe",                       nullptr,                            nullptr,                L"Process Monitor"),
    KobMake(L"tcpview.exe",                       nullptr,                            nullptr,                L"TCPView"),
    KobMake(L"vmmap.exe",                         nullptr,                            nullptr,                L"VMMap"),
    KobMake(L"listdlls.exe",                      nullptr,                            nullptr,                L"ListDLLs"),
    KobMake(L"autoruns.exe",                      nullptr,                            nullptr,                L"Autoruns"),
    KobMake(L"autorunsc.exe",                     nullptr,                            nullptr,                L"Autoruns"),
    KobMake(L"charles.exe",                       nullptr,                            nullptr,                L"Charles Proxy"),
    KobMake(L"mitmweb.exe",                       nullptr,                            nullptr,                L"mitmproxy"),
    KobMake(L"mitmdump.exe",                      nullptr,                            nullptr,                L"mitmproxy"),
    KobMake(L"burpsuite.exe",                     nullptr,                            nullptr,                L"Burp Suite"),
    KobMake(L"iMonitor.exe",                      nullptr,                            nullptr,                L"iMonitor"),
    KobMake(L"iMonitor64.exe",                    nullptr,                            nullptr,                L"iMonitor"),
    KobMake(L"iMonitorApp.exe",                   nullptr,                            nullptr,                L"iMonitor"),
    KobMake(nullptr,                              L"Cheat Engine",                    nullptr,                L"Cheat Engine (renamed)"),
    KobMake(nullptr,                              L"x64dbg",                          nullptr,                L"x64dbg (renamed)"),
    KobMake(nullptr,                              L"Hex-Rays",                        nullptr,                L"IDA (renamed)"),
    KobMake(nullptr,                              L"Vector 35",                       nullptr,                L"Binary Ninja (renamed)"),
    KobMake(nullptr,                              L"Winsider Seminars & Solutions Inc.", nullptr,             L"System Informer (renamed)"),
    KobMake(nullptr,                              L"Wen Jia Liu",                     nullptr,                L"Process Hacker (renamed)"),
    KobMake(nullptr,                              L"Sysinternals",                    nullptr,                L"Sysinternals tool (renamed)"),
    KobMake(nullptr,                              L"Rapid7",                          nullptr,                L"Metasploit (renamed)"),
    KobMake(nullptr,                              nullptr,                            L"cheatengine.exe",     L"Cheat Engine (renamed)"),
    KobMake(nullptr,                              nullptr,                            L"scyllahide.exe",      L"ScyllaHide (renamed)"),
    KobMake(nullptr,                              nullptr,                            L"processhacker.exe",   L"Process Hacker (renamed)"),
    KobMake(nullptr,                              nullptr,                            L"systeminformer.exe",  L"System Informer (renamed)"),
    KobMake(nullptr,                              nullptr,                            L"dnspy.exe",           L"dnSpy (renamed)"),
    KobMake(nullptr,                              nullptr,                            L"radare2.exe",         L"radare2 (renamed)"),
    KobMake(nullptr,                              nullptr,                            L"iMonitor.exe",        L"iMonitor (renamed)"),
    KobMake(nullptr,                              nullptr,                            L"iMonitor64.exe",      L"iMonitor (renamed)"),
    KobMake(nullptr,                              nullptr,                            L"iMonitorApp.exe",     L"iMonitor (renamed)"),
    KobMake(nullptr,                              L"wecooperate",                     nullptr,                L"iMonitor (renamed)"),
};

static const UINT32 g_KnownIconFnv32[] = {
    0x00000000,
};

#define KG_ICON_HASH_COUNT (sizeof(g_KnownIconFnv32) / sizeof(g_KnownIconFnv32[0]))

static
BOOLEAN
BaseEquals(
    _In_ PCUNICODE_STRING Path,
    _In_ const wchar_t*   Target
)
{
    if (Path == NULL ||
        Path->Length == 0 ||
        Path->Buffer == NULL ||
        Target == NULL ||
        !Target[0])
        return FALSE;

    USHORT Chars = Path->Length / sizeof(WCHAR);
    LONG   Split = -1;

    for (LONG i = (LONG)Chars - 1; i >= 0; --i) {
        if (Path->Buffer[i] == L'\\' || Path->Buffer[i] == L'/') {
            Split = i;
            break;
        }
    }

    UNICODE_STRING Base;
    Base.Buffer        = Path->Buffer + (Split + 1);
    Base.Length        = (USHORT)((Chars - (Split + 1)) * sizeof(WCHAR));
    Base.MaximumLength = Base.Length;

    UNICODE_STRING Want;
    KlazyMakeUS(&Want, Target);
    return KL_NT(RtlEqualUnicodeString)(&Base, &Want, TRUE);
}

static
NTSTATUS
ReadEntireFile(
    _In_     PCUNICODE_STRING Path,
    _Outptr_ PVOID*           Out,
    _Out_    SIZE_T*          OutLen
)
{
    if (Path == NULL || Out == NULL || OutLen == NULL)
        return STATUS_INVALID_PARAMETER;

    OBJECT_ATTRIBUTES Attributes;
    InitializeObjectAttributes(&Attributes,
                               (PUNICODE_STRING)Path,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    HANDLE          FileHandle = NULL;
    IO_STATUS_BLOCK Iosb       = { 0 };
    NTSTATUS        Status     = KL_NT(ZwCreateFile)(&FileHandle,
                                                     FILE_GENERIC_READ,
                                                     &Attributes,
                                                     &Iosb,
                                                     NULL,
                                                     FILE_ATTRIBUTE_NORMAL,
                                                     FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                                     FILE_OPEN,
                                                     FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
                                                     NULL,
                                                     0);
    if (!NT_SUCCESS(Status))
        return Status;

    FILE_STANDARD_INFORMATION StandardInfo = { 0 };
    Status = KL_NT(ZwQueryInformationFile)(FileHandle,
                                           &Iosb,
                                           &StandardInfo,
                                           sizeof(StandardInfo),
                                           FileStandardInformation);
    if (!NT_SUCCESS(Status)) {
        KL_NT(ZwClose)(FileHandle);
        return Status;
    }

    if (StandardInfo.EndOfFile.QuadPart <= 0 ||
        StandardInfo.EndOfFile.QuadPart > 32ULL * 1024 * 1024) {
        KL_NT(ZwClose)(FileHandle);
        return STATUS_FILE_TOO_LARGE;
    }

    SIZE_T Size   = (SIZE_T)StandardInfo.EndOfFile.QuadPart;
    PVOID  Buffer = KL_NT(ExAllocatePool2)(POOL_FLAG_PAGED, Size, 'BvKn');
    if (Buffer == NULL) {
        KL_NT(ZwClose)(FileHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    LARGE_INTEGER Offset = { 0 };
    Status = KL_NT(ZwReadFile)(FileHandle,
                               NULL,
                               NULL,
                               NULL,
                               &Iosb,
                               Buffer,
                               (ULONG)Size,
                               &Offset,
                               NULL);
    KL_NT(ZwClose)(FileHandle);
    if (!NT_SUCCESS(Status)) {
        g_KH.ExFreePoolWithTag(Buffer, 0);
        return Status;
    }

    *Out    = Buffer;
    *OutLen = Iosb.Information;
    return STATUS_SUCCESS;
}

static
SIZE_T
CountWideChars(
    _In_z_ const WCHAR* Str
)
{
    SIZE_T Count = 0;
    while (Str[Count])
        Count++;

    return Count;
}

static
BOOLEAN
FindWideCI(
    _In_    PVOID        Buf,
    _In_    SIZE_T       BufLen,
    _In_z_  const WCHAR* Needle,
    _In_    SIZE_T       Start,
    _Out_   SIZE_T*      OutOffset
)
{
    if (Buf == NULL || Needle == NULL)
        return FALSE;

    SIZE_T NeedleChars = CountWideChars(Needle);
    if (NeedleChars == 0)
        return FALSE;

    SIZE_T NeedleBytes = NeedleChars * sizeof(WCHAR);
    if (Start + NeedleBytes > BufLen)
        return FALSE;

    UCHAR* Base = (UCHAR*)Buf;
    SIZE_T End  = BufLen - NeedleBytes;

    for (SIZE_T i = Start; i <= End; i += 2) {
        BOOLEAN Match = TRUE;

        for (SIZE_T k = 0; k < NeedleChars; k++) {
            WCHAR A = *(WCHAR*)(Base + i + k * sizeof(WCHAR));
            WCHAR B = Needle[k];

            if (A >= L'A' && A <= L'Z') A = (WCHAR)(A + 32);
            if (B >= L'A' && B <= L'Z') B = (WCHAR)(B + 32);

            if (A != B) {
                Match = FALSE;
                break;
            }
        }

        if (Match) {
            *OutOffset = i;
            return TRUE;
        }
    }

    return FALSE;
}

static
BOOLEAN
ExtractVersionValue(
    _In_                   PVOID        FileBuf,
    _In_                   SIZE_T       FileLen,
    _In_z_                 const WCHAR* Key,
    _Out_writes_(OutChars) WCHAR*       Out,
    _In_                   SIZE_T       OutChars
)
{
    SIZE_T MarkerOffset = 0;
    if (!FindWideCI(FileBuf, FileLen, PX_W(L"VS_VERSION_INFO"), 0, &MarkerOffset))
        return FALSE;

    UCHAR* Base        = (UCHAR*)FileBuf;
    SIZE_T SearchStart = MarkerOffset;
    SIZE_T SearchEnd   = FileLen;
    if (SearchStart + 0x8000 < SearchEnd)
        SearchEnd = SearchStart + 0x8000;

    SIZE_T KeyOffset = 0;
    if (!FindWideCI(FileBuf, SearchEnd, Key, SearchStart, &KeyOffset))
        return FALSE;

    SIZE_T KeyChars = CountWideChars(Key);
    SIZE_T After    = KeyOffset + KeyChars * sizeof(WCHAR) + sizeof(WCHAR);

    while (After + sizeof(WCHAR) <= SearchEnd && *(WCHAR*)(Base + After) == 0)
        After += sizeof(WCHAR);

    if (After >= SearchEnd)
        return FALSE;

    SIZE_T Copied = 0;
    while (After + sizeof(WCHAR) <= SearchEnd && Copied + 1 < OutChars) {
        WCHAR Ch = *(WCHAR*)(Base + After);
        if (Ch == 0)
            break;

        Out[Copied++] = Ch;
        After += sizeof(WCHAR);
    }

    Out[Copied] = 0;
    return Copied > 0;
}

static
BOOLEAN
WideEqualsCI(
    _In_z_ const WCHAR* A,
    _In_z_ const WCHAR* B
)
{
    if (A == NULL || B == NULL)
        return FALSE;

    while (*A && *B) {
        WCHAR a = *A;
        WCHAR b = *B;

        if (a >= L'A' && a <= L'Z') a = (WCHAR)(a + 32);
        if (b >= L'A' && b <= L'Z') b = (WCHAR)(b + 32);

        if (a != b)
            return FALSE;

        A++;
        B++;
    }

    return *A == 0 && *B == 0;
}

static
UINT32
Fnv1a32(
    _In_reads_bytes_(Len) const UCHAR* Data,
    _In_                  SIZE_T       Len
)
{
    UINT32 Hash = 2166136261u;

    for (SIZE_T i = 0; i < Len; i++) {
        Hash ^= Data[i];
        Hash *= 16777619u;
    }

    return Hash;
}

static
UINT32
ReadU32Le(
    _In_reads_(4) const UCHAR* Bytes
)
{
    return (UINT32)Bytes[0] |
           ((UINT32)Bytes[1] << 8) |
           ((UINT32)Bytes[2] << 16) |
           ((UINT32)Bytes[3] << 24);
}

static
UINT16
ReadU16Le(
    _In_reads_(2) const UCHAR* Bytes
)
{
    return (UINT16)(Bytes[0] | (Bytes[1] << 8));
}

static
BOOLEAN
IconHashMatches(
    _In_ PVOID  FileBuf,
    _In_ SIZE_T FileLen
)
{
    if (KG_ICON_HASH_COUNT == 1 && g_KnownIconFnv32[0] == 0)
        return FALSE;

    if (FileLen < 0x400)
        return FALSE;

    UCHAR* Base = (UCHAR*)FileBuf;
    if (Base[0] != 'M' || Base[1] != 'Z')
        return FALSE;

    UINT32 PeOffset = ReadU32Le(Base + 0x3C);
    if (PeOffset + 0x108 > FileLen)
        return FALSE;

    if (ReadU32Le(Base + PeOffset) != 0x00004550u)
        return FALSE;

    UINT16 Magic        = ReadU16Le(Base + PeOffset + 0x18);
    UINT32 DataDirOff   = PeOffset + 0x18 + ((Magic == 0x20b) ? 0x70 : 0x60);
    UINT32 ResRva       = ReadU32Le(Base + DataDirOff + 2 * 8);
    UINT32 ResSize      = ReadU32Le(Base + DataDirOff + 2 * 8 + 4);
    if (ResRva == 0 || ResSize == 0)
        return FALSE;

    UINT16 NumSec = ReadU16Le(Base + PeOffset + 6);
    UINT32 SecOff = PeOffset + 0x18 + ReadU16Le(Base + PeOffset + 0x14);
    if (SecOff + NumSec * 0x28 > FileLen)
        return FALSE;

    UINT32 ResFileOff = 0;
    for (UINT16 i = 0; i < NumSec; i++) {
        UINT32 Va   = ReadU32Le(Base + SecOff + i * 0x28 + 0x0C);
        UINT32 Vsz  = ReadU32Le(Base + SecOff + i * 0x28 + 0x08);
        UINT32 RawO = ReadU32Le(Base + SecOff + i * 0x28 + 0x14);

        if (ResRva >= Va && ResRva < Va + Vsz) {
            ResFileOff = RawO + (ResRva - Va);
            break;
        }
    }

    if (ResFileOff == 0 || ResFileOff + 16 > FileLen)
        return FALSE;

    UCHAR* Rd     = Base + ResFileOff;
    UINT16 NNamed = ReadU16Le(Rd + 12);
    UINT16 NIdEnt = ReadU16Le(Rd + 14);
    UINT32 EntOff = 16;

    for (UINT16 i = 0; i < (UINT16)(NNamed + NIdEnt); i++) {
        UINT32 EntryPos = ResFileOff + EntOff + i * 8;
        if (EntryPos + 8 > FileLen)
            break;

        UINT32 TypeId = ReadU32Le(Base + EntryPos);
        UINT32 SubOff = ReadU32Le(Base + EntryPos + 4);

        if ((TypeId & 0x80000000u) != 0)
            continue;
        if (TypeId != 3)
            continue;
        if ((SubOff & 0x80000000u) == 0)
            continue;

        UINT32 Sub = ResFileOff + (SubOff & 0x7FFFFFFFu);
        if (Sub + 16 > FileLen)
            return FALSE;

        UINT16 SNamed = ReadU16Le(Base + Sub + 12);
        UINT16 SIdEnt = ReadU16Le(Base + Sub + 14);

        for (UINT16 j = 0; j < (UINT16)(SNamed + SIdEnt); j++) {
            UINT32 SubEntry = Sub + 16 + j * 8;
            if (SubEntry + 8 > FileLen)
                break;

            UINT32 SubLangOff = ReadU32Le(Base + SubEntry + 4);
            if ((SubLangOff & 0x80000000u) == 0)
                continue;

            UINT32 LangDir = ResFileOff + (SubLangOff & 0x7FFFFFFFu);
            if (LangDir + 24 > FileLen)
                return FALSE;

            UINT32 DataEnt = ReadU32Le(Base + LangDir + 20);
            if ((DataEnt & 0x80000000u) != 0)
                continue;

            UINT32 De = ResFileOff + DataEnt;
            if (De + 16 > FileLen)
                return FALSE;

            UINT32 DRva  = ReadU32Le(Base + De);
            UINT32 DSize = ReadU32Le(Base + De + 4);
            if (DSize == 0 || DSize > 0x40000)
                return FALSE;

            UINT32 DFileOff = 0;
            for (UINT16 k = 0; k < NumSec; k++) {
                UINT32 Va   = ReadU32Le(Base + SecOff + k * 0x28 + 0x0C);
                UINT32 Vsz  = ReadU32Le(Base + SecOff + k * 0x28 + 0x08);
                UINT32 RawO = ReadU32Le(Base + SecOff + k * 0x28 + 0x14);

                if (DRva >= Va && DRva < Va + Vsz) {
                    DFileOff = RawO + (DRva - Va);
                    break;
                }
            }

            if (DFileOff == 0 || DFileOff + DSize > FileLen)
                return FALSE;

            UINT32 Hash = Fnv1a32(Base + DFileOff, DSize);
            for (SIZE_T x = 0; x < KG_ICON_HASH_COUNT; x++) {
                if (g_KnownIconFnv32[x] != 0 && Hash == g_KnownIconFnv32[x])
                    return TRUE;
            }
        }

        return FALSE;
    }

    return FALSE;
}

static
VOID
FillReason(
    _Out_ KG_BLOCKED_HIT* Out,
    _In_  const wchar_t*  Reason
)
{
    if (Out == NULL || Reason == NULL)
        return;

    RtlZeroMemory(Out->Reason, sizeof(Out->Reason));
    SIZE_T MaxChars = (sizeof(Out->Reason) / sizeof(WCHAR)) - 1;
    SIZE_T i        = 0;

    while (Reason[i] && i < MaxChars) {
        Out->Reason[i] = Reason[i];
        i++;
    }
}

_Use_decl_annotations_
BOOLEAN
BlocklistMatchByPath(
    PCUNICODE_STRING ImagePath,
    KG_BLOCKED_HIT*  Out
)
{
    if (ImagePath == NULL || ImagePath->Length == 0 || ImagePath->Buffer == NULL)
        return FALSE;

    wchar_t Base[KG_STR_MAX];
    wchar_t Company[KG_STR_MAX];
    wchar_t Original[KG_STR_MAX];
    wchar_t Reason[KG_STR_MAX];

    for (ULONG i = 0; i < ARRAYSIZE(g_Blocklist); ++i) {
        KobDecode(g_Blocklist[i].Basename, Base);

        if (Base[0] && BaseEquals(ImagePath, Base)) {
            KobDecode(g_Blocklist[i].Reason, Reason);
            FillReason(Out, Reason);
            return TRUE;
        }
    }

    PVOID  FileBuf = NULL;
    SIZE_T FileLen = 0;
    if (!NT_SUCCESS(ReadEntireFile(ImagePath, &FileBuf, &FileLen)))
        return FALSE;

    wchar_t FileCompany[128]  = { 0 };
    wchar_t FileOriginal[128] = { 0 };
    BOOLEAN GotCompany  = ExtractVersionValue(FileBuf,
                                              FileLen,
                                              PX_W(L"CompanyName"),
                                              FileCompany,
                                              ARRAYSIZE(FileCompany));
    BOOLEAN GotOriginal = ExtractVersionValue(FileBuf,
                                              FileLen,
                                              PX_W(L"OriginalFilename"),
                                              FileOriginal,
                                              ARRAYSIZE(FileOriginal));

    for (ULONG i = 0; i < ARRAYSIZE(g_Blocklist); ++i) {
        KobDecode(g_Blocklist[i].Company,  Company);
        KobDecode(g_Blocklist[i].Original, Original);

        BOOLEAN CompanyOk  = !Company[0]  || (GotCompany  && WideEqualsCI(FileCompany,  Company));
        BOOLEAN OriginalOk = !Original[0] || (GotOriginal && WideEqualsCI(FileOriginal, Original));
        BOOLEAN AnyGiven   = Company[0] || Original[0];

        if (AnyGiven && CompanyOk && OriginalOk) {
            KobDecode(g_Blocklist[i].Reason, Reason);
            FillReason(Out, Reason);
            g_KH.ExFreePoolWithTag(FileBuf, 0);
            return TRUE;
        }
    }

    if (IconHashMatches(FileBuf, FileLen)) {
        FillReason(Out, PX_W(L"icon match"));
        g_KH.ExFreePoolWithTag(FileBuf, 0);
        return TRUE;
    }

    g_KH.ExFreePoolWithTag(FileBuf, 0);
    return FALSE;
}

static
VOID
TerminateByPid(
    _In_ HANDLE Pid
)
{
    HANDLE            ProcessHandle = NULL;
    CLIENT_ID         ClientId      = { Pid, NULL };
    OBJECT_ATTRIBUTES Attributes;
    InitializeObjectAttributes(&Attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    if (NT_SUCCESS(KL_NT(ZwOpenProcess)(&ProcessHandle,
                                        PROCESS_TERMINATE,
                                        &Attributes,
                                        &ClientId))) {
        KL_NT(ZwTerminateProcess)(ProcessHandle, STATUS_ACCESS_DENIED);
        KL_NT(ZwClose)(ProcessHandle);
    }
}

_Use_decl_annotations_
VOID
BlocklistSweepRunning(
)
{
    ULONG Size = 0;
    KL_NT(ZwQuerySystemInformation)(SystemProcessInformation, NULL, 0, &Size);
    if (Size == 0)
        return;

    Size += 4096;

    PVOID Buffer = KL_NT(ExAllocatePool2)(POOL_FLAG_PAGED, Size, 'SwKn');
    if (Buffer == NULL)
        return;

    ULONG Returned = 0;
    if (!NT_SUCCESS(KL_NT(ZwQuerySystemInformation)(SystemProcessInformation,
                                                    Buffer,
                                                    Size,
                                                    &Returned))) {
        g_KH.ExFreePoolWithTag(Buffer, 0);
        return;
    }

    PKG_SPI Entry = (PKG_SPI)Buffer;
    for (;;) {
        HANDLE Pid = Entry->UniqueProcessId;
        if (Pid) {
            PEPROCESS Process = NULL;
            if (NT_SUCCESS(KL_NT(PsLookupProcessByProcessId)(Pid, &Process)) && Process) {
                PUNICODE_STRING Image = NULL;
                if (NT_SUCCESS(KL_NT(SeLocateProcessImageName)(Process, &Image)) && Image) {
                    KG_BLOCKED_HIT Hit = { 0 };
                    if (BlocklistMatchByPath(Image, &Hit)) {
                        BlocklistRecordFromKernel(Image, Hit.Reason);
#if !KG_BLOCKLIST_REPORT_ONLY
                        TerminateByPid(Pid);
                        BlocklistKillProtectedFromKernel();
#endif
                    }
                    g_KH.ExFreePoolWithTag(Image, 0);
                }
                KL_NT(ObfDereferenceObject)(Process);
            }
        }

        if (Entry->NextEntryOffset == 0)
            break;

        Entry = (PKG_SPI)((PUCHAR)Entry + Entry->NextEntryOffset);
    }

    g_KH.ExFreePoolWithTag(Buffer, 0);
}
