#include "win32k.hpp"
#include <ntimage.h>
#include "klazy.hpp"
#include "pxstr.hpp"

extern "C" NTSTATUS NTAPI
ZwQuerySystemInformation(
    _In_      ULONG SystemInformationClass,
    _Inout_   PVOID SystemInformation,
    _In_      ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

#define SystemModuleInformation  11
#define SystemProcessInformation 5

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES;

typedef struct _SYSTEM_PROCESS_INFORMATION_MIN {
    ULONG          NextEntryOffset;
    ULONG          NumberOfThreads;
    LARGE_INTEGER  Reserved0[3];
    LARGE_INTEGER  CreateTime;
    LARGE_INTEGER  UserTime;
    LARGE_INTEGER  KernelTime;
    UNICODE_STRING ImageName;
    ULONG          BasePriority;
    HANDLE         UniqueProcessId;
} SYSTEM_PROCESS_INFORMATION_MIN;

extern "C" BOOLEAN
InvokeGreProtect(
    _In_ PVOID  Fn,
    _In_ HANDLE Arg1,
    _In_ HANDLE Arg2,
    _In_ ULONG  Arg3,
    _In_ ULONG  Arg4
);

static PVOID g_pGreProtectSpriteContent = NULL;
static LONG  g_InitState = 0;

static
BOOLEAN
NameEndsWithCI(
    const CHAR* Path,
    const CHAR* Needle
)
{
    SIZE_T pathLen = 0;
    SIZE_T needleLen = 0;
    while (Path[pathLen])   pathLen++;
    while (Needle[needleLen]) needleLen++;
    if (needleLen > pathLen) return FALSE;

    const CHAR* tail = Path + pathLen - needleLen;
    for (SIZE_T i = 0; i < needleLen; ++i) {
        CHAR a = tail[i];
        CHAR b = Needle[i];
        if (a >= 'A' && a <= 'Z') a = (CHAR)(a + 32);
        if (b >= 'A' && b <= 'Z') b = (CHAR)(b + 32);
        if (a != b) return FALSE;
    }
    return TRUE;
}

static
NTSTATUS
FindExplorerProcess(
    _Out_ PEPROCESS* OutProcess
)
{
    *OutProcess = NULL;

    ULONG needed = 0;
    NTSTATUS st = KL_NT(ZwQuerySystemInformation)(SystemProcessInformation, NULL, 0, &needed);
    if (needed == 0)
        return STATUS_UNSUCCESSFUL;

    ULONG allocLen = needed + 0x4000;
    PVOID buf = KL_NT(ExAllocatePool2)(POOL_FLAG_NON_PAGED, allocLen, 'pKgP');
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;

    st = KL_NT(ZwQuerySystemInformation)(SystemProcessInformation, buf, allocLen, &needed);
    if (!NT_SUCCESS(st)) { g_KH.ExFreePoolWithTag(buf, 'pKgP'); return st; }

    PUCHAR cursor = (PUCHAR)buf;
    NTSTATUS result = STATUS_NOT_FOUND;
    const WCHAR* target = PX_W(L"explorer.exe");
    const USHORT tlen   = 12;
    for (;;) {
        SYSTEM_PROCESS_INFORMATION_MIN* p = (SYSTEM_PROCESS_INFORMATION_MIN*)cursor;
        if (p->ImageName.Buffer && p->ImageName.Length >= (USHORT)(tlen * sizeof(WCHAR))) {
            USHORT wlen = p->ImageName.Length / sizeof(WCHAR);
            const WCHAR* w = p->ImageName.Buffer;
            if (wlen >= tlen) {
                const WCHAR* tail = w + wlen - tlen;
                BOOLEAN match = TRUE;
                for (USHORT i = 0; i < tlen; ++i) {
                    WCHAR a = tail[i];
                    WCHAR b = target[i];
                    if (a >= L'A' && a <= L'Z') a = (WCHAR)(a + 32);
                    if (b >= L'A' && b <= L'Z') b = (WCHAR)(b + 32);
                    if (a != b) { match = FALSE; break; }
                }
                if (match && p->UniqueProcessId) {
                    PEPROCESS ep = NULL;
                    if (NT_SUCCESS(KL_NT(PsLookupProcessByProcessId)(p->UniqueProcessId, &ep))) {
                        *OutProcess = ep;
                        result = STATUS_SUCCESS;
                        break;
                    }
                }
            }
        }
        if (p->NextEntryOffset == 0) break;
        cursor += p->NextEntryOffset;
    }

    g_KH.ExFreePoolWithTag(buf, 'pKgP');
    return result;
}

static
NTSTATUS
FindKernelModule(
    _In_  const CHAR* NameCiSuffix,
    _Out_ PVOID*      OutBase,
    _Out_ ULONG*      OutSize
)
{
    *OutBase = NULL;
    *OutSize = 0;

    ULONG needed = 0;
    KL_NT(ZwQuerySystemInformation)(SystemModuleInformation, NULL, 0, &needed);
    if (needed == 0)
        return STATUS_UNSUCCESSFUL;

    ULONG allocLen = needed + 0x1000;
    PVOID buf = KL_NT(ExAllocatePool2)(POOL_FLAG_NON_PAGED, allocLen, 'mKgP');
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS st = KL_NT(ZwQuerySystemInformation)(SystemModuleInformation, buf, allocLen, &needed);
    if (!NT_SUCCESS(st)) { g_KH.ExFreePoolWithTag(buf, 'mKgP'); return st; }

    RTL_PROCESS_MODULES* mods = (RTL_PROCESS_MODULES*)buf;
    NTSTATUS result = STATUS_NOT_FOUND;
    for (ULONG i = 0; i < mods->NumberOfModules; ++i) {
        RTL_PROCESS_MODULE_INFORMATION* m = &mods->Modules[i];
        const CHAR* fullPath = (const CHAR*)m->FullPathName;
        if (NameEndsWithCI(fullPath, NameCiSuffix)) {
            *OutBase = m->ImageBase;
            *OutSize = m->ImageSize;
            result = STATUS_SUCCESS;
            break;
        }
    }

    g_KH.ExFreePoolWithTag(buf, 'mKgP');
    return result;
}

static
NTSTATUS
FindTextSection(
    _In_  PVOID   ImageBase,
    _Out_ PUCHAR* OutStart,
    _Out_ ULONG*  OutSize
)
{
    *OutStart = NULL;
    *OutSize  = 0;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ImageBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return STATUS_INVALID_IMAGE_FORMAT;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PUCHAR)ImageBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return STATUS_INVALID_IMAGE_FORMAT;

    PIMAGE_SECTION_HEADER sec = (PIMAGE_SECTION_HEADER)(
        (ULONG_PTR)nt +
        FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) +
        nt->FileHeader.SizeOfOptionalHeader);
    USHORT nSections = nt->FileHeader.NumberOfSections;
    for (USHORT i = 0; i < nSections; ++i, ++sec) {
        if (sec->Name[0] == '.' &&
            sec->Name[1] == 't' &&
            sec->Name[2] == 'e' &&
            sec->Name[3] == 'x' &&
            sec->Name[4] == 't') {
            *OutStart = (PUCHAR)ImageBase + sec->VirtualAddress;
            *OutSize  = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_NOT_FOUND;
}

static
PUCHAR
ScanBytes(
    _In_ PUCHAR       Base,
    _In_ SIZE_T       Size,
    _In_ const UCHAR* Bytes,
    _In_ const CHAR*  Mask
)
{
    SIZE_T patLen = 0;
    while (Mask[patLen]) patLen++;
    if (patLen == 0 || patLen > Size) return NULL;

    for (SIZE_T i = 0; i <= Size - patLen; ++i) {
        BOOLEAN match = TRUE;
        for (SIZE_T j = 0; j < patLen; ++j) {
            if (Mask[j] == 'x' && Base[i + j] != Bytes[j]) { match = FALSE; break; }
        }
        if (match) return Base + i;
    }
    return NULL;
}

static
PVOID
ResolveCallRel32(
    _In_ PUCHAR CallSite
)
{
    LONG rel = *(LONG*)(CallSite + 1);
    return (PVOID)(CallSite + 5 + rel);
}

static
NTSTATUS
DoResolveInAttachedContext(
    VOID
)
{
    PVOID base = NULL;
    ULONG size = 0;
    NTSTATUS st = FindKernelModule(PX_A("win32kfull.sys"), &base, &size);
    if (!NT_SUCCESS(st)) return st;

    PUCHAR text = NULL;
    ULONG  textSize = 0;
    st = FindTextSection(base, &text, &textSize);
    if (!NT_SUCCESS(st)) return st;

    static const UCHAR pat1[] = { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x8B, 0xF8, 0x85, 0xC0, 0x75, 0x0E };
    static const UCHAR pat2[] = { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x8B, 0xD8, 0x85, 0xC0, 0x75, 0x0E };
    static const CHAR  mask[] = "x????xxxxxx";

    PUCHAR site = ScanBytes(text, textSize, pat1, mask);
    if (!site) site = ScanBytes(text, textSize, pat2, mask);
    if (!site) return STATUS_NOT_FOUND;

    g_pGreProtectSpriteContent = ResolveCallRel32(site);
    return STATUS_SUCCESS;
}

NTSTATUS
Win32kInit(
    VOID
)
{
    LONG prev = InterlockedCompareExchange(&g_InitState, 1, 0);
    if (prev != 0) {
        return g_pGreProtectSpriteContent ? STATUS_SUCCESS : STATUS_NOT_FOUND;
    }

    PEPROCESS explorer = NULL;
    NTSTATUS st = FindExplorerProcess(&explorer);
    if (!NT_SUCCESS(st)) {
        InterlockedExchange(&g_InitState, 2);
        return st;
    }

    KAPC_STATE apc = { 0 };
    KL_NT(KeStackAttachProcess)(explorer, &apc);
    __try {
        st = DoResolveInAttachedContext();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        st = STATUS_UNSUCCESSFUL;
    }
    KL_NT(KeUnstackDetachProcess)(&apc);
    KL_NT(ObfDereferenceObject)(explorer);

    InterlockedExchange(&g_InitState, NT_SUCCESS(st) ? 3 : 2);
    return st;
}

NTSTATUS
Win32kUncloakWindow(
    _In_ HANDLE HWnd,
    _In_ ULONG  Value
)
{
    if (!HWnd) return STATUS_INVALID_PARAMETER;

    if (!g_pGreProtectSpriteContent) {
        NTSTATUS s = Win32kInit();
        if (!NT_SUCCESS(s)) return s;
        if (!g_pGreProtectSpriteContent) return STATUS_NOT_FOUND;
    }

    PEPROCESS explorer = NULL;
    NTSTATUS st = FindExplorerProcess(&explorer);
    if (!NT_SUCCESS(st)) return st;

    KAPC_STATE apc = { 0 };
    KL_NT(KeStackAttachProcess)(explorer, &apc);
    __try {
        BOOLEAN ok = InvokeGreProtect(g_pGreProtectSpriteContent,
                                      NULL, HWnd, 1, Value);
        st = ok ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        st = STATUS_UNSUCCESSFUL;
    }
    KL_NT(KeUnstackDetachProcess)(&apc);
    KL_NT(ObfDereferenceObject)(explorer);
    return st;
}
