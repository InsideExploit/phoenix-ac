#pragma once

#include <ntifs.h>

#include "config.hpp"
#include "pxstr.hpp"

typedef PVOID (NTAPI *PMmGetSystemRoutineAddress_t)(PUNICODE_STRING);

extern "C" PVOID                        g_KlazyAnchor;
extern "C" PMmGetSystemRoutineAddress_t g_KlazyMmGetSRA;

extern "C" NTSTATUS NTAPI MmCopyVirtualMemory(
    PEPROCESS       SourceProcess,
    PVOID           SourceAddress,
    PEPROCESS       TargetProcess,
    PVOID           TargetAddress,
    SIZE_T          BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T         ReturnSize);

extern "C" PCHAR NTAPI PsGetProcessImageFileName(PEPROCESS Process);
extern "C" PVOID NTAPI PsGetProcessSectionBaseAddress(PEPROCESS Process);
extern "C" NTSTATUS NTAPI PsLookupThreadByThreadId(_In_ HANDLE ThreadId, _Out_ PETHREAD* Thread);

extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength);

extern "C" NTSTATUS NTAPI ZwOpenThread(
    PHANDLE            ThreadHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId);

extern "C" NTSTATUS NTAPI ZwQueryInformationThread(
    HANDLE  ThreadHandle,
    ULONG   ThreadInformationClass,
    PVOID   ThreadInformation,
    ULONG   ThreadInformationLength,
    PULONG  ReturnLength);

extern "C" NTSTATUS NTAPI ZwAllocateVirtualMemory(
    HANDLE     ProcessHandle,
    PVOID*     BaseAddress,
    ULONG_PTR  ZeroBits,
    PSIZE_T    RegionSize,
    ULONG      AllocationType,
    ULONG      Protect);

typedef enum _KG_APC_ENVIRONMENT {
    KgOriginalApcEnvironment = 0,
    KgAttachedApcEnvironment = 1,
    KgCurrentApcEnvironment  = 2,
    KgInsertApcEnvironment   = 3
} KG_APC_ENVIRONMENT;

typedef VOID (NTAPI *PKG_NORMAL_ROUTINE)(
    PVOID NormalContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2);

typedef VOID (NTAPI *PKG_KERNEL_ROUTINE)(
    PKAPC              Apc,
    PKG_NORMAL_ROUTINE* NormalRoutine,
    PVOID*              NormalContext,
    PVOID*              SystemArgument1,
    PVOID*              SystemArgument2);

typedef VOID (NTAPI *PKG_RUNDOWN_ROUTINE)(PKAPC Apc);

extern "C" NTKERNELAPI VOID NTAPI KeInitializeApc(
    PKAPC               Apc,
    PETHREAD            Thread,
    KG_APC_ENVIRONMENT  Environment,
    PKG_KERNEL_ROUTINE  KernelRoutine,
    PKG_RUNDOWN_ROUTINE RundownRoutine,
    PKG_NORMAL_ROUTINE  NormalRoutine,
    KPROCESSOR_MODE     ApcMode,
    PVOID               NormalContext);

extern "C" NTKERNELAPI BOOLEAN NTAPI KeInsertQueueApc(
    PKAPC     Apc,
    PVOID     SystemArgument1,
    PVOID     SystemArgument2,
    KPRIORITY Increment);

extern "C" NTKERNELAPI VOID NTAPI KeTestAlertThread(
    KPROCESSOR_MODE AlertMode);

typedef struct _KG_LDR_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} KG_LDR_ENTRY, *PKG_LDR_ENTRY;

static
__forceinline
BOOLEAN
KlazyWideEqualsCI(
    _In_reads_(ALen) const WCHAR* A,
    _In_             USHORT       ALen,
    _In_z_           const WCHAR* B
)
{
    USHORT BLen = 0;
    while (B[BLen])
        BLen++;

    if (ALen != BLen)
        return FALSE;

    for (USHORT i = 0; i < ALen; i++) {
        WCHAR Ca = A[i];
        WCHAR Cb = B[i];

        if (Ca >= L'A' && Ca <= L'Z') Ca = (WCHAR)(Ca + 32);
        if (Cb >= L'A' && Cb <= L'Z') Cb = (WCHAR)(Cb + 32);

        if (Ca != Cb)
            return FALSE;
    }

    return TRUE;
}

static
__forceinline
VOID
KlazyMakeUS(
    _Out_  UNICODE_STRING* Us,
    _In_z_ const WCHAR*    Name
)
{
    Us->Buffer = (PWCH)Name;

    USHORT Len = 0;
    while (Name[Len])
        Len++;

    Us->Length        = (USHORT)(Len * sizeof(WCHAR));
    Us->MaximumLength = (USHORT)(Us->Length + sizeof(WCHAR));
}

static
__forceinline
PVOID
KlazyFindModuleBase(
    _In_z_ const WCHAR* DllName
)
{
    if (!g_KlazyAnchor)
        return NULL;

    LIST_ENTRY* Start = &((PKG_LDR_ENTRY)g_KlazyAnchor)->InLoadOrderLinks;
    LIST_ENTRY* Cur   = Start;

    for (int Guard = 0; Guard < 4096; Guard++) {
        PKG_LDR_ENTRY Entry = (PKG_LDR_ENTRY)Cur;
        if (Entry->BaseDllName.Buffer && Entry->BaseDllName.Length > 0) {
            USHORT Chars = (USHORT)(Entry->BaseDllName.Length / sizeof(WCHAR));
            if (KlazyWideEqualsCI(Entry->BaseDllName.Buffer, Chars, DllName))
                return Entry->DllBase;
        }

        Cur = Cur->Flink;
        if (!Cur || Cur == Start)
            break;
    }

    return NULL;
}

static
__forceinline
PVOID
KlazyResolveExport(
    _In_   PVOID       ModBase,
    _In_z_ const char* FnName
)
{
    if (!ModBase || !FnName)
        return NULL;

    UCHAR* Base = (UCHAR*)ModBase;
    if (*(USHORT*)Base != 0x5A4D)
        return NULL;

    ULONG PeOff = *(ULONG*)(Base + 0x3C);
    if (*(ULONG*)(Base + PeOff) != 0x00004550u)
        return NULL;

    USHORT Magic      = *(USHORT*)(Base + PeOff + 0x18);
    ULONG  DataDirOff = PeOff + 0x18 + (Magic == 0x20B ? 0x70u : 0x60u);
    ULONG  ExpRva     = *(ULONG*)(Base + DataDirOff);
    if (ExpRva == 0)
        return NULL;

    UCHAR* ExpDir      = Base + ExpRva;
    ULONG  NumNames    = *(ULONG*)(ExpDir + 0x18);
    ULONG  FuncsRva    = *(ULONG*)(ExpDir + 0x1C);
    ULONG  NamesRva    = *(ULONG*)(ExpDir + 0x20);
    ULONG  OrdinalsRva = *(ULONG*)(ExpDir + 0x24);

    ULONG*  FuncArr = (ULONG*)(Base + FuncsRva);
    ULONG*  NameArr = (ULONG*)(Base + NamesRva);
    USHORT* OrdArr  = (USHORT*)(Base + OrdinalsRva);

    for (ULONG i = 0; i < NumNames; i++) {
        const char* Nm = (const char*)(Base + NameArr[i]);
        int j = 0;
        while (Nm[j] && FnName[j] && Nm[j] == FnName[j])
            j++;

        if (Nm[j] == 0 && FnName[j] == 0)
            return Base + FuncArr[OrdArr[i]];
    }

    return NULL;
}

static
__forceinline
NTSTATUS
KlazyBootstrap(
    _In_ PVOID DriverSection
)
{
    g_KlazyAnchor = DriverSection;

    PVOID NtBase = KlazyFindModuleBase(PX_W(L"ntoskrnl.exe"));
    if (!NtBase)
        return STATUS_UNSUCCESSFUL;

    g_KlazyMmGetSRA = (PMmGetSystemRoutineAddress_t)KlazyResolveExport(NtBase,
                                                                        PX_A("MmGetSystemRoutineAddress"));
    return g_KlazyMmGetSRA ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

static constexpr UINT32 KlazyHashW(const wchar_t* s, UINT32 h = 2166136261u) {
    return *s ? KlazyHashW(s + 1, (h ^ (UINT32)*s) * 16777619u) : h;
}

#define KL_HASH(name) KlazyHashW(L#name)

#define KL_CACHE_SLOTS 256

typedef struct _KLAZY_SLOT {
    UINT32 Hash;
    PVOID  Ptr;
} KLAZY_SLOT, *PKLAZY_SLOT;

__declspec(selectany) KLAZY_SLOT g_KL_Slots[KL_CACHE_SLOTS] = { 0 };

static
__forceinline
PVOID
KlazyLookup(
    UINT32 hash
)
{
    UINT32 idx = hash & (KL_CACHE_SLOTS - 1);
    for (UINT32 i = 0; i < KL_CACHE_SLOTS; ++i) {
        UINT32 probe = (idx + i) & (KL_CACHE_SLOTS - 1);
        if (g_KL_Slots[probe].Hash == hash) return g_KL_Slots[probe].Ptr;
        if (g_KL_Slots[probe].Hash == 0)    return nullptr;
    }
    return nullptr;
}

static
__forceinline
PVOID
KlazyInsert(
    UINT32          hash,
    PVOID           ptr
)
{
    UINT32 idx = hash & (KL_CACHE_SLOTS - 1);
    for (UINT32 i = 0; i < KL_CACHE_SLOTS; ++i) {
        UINT32 probe = (idx + i) & (KL_CACHE_SLOTS - 1);
        if (g_KL_Slots[probe].Hash == 0 || g_KL_Slots[probe].Hash == hash) {
            g_KL_Slots[probe].Hash = hash;
            g_KL_Slots[probe].Ptr  = ptr;
            return ptr;
        }
    }
    return nullptr;
}

#define KL_NT(name) \
    ([&]() -> decltype(&name) { \
        constexpr UINT32 _h = KL_HASH(name); \
        PVOID _p = KlazyLookup(_h); \
        if (_p) return (decltype(&name))_p; \
        if (g_KlazyMmGetSRA) { \
            UNICODE_STRING _kli_us; \
            KlazyMakeUS(&_kli_us, PX_W(L#name)); \
            PVOID _r = g_KlazyMmGetSRA(&_kli_us); \
            if (_r) KlazyInsert(_h, _r); \
            return (decltype(&name))_r; \
        } \
        return nullptr; \
    }())

#if KG_DRV_DEBUG_LOG
#define KG_DRV_LOG(fmt, ...) \
    KL_NT(DbgPrintEx)(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, PX_A(fmt), ##__VA_ARGS__)
#else
#define KG_DRV_LOG(fmt, ...) ((void)0)
#endif

#define KL_MOD(dll, name) \
    ([&]() -> decltype(&name) { \
        static decltype(&name) _klm_ptr = nullptr; \
        if (!_klm_ptr) { \
            PVOID _klm_mod = KlazyFindModuleBase(PX_W(dll)); \
            if (_klm_mod) _klm_ptr = (decltype(&name))KlazyResolveExport(_klm_mod, PX_A(#name)); \
        } \
        return _klm_ptr; \
    }())

#define KL_KSECDD(name) KL_MOD(L"ksecdd.sys", name)

#define KL_FWPK(name)   KL_MOD(L"fwpkclnt.sys", name)

#define KL_NTVAR(name) \
    ([&]() -> decltype(name) { \
        static decltype(name) * _klv_p = nullptr; \
        if (!_klv_p) { \
            PVOID _klv_mod = KlazyFindModuleBase(PX_W(L"ntoskrnl.exe")); \
            if (_klv_mod) _klv_p = (decltype(name) *)KlazyResolveExport(_klv_mod, PX_A(#name)); \
        } \
        return _klv_p ? *_klv_p : decltype(name){}; \
    }())

typedef struct _KLAZY_HOT {
    decltype(&KeAcquireSpinLockRaiseToDpc) KeAcquireSpinLockRaiseToDpc;
    decltype(&KeReleaseSpinLock)           KeReleaseSpinLock;
    decltype(&ExFreePoolWithTag)           ExFreePoolWithTag;
    decltype(&IoReleaseRemoveLockEx)       IoReleaseRemoveLockEx;
    decltype(&KfRaiseIrql)                 KfRaiseIrql;
    decltype(&KeLowerIrql)                 KeLowerIrql;
} KLAZY_HOT, *PKLAZY_HOT;

__declspec(selectany) KLAZY_HOT g_KH = { 0 };

static
__forceinline
VOID
KlazyHotInit(
    VOID
)
{
    KL_NT(CmCallbackGetKeyObjectIDEx);
    KL_NT(CmCallbackReleaseKeyObjectIDEx);
    KL_NT(CmRegisterCallback);
    KL_NT(CmUnRegisterCallback);
    KL_NT(DbgPrintEx);
    KL_NT(ExAllocatePool2);
    KL_NT(ExFreePoolWithTag);
    KL_NT(ExGetFirmwareEnvironmentVariable);
    KL_NT(IoCreateDevice);
    KL_NT(IoCreateSymbolicLink);
    KL_NT(IoDeleteDevice);
    KL_NT(IoDeleteSymbolicLink);
    KL_NT(IoGetCurrentProcess);
    KL_NT(IoReleaseRemoveLockEx);
    KL_NT(IofCompleteRequest);
    KL_NT(KeAcquireSpinLockRaiseToDpc);
    KL_NT(KeDelayExecutionThread);
    KL_NT(KeGetCurrentIrql);
    KL_NT(KeInitializeApc);
    KL_NT(KeInitializeEvent);
    KL_NT(KeInitializeSpinLock);
    KL_NT(KeInsertQueueApc);
    KL_NT(KeTestAlertThread);
    KL_NT(KeLowerIrql);
    KL_NT(KeQuerySystemTimePrecise);
    KL_NT(KeReleaseSpinLock);
    KL_NT(KeSetEvent);
    KL_NT(KeStackAttachProcess);
    KL_NT(KeUnstackDetachProcess);
    KL_NT(KeWaitForSingleObject);
    KL_NT(KfRaiseIrql);
    KL_NT(MmCopyVirtualMemory);
    KL_NT(ObReferenceObjectByHandle);
    KL_NT(ObRegisterCallbacks);
    KL_NT(ObUnRegisterCallbacks);
    KL_NT(ObfDereferenceObject);
    KL_NT(PsCreateSystemThread);
    KL_NT(PsGetCurrentProcessId);
    KL_NT(PsGetCurrentThreadId);
    KL_NT(PsGetProcessId);
    KL_NT(PsGetProcessImageFileName);
    KL_NT(PsGetProcessSectionBaseAddress);
    KL_NT(PsGetThreadProcessId);
    KL_NT(PsLookupThreadByThreadId);
    KL_NT(PsLookupProcessByProcessId);
    KL_NT(PsRemoveLoadImageNotifyRoutine);
    KL_NT(PsSetCreateProcessNotifyRoutineEx);
    KL_NT(PsSetLoadImageNotifyRoutine);
    KL_NT(PsTerminateSystemThread);
    KL_NT(RtlCompareMemory);
    KL_NT(RtlEqualUnicodeString);
    KL_NT(SeLocateProcessImageName);
    KL_NT(ZwClose);
    KL_NT(ZwCreateFile);
    KL_NT(ZwEnumerateKey);
    KL_NT(ZwOpenFile);
    KL_NT(ZwOpenKey);
    KL_NT(ZwAllocateVirtualMemory);
    KL_NT(ZwOpenProcess);
    KL_NT(ZwOpenThread);
    KL_NT(ZwQueryInformationFile);
    KL_NT(ZwQueryInformationThread);
    KL_NT(ZwQuerySystemInformation);
    KL_NT(ZwQueryValueKey);
    KL_NT(ZwReadFile);
    KL_NT(ZwTerminateProcess);

    g_KH.KeAcquireSpinLockRaiseToDpc = KL_NT(KeAcquireSpinLockRaiseToDpc);
    g_KH.KeReleaseSpinLock           = KL_NT(KeReleaseSpinLock);
    g_KH.ExFreePoolWithTag           = KL_NT(ExFreePoolWithTag);
    g_KH.IoReleaseRemoveLockEx       = KL_NT(IoReleaseRemoveLockEx);
    g_KH.KfRaiseIrql                 = KL_NT(KfRaiseIrql);
    g_KH.KeLowerIrql                 = KL_NT(KeLowerIrql);
}
