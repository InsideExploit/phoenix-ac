#include "ptrcrypt.hpp"

#include "shared.hpp"
#include "klazy.hpp"
#include "pxstr.hpp"

#include "inject/inject.hpp"
#include "mem/mem.hpp"

#ifndef SystemProcessInformation
#define SystemProcessInformation 5
#endif

typedef struct _KG_PC_THREAD_INFO {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG         WaitTime;
    PVOID         StartAddress;
    CLIENT_ID     ClientId;
    KPRIORITY     Priority;
    LONG          BasePriority;
    ULONG         ContextSwitches;
    ULONG         ThreadState;
    ULONG         WaitReason;
} KG_PC_THREAD_INFO;

typedef struct _KG_PC_PROC_INFO {
    ULONG             NextEntryOffset;
    ULONG             NumberOfThreads;
    UCHAR             Reserved1[48];
    UNICODE_STRING    ImageName;
    KPRIORITY         BasePriority;
    HANDLE            UniqueProcessId;
    HANDLE            InheritedFromUniqueProcessId;
    ULONG             HandleCount;
    ULONG             SessionId;
    ULONG_PTR         UniqueProcessKey;
    SIZE_T            PeakVirtualSize;
    SIZE_T            VirtualSize;
    ULONG             PageFaultCount;
    SIZE_T            PeakWorkingSetSize;
    SIZE_T            WorkingSetSize;
    SIZE_T            QuotaPeakPagedPoolUsage;
    SIZE_T            QuotaPagedPoolUsage;
    SIZE_T            QuotaPeakNonPagedPoolUsage;
    SIZE_T            QuotaNonPagedPoolUsage;
    SIZE_T            PagefileUsage;
    SIZE_T            PeakPagefileUsage;
    SIZE_T            PrivatePageCount;
    LARGE_INTEGER     ReadOperationCount;
    LARGE_INTEGER     WriteOperationCount;
    LARGE_INTEGER     OtherOperationCount;
    LARGE_INTEGER     ReadTransferCount;
    LARGE_INTEGER     WriteTransferCount;
    LARGE_INTEGER     OtherTransferCount;
    KG_PC_THREAD_INFO Threads[1];
} KG_PC_PROC_INFO;

KG_NO_OBFUSCATE
static
ULONG
PtrCryptBroadcastApc(
    _In_ HANDLE Pid,
    _In_ PVOID  UserRoutine,
    _In_ PVOID  MetaCtx
)
{
    auto QueryFn = KL_NT(ZwQuerySystemInformation);
    auto AllocFn = KL_NT(ExAllocatePool2);
    if (QueryFn == NULL || AllocFn == NULL)
        return 0;

    ULONG Size = 0;
    QueryFn(SystemProcessInformation, NULL, 0, &Size);
    if (Size == 0)
        Size = 0x80000;

    PVOID    Buffer   = NULL;
    NTSTATUS Status   = STATUS_INFO_LENGTH_MISMATCH;
    ULONG    Returned = 0;

    for (ULONG Attempt = 0; Attempt < 6; ++Attempt) {
        ULONG Try = Size + 0x10000 * (Attempt + 1);
        Buffer = AllocFn(POOL_FLAG_NON_PAGED, Try, 'bPcP');
        if (Buffer == NULL)
            return 0;

        Returned = 0;
        Status = QueryFn(SystemProcessInformation, Buffer, Try, &Returned);
        if (NT_SUCCESS(Status)) {
            Size = Try;
            break;
        }

        g_KH.ExFreePoolWithTag(Buffer, 0);
        Buffer = NULL;

        if (Status != STATUS_INFO_LENGTH_MISMATCH)
            return 0;

        if (Returned > Size)
            Size = Returned;
    }

    if (!NT_SUCCESS(Status) || Buffer == NULL)
        return 0;

    ULONG Queued = 0;
    KG_PC_PROC_INFO* Entry = (KG_PC_PROC_INFO*)Buffer;
    for (;;) {
        if (Entry->UniqueProcessId == Pid) {
            for (ULONG i = 0; i < Entry->NumberOfThreads; ++i) {
                HANDLE Tid = Entry->Threads[i].ClientId.UniqueThread;
                if (Tid == NULL)
                    continue;

                NTSTATUS Rs = InjectQueueUserApc(Pid,
                                                 Tid,
                                                 UserRoutine,
                                                 MetaCtx,
                                                 NULL,
                                                 NULL);
                if (NT_SUCCESS(Rs))
                    Queued++;
            }
            break;
        }

        if (Entry->NextEntryOffset == 0)
            break;

        Entry = (KG_PC_PROC_INFO*)((PUCHAR)Entry + Entry->NextEntryOffset);
    }

    g_KH.ExFreePoolWithTag(Buffer, 0);
    return Queued;
}

#define KG_PC_ALLOC_SIZE        0x1000
#define KG_PC_META_OFF          0
#define KG_PC_REGISTRAR_OFF     64
#define KG_PC_HANDLER_OFF       128
#define KG_PC_HANDLER_IMM64_OFF (KG_PC_HANDLER_OFF + 21)

typedef struct _KG_PC_META {
    UINT64 RtlAvehFn;
    UINT64 HandlerFn;
    UINT64 Sentinel;
    UINT64 RealValue;
    UINT64 Cookie;
    UINT64 TargetPtrAddr;
    UINT64 _Pad[2];
} KG_PC_META;

static const UINT8 g_RegistrarCode[43] = {
    0x53,
    0x48, 0x83, 0xEC, 0x20,
    0x48, 0x89, 0xCB,
    0x48, 0x8B, 0x43, 0x20,
    0x48, 0x85, 0xC0,
    0x75, 0x12,
    0x48, 0x8B, 0x03,
    0x48, 0x8B, 0x53, 0x08,
    0xB9, 0x01, 0x00, 0x00, 0x00,
    0xFF, 0xD0,
    0x48, 0x89, 0x43, 0x20,
    0x33, 0xC0,
    0x48, 0x83, 0xC4, 0x20,
    0x5B,
    0xC3
};

static const UINT8 g_HandlerCode[128] = {
    0x48, 0x83, 0xEC, 0x38,
    0x48, 0x8B, 0x01,
    0x81, 0x38, 0x05, 0x00, 0x00, 0xC0,
    0x75, 0x6A,
    0x4C, 0x8B, 0x40, 0x28,
    0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x4D, 0x8B, 0x4A, 0x10,
    0x4D, 0x89, 0xC3,
    0x4D, 0x29, 0xCB,
    0x49, 0x81, 0xFB, 0x00, 0x00, 0x00, 0x40,
    0x73, 0x49,
    0x48, 0x8B, 0x51, 0x08,
    0x4D, 0x8B, 0x5A, 0x18,
    0x48, 0x8D, 0x42, 0x78,
    0xB9, 0x10, 0x00, 0x00, 0x00,
    0x4C, 0x8B, 0x00,
    0x4C, 0x89, 0xC2,
    0x4C, 0x29, 0xCA,
    0x48, 0x81, 0xFA, 0x00, 0x00, 0x00, 0x40,
    0x73, 0x09,
    0x4D, 0x01, 0xD8,
    0x4D, 0x29, 0xC8,
    0x4C, 0x89, 0x00,
    0x48, 0x83, 0xC0, 0x08,
    0xFF, 0xC9,
    0x75, 0xDD,
    0x49, 0x8B, 0x42, 0x28,
    0x49, 0x8B, 0x52, 0x18,
    0x48, 0x89, 0x10,
    0xB8, 0xFF, 0xFF, 0xFF, 0xFF,
    0x48, 0x83, 0xC4, 0x38,
    0xC3,
    0x33, 0xC0,
    0x48, 0x83, 0xC4, 0x38,
    0xC3
};

KG_NO_OBFUSCATE
static
NTSTATUS
PtrCryptWriteTargetBytes(
    _In_ HANDLE       Pid,
    _In_ PVOID        Addr,
    _In_ const UINT8* Data,
    _In_ SIZE_T       Size
)
{
    SIZE_T Copied = 0;
    return MemWrite((ULONG)(ULONG_PTR)Pid,
                    (UINT64)(ULONG_PTR)Addr,
                    (PVOID)Data,
                    (ULONG)Size,
                    &Copied);
}

_Use_decl_annotations_
KG_NO_OBFUSCATE
NTSTATUS
PtrCryptArm(
    HANDLE  Pid,
    HANDLE  Tid,
    PVOID   TargetPtrAddr,
    PVOID   RtlAvehAddr,
    UINT64  Sentinel,
    PVOID*  OutAllocBase,
    UINT64* OutRealValue
)
{
    PAGED_CODE();

    if (OutAllocBase == NULL || OutRealValue == NULL)
        return STATUS_INVALID_PARAMETER;

    *OutAllocBase = NULL;
    *OutRealValue = 0;

    if (TargetPtrAddr == NULL || RtlAvehAddr == NULL || Sentinel == 0)
        return STATUS_INVALID_PARAMETER;

    UINT64 RealValue = 0;
    SIZE_T Copied = 0;
    NTSTATUS Status = MemRead((ULONG)(ULONG_PTR)Pid,
                              (UINT64)(ULONG_PTR)TargetPtrAddr,
                              &RealValue,
                              sizeof(RealValue),
                              &Copied);
    if (!NT_SUCCESS(Status) || Copied != sizeof(RealValue))
        return NT_SUCCESS(Status) ? STATUS_PARTIAL_COPY : Status;

    if (RealValue == 0) {
        KG_DRV_LOG("[PhoenixDrv/PtrCrypt] target=0x%p real=NULL (game not ready), retry later\n",
                   TargetPtrAddr);
        return STATUS_NOT_FOUND;
    }

    KG_DRV_LOG("[PhoenixDrv/PtrCrypt] target=0x%p real=0x%llX sentinel=0x%llX\n",
               TargetPtrAddr, (ULONG64)RealValue, (ULONG64)Sentinel);

    PVOID AllocBase = NULL;
    Status = InjectAllocInTarget(Pid, KG_PC_ALLOC_SIZE, PAGE_EXECUTE_READWRITE, &AllocBase);
    if (!NT_SUCCESS(Status) || AllocBase == NULL)
        return NT_SUCCESS(Status) ? STATUS_UNSUCCESSFUL : Status;

    KG_PC_META Meta = { 0 };
    Meta.RtlAvehFn     = (UINT64)(ULONG_PTR)RtlAvehAddr;
    Meta.HandlerFn     = (UINT64)(ULONG_PTR)AllocBase + KG_PC_HANDLER_OFF;
    Meta.Sentinel      = Sentinel;
    Meta.RealValue     = RealValue;
    Meta.Cookie        = 0;
    Meta.TargetPtrAddr = (UINT64)(ULONG_PTR)TargetPtrAddr;

    Status = PtrCryptWriteTargetBytes(Pid,
                                      (PUCHAR)AllocBase + KG_PC_META_OFF,
                                      (const UINT8*)&Meta,
                                      sizeof(Meta));
    if (!NT_SUCCESS(Status))
        return Status;

    Status = PtrCryptWriteTargetBytes(Pid,
                                      (PUCHAR)AllocBase + KG_PC_REGISTRAR_OFF,
                                      g_RegistrarCode,
                                      sizeof(g_RegistrarCode));
    if (!NT_SUCCESS(Status))
        return Status;

    UINT8 HandlerImage[sizeof(g_HandlerCode)];
    RtlCopyMemory(HandlerImage, g_HandlerCode, sizeof(g_HandlerCode));
    UINT64 MetaVA = (UINT64)(ULONG_PTR)AllocBase + KG_PC_META_OFF;
    RtlCopyMemory(HandlerImage + 21, &MetaVA, sizeof(MetaVA));

    Status = PtrCryptWriteTargetBytes(Pid,
                                      (PUCHAR)AllocBase + KG_PC_HANDLER_OFF,
                                      HandlerImage,
                                      sizeof(HandlerImage));
    if (!NT_SUCCESS(Status))
        return Status;

    ULONG Queued = PtrCryptBroadcastApc(Pid,
                                        (PUCHAR)AllocBase + KG_PC_REGISTRAR_OFF,
                                        (PUCHAR)AllocBase + KG_PC_META_OFF);
    KG_DRV_LOG("[PhoenixDrv/PtrCrypt] broadcast APC to %lu threads\n", Queued);
    if (Queued == 0)
        return STATUS_UNSUCCESSFUL;

    UNREFERENCED_PARAMETER(Tid);

    LARGE_INTEGER Delay;
    Delay.QuadPart = -((LONGLONG)200 * 10000LL);
    UINT64 Cookie = 0;
    for (ULONG Attempt = 0; Attempt < 25; ++Attempt) {
        auto DelayFn = KL_NT(KeDelayExecutionThread);
        if (DelayFn != NULL)
            DelayFn(KernelMode, FALSE, &Delay);

        Copied = 0;
        NTSTATUS Rs = MemRead((ULONG)(ULONG_PTR)Pid,
                              (UINT64)(ULONG_PTR)AllocBase + FIELD_OFFSET(KG_PC_META, Cookie),
                              &Cookie,
                              sizeof(Cookie),
                              &Copied);
        if (NT_SUCCESS(Rs) && Cookie != 0)
            break;
    }

    if (Cookie == 0) {
        KG_DRV_LOG("[PhoenixDrv/PtrCrypt] APC did not run (no cookie), aborting\n");
        return STATUS_TIMEOUT;
    }

    KG_DRV_LOG("[PhoenixDrv/PtrCrypt] VEH registered cookie=0x%llX, writing sentinel\n",
               (ULONG64)Cookie);

    Status = PtrCryptWriteTargetBytes(Pid,
                                      TargetPtrAddr,
                                      (const UINT8*)&Sentinel,
                                      sizeof(Sentinel));
    if (!NT_SUCCESS(Status))
        return Status;

    *OutAllocBase = AllocBase;
    *OutRealValue = RealValue;
    return STATUS_SUCCESS;
}
