#include "inject.hpp"

#include "shared.hpp"
#include "klazy.hpp"
#include "pxstr.hpp"

#define KG_INJECT_APC_TAG      'ApGP'
#define KG_INJECT_HANDLE_ALL   ((HANDLE)-1)

KG_NO_OBFUSCATE
_Use_decl_annotations_
NTSTATUS
InjectAllocInTarget(
    HANDLE  TargetPid,
    SIZE_T  Size,
    ULONG   Protect,
    PVOID*  OutBase
)
{
    PAGED_CODE();

    if (OutBase == NULL || Size == 0)
        return STATUS_INVALID_PARAMETER;

    *OutBase = NULL;

    auto LookupFn = KL_NT(PsLookupProcessByProcessId);
    auto DerefFn  = KL_NT(ObfDereferenceObject);
    auto AttachFn = KL_NT(KeStackAttachProcess);
    auto DetachFn = KL_NT(KeUnstackDetachProcess);
    auto AllocVmFn = KL_NT(ZwAllocateVirtualMemory);
    if (LookupFn == NULL || DerefFn == NULL || AttachFn == NULL ||
        DetachFn == NULL || AllocVmFn == NULL)
        return STATUS_UNSUCCESSFUL;

    PEPROCESS Target = NULL;
    NTSTATUS Status = LookupFn(TargetPid, &Target);
    if (!NT_SUCCESS(Status) || Target == NULL)
        return Status;

    KAPC_STATE Apc = { 0 };
    AttachFn(Target, &Apc);

    PVOID   Base    = NULL;
    SIZE_T  RegionSz = Size;
    Status = AllocVmFn(KG_INJECT_HANDLE_ALL,
                       &Base,
                       0,
                       &RegionSz,
                       MEM_COMMIT | MEM_RESERVE,
                       Protect);

    DetachFn(&Apc);
    DerefFn(Target);

    if (!NT_SUCCESS(Status))
        return Status;

    *OutBase = Base;
    KG_DRV_LOG("[PhoenixDrv/Inject] alloc pid=%lu size=0x%llX prot=0x%X -> 0x%p\n",
               (ULONG)(ULONG_PTR)TargetPid,
               (ULONG64)Size,
               Protect,
               Base);
    return STATUS_SUCCESS;
}

typedef struct _KG_APC_PACKET {
    KAPC   Apc;
    PVOID  Arg1;
    PVOID  Arg2;
    PVOID  Arg3;
} KG_APC_PACKET, *PKG_APC_PACKET;

KG_NO_OBFUSCATE
static
VOID
NTAPI
InjectApcKernelRoutine(
    _In_    PKAPC               Apc,
    _Inout_ PKG_NORMAL_ROUTINE* NormalRoutine,
    _Inout_ PVOID*              NormalContext,
    _Inout_ PVOID*              SystemArgument1,
    _Inout_ PVOID*              SystemArgument2
)
{
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    auto FreeFn = KL_NT(ExFreePoolWithTag);
    if (FreeFn != NULL)
        FreeFn(CONTAINING_RECORD(Apc, KG_APC_PACKET, Apc), KG_INJECT_APC_TAG);
}

KG_NO_OBFUSCATE
_Use_decl_annotations_
NTSTATUS
InjectQueueUserApc(
    HANDLE  TargetPid,
    HANDLE  TargetTid,
    PVOID   UserRoutine,
    PVOID   Arg1,
    PVOID   Arg2,
    PVOID   Arg3
)
{
    PAGED_CODE();

    if (UserRoutine == NULL)
        return STATUS_INVALID_PARAMETER;

    auto LookupPidFn = KL_NT(PsLookupProcessByProcessId);
    auto LookupTidFn = KL_NT(PsLookupThreadByThreadId);
    auto DerefFn     = KL_NT(ObfDereferenceObject);
    auto AllocFn     = KL_NT(ExAllocatePool2);
    auto InitApcFn   = KL_NT(KeInitializeApc);
    auto InsertApcFn = KL_NT(KeInsertQueueApc);
    auto TestAlertFn = KL_NT(KeTestAlertThread);
    if (LookupPidFn == NULL || LookupTidFn == NULL || DerefFn == NULL ||
        AllocFn == NULL || InitApcFn == NULL || InsertApcFn == NULL || TestAlertFn == NULL)
        return STATUS_UNSUCCESSFUL;

    PEPROCESS Target = NULL;
    NTSTATUS Status = LookupPidFn(TargetPid, &Target);
    if (!NT_SUCCESS(Status) || Target == NULL)
        return Status;

    PETHREAD Thread = NULL;
    Status = LookupTidFn(TargetTid, &Thread);
    if (!NT_SUCCESS(Status) || Thread == NULL) {
        DerefFn(Target);
        return Status;
    }

    PKG_APC_PACKET Packet = (PKG_APC_PACKET)AllocFn(POOL_FLAG_NON_PAGED,
                                                    sizeof(KG_APC_PACKET),
                                                    KG_INJECT_APC_TAG);
    if (Packet == NULL) {
        DerefFn(Thread);
        DerefFn(Target);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Packet, sizeof(*Packet));
    Packet->Arg1 = Arg1;
    Packet->Arg2 = Arg2;
    Packet->Arg3 = Arg3;

    InitApcFn(&Packet->Apc,
              Thread,
              KgOriginalApcEnvironment,
              (PKG_KERNEL_ROUTINE)InjectApcKernelRoutine,
              NULL,
              (PKG_NORMAL_ROUTINE)UserRoutine,
              UserMode,
              Arg1);

    if (!InsertApcFn(&Packet->Apc, Arg2, Arg3, 0)) {
        auto FreeFn = KL_NT(ExFreePoolWithTag);
        if (FreeFn != NULL)
            FreeFn(Packet, KG_INJECT_APC_TAG);
        DerefFn(Thread);
        DerefFn(Target);
        return STATUS_UNSUCCESSFUL;
    }

    TestAlertFn(UserMode);

    KG_DRV_LOG("[PhoenixDrv/Inject] APC queued pid=%lu tid=%lu routine=0x%p\n",
               (ULONG)(ULONG_PTR)TargetPid,
               (ULONG)(ULONG_PTR)TargetTid,
               UserRoutine);

    DerefFn(Thread);
    DerefFn(Target);
    return STATUS_SUCCESS;
}
