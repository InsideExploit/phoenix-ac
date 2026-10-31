#include "comm.hpp"

#include "shared.hpp"
#include "pxstr.hpp"
#include "klazy.hpp"

#include "crypto/crypto.hpp"
#include "protect/protect.hpp"
#include "checks/checks.hpp"
#include "steam/steam.hpp"
#include "vm/vm.hpp"
#include "mem/mem.hpp"
#include "hwid/hwid.hpp"
#include "wfp/wfp.hpp"
#include "mmap/mmap.hpp"
#include "irpscan/irpscan.hpp"
#include "win32k/win32k.hpp"
#include "inject/inject.hpp"
#include "ptrcrypt/ptrcrypt.hpp"

#ifndef STATUS_HV_INVALID_PARTITION_STATE
#define STATUS_HV_INVALID_PARTITION_STATE ((NTSTATUS)0xC0350012L)
#endif

static volatile LONG g_Registered = 0;

KG_NO_OBFUSCATE
static
NTSTATUS
Complete(
    _Inout_ PIRP      Irp,
    _In_    NTSTATUS  Status,
    _In_    ULONG_PTR Info
)
{
    Irp->IoStatus.Status      = Status;
    Irp->IoStatus.Information = Info;
    KL_NT(IofCompleteRequest)(Irp, IO_NO_INCREMENT);
    return Status;
}

static
NTSTATUS
HandleRegister(
    _In_ PIRP                Irp,
    _In_ PIO_STACK_LOCATION  Io
)
{
    if (Io->Parameters.DeviceIoControl.InputBufferLength < sizeof(KG_REGISTER_REQUEST))
        return STATUS_INVALID_BUFFER_SIZE;

    if (InterlockedCompareExchange(&g_Registered, 1, 0) != 0)
        return STATUS_ACCESS_DENIED;

    KG_REGISTER_REQUEST* Request = (KG_REGISTER_REQUEST*)Irp->AssociatedIrp.SystemBuffer;

    UINT8 Key[32];
    GetHmacKey(Key);

    UINT8 Message[KG_REGISTER_CONTEXT_LEN + KG_NONCE_LEN];
    RtlCopyMemory(Message, KG_REGISTER_CONTEXT, KG_REGISTER_CONTEXT_LEN);
    RtlCopyMemory(Message + KG_REGISTER_CONTEXT_LEN, Request->Nonce, KG_NONCE_LEN);

    UINT8 Mac[32];
    NTSTATUS Status = HmacSha256(Key, sizeof(Key), Message, sizeof(Message), Mac);
    RtlSecureZeroMemory(Key, sizeof(Key));
    if (!NT_SUCCESS(Status)) {
        InterlockedExchange(&g_Registered, 0);
        return Status;
    }

    UINT8 Diff = 0;
    for (int i = 0; i < 32; ++i)
        Diff |= (UINT8)(Mac[i] ^ Request->Mac[i]);

    RtlSecureZeroMemory(Mac, sizeof(Mac));

    if (Diff != 0) {
        InterlockedExchange(&g_Registered, 0);
        return STATUS_ACCESS_DENIED;
    }

    InterlockedExchangePointer((PVOID*)&g_ProtectedOwner, KL_NT(PsGetCurrentProcessId)());
    return STATUS_SUCCESS;
}

static
NTSTATUS
HandleArmRelaunch(
    _In_ PIRP                Irp,
    _In_ PIO_STACK_LOCATION  Io
)
{
    if (Io->Parameters.DeviceIoControl.InputBufferLength < sizeof(KG_ARM_REQUEST))
        return STATUS_INVALID_BUFFER_SIZE;

    KG_ARM_REQUEST* Request = (KG_ARM_REQUEST*)Irp->AssociatedIrp.SystemBuffer;

    if (Request->BasenameLen == 0 || Request->BasenameLen > sizeof(Request->Basename))
        return STATUS_INVALID_PARAMETER;

    if ((Request->BasenameLen % sizeof(WCHAR)) != 0)
        return STATUS_INVALID_PARAMETER;

    UINT8 Key[32];
    GetHmacKey(Key);

    UINT8 Message[KG_ARM_CONTEXT_LEN + KG_NONCE_LEN + sizeof(Request->Basename) + KG_TOKEN_LEN];
    ULONG MessageLen = 0;

    RtlCopyMemory(Message,              KG_ARM_CONTEXT,   KG_ARM_CONTEXT_LEN);    MessageLen += KG_ARM_CONTEXT_LEN;
    RtlCopyMemory(Message + MessageLen, Request->Nonce,   KG_NONCE_LEN);          MessageLen += KG_NONCE_LEN;
    RtlCopyMemory(Message + MessageLen, Request->Basename, Request->BasenameLen); MessageLen += Request->BasenameLen;
    RtlCopyMemory(Message + MessageLen, Request->Token,   KG_TOKEN_LEN);          MessageLen += KG_TOKEN_LEN;

    UINT8 Mac[32];
    NTSTATUS Status = HmacSha256(Key, sizeof(Key), Message, MessageLen, Mac);
    RtlSecureZeroMemory(Key, sizeof(Key));
    if (!NT_SUCCESS(Status))
        return Status;

    UINT8 Diff = 0;
    for (int i = 0; i < 32; ++i)
        Diff |= (UINT8)(Mac[i] ^ Request->Mac[i]);

    RtlSecureZeroMemory(Mac, sizeof(Mac));

    if (Diff != 0)
        return STATUS_ACCESS_DENIED;

    if (IsRunningInDisallowedVm())
        return STATUS_HV_INVALID_PARTITION_STATE;

    KG_STATUS_REPORT Posture = { 0 };
    CollectSecurityState(&Posture);
    if (!PostureMeetsPolicy(&Posture))
        return STATUS_NOT_SUPPORTED;

    RunHvciSpoofProbeAndReport();

    return ArmRelaunch(KL_NT(PsGetCurrentProcessId)(),
                       Request->Basename,
                       Request->BasenameLen,
                       Request->Token);
}

static
NTSTATUS
HandleAttest(
    _In_ PIRP                Irp,
    _In_ PIO_STACK_LOCATION  Io
)
{
    if (Io->Parameters.DeviceIoControl.InputBufferLength < sizeof(KG_ATTEST_REQUEST))
        return STATUS_INVALID_BUFFER_SIZE;

    KG_ATTEST_REQUEST* Request = (KG_ATTEST_REQUEST*)Irp->AssociatedIrp.SystemBuffer;
    return AttestOwner(KL_NT(PsGetCurrentProcessId)(), Request->Token);
}

static
NTSTATUS
HandleStatus(
    _In_  PIRP                Irp,
    _In_  PIO_STACK_LOCATION  Io,
    _Out_ ULONG_PTR*          InfoOut
)
{
    if (Io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(KG_STATUS_REPORT))
        return STATUS_BUFFER_TOO_SMALL;

    KG_STATUS_REPORT* Out = (KG_STATUS_REPORT*)Irp->AssociatedIrp.SystemBuffer;
    RtlZeroMemory(Out, sizeof(*Out));
    CollectSecurityState(Out);

    *InfoOut = sizeof(*Out);
    return STATUS_SUCCESS;
}

static
NTSTATUS
HandleTrustedCount(
    _In_  PIRP                Irp,
    _In_  PIO_STACK_LOCATION  Io,
    _Out_ ULONG_PTR*          InfoOut
)
{
    if (Io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(UINT32))
        return STATUS_BUFFER_TOO_SMALL;

    UINT32* Out = (UINT32*)Irp->AssociatedIrp.SystemBuffer;
    *Out = TrustedCount();
    *InfoOut = sizeof(*Out);
    return STATUS_SUCCESS;
}

static
NTSTATUS
HandleKillTrusted(
    VOID
)
{
    HANDLE Owner = ProtectedOwnerId();
    if (Owner == NULL || KL_NT(PsGetCurrentProcessId)() != Owner)
        return STATUS_ACCESS_DENIED;

    KillAllTrusted();
    return STATUS_SUCCESS;
}

static
NTSTATUS
HandleLastBlock(
    _In_  PIRP                Irp,
    _In_  PIO_STACK_LOCATION  Io,
    _Out_ ULONG_PTR*          InfoOut
)
{
    if (Io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(KG_LAST_BLOCK))
        return STATUS_BUFFER_TOO_SMALL;

    KG_LAST_BLOCK* Out = (KG_LAST_BLOCK*)Irp->AssociatedIrp.SystemBuffer;
    GetLastBlock(Out);

    *InfoOut = sizeof(*Out);
    return STATUS_SUCCESS;
}

static
NTSTATUS
HandleShutdown(
    VOID
)
{
    HANDLE Owner = ProtectedOwnerId();
    if (Owner == NULL || KL_NT(PsGetCurrentProcessId)() != Owner)
        return STATUS_ACCESS_DENIED;

    DisableProtection();
    return STATUS_SUCCESS;
}

KG_NO_OBFUSCATE
static
bool
CallerIsOwner(
    VOID
)
{
    HANDLE Owner = ProtectedOwnerId();
    return Owner != NULL && KL_NT(PsGetCurrentProcessId)() == Owner;
}

KG_NO_OBFUSCATE
static
NTSTATUS
HandleModuleInfo(
    _In_  PIRP                Irp,
    _In_  PIO_STACK_LOCATION  Io,
    _Out_ ULONG_PTR*          InfoOut
)
{
    if (!CallerIsOwner())
        return STATUS_ACCESS_DENIED;

    if (Io->Parameters.DeviceIoControl.InputBufferLength < sizeof(KG_MODULE_REQUEST))
        return STATUS_INVALID_BUFFER_SIZE;

    if (Io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(KG_MODULE_RESULT))
        return STATUS_BUFFER_TOO_SMALL;

    KG_MODULE_REQUEST Request = *(KG_MODULE_REQUEST*)Irp->AssociatedIrp.SystemBuffer;
    if (!TrustedContains((HANDLE)(ULONG_PTR)Request.Pid)) {
        KG_DRV_LOG("[PhoenixDrv/Comm] MEM guard: ModuleInfo target pid=%u not trusted\n", Request.Pid);
        return STATUS_ACCESS_DENIED;
    }

    KG_MODULE_RESULT* Out = (KG_MODULE_RESULT*)Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS Status = MemQueryModule(Request.Pid, Out);
    if (!NT_SUCCESS(Status))
        return Status;

    *InfoOut = sizeof(*Out);
    return STATUS_SUCCESS;
}

KG_NO_OBFUSCATE
static
NTSTATUS
HandleScan(
    _In_  PIRP                Irp,
    _In_  PIO_STACK_LOCATION  Io,
    _Out_ ULONG_PTR*          InfoOut
)
{
    if (!CallerIsOwner())
        return STATUS_ACCESS_DENIED;

    if (Io->Parameters.DeviceIoControl.InputBufferLength < sizeof(KG_SCAN_REQUEST))
        return STATUS_INVALID_BUFFER_SIZE;

    if (Io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(KG_SCAN_RESULT))
        return STATUS_BUFFER_TOO_SMALL;

    KG_SCAN_REQUEST Request = *(KG_SCAN_REQUEST*)Irp->AssociatedIrp.SystemBuffer;
    if (!TrustedContains((HANDLE)(ULONG_PTR)Request.Pid)) {
        KG_DRV_LOG("[PhoenixDrv/Comm] MEM guard: Scan target pid=%u not trusted\n", Request.Pid);
        return STATUS_ACCESS_DENIED;
    }

    KG_SCAN_RESULT* Out = (KG_SCAN_RESULT*)Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS Status = MemScan(&Request, Out);
    if (!NT_SUCCESS(Status))
        return Status;

    *InfoOut = sizeof(*Out);
    return STATUS_SUCCESS;
}

KG_NO_OBFUSCATE
static
NTSTATUS
HandleMemRead(
    _In_  PIRP                Irp,
    _In_  PIO_STACK_LOCATION  Io,
    _Out_ ULONG_PTR*          InfoOut
)
{
    if (!CallerIsOwner())
        return STATUS_ACCESS_DENIED;

    if (Io->Parameters.DeviceIoControl.InputBufferLength < sizeof(KG_MEM_READ_REQUEST))
        return STATUS_INVALID_BUFFER_SIZE;

    KG_MEM_READ_REQUEST Request = *(KG_MEM_READ_REQUEST*)Irp->AssociatedIrp.SystemBuffer;
    if (Request.Size == 0 || Request.Size > KG_MEM_MAX_IO)
        return STATUS_INVALID_PARAMETER;

    if (Io->Parameters.DeviceIoControl.OutputBufferLength < Request.Size)
        return STATUS_BUFFER_TOO_SMALL;

    if (!TrustedContains((HANDLE)(ULONG_PTR)Request.Pid)) {
        KG_DRV_LOG("[PhoenixDrv/Comm] MEM guard: MemRead target pid=%u not trusted\n", Request.Pid);
        return STATUS_ACCESS_DENIED;
    }

    PVOID  Destination = Irp->AssociatedIrp.SystemBuffer;
    SIZE_T Copied      = 0;
    NTSTATUS Status = MemRead(Request.Pid, Request.Address, Destination, Request.Size, &Copied);
    if (!NT_SUCCESS(Status))
        return Status;

    *InfoOut = Copied;
    return STATUS_SUCCESS;
}

static
NTSTATUS
HandleHwid(
    _In_  PIRP                Irp,
    _In_  PIO_STACK_LOCATION  Io,
    _Out_ ULONG_PTR*          InfoOut
)
{
    if (Io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(KG_HWID_RESULT))
        return STATUS_BUFFER_TOO_SMALL;

    KG_HWID_RESULT* Out = (KG_HWID_RESULT*)Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS Status = HwidCollect(Out);
    if (!NT_SUCCESS(Status))
        return Status;

    *InfoOut = sizeof(*Out);
    return STATUS_SUCCESS;
}

static
NTSTATUS
HandleCriticalCommit(
    _In_ PIRP                Irp,
    _In_ PIO_STACK_LOCATION  Io
)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(Io);

    if (!CallerIsOwner())
        return STATUS_ACCESS_DENIED;

    KG_DRV_LOG("[PhoenixDrv/Comm] critical commit: killing protected except caller\n");
    KillAllProtectedExceptCaller();
    return STATUS_SUCCESS;
}

KG_NO_OBFUSCATE
static
NTSTATUS
HandleMemWrite(
    _In_ PIRP                Irp,
    _In_ PIO_STACK_LOCATION  Io
)
{
    if (!CallerIsOwner())
        return STATUS_ACCESS_DENIED;

    if (Io->Parameters.DeviceIoControl.InputBufferLength <
        RTL_SIZEOF_THROUGH_FIELD(KG_MEM_WRITE_REQUEST, Address))
        return STATUS_INVALID_BUFFER_SIZE;

    KG_MEM_WRITE_REQUEST* Request = (KG_MEM_WRITE_REQUEST*)Irp->AssociatedIrp.SystemBuffer;
    if (Request->Size == 0 || Request->Size > KG_MEM_MAX_IO)
        return STATUS_INVALID_PARAMETER;

    ULONG Needed = FIELD_OFFSET(KG_MEM_WRITE_REQUEST, Data) + Request->Size;
    if (Io->Parameters.DeviceIoControl.InputBufferLength < Needed)
        return STATUS_INVALID_BUFFER_SIZE;

    if (!TrustedContains((HANDLE)(ULONG_PTR)Request->Pid)) {
        KG_DRV_LOG("[PhoenixDrv/Comm] MEM guard: MemWrite target pid=%u not trusted\n", Request->Pid);
        return STATUS_ACCESS_DENIED;
    }

    SIZE_T Copied = 0;
    NTSTATUS Status = MemWrite(Request->Pid, Request->Address, Request->Data, Request->Size, &Copied);
    if (!NT_SUCCESS(Status))
        return Status;

    return (Copied == Request->Size) ? STATUS_SUCCESS : STATUS_PARTIAL_COPY;
}

static
NTSTATUS
HandleSteamId(
    _In_  PIRP                Irp,
    _In_  PIO_STACK_LOCATION  Io,
    _Out_ ULONG_PTR*          InfoOut
)
{
    KG_DRV_LOG("[PhoenixDrv/Comm] HandleSteamId enter\n");

    if (Io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(KG_STEAM_ID)) {
        KG_DRV_LOG("[PhoenixDrv/Comm] HandleSteamId buffer too small\n");
        return STATUS_BUFFER_TOO_SMALL;
    }

    KG_STEAM_ID* Out = (KG_STEAM_ID*)Irp->AssociatedIrp.SystemBuffer;
    RtlZeroMemory(Out, sizeof(*Out));

    NTSTATUS Status = ReadActiveSteamId64(&Out->SteamId64);
    KG_DRV_LOG("[PhoenixDrv/Comm] HandleSteamId exit rc=0x%08X\n", Status);
    if (!NT_SUCCESS(Status))
        return Status;

    *InfoOut = sizeof(*Out);
    return STATUS_SUCCESS;
}

KG_NO_OBFUSCATE
_Use_decl_annotations_
NTSTATUS
DispatchCreate(
    PDEVICE_OBJECT DeviceObject,
    PIRP           Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return Complete(Irp, STATUS_SUCCESS, 0);
}

KG_NO_OBFUSCATE
_Use_decl_annotations_
NTSTATUS
DispatchClose(
    PDEVICE_OBJECT DeviceObject,
    PIRP           Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return Complete(Irp, STATUS_SUCCESS, 0);
}

KG_NO_OBFUSCATE
_Use_decl_annotations_
NTSTATUS
DispatchRead(
    PDEVICE_OBJECT DeviceObject,
    PIRP           Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return Complete(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
}

KG_NO_OBFUSCATE
_Use_decl_annotations_
NTSTATUS
DispatchGeneric(
    PDEVICE_OBJECT DeviceObject,
    PIRP           Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return Complete(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
}

KG_NO_OBFUSCATE
static
NTSTATUS
HandleAllocInTarget(
    _In_  PIRP                Irp,
    _In_  PIO_STACK_LOCATION  Io,
    _Out_ ULONG_PTR*          InfoOut
)
{
    if (!CallerIsOwner())
        return STATUS_ACCESS_DENIED;

    if (Io->Parameters.DeviceIoControl.InputBufferLength < sizeof(KG_ALLOC_REQUEST))
        return STATUS_INVALID_BUFFER_SIZE;
    if (Io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(KG_ALLOC_RESULT))
        return STATUS_BUFFER_TOO_SMALL;

    KG_ALLOC_REQUEST* Request = (KG_ALLOC_REQUEST*)Irp->AssociatedIrp.SystemBuffer;
    if (!TrustedContains((HANDLE)(ULONG_PTR)Request->Pid))
        return STATUS_ACCESS_DENIED;

    if (Request->Size == 0 || Request->Size > 0x00100000)
        return STATUS_INVALID_PARAMETER;

    PVOID Base = NULL;
    NTSTATUS Status = InjectAllocInTarget((HANDLE)(ULONG_PTR)Request->Pid,
                                          (SIZE_T)Request->Size,
                                          Request->Protect,
                                          &Base);
    if (!NT_SUCCESS(Status))
        return Status;

    KG_ALLOC_RESULT* Result = (KG_ALLOC_RESULT*)Irp->AssociatedIrp.SystemBuffer;
    Result->Address = (UINT64)(ULONG_PTR)Base;
    *InfoOut = sizeof(*Result);
    return STATUS_SUCCESS;
}

KG_NO_OBFUSCATE
static
NTSTATUS
HandleApcInject(
    _In_ PIRP                Irp,
    _In_ PIO_STACK_LOCATION  Io
)
{
    if (!CallerIsOwner())
        return STATUS_ACCESS_DENIED;

    if (Io->Parameters.DeviceIoControl.InputBufferLength < sizeof(KG_APC_REQUEST))
        return STATUS_INVALID_BUFFER_SIZE;

    KG_APC_REQUEST* Request = (KG_APC_REQUEST*)Irp->AssociatedIrp.SystemBuffer;
    if (!TrustedContains((HANDLE)(ULONG_PTR)Request->Pid))
        return STATUS_ACCESS_DENIED;

    if (Request->Tid == 0 || Request->UserRoutine == 0)
        return STATUS_INVALID_PARAMETER;

    return InjectQueueUserApc((HANDLE)(ULONG_PTR)Request->Pid,
                              (HANDLE)(ULONG_PTR)Request->Tid,
                              (PVOID)(ULONG_PTR)Request->UserRoutine,
                              (PVOID)(ULONG_PTR)Request->Arg1,
                              (PVOID)(ULONG_PTR)Request->Arg2,
                              (PVOID)(ULONG_PTR)Request->Arg3);
}

KG_NO_OBFUSCATE
static
NTSTATUS
HandlePtrCryptArm(
    _In_  PIRP                Irp,
    _In_  PIO_STACK_LOCATION  Io,
    _Out_ ULONG_PTR*          InfoOut
)
{
    if (!CallerIsOwner())
        return STATUS_ACCESS_DENIED;

    if (Io->Parameters.DeviceIoControl.InputBufferLength < sizeof(KG_PTRCRYPT_ARM_REQUEST))
        return STATUS_INVALID_BUFFER_SIZE;
    if (Io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(KG_PTRCRYPT_ARM_RESULT))
        return STATUS_BUFFER_TOO_SMALL;

    KG_PTRCRYPT_ARM_REQUEST* Request = (KG_PTRCRYPT_ARM_REQUEST*)Irp->AssociatedIrp.SystemBuffer;
    if (!TrustedContains((HANDLE)(ULONG_PTR)Request->Pid))
        return STATUS_ACCESS_DENIED;

    if (Request->Tid == 0 || Request->TargetPtrAddr == 0 ||
        Request->RtlAvehAddr == 0 || Request->Sentinel == 0)
        return STATUS_INVALID_PARAMETER;

    PVOID  AllocBase = NULL;
    UINT64 RealValue = 0;
    NTSTATUS Status = PtrCryptArm((HANDLE)(ULONG_PTR)Request->Pid,
                                  (HANDLE)(ULONG_PTR)Request->Tid,
                                  (PVOID)(ULONG_PTR)Request->TargetPtrAddr,
                                  (PVOID)(ULONG_PTR)Request->RtlAvehAddr,
                                  Request->Sentinel,
                                  &AllocBase,
                                  &RealValue);
    if (!NT_SUCCESS(Status))
        return Status;

    KG_PTRCRYPT_ARM_RESULT* Result = (KG_PTRCRYPT_ARM_RESULT*)Irp->AssociatedIrp.SystemBuffer;
    Result->AllocBase = (UINT64)(ULONG_PTR)AllocBase;
    Result->RealValue = RealValue;
    *InfoOut = sizeof(*Result);
    return STATUS_SUCCESS;
}

KG_NO_OBFUSCATE
_Use_decl_annotations_
NTSTATUS
DispatchDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP           Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION Io = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS  Status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR Info   = 0;

    switch (Io->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_KG_REGISTER:
        Status = HandleRegister(Irp, Io);
        break;
    case IOCTL_KG_STATUS:
        Status = HandleStatus(Irp, Io, &Info);
        break;
    case IOCTL_KG_ARM_RELAUNCH:
        Status = HandleArmRelaunch(Irp, Io);
        break;
    case IOCTL_KG_ATTEST:
        Status = HandleAttest(Irp, Io);
        break;
    case IOCTL_KG_STEAMID:
        Status = HandleSteamId(Irp, Io, &Info);
        break;
    case IOCTL_KG_SHUTDOWN:
        Status = HandleShutdown();
        break;
    case IOCTL_KG_LAST_BLOCK:
        Status = HandleLastBlock(Irp, Io, &Info);
        break;
    case IOCTL_KG_KILL_TRUSTED:
        Status = HandleKillTrusted();
        break;
    case IOCTL_KG_TRUSTED_COUNT:
        Status = HandleTrustedCount(Irp, Io, &Info);
        break;
    case IOCTL_KG_MODULE_INFO:
        Status = HandleModuleInfo(Irp, Io, &Info);
        break;
    case IOCTL_KG_SCAN:
        Status = HandleScan(Irp, Io, &Info);
        break;
    case IOCTL_KG_MEM_READ:
        Status = HandleMemRead(Irp, Io, &Info);
        break;
    case IOCTL_KG_MEM_WRITE:
        Status = HandleMemWrite(Irp, Io);
        break;
    case IOCTL_KG_HWID:
        Status = HandleHwid(Irp, Io, &Info);
        break;
    case IOCTL_KG_CRITICAL_COMMIT:
        Status = HandleCriticalCommit(Irp, Io);
        break;
    case IOCTL_KG_NETMON_POP:
    {
        ULONG Got = 0;
        Status = NetmonPop(Irp->AssociatedIrp.SystemBuffer,
                           Io->Parameters.DeviceIoControl.OutputBufferLength,
                           &Got);
        Info = Got;
        break;
    }
    case IOCTL_KG_UNCLOAK_WINDOW:
    {
        if (Io->Parameters.DeviceIoControl.InputBufferLength < sizeof(KG_UNCLOAK_WINDOW_REQ)) {
            Status = STATUS_INVALID_BUFFER_SIZE;
            break;
        }
        KG_UNCLOAK_WINDOW_REQ* Req = (KG_UNCLOAK_WINDOW_REQ*)Irp->AssociatedIrp.SystemBuffer;
        Status = Win32kUncloakWindow((HANDLE)(ULONG_PTR)Req->WindowHandle, Req->Value);
        break;
    }
    case IOCTL_KG_MMAP_POP:
    {
        ULONG Got = 0;
        Status = MmapPop(Irp->AssociatedIrp.SystemBuffer,
                         Io->Parameters.DeviceIoControl.OutputBufferLength,
                         &Got);
        Info = Got;
        break;
    }
    case IOCTL_KG_IRP_POP:
    {
        ULONG Got = 0;
        Status = IrpScanPop(Irp->AssociatedIrp.SystemBuffer,
                            Io->Parameters.DeviceIoControl.OutputBufferLength,
                            &Got);
        Info = Got;
        break;
    }
    case IOCTL_KG_ALLOC_IN_TARGET:
        Status = HandleAllocInTarget(Irp, Io, &Info);
        break;
    case IOCTL_KG_APC_INJECT:
        Status = HandleApcInject(Irp, Io);
        break;
    case IOCTL_KG_PTRCRYPT_ARM:
        Status = HandlePtrCryptArm(Irp, Io, &Info);
        break;
    }

    return Complete(Irp, Status, Info);
}
