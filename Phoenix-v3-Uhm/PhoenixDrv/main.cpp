#include <ntifs.h>

#include "shared.hpp"
#include "klazy.hpp"

#include "comm/comm.hpp"
#include "protect/protect.hpp"
#include "blockdrv/blockdrv.hpp"
#include "regfilter/regfilter.hpp"
#include "checks/checks.hpp"
#include "wfp/wfp.hpp"
#include "integrity/integrity.hpp"
#include "mmap/mmap.hpp"
#include "irpscan/irpscan.hpp"
#include "stackattach/stackattach.hpp"

static PDEVICE_OBJECT g_Device = NULL;

extern "C" PVOID                        g_KlazyAnchor   = NULL;
extern "C" PMmGetSystemRoutineAddress_t g_KlazyMmGetSRA = NULL;

DRIVER_UNLOAD DriverUnload;

_Use_decl_annotations_
KG_NO_OBFUSCATE
VOID
DriverUnload(
    PDRIVER_OBJECT Driver
)
{
    PAGED_CODE();
    UNREFERENCED_PARAMETER(Driver);

    UNICODE_STRING Link;
    KlazyMakeUS(&Link, PX_W(KG_SYMLINK_NAME));
    KL_NT(IoDeleteSymbolicLink)(&Link);

    StackAttachStop();
    IrpScanStop();
    MmapStop();
    IntegrityStop();
    WfpUninstall();
    RegFilterUninstall();
    BlockdrvUninstall();
    ProcessNotifyRemove();
    UnregisterProtection();

    if (g_Device != NULL) {
        KL_NT(IoDeleteDevice)(g_Device);
        g_Device = NULL;
    }
}

KG_NO_OBFUSCATE
static
__declspec(noinline)
NTSTATUS
SetupDeviceAndLink(
    _In_  PDRIVER_OBJECT   Driver,
    _Out_ PUNICODE_STRING  OutLink
)
{
    PAGED_CODE();

    UNICODE_STRING DeviceName;
    KlazyMakeUS(&DeviceName, PX_W(KG_DEVICE_NAME));

    NTSTATUS Status = KL_NT(IoCreateDevice)(Driver,
                                            0,
                                            &DeviceName,
                                            KG_FILE_DEVICE,
                                            FILE_DEVICE_SECURE_OPEN,
                                            FALSE,
                                            &g_Device);
    if (!NT_SUCCESS(Status))
        return Status;

    KlazyMakeUS(OutLink, PX_W(KG_SYMLINK_NAME));
    Status = KL_NT(IoCreateSymbolicLink)(OutLink, &DeviceName);
    if (!NT_SUCCESS(Status)) {
        KL_NT(IoDeleteDevice)(g_Device);
        g_Device = NULL;
    }

    return Status;
}

KG_NO_OBFUSCATE
static
__declspec(noinline)
VOID
WireDispatchTable(
    _In_ PDRIVER_OBJECT Driver
)
{
    PAGED_CODE();

    for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        Driver->MajorFunction[i] = DispatchGeneric;

    Driver->MajorFunction[IRP_MJ_CREATE]         = DispatchCreate;
    Driver->MajorFunction[IRP_MJ_CLOSE]          = DispatchClose;
    Driver->MajorFunction[IRP_MJ_READ]           = DispatchRead;
    Driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    Driver->DriverUnload                         = DriverUnload;
}

KG_NO_OBFUSCATE
extern "C"
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT   Driver,
    _In_ PUNICODE_STRING  Registry
)
{
    PAGED_CODE();
    UNREFERENCED_PARAMETER(Registry);

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    NTSTATUS Boot = KlazyBootstrap(Driver->DriverSection);
    if (!NT_SUCCESS(Boot))
        return Boot;

    KlazyHotInit();

    if (IsSystemInsecureBootMode())
        return STATUS_NOT_SAFE_MODE_DRIVER;

    UNICODE_STRING Link = { 0 };
    NTSTATUS Status = SetupDeviceAndLink(Driver, &Link);
    if (!NT_SUCCESS(Status))
        return Status;

    enum {
        STAGE_PROTECT = 1,
        STAGE_PROCNOTIFY,
        STAGE_BLOCKDRV,
        STAGE_REGFILTER,
        STAGE_WFP
    } Stage = STAGE_PROTECT;

    Status = RegisterProtection();
    if (!NT_SUCCESS(Status))
        goto Fail;

    Stage = STAGE_PROCNOTIFY;
    Status = ProcessNotifyInstall();
    if (!NT_SUCCESS(Status))
        goto Fail;

    Stage = STAGE_BLOCKDRV;
    Status = BlockdrvInstall();
    if (!NT_SUCCESS(Status))
        goto Fail;

    BlockdrvScanLoadedAsync();

    Stage = STAGE_REGFILTER;
    Status = RegFilterInstall();
    if (!NT_SUCCESS(Status))
        goto Fail;

    RegFilterScanNvStreamProof();

    Stage = STAGE_WFP;
    Status = WfpInstall(Driver);
    if (!NT_SUCCESS(Status))
        goto Fail;

    IntegrityStart();
    MmapStart();
    IrpScanStart();
    StackAttachStart();

    WireDispatchTable(Driver);

    g_Device->Flags |=  DO_BUFFERED_IO;
    g_Device->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;

Fail:
    if (Stage >= STAGE_WFP)        WfpUninstall();
    if (Stage >= STAGE_REGFILTER)  RegFilterUninstall();
    if (Stage >= STAGE_BLOCKDRV)   BlockdrvUninstall();
    if (Stage >= STAGE_PROCNOTIFY) ProcessNotifyRemove();
    if (Stage >= STAGE_PROTECT)    UnregisterProtection();

    KL_NT(IoDeleteSymbolicLink)(&Link);
    KL_NT(IoDeleteDevice)(g_Device);
    g_Device = NULL;
    return Status;
}
