#include "checks.hpp"

#include <ntifs.h>

#include "klazy.hpp"
#include "pxstr.hpp"

extern "C" ULONG_PTR KgReadCr4(VOID);
extern "C" VOID      KgWriteCr4(ULONG_PTR Value);
extern "C" VOID      KgDisableInterrupts(VOID);
extern "C" VOID      KgEnableInterrupts(VOID);

extern "C" {
	NTSTATUS
	NTAPI
	ZwQuerySystemInformation(
	    _In_       ULONG   SystemInformationClass,
	    _Inout_    PVOID   SystemInformation,
	    _In_       ULONG   SystemInformationLength,
	    _Out_opt_  PULONG  ReturnLength
	);

	NTKERNELAPI
	NTSTATUS
	ExGetFirmwareEnvironmentVariable(
	    _In_      PUNICODE_STRING VariableName,
	    _In_      LPGUID          VendorGuid,
	    _Inout_   PVOID           Value,
	    _Inout_   PULONG          ValueLength,
	    _Out_opt_ PULONG          Attributes
	);

	VOID
	BlocklistRecordFromKernel(
	    _In_ PCUNICODE_STRING Path,
	    _In_ const WCHAR*     Reason
	);
}

static volatile LONG g_HvciSpoofReported = 0;

#ifndef SystemCodeIntegrityInformation
#define SystemCodeIntegrityInformation     103
#endif
#ifndef SystemSecureBootInformation
#define SystemSecureBootInformation        145
#endif
#ifndef SystemIsolatedUserModeInformation
#define SystemIsolatedUserModeInformation  165
#endif
#ifndef SystemDmaGuardPolicyInformation
#define SystemDmaGuardPolicyInformation    202
#endif

#define CI_OPTION_ENABLED           0x001
#define CI_OPTION_TESTSIGN          0x002
#define CI_OPTION_HVCI_KMCI_ENABLED 0x400

#define KG_KUSER_SHARED_DATA_BASE           0xFFFFF78000000000ULL
#define KG_KUSER_KD_DEBUGGER_ENABLED_OFFSET 0x2D4

typedef struct _CI_INFO {
    ULONG Length;
    ULONG CodeIntegrityOptions;
} CI_INFO, *PCI_INFO;

typedef struct _SB_INFO {
    BOOLEAN SecureBootEnabled;
    BOOLEAN SecureBootCapable;
} SB_INFO, *PSB_INFO;

typedef struct _IUM_INFO {
    BOOLEAN   SecureKernelRunning : 1;
    BOOLEAN   HvciEnabled : 1;
    BOOLEAN   HvciStrictMode : 1;
    BOOLEAN   DebugEnabled : 1;
    BOOLEAN   FirmwarePageProtection : 1;
    BOOLEAN   EncryptionKeyAvailable : 1;
    BOOLEAN   SpareFlags : 2;
    BOOLEAN   TrustletRunningWithVsm : 1;
    BOOLEAN   HvciDisabledByNoExecute : 1;
    BOOLEAN   SpareFlags2 : 6;
    BOOLEAN   Reserved[6];
    ULONGLONG BootId;
} IUM_INFO, *PIUM_INFO;

typedef struct _DMA_INFO {
    BOOLEAN Enabled;
} DMA_INFO, *PDMA_INFO;

static const GUID g_EfiGlobal = {
    0x8be4df61, 0x93ca, 0x11d2,
    { 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c }
};

static
KG_STATE
QuerySecureBoot(
    VOID
)
{
    SB_INFO Info = { 0 };
    ULONG Returned = 0;

    NTSTATUS Status = KL_NT(ZwQuerySystemInformation)(SystemSecureBootInformation,
                                                      &Info,
                                                      sizeof(Info),
                                                      &Returned);
    if (!NT_SUCCESS(Status))
        return KgStateUnknown;

    if (!Info.SecureBootCapable)
        return KgStateUnavailable;

    return Info.SecureBootEnabled ? KgStateEnabled : KgStateDisabled;
}

static
KG_STATE
QuerySecureBootFirmware(
    VOID
)
{
    UNICODE_STRING Name;
    KlazyMakeUS(&Name, PX_W(L"SecureBoot"));

    UCHAR Value      = 0;
    ULONG Returned   = 0;
    ULONG Attributes = 0;

    NTSTATUS Status = KL_NT(ExGetFirmwareEnvironmentVariable)(&Name,
                                                              (LPGUID)&g_EfiGlobal,
                                                              &Value,
                                                              &Returned,
                                                              &Attributes);
    if (!NT_SUCCESS(Status)) {
        if (Status == STATUS_NOT_IMPLEMENTED || Status == STATUS_INVALID_PARAMETER)
            return KgStateUnavailable;

        return KgStateUnknown;
    }

    return (Returned >= 1 && Value == 1) ? KgStateEnabled : KgStateDisabled;
}

typedef enum _KG_HVCI_SIGNAL {
    KgHvciSignalUnknown = 0,
    KgHvciSignalOn      = 1,
    KgHvciSignalOff     = 2
} KG_HVCI_SIGNAL;

static
KG_HVCI_SIGNAL
QueryHvciIum(
    VOID
)
{
    IUM_INFO Ium = { 0 };
    ULONG    Returned = 0;
    NTSTATUS Status = KL_NT(ZwQuerySystemInformation)(SystemIsolatedUserModeInformation,
                                                      &Ium, sizeof(Ium), &Returned);
    if (!NT_SUCCESS(Status) || Returned < sizeof(Ium))
        return KgHvciSignalUnknown;
    if (Ium.SecureKernelRunning && Ium.HvciEnabled)
        return KgHvciSignalOn;
    return KgHvciSignalOff;
}

static
KG_HVCI_SIGNAL
QueryHvciCi(
    VOID
)
{
    CI_INFO Info = { sizeof(CI_INFO), 0 };
    ULONG    Returned = 0;
    NTSTATUS Status = KL_NT(ZwQuerySystemInformation)(SystemCodeIntegrityInformation,
                                                      &Info, sizeof(Info), &Returned);
    if (!NT_SUCCESS(Status))
        return KgHvciSignalUnknown;
    return (Info.CodeIntegrityOptions & CI_OPTION_HVCI_KMCI_ENABLED)
         ? KgHvciSignalOn
         : KgHvciSignalOff;
}

#define KG_CR4_SMEP (1ULL << 20)
#define KG_CR4_SMAP (1ULL << 21)

KG_NO_OBFUSCATE
static
KG_HVCI_SIGNAL
ProbeHvciCr4(
    VOID
)
{
    KIRQL OldIrql = g_KH.KfRaiseIrql(DISPATCH_LEVEL);

    ULONG_PTR Original = KgReadCr4();

    ULONG_PTR TargetBits = 0;
    if (Original & KG_CR4_SMEP) TargetBits |= KG_CR4_SMEP;
    if (Original & KG_CR4_SMAP) TargetBits |= KG_CR4_SMAP;

    if (TargetBits == 0) {
        g_KH.KeLowerIrql(OldIrql);
        return KgHvciSignalUnknown;
    }

    KG_HVCI_SIGNAL Result = KgHvciSignalUnknown;
    KgDisableInterrupts();

    __try {
        KgWriteCr4(Original & ~TargetBits);
        ULONG_PTR Observed = KgReadCr4();
        KgWriteCr4(Original);

        if ((Observed & TargetBits) == TargetBits)
            Result = KgHvciSignalOn;
        else
            Result = KgHvciSignalOff;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        __try { KgWriteCr4(Original); } __except (EXCEPTION_EXECUTE_HANDLER) { }
        Result = KgHvciSignalOn;
    }

    KgEnableInterrupts();
    g_KH.KeLowerIrql(OldIrql);
    return Result;
}

static
KG_HVCI_SIGNAL
QueryHvciRegistry(
    VOID
)
{
    OBJECT_ATTRIBUTES KeyAttr;
    UNICODE_STRING    KeyName;
    KlazyMakeUS(&KeyName,
        PX_W(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity"));
    InitializeObjectAttributes(&KeyAttr, &KeyName,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL, NULL);

    HANDLE KeyHandle = NULL;
    NTSTATUS Status = KL_NT(ZwOpenKey)(&KeyHandle, KEY_READ, &KeyAttr);
    if (!NT_SUCCESS(Status))
        return KgHvciSignalUnknown;

    UNICODE_STRING ValueName;
    KlazyMakeUS(&ValueName, PX_W(L"Enabled"));

    UCHAR Buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)] = { 0 };
    ULONG Returned = 0;
    Status = KL_NT(ZwQueryValueKey)(KeyHandle, &ValueName,
                                    KeyValuePartialInformation,
                                    Buffer, sizeof(Buffer), &Returned);
    KL_NT(ZwClose)(KeyHandle);
    if (!NT_SUCCESS(Status))
        return KgHvciSignalUnknown;

    PKEY_VALUE_PARTIAL_INFORMATION Info = (PKEY_VALUE_PARTIAL_INFORMATION)Buffer;
    if (Info->Type != REG_DWORD || Info->DataLength < sizeof(ULONG))
        return KgHvciSignalUnknown;

    ULONG Value = *(ULONG*)Info->Data;
    return (Value != 0) ? KgHvciSignalOn : KgHvciSignalOff;
}

static
KG_STATE
QueryHvci(
    VOID
)
{
    KG_HVCI_SIGNAL Ium = QueryHvciIum();
    KG_HVCI_SIGNAL Ci  = QueryHvciCi();

    if (Ium == KgHvciSignalOn  && Ci == KgHvciSignalOn)  return KgStateEnabled;
    if (Ium == KgHvciSignalOff && Ci == KgHvciSignalOff) return KgStateDisabled;
    if (Ium == KgHvciSignalOn  || Ci == KgHvciSignalOn)  return KgStateEnabled;
    if (Ium == KgHvciSignalOff || Ci == KgHvciSignalOff) return KgStateDisabled;
    return KgStateUnknown;
}

static
KG_STATE
QueryVbs(
    VOID
)
{
    IUM_INFO Info = { 0 };
    ULONG Returned = 0;

    NTSTATUS Status = KL_NT(ZwQuerySystemInformation)(SystemIsolatedUserModeInformation,
                                                      &Info,
                                                      sizeof(Info),
                                                      &Returned);
    if (!NT_SUCCESS(Status))
        return KgStateUnknown;

    return Info.SecureKernelRunning ? KgStateEnabled : KgStateDisabled;
}

static
KG_STATE
QueryKernelDma(
    VOID
)
{
    DMA_INFO Info = { 0 };
    ULONG Returned = 0;

    NTSTATUS Status = KL_NT(ZwQuerySystemInformation)(SystemDmaGuardPolicyInformation,
                                                      &Info,
                                                      sizeof(Info),
                                                      &Returned);
    if (!NT_SUCCESS(Status))
        return KgStateUnknown;

    return Info.Enabled ? KgStateEnabled : KgStateDisabled;
}

static
KG_STATE
QueryTpm(
    VOID
)
{
    OBJECT_ATTRIBUTES DeviceAttributes;
    UNICODE_STRING    DeviceName;
    KlazyMakeUS(&DeviceName, PX_W(L"\\Device\\Tpm"));
    InitializeObjectAttributes(&DeviceAttributes,
                               &DeviceName,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    HANDLE          DeviceHandle = NULL;
    IO_STATUS_BLOCK IoStatus     = { 0 };

    NTSTATUS Status = KL_NT(ZwOpenFile)(&DeviceHandle,
                                        GENERIC_READ,
                                        &DeviceAttributes,
                                        &IoStatus,
                                        FILE_SHARE_READ,
                                        0);
    if (NT_SUCCESS(Status)) {
        KL_NT(ZwClose)(DeviceHandle);
        return KgStateEnabled;
    }

    OBJECT_ATTRIBUTES KeyAttributes;
    UNICODE_STRING    KeyName;
    KlazyMakeUS(&KeyName, PX_W(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\ACPI\\MSFT0101"));
    InitializeObjectAttributes(&KeyAttributes,
                               &KeyName,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    HANDLE KeyHandle = NULL;
    Status = KL_NT(ZwOpenKey)(&KeyHandle, KEY_READ, &KeyAttributes);
    if (NT_SUCCESS(Status)) {
        KL_NT(ZwClose)(KeyHandle);
        return KgStateEnabled;
    }

    return KgStateDisabled;
}

_Use_decl_annotations_
KG_NO_OBFUSCATE
VOID
CollectSecurityState(
    KG_STATUS_REPORT* Out
)
{
    KG_STATE Query    = QuerySecureBoot();
    KG_STATE Firmware = QuerySecureBootFirmware();

    KG_STATE Composite = KgStateUnknown;
    if (Query == KgStateEnabled && Firmware == KgStateEnabled)
        Composite = KgStateEnabled;
    else if (Query == KgStateDisabled || Firmware == KgStateDisabled)
        Composite = KgStateDisabled;
    else if (Query == KgStateUnavailable || Firmware == KgStateUnavailable)
        Composite = KgStateUnavailable;
    else if (Query == KgStateEnabled || Firmware == KgStateEnabled)
        Composite = KgStateEnabled;

    Out->SecureBoot         = Composite;
    Out->SecureBootFirmware = Firmware;
    Out->Hvci               = QueryHvci();
    Out->HvciPoolProbe      = KgStateUnknown;
    Out->Vbs                = QueryVbs();
    Out->KernelDma          = QueryKernelDma();
    Out->Tpm                = QueryTpm();
    Out->Reserved           = 0;
}

_Use_decl_annotations_
KG_NO_OBFUSCATE
VOID
RunHvciSpoofProbeAndReport(
    VOID
)
{
    KG_HVCI_SIGNAL Ium = QueryHvciIum();
    KG_HVCI_SIGNAL Ci  = QueryHvciCi();

    if (Ium != KgHvciSignalOn && Ci != KgHvciSignalOn)
        return;

    KG_HVCI_SIGNAL Cr4Vote1 = ProbeHvciCr4();
    if (Cr4Vote1 != KgHvciSignalOff)
        return;

    KG_HVCI_SIGNAL Cr4Vote2 = ProbeHvciCr4();
    if (Cr4Vote2 != KgHvciSignalOff)
        return;

    KG_HVCI_SIGNAL Cr4Vote3 = ProbeHvciCr4();
    if (Cr4Vote3 != KgHvciSignalOff)
        return;

    if (InterlockedCompareExchange(&g_HvciSpoofReported, 1, 0) != 0)
        return;

    KG_DRV_LOG("[PhoenixDrv/Checks] HVCI SPOOF: apis=on cr4 flip persisted 3x\n");

    UNICODE_STRING Path;
    KlazyMakeUS(&Path, PX_W(L"system:core-isolation"));
    BlocklistRecordFromKernel(&Path, PX_W(L"hvci-spoof"));
}

_Use_decl_annotations_
KG_NO_OBFUSCATE
BOOLEAN
IsSystemInsecureBootMode(
    VOID
)
{
#if !KG_ENFORCE_SECURE_BOOTMODE
    return FALSE;
#else
    __try {
        volatile UCHAR* KdEnabled =
            (volatile UCHAR*)(KG_KUSER_SHARED_DATA_BASE + KG_KUSER_KD_DEBUGGER_ENABLED_OFFSET);
        if (*KdEnabled != 0) {
            KG_DRV_LOG("[PhoenixDrv/Checks] refuse load: kernel debugger enabled (bcdedit /debug on)\n");
            return TRUE;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }

    CI_INFO Info = { sizeof(CI_INFO), 0 };
    ULONG Returned = 0;

    NTSTATUS Status = KL_NT(ZwQuerySystemInformation)(SystemCodeIntegrityInformation,
                                                      &Info,
                                                      sizeof(Info),
                                                      &Returned);
    if (NT_SUCCESS(Status)) {
        if (Info.CodeIntegrityOptions & CI_OPTION_TESTSIGN) {
            KG_DRV_LOG("[PhoenixDrv/Checks] refuse load: testsigning enabled (bcdedit /set testsigning yes)\n");
            return TRUE;
        }

        if ((Info.CodeIntegrityOptions & CI_OPTION_ENABLED) == 0) {
            KG_DRV_LOG("[PhoenixDrv/Checks] refuse load: code integrity disabled (bcdedit /set nointegritychecks yes)\n");
            return TRUE;
        }
    }

    return FALSE;
#endif
}

_Use_decl_annotations_
KG_NO_OBFUSCATE
BOOLEAN
PostureMeetsPolicy(
    const KG_STATUS_REPORT* Report
)
{
#if KG_POSTURE_ENFORCE
    if (Report == NULL)
        return FALSE;

    return (Report->SecureBoot == KgStateEnabled) &&
           (Report->Hvci       == KgStateEnabled);
#else
    UNREFERENCED_PARAMETER(Report);
    return TRUE;
#endif
}
