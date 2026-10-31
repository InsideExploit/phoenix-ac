#include "protect.hpp"
#include "shared.hpp"
#include "pxstr.hpp"
#include "klazy.hpp"
#include "blocklist/blocklist.hpp"
#include "integrity/integrity.hpp"

static
VOID
RecordBlock(
    _In_ PCUNICODE_STRING Path,
    _In_ const WCHAR*     Reason
);

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif
#ifndef THREAD_QUERY_LIMITED_INFORMATION
#define THREAD_QUERY_LIMITED_INFORMATION  0x0800
#endif
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ                   0x0010
#endif
#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION         0x0400
#endif
#ifndef THREAD_QUERY_INFORMATION
#define THREAD_QUERY_INFORMATION          0x0040
#endif
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE                 0x0001
#endif

volatile PVOID g_ProtectedOwner = NULL;

static PVOID g_ObHandle = NULL;

typedef struct _KG_ARM_STATE {
    KSPIN_LOCK    Lock;
    volatile LONG Armed;
    volatile LONG Attested;
    HANDLE        ExpectedCreator;
    WCHAR         Basename[KG_BASENAME_MAX];
    USHORT        BasenameLen;
    UINT8         Token[KG_TOKEN_LEN];
} KG_ARM_STATE, *PKG_ARM_STATE;

static KG_ARM_STATE   g_Arm                 = { 0 };
static BOOLEAN        g_ProcNotifyInstalled = FALSE;
static volatile PVOID g_TrustedCreator      = NULL;

#define KEEP_PROCESS_MASK (PROCESS_QUERY_LIMITED_INFORMATION | \
                           PROCESS_QUERY_INFORMATION         | \
                           PROCESS_VM_READ                   | \
                           SYNCHRONIZE)
#define KEEP_THREAD_MASK  (THREAD_QUERY_LIMITED_INFORMATION  | \
                           THREAD_QUERY_INFORMATION          | \
                           SYNCHRONIZE)

extern "C" {
	PCHAR
	PsGetProcessImageFileName(
	    _In_ PEPROCESS Process
	);

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

typedef struct _KG_SYSTEM_PROCESS_INFO {
    ULONG          NextEntryOffset;
    ULONG          NumberOfThreads;
    UCHAR          Reserved1[48];
    UNICODE_STRING ImageName;
    LONG           BasePriority;
    HANDLE         UniqueProcessId;
    HANDLE         InheritedFromUniqueProcessId;
} KG_SYSTEM_PROCESS_INFO, *PKG_SYSTEM_PROCESS_INFO;

#define KG_SYSPATH_COUNT 17

static
const WCHAR*
GetSystemPathSuffix(
    _In_ ULONG Index
)
{
    switch (Index) {
    case 0:  return PX_W(L"\\Windows\\System32\\csrss.exe");
    case 1:  return PX_W(L"\\Windows\\System32\\smss.exe");
    case 2:  return PX_W(L"\\Windows\\System32\\wininit.exe");
    case 3:  return PX_W(L"\\Windows\\System32\\winlogon.exe");
    case 4:  return PX_W(L"\\Windows\\System32\\services.exe");
    case 5:  return PX_W(L"\\Windows\\System32\\lsass.exe");
    case 6:  return PX_W(L"\\Windows\\System32\\svchost.exe");
    case 7:  return PX_W(L"\\Windows\\System32\\audiodg.exe");
    case 8:  return PX_W(L"\\Windows\\System32\\dwm.exe");
    case 9:  return PX_W(L"\\Windows\\System32\\WerFault.exe");
    case 10: return PX_W(L"\\Windows\\System32\\WerFaultSecure.exe");
    case 11: return PX_W(L"\\Windows\\System32\\ctfmon.exe");
    case 12: return PX_W(L"\\Windows\\explorer.exe");
    case 13: return PX_W(L"\\Steam\\steam.exe");
    case 14: return PX_W(L"\\Windows\\System32\\wbem\\WmiPrvSE.exe");
    case 15: return PX_W(L"\\Windows\\System32\\conhost.exe");
    case 16: return PX_W(L"\\LGHUB\\lghub_agent.exe");
    default: return NULL;
    }
}

static
BOOLEAN
PathContainsCi(
    _In_ PCUNICODE_STRING Hay,
    _In_ const WCHAR*     Needle
)
{
    if (Hay == NULL || Hay->Buffer == NULL || Needle == NULL)
        return FALSE;

    UNICODE_STRING Want;
    KlazyMakeUS(&Want, Needle);

    if (Hay->Length < Want.Length)
        return FALSE;

    USHORT HayChars  = Hay->Length / sizeof(WCHAR);
    USHORT WantChars = Want.Length / sizeof(WCHAR);

    for (USHORT i = 0; i + WantChars <= HayChars; i++) {
        UNICODE_STRING Sub;
        Sub.Buffer        = Hay->Buffer + i;
        Sub.Length        = Want.Length;
        Sub.MaximumLength = Want.Length;

        if (KL_NT(RtlEqualUnicodeString)(&Sub, &Want, TRUE))
            return TRUE;
    }

    return FALSE;
}

static
BOOLEAN
PathMatchesSystemAllowList(
    _In_ PCUNICODE_STRING Path
)
{
    if (Path == NULL || Path->Length == 0 || Path->Buffer == NULL)
        return FALSE;

    for (ULONG i = 0; i < KG_SYSPATH_COUNT; ++i) {
        UNICODE_STRING Suffix;
        KlazyMakeUS(&Suffix, GetSystemPathSuffix(i));

        if (Path->Length < Suffix.Length)
            continue;

        UNICODE_STRING Tail;
        Tail.Buffer        = (PWCH)((PUCHAR)Path->Buffer + Path->Length - Suffix.Length);
        Tail.Length        = Suffix.Length;
        Tail.MaximumLength = Tail.Length;

        if (KL_NT(RtlEqualUnicodeString)(&Tail, &Suffix, TRUE))
            return TRUE;
    }

    if (PathContainsCi(Path, PX_W(L"\\Rockstar Games\\")))
        return TRUE;

    return FALSE;
}

#define KG_SYSTEM_ALLOW_MAX 512

typedef struct _KG_ALLOW_SET {
    KSPIN_LOCK Lock;
    HANDLE     Pids[KG_SYSTEM_ALLOW_MAX];
} KG_ALLOW_SET, *PKG_ALLOW_SET;

static KG_ALLOW_SET g_SystemAllow = { 0 };

KG_NO_OBFUSCATE
static
BOOLEAN
SystemAllowContainsLocked(
    _In_ HANDLE Pid
)
{
    for (ULONG i = 0; i < KG_SYSTEM_ALLOW_MAX; ++i) {
        if (g_SystemAllow.Pids[i] == Pid)
            return TRUE;
    }

    return FALSE;
}

KG_NO_OBFUSCATE
static
BOOLEAN
SystemAllowContains(
    _In_ HANDLE Pid
)
{
    if (!Pid)
        return FALSE;

    KIRQL   Irql      = g_KH.KeAcquireSpinLockRaiseToDpc(&g_SystemAllow.Lock);
    BOOLEAN Contained = SystemAllowContainsLocked(Pid);
    g_KH.KeReleaseSpinLock(&g_SystemAllow.Lock, Irql);
    return Contained;
}

static
VOID
SystemAllowAdd(
    _In_ HANDLE Pid
);

KG_NO_OBFUSCATE
static
BOOLEAN
SystemAllowResolveByImage(
    _In_ HANDLE Pid
)
{
    if (!Pid) return FALSE;
    if (KL_NT(KeGetCurrentIrql)() > APC_LEVEL) return FALSE;

    PEPROCESS Process = NULL;
    if (!NT_SUCCESS(KL_NT(PsLookupProcessByProcessId)(Pid, &Process)) || !Process)
        return FALSE;

    PUNICODE_STRING Image = NULL;
    NTSTATUS Status = KL_NT(SeLocateProcessImageName)(Process, &Image);
    KL_NT(ObfDereferenceObject)(Process);

    if (!NT_SUCCESS(Status) || !Image)
        return FALSE;

    BOOLEAN Match = PathMatchesSystemAllowList(Image);
    g_KH.ExFreePoolWithTag(Image, 0);

    if (Match)
        SystemAllowAdd(Pid);
    return Match;
}

static
VOID
SystemAllowAdd(
    _In_ HANDLE Pid
)
{
    if (!Pid)
        return;

    KIRQL Irql = g_KH.KeAcquireSpinLockRaiseToDpc(&g_SystemAllow.Lock);
    if (!SystemAllowContainsLocked(Pid)) {
        for (ULONG i = 0; i < KG_SYSTEM_ALLOW_MAX; ++i) {
            if (g_SystemAllow.Pids[i] == NULL) {
                g_SystemAllow.Pids[i] = Pid;
                break;
            }
        }
    }

    g_KH.KeReleaseSpinLock(&g_SystemAllow.Lock, Irql);
}

static
VOID
SystemAllowRemove(
    _In_ HANDLE Pid
)
{
    if (!Pid)
        return;

    KIRQL Irql = g_KH.KeAcquireSpinLockRaiseToDpc(&g_SystemAllow.Lock);
    for (ULONG i = 0; i < KG_SYSTEM_ALLOW_MAX; ++i) {
        if (g_SystemAllow.Pids[i] == Pid) {
            g_SystemAllow.Pids[i] = NULL;
            break;
        }
    }

    g_KH.KeReleaseSpinLock(&g_SystemAllow.Lock, Irql);
}

static
VOID
SeedSystemAllowFromRunning(
    VOID
)
{
    ULONG Size = 0;
    KL_NT(ZwQuerySystemInformation)(SystemProcessInformation, NULL, 0, &Size);
    if (Size == 0)
        Size = 0x10000;

    PVOID    Buffer   = NULL;
    ULONG    Returned = 0;
    NTSTATUS Status   = STATUS_INFO_LENGTH_MISMATCH;

    for (ULONG Attempt = 0; Attempt < 6; ++Attempt) {
        ULONG Try = Size + 0x10000 * (Attempt + 1);
        Buffer = KL_NT(ExAllocatePool2)(POOL_FLAG_PAGED, Try, 'PxEn');
        if (Buffer == NULL)
            return;

        Returned = 0;
        Status = KL_NT(ZwQuerySystemInformation)(SystemProcessInformation,
                                                  Buffer,
                                                  Try,
                                                  &Returned);
        if (NT_SUCCESS(Status)) {
            Size = Try;
            break;
        }

        g_KH.ExFreePoolWithTag(Buffer, 0);
        Buffer = NULL;

        if (Status != STATUS_INFO_LENGTH_MISMATCH)
            return;

        if (Returned > Size)
            Size = Returned;
    }

    if (!NT_SUCCESS(Status) || Buffer == NULL)
        return;

    PKG_SYSTEM_PROCESS_INFO Entry = (PKG_SYSTEM_PROCESS_INFO)Buffer;
    for (;;) {
        HANDLE Pid = Entry->UniqueProcessId;
        if (Pid) {
            PEPROCESS Process = NULL;
            if (NT_SUCCESS(KL_NT(PsLookupProcessByProcessId)(Pid, &Process))) {
                PUNICODE_STRING Image = NULL;
                if (NT_SUCCESS(KL_NT(SeLocateProcessImageName)(Process, &Image)) && Image) {
                    if (PathMatchesSystemAllowList(Image))
                        SystemAllowAdd(Pid);

                    g_KH.ExFreePoolWithTag(Image, 0);
                }
                KL_NT(ObfDereferenceObject)(Process);
            }
        }

        if (Entry->NextEntryOffset == 0)
            break;

        Entry = (PKG_SYSTEM_PROCESS_INFO)((PUCHAR)Entry + Entry->NextEntryOffset);
    }

    g_KH.ExFreePoolWithTag(Buffer, 0);
}

#define KG_TRUSTED_MAX 256

typedef struct _KG_TRUSTED_SET {
    KSPIN_LOCK Lock;
    HANDLE     Pids[KG_TRUSTED_MAX];
} KG_TRUSTED_SET, *PKG_TRUSTED_SET;

static KG_TRUSTED_SET g_Trusted = { 0 };

KG_NO_OBFUSCATE
static
BOOLEAN
TrustedContainsLocked(
    _In_ HANDLE Pid
)
{
    for (ULONG i = 0; i < KG_TRUSTED_MAX; ++i) {
        if (g_Trusted.Pids[i] == Pid)
            return TRUE;
    }

    return FALSE;
}

KG_NO_OBFUSCATE
_Use_decl_annotations_
BOOLEAN
TrustedContains(
    HANDLE Pid
)
{
    if (!Pid)
        return FALSE;

    KIRQL   Irql      = g_KH.KeAcquireSpinLockRaiseToDpc(&g_Trusted.Lock);
    BOOLEAN Contained = TrustedContainsLocked(Pid);
    g_KH.KeReleaseSpinLock(&g_Trusted.Lock, Irql);
    return Contained;
}

static
VOID
TrustedAdd(
    _In_ HANDLE Pid
)
{
    if (!Pid)
        return;

    KIRQL Irql = g_KH.KeAcquireSpinLockRaiseToDpc(&g_Trusted.Lock);
    if (!TrustedContainsLocked(Pid)) {
        for (ULONG i = 0; i < KG_TRUSTED_MAX; ++i) {
            if (g_Trusted.Pids[i] == NULL) {
                g_Trusted.Pids[i] = Pid;
                break;
            }
        }
    }

    g_KH.KeReleaseSpinLock(&g_Trusted.Lock, Irql);
}

static
VOID
TrustedRemove(
    _In_ HANDLE Pid
)
{
    if (!Pid)
        return;

    KIRQL Irql = g_KH.KeAcquireSpinLockRaiseToDpc(&g_Trusted.Lock);
    for (ULONG i = 0; i < KG_TRUSTED_MAX; ++i) {
        if (g_Trusted.Pids[i] == Pid) {
            g_Trusted.Pids[i] = NULL;
            break;
        }
    }

    g_KH.KeReleaseSpinLock(&g_Trusted.Lock, Irql);
}

static
BOOLEAN
ImagePathInFiveMDir(
    _In_ PCUNICODE_STRING Img
)
{
    if (Img == NULL || Img->Length == 0 || Img->Buffer == NULL)
        return FALSE;

    UNICODE_STRING Needle;
    KlazyMakeUS(&Needle, PX_W(L"\\FiveM\\"));

    if (Img->Length < Needle.Length)
        return FALSE;

    USHORT Chars       = Img->Length / sizeof(WCHAR);
    USHORT NeedleChars = Needle.Length / sizeof(WCHAR);

    for (USHORT i = 0; i + NeedleChars <= Chars; ++i) {
        UNICODE_STRING Sub;
        Sub.Buffer        = Img->Buffer + i;
        Sub.Length        = Needle.Length;
        Sub.MaximumLength = Needle.Length;

        if (KL_NT(RtlEqualUnicodeString)(&Sub, &Needle, TRUE))
            return TRUE;
    }

    return FALSE;
}

#define KG_PROC_ACCESS_COOLDOWN_100NS (10LL * 1000LL * 1000LL * 10LL)
static volatile LONGLONG g_LastProcAccessAt = 0;

static
ULONGLONG
ProtectReadInterruptTime(
    VOID
)
{
    volatile ULONG* Base = (volatile ULONG*)(0xFFFFF78000000000ULL + 0x08);
    ULONG Low;
    ULONG High1;
    ULONG High2;

    do {
        High1 = Base[1];
        Low   = Base[0];
        High2 = Base[2];
    } while (High1 != (ULONG)High2);

    return ((ULONGLONG)High1 << 32) | Low;
}

#define KG_PROC_ALL_MASK    0x001FFFFFu
#define KG_PROC_CRIT_MASK   (0x0001u | 0x0002u | 0x0008u | 0x0040u | 0x0080u | 0x0800u)
#define KG_PROC_WRITE_MASK  0x0020u
#define KG_PROC_READ_MASK   0x0010u
#define KG_THREAD_ALL_MASK  0x001FFFFFu
#define KG_THREAD_CRIT_MASK (0x0001u | 0x0002u | 0x0008u | 0x0010u | 0x0020u | 0x0080u | 0x0100u | 0x0200u)

static
const WCHAR*
CategorizeAccess(
    _In_ ACCESS_MASK Requested,
    _In_ BOOLEAN     ForThread
)
{
    if (ForThread) {
        if ((Requested & KG_THREAD_ALL_MASK) == KG_THREAD_ALL_MASK)
            return PX_W(L"proc-access-all");

        if (Requested & KG_THREAD_CRIT_MASK)
            return PX_W(L"proc-access-crit");

        return NULL;
    }

    if ((Requested & KG_PROC_ALL_MASK) == KG_PROC_ALL_MASK)
        return PX_W(L"proc-access-all");

    if (Requested & KG_PROC_CRIT_MASK)
        return PX_W(L"proc-access-crit");

    if (Requested & KG_PROC_WRITE_MASK)
        return PX_W(L"proc-access-write");

    if (Requested & KG_PROC_READ_MASK)
        return PX_W(L"proc-access-read");

    return NULL;
}

static
BOOLEAN
AnsiEqualsCi(
    _In_z_ const char* A,
    _In_z_ const char* B
)
{
    while (*A && *B) {
        char Ca = *A;
        char Cb = *B;

        if (Ca >= 'A' && Ca <= 'Z') Ca = (char)(Ca + 32);
        if (Cb >= 'A' && Cb <= 'Z') Cb = (char)(Cb + 32);

        if (Ca != Cb)
            return FALSE;

        A++;
        B++;
    }

    return *A == 0 && *B == 0;
}

static
BOOLEAN
TargetIsGta(
    _In_opt_ PEPROCESS Process
)
{
    if (Process == NULL)
        return FALSE;

    PCHAR Name = KL_NT(PsGetProcessImageFileName)(Process);
    if (Name == NULL)
        return FALSE;

    return AnsiEqualsCi(Name, PX_A("GTAProcess.exe"));
}

static
VOID
ReportSuspiciousAccess(
    _In_ HANDLE      Caller,
    _In_ ACCESS_MASK Requested,
    _In_ BOOLEAN     ForThread
)
{
    if (KL_NT(KeGetCurrentIrql)() > PASSIVE_LEVEL)
        return;

    const WCHAR* Category = CategorizeAccess(Requested, ForThread);
    if (Category == NULL)
        return;

    if ((ULONG_PTR)Caller <= 4)
        return;

    LONGLONG Now  = (LONGLONG)ProtectReadInterruptTime();
    LONGLONG Last = g_LastProcAccessAt;
    if (Last != 0 && (Now - Last) < KG_PROC_ACCESS_COOLDOWN_100NS)
        return;

    g_LastProcAccessAt = Now;

    PEPROCESS CallerProcess = NULL;
    if (!NT_SUCCESS(KL_NT(PsLookupProcessByProcessId)(Caller, &CallerProcess)) || !CallerProcess)
        return;

    PUNICODE_STRING Image  = NULL;
    NTSTATUS        Status = KL_NT(SeLocateProcessImageName)(CallerProcess, &Image);
    KL_NT(ObfDereferenceObject)(CallerProcess);

    if (!NT_SUCCESS(Status) || !Image)
        return;

    RecordBlock(Image, Category);
    g_KH.ExFreePoolWithTag(Image, 0);
}

KG_NO_OBFUSCATE
static
OB_PREOP_CALLBACK_STATUS
ProcessThreadPreOp(
    _In_ PVOID                         Context,
    _In_ POB_PRE_OPERATION_INFORMATION Info
)
{
    UNREFERENCED_PARAMETER(Context);

    if (KL_NT(KeGetCurrentIrql)() > APC_LEVEL)
        return OB_PREOP_SUCCESS;

    if (Info->KernelHandle)
        return OB_PREOP_SUCCESS;

    HANDLE      Target    = NULL;
    ACCESS_MASK Keep      = 0;
    BOOLEAN     ForThread = FALSE;

    if (Info->ObjectType == *KL_NTVAR(PsProcessType)) {
        Target = KL_NT(PsGetProcessId)((PEPROCESS)Info->Object);
        Keep   = KEEP_PROCESS_MASK;
    } else if (Info->ObjectType == *KL_NTVAR(PsThreadType)) {
        Target    = KL_NT(PsGetThreadProcessId)((PETHREAD)Info->Object);
        Keep      = KEEP_THREAD_MASK;
        ForThread = TRUE;
    } else return OB_PREOP_SUCCESS;

    HANDLE  Owner       = (HANDLE)ReadPointerAcquire(&g_ProtectedOwner);
    BOOLEAN TargetOwned = (Owner && Target == Owner);
    BOOLEAN TargetTrust = TrustedContains(Target);
    if (!TargetOwned && !TargetTrust)
        return OB_PREOP_SUCCESS;

    HANDLE Caller = KL_NT(PsGetCurrentProcessId)();
    if (Caller == Target)
        return OB_PREOP_SUCCESS;

    if (Owner && Caller == Owner)
        return OB_PREOP_SUCCESS;

    HANDLE TrustedCreator = (HANDLE)ReadPointerAcquire(&g_TrustedCreator);
    if (TrustedCreator && Caller == TrustedCreator)
        return OB_PREOP_SUCCESS;

    if (TrustedContains(Caller))
        return OB_PREOP_SUCCESS;

    if (SystemAllowContains(Caller))
        return OB_PREOP_SUCCESS;

    if (SystemAllowResolveByImage(Caller))
        return OB_PREOP_SUCCESS;

    ACCESS_MASK Requested;
    if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
        Requested = Info->Parameters->CreateHandleInformation.DesiredAccess;
    else
        Requested = Info->Parameters->DuplicateHandleInformation.DesiredAccess;

    if (!ForThread &&
        (Requested & KG_PROC_ALL_MASK) == KG_PROC_ALL_MASK &&
        TargetIsGta((PEPROCESS)Info->Object)) {
        ReportSuspiciousAccess(Caller, Requested, ForThread);
    }

#if KG_ENFORCE_HANDLE_STRIP
    if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
        Info->Parameters->CreateHandleInformation.DesiredAccess &= Keep;
    else
        Info->Parameters->DuplicateHandleInformation.DesiredAccess &= Keep;
#endif
    return OB_PREOP_SUCCESS;
}

KG_NO_OBFUSCATE
_Use_decl_annotations_
NTSTATUS
RegisterProtection(
)
{
    (void)KL_NT(PsGetProcessId);
    (void)KL_NT(PsGetThreadProcessId);
    (void)KL_NT(PsGetCurrentProcessId);
    (void)KL_NT(PsGetProcessImageFileName);
    (void)KL_NT(IoGetCurrentProcess);
    (void)KL_NT(DbgPrintEx);
    (void)KL_NT(PsLookupProcessByProcessId);
    (void)KL_NT(SeLocateProcessImageName);
    (void)KL_NT(ObfDereferenceObject);
    (void)g_KH.ExFreePoolWithTag;
    (void)g_KH.KeAcquireSpinLockRaiseToDpc;
    (void)g_KH.KeReleaseSpinLock;

    OB_OPERATION_REGISTRATION Ops[2] = { 0 };
    Ops[0].ObjectType   = KL_NTVAR(PsProcessType);
    Ops[0].Operations   = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    Ops[0].PreOperation = ProcessThreadPreOp;

    Ops[1].ObjectType   = KL_NTVAR(PsThreadType);
    Ops[1].Operations   = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    Ops[1].PreOperation = ProcessThreadPreOp;

    UNICODE_STRING Altitude;
    KlazyMakeUS(&Altitude, PX_W(L"321100"));

    OB_CALLBACK_REGISTRATION Reg = { 0 };
    Reg.Version                    = OB_FLT_REGISTRATION_VERSION;
    Reg.OperationRegistrationCount = 2;
    Reg.Altitude                   = Altitude;
    Reg.RegistrationContext        = NULL;
    Reg.OperationRegistration      = Ops;

    NTSTATUS Status = KL_NT(ObRegisterCallbacks)(&Reg, &g_ObHandle);
    if (NT_SUCCESS(Status))
        IntegrityRegister((PVOID)&ProcessThreadPreOp);

    return Status;
}

KG_NO_OBFUSCATE
_Use_decl_annotations_
VOID
UnregisterProtection(
)
{
    if (g_ObHandle) {
        KL_NT(ObUnRegisterCallbacks)(g_ObHandle);
        g_ObHandle = NULL;
    }

    InterlockedExchangePointer((PVOID*)&g_ProtectedOwner, NULL);
}

KG_NO_OBFUSCATE
static
VOID
ProcessCreateNotify(
    _Inout_     PEPROCESS              Process,
    _In_        HANDLE                 ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo == NULL) {
        HANDLE Current = (HANDLE)ReadPointerAcquire(&g_ProtectedOwner);
        if (Current == ProcessId) {
            InterlockedExchangePointer((PVOID*)&g_ProtectedOwner, NULL);
            KG_DRV_LOG("[PhoenixDrv/Protect] owner pid=%lu exited, killing all trusted\n",
                       (ULONG)(ULONG_PTR)ProcessId);
            KillAllTrusted();
        }

        HANDLE Trusted = (HANDLE)ReadPointerAcquire(&g_TrustedCreator);
        if (Trusted == ProcessId) {
            InterlockedExchangePointer((PVOID*)&g_TrustedCreator, NULL);

            KIRQL Irql = g_KH.KeAcquireSpinLockRaiseToDpc(&g_Arm.Lock);
            if (g_Arm.ExpectedCreator == ProcessId) {
                g_Arm.Armed           = 0;
                g_Arm.ExpectedCreator = NULL;
                g_Arm.BasenameLen     = 0;

                RtlZeroMemory(g_Arm.Basename, sizeof(g_Arm.Basename));
                RtlSecureZeroMemory(g_Arm.Token, sizeof(g_Arm.Token));
            }

            g_KH.KeReleaseSpinLock(&g_Arm.Lock, Irql);
        }

        TrustedRemove(ProcessId);
        SystemAllowRemove(ProcessId);
        return;
    }

    if (PathMatchesSystemAllowList(CreateInfo->ImageFileName))
        SystemAllowAdd(ProcessId);

#if KG_BLOCKLIST_ENABLE
    {
        KG_BLOCKED_HIT Hit = { 0 };
        if (BlocklistMatchByPath(CreateInfo->ImageFileName, &Hit)) {
            RecordBlock(CreateInfo->ImageFileName, Hit.Reason);
            CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
            KillAllTrusted();
            return;
        }
    }
#endif

    HANDLE  Parent          = CreateInfo->ParentProcessId;
    HANDLE  Creator         = CreateInfo->CreatingThreadId.UniqueProcess;
    BOOLEAN ImageInFiveM    = ImagePathInFiveMDir(CreateInfo->ImageFileName);
    BOOLEAN ParentTrusted   = (Parent  && TrustedContains(Parent));
    BOOLEAN CreatorTrusted  = (Creator && TrustedContains(Creator));

    if (ImageInFiveM || ParentTrusted || CreatorTrusted) {
        TrustedAdd(ProcessId);
        KG_DRV_LOG("[PhoenixDrv/Protect] TRUST pid=%lu img=%wZ parent=%lu creator=%lu "
                   "(imgDir=%d parentT=%d createT=%d)\n",
                   (ULONG)(ULONG_PTR)ProcessId,
                   CreateInfo->ImageFileName,
                   (ULONG)(ULONG_PTR)Parent,
                   (ULONG)(ULONG_PTR)Creator,
                   ImageInFiveM,
                   ParentTrusted,
                   CreatorTrusted);
    }

    if (!InterlockedCompareExchange(&g_Arm.Armed, 1, 1))
        return;

    KIRQL Irql = g_KH.KeAcquireSpinLockRaiseToDpc(&g_Arm.Lock);
    if (!g_Arm.Armed) {
        g_KH.KeReleaseSpinLock(&g_Arm.Lock, Irql);
        return;
    }

    HANDLE Expected = g_Arm.ExpectedCreator;
    USHORT ArmedLen = g_Arm.BasenameLen;
    WCHAR  ArmedBuf[KG_BASENAME_MAX];
    RtlCopyMemory(ArmedBuf, g_Arm.Basename, ArmedLen);
    g_KH.KeReleaseSpinLock(&g_Arm.Lock, Irql);

    if (!Expected || ArmedLen == 0)
        return;

    if (CreateInfo->CreatingThreadId.UniqueProcess != Expected)
        return;

    PCUNICODE_STRING Image = CreateInfo->ImageFileName;
    if (Image == NULL || Image->Length == 0 || Image->Buffer == NULL)
        return;

    USHORT Chars = Image->Length / sizeof(WCHAR);
    LONG   Split = -1;
    for (LONG i = (LONG)Chars - 1; i >= 0; --i) {
        if (Image->Buffer[i] == L'\\' || Image->Buffer[i] == L'/') {
            Split = i;
            break;
        }
    }

    UNICODE_STRING Actual;
    Actual.Buffer        = Image->Buffer + (Split + 1);
    Actual.Length        = (USHORT)((Chars - (Split + 1)) * sizeof(WCHAR));
    Actual.MaximumLength = Actual.Length;

    UNICODE_STRING Armed;
    Armed.Buffer        = ArmedBuf;
    Armed.Length        = ArmedLen;
    Armed.MaximumLength = ArmedLen;

    if (!KL_NT(RtlEqualUnicodeString)(&Actual, &Armed, TRUE))
        return;

    InterlockedExchangePointer((PVOID*)&g_ProtectedOwner, ProcessId);

    Irql = g_KH.KeAcquireSpinLockRaiseToDpc(&g_Arm.Lock);

    g_Arm.Armed           = 0;
    g_Arm.ExpectedCreator = NULL;
    g_Arm.BasenameLen     = 0;

    RtlZeroMemory(g_Arm.Basename, sizeof(g_Arm.Basename));

    g_KH.KeReleaseSpinLock(&g_Arm.Lock, Irql);
}

static BOOLEAN g_ImageNotifyInstalled = FALSE;

static
VOID
TerminateProcessById(
    _In_ HANDLE   Pid,
    _In_ NTSTATUS ExitStatus
);

static KSPIN_LOCK   g_LastBlockLock;
static KG_LAST_BLOCK g_LastBlock = { 0 };

static
VOID
RecordBlock(
    _In_ PCUNICODE_STRING Path,
    _In_ const WCHAR*     Reason
)
{
    if (Path == NULL || Path->Length == 0 || Path->Buffer == NULL)
        return;

    KIRQL Irql = g_KH.KeAcquireSpinLockRaiseToDpc(&g_LastBlockLock);

    USHORT Bytes = Path->Length;
    if (Bytes > (KG_BLOCK_PATH_MAX - 1) * sizeof(WCHAR))
        Bytes = (KG_BLOCK_PATH_MAX - 1) * sizeof(WCHAR);

    RtlZeroMemory(g_LastBlock.Path, sizeof(g_LastBlock.Path));
    RtlCopyMemory(g_LastBlock.Path, Path->Buffer, Bytes);
    g_LastBlock.PathLen = Bytes;

    RtlZeroMemory(g_LastBlock.Reason, sizeof(g_LastBlock.Reason));
    USHORT ReasonBytes = 0;
    if (Reason) {
        while (Reason[ReasonBytes / sizeof(WCHAR)] &&
               ReasonBytes < sizeof(g_LastBlock.Reason) - sizeof(WCHAR)) {
            ReasonBytes += sizeof(WCHAR);
        }

        if (ReasonBytes)
            RtlCopyMemory(g_LastBlock.Reason, Reason, ReasonBytes);
    }

    g_LastBlock.ReasonLen = ReasonBytes;
    g_LastBlock.Sequence++;

    g_KH.KeReleaseSpinLock(&g_LastBlockLock, Irql);
}

extern "C"
VOID
BlocklistRecordFromKernel(
    _In_ PCUNICODE_STRING Path,
    _In_ const WCHAR*     Reason
)
{
    RecordBlock(Path, Reason);
}

extern "C"
VOID
BlocklistKillProtectedFromKernel(
    VOID
)
{
    KillAllTrusted();
}

_Use_decl_annotations_
VOID
GetLastBlock(
    KG_LAST_BLOCK* Out
)
{
    if (Out == NULL)
        return;

    KIRQL Irql = g_KH.KeAcquireSpinLockRaiseToDpc(&g_LastBlockLock);
    RtlCopyMemory(Out, &g_LastBlock, sizeof(*Out));
    g_KH.KeReleaseSpinLock(&g_LastBlockLock, Irql);
}

_Use_decl_annotations_
VOID
KillAllTrusted(
)
{
    HANDLE Pids[KG_TRUSTED_MAX];
    KIRQL  Irql = g_KH.KeAcquireSpinLockRaiseToDpc(&g_Trusted.Lock);
    RtlCopyMemory(Pids, g_Trusted.Pids, sizeof(Pids));
    g_KH.KeReleaseSpinLock(&g_Trusted.Lock, Irql);

    for (ULONG i = 0; i < KG_TRUSTED_MAX; ++i) {
        if (Pids[i])
            TerminateProcessById(Pids[i], STATUS_ACCESS_DENIED);
    }
}

_Use_decl_annotations_
VOID
KillAllProtected(
)
{
    HANDLE Owner = (HANDLE)ReadPointerAcquire(&g_ProtectedOwner);
    if (Owner)
        TerminateProcessById(Owner, STATUS_ACCESS_DENIED);

    KillAllTrusted();
}

_Use_decl_annotations_
VOID
KillAllProtectedExceptCaller(
)
{
    HANDLE Caller = KL_NT(PsGetCurrentProcessId)();

    HANDLE Owner = (HANDLE)ReadPointerAcquire(&g_ProtectedOwner);
    if (Owner && Owner != Caller)
        TerminateProcessById(Owner, STATUS_ACCESS_DENIED);

    HANDLE Pids[KG_TRUSTED_MAX];
    KIRQL  Irql = g_KH.KeAcquireSpinLockRaiseToDpc(&g_Trusted.Lock);
    RtlCopyMemory(Pids, g_Trusted.Pids, sizeof(Pids));
    g_KH.KeReleaseSpinLock(&g_Trusted.Lock, Irql);

    for (ULONG i = 0; i < KG_TRUSTED_MAX; ++i) {
        if (Pids[i] && Pids[i] != Caller)
            TerminateProcessById(Pids[i], STATUS_ACCESS_DENIED);
    }
}

_Use_decl_annotations_
UINT32
TrustedSnapshot(
    HANDLE* Pids,
    UINT32  MaxPids
)
{
    if (Pids == NULL || MaxPids == 0)
        return 0;

    UINT32 Count = 0;
    KIRQL  Irql  = g_KH.KeAcquireSpinLockRaiseToDpc(&g_Trusted.Lock);
    for (ULONG i = 0; i < KG_TRUSTED_MAX && Count < MaxPids; ++i) {
        if (g_Trusted.Pids[i])
            Pids[Count++] = g_Trusted.Pids[i];
    }
    g_KH.KeReleaseSpinLock(&g_Trusted.Lock, Irql);
    return Count;
}

_Use_decl_annotations_
UINT32
TrustedCount(
)
{
    UINT32 Count = 0;
    KIRQL  Irql  = g_KH.KeAcquireSpinLockRaiseToDpc(&g_Trusted.Lock);
    for (ULONG i = 0; i < KG_TRUSTED_MAX; ++i) {
        if (g_Trusted.Pids[i])
            Count++;
    }

    g_KH.KeReleaseSpinLock(&g_Trusted.Lock, Irql);
    return Count;
}

static
BOOLEAN
PathContainsForbiddenPluginDir(
    _In_ PCUNICODE_STRING Img
)
{
    if (Img == NULL || Img->Length == 0 || Img->Buffer == NULL)
        return FALSE;

    UNICODE_STRING Needle;
    KlazyMakeUS(&Needle, PX_W(L"\\FiveM\\FiveM.app\\plugins\\"));

    if (Img->Length < Needle.Length)
        return FALSE;

    USHORT Chars       = Img->Length / sizeof(WCHAR);
    USHORT NeedleChars = Needle.Length / sizeof(WCHAR);

    for (USHORT i = 0; i + NeedleChars <= Chars; ++i) {
        UNICODE_STRING Sub;
        Sub.Buffer        = Img->Buffer + i;
        Sub.Length        = Needle.Length;
        Sub.MaximumLength = Needle.Length;

        if (KL_NT(RtlEqualUnicodeString)(&Sub, &Needle, TRUE))
            return TRUE;
    }

    return FALSE;
}

static
BOOLEAN
ImageBasenameEquals(
    _In_ PCUNICODE_STRING Img,
    _In_ PCWSTR           Target
)
{
    if (Img == NULL || Img->Length == 0 || Img->Buffer == NULL || Target == NULL)
        return FALSE;

    USHORT Chars = Img->Length / sizeof(WCHAR);
    LONG   Split = -1;
    for (LONG i = (LONG)Chars - 1; i >= 0; --i) {
        if (Img->Buffer[i] == L'\\' || Img->Buffer[i] == L'/') {
            Split = i;
            break;
        }
    }

    UNICODE_STRING BaseName;
    BaseName.Buffer        = Img->Buffer + (Split + 1);
    BaseName.Length        = (USHORT)((Chars - (Split + 1)) * sizeof(WCHAR));
    BaseName.MaximumLength = BaseName.Length;

    UNICODE_STRING Want;
    KlazyMakeUS(&Want, Target);
    return KL_NT(RtlEqualUnicodeString)(&BaseName, &Want, TRUE);
}

static
BOOLEAN
ProcessImagePathEndsWith(
    _In_ HANDLE Pid,
    _In_ PCWSTR Suffix
)
{
    if (!Pid || !Suffix)
        return FALSE;

    PEPROCESS Process = NULL;
    if (!NT_SUCCESS(KL_NT(PsLookupProcessByProcessId)(Pid, &Process)) || !Process)
        return FALSE;

    PUNICODE_STRING ImageName = NULL;
    NTSTATUS        Status    = KL_NT(SeLocateProcessImageName)(Process, &ImageName);
    KL_NT(ObfDereferenceObject)(Process);
    if (!NT_SUCCESS(Status) || !ImageName)
        return FALSE;

    UNICODE_STRING Want;
    KlazyMakeUS(&Want, Suffix);

    BOOLEAN Result = FALSE;
    if (ImageName->Length >= Want.Length) {
        UNICODE_STRING Tail;
        Tail.Buffer        = (PWCH)((PUCHAR)ImageName->Buffer + ImageName->Length - Want.Length);
        Tail.Length        = Want.Length;
        Tail.MaximumLength = Tail.Length;
        Result = KL_NT(RtlEqualUnicodeString)(&Tail, &Want, TRUE);
    }

    g_KH.ExFreePoolWithTag(ImageName, 0);
    return Result;
}

static
VOID
TerminateProcessById(
    _In_ HANDLE   Pid,
    _In_ NTSTATUS ExitStatus
)
{
    HANDLE            ProcessHandle = NULL;
    CLIENT_ID         ClientId      = { Pid, NULL };
    OBJECT_ATTRIBUTES Attributes;
    InitializeObjectAttributes(&Attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    NTSTATUS Status = KL_NT(ZwOpenProcess)(&ProcessHandle,
                                           PROCESS_TERMINATE,
                                           &Attributes,
                                           &ClientId);
    if (NT_SUCCESS(Status)) {
        KL_NT(ZwTerminateProcess)(ProcessHandle, ExitStatus);
        KL_NT(ZwClose)(ProcessHandle);
    }
}

KG_NO_OBFUSCATE
static
VOID
ImageLoadNotify(
    _In_ PUNICODE_STRING FullImageName,
    _In_ HANDLE          ProcessId,
    _In_ PIMAGE_INFO     ImageInfo
)
{
    UNREFERENCED_PARAMETER(ImageInfo);

    if (!FullImageName || !ProcessId)
        return;

    if (!TrustedContains(ProcessId))
        return;

    BOOLEAN PluginDir = PathContainsForbiddenPluginDir(FullImageName);
    UNREFERENCED_PARAMETER(PluginDir);

    //if (PluginDir) {
    //    KG_DRV_LOG("[PhoenixDrv/Protect] LOAD BLOCKED pid=%lu img=%wZ reason=plugin-dir - terminating\n",
    //               (ULONG)(ULONG_PTR)ProcessId, FullImageName);
    //    RecordBlock(FullImageName, PX_W(L"forbidden plugin"));
    //    TerminateProcessById(ProcessId, STATUS_ACCESS_DENIED);
    //    return;
    //}
}

KG_NO_OBFUSCATE
_Use_decl_annotations_
NTSTATUS
ProcessNotifyInstall(
)
{
    g_Arm.Lock         = 0;
    g_Trusted.Lock     = 0;
    g_SystemAllow.Lock = 0;
    g_LastBlockLock    = 0;
    RtlZeroMemory(g_Trusted.Pids, sizeof(g_Trusted.Pids));
    RtlZeroMemory(g_SystemAllow.Pids, sizeof(g_SystemAllow.Pids));
    SeedSystemAllowFromRunning();

    NTSTATUS Status = KL_NT(PsSetCreateProcessNotifyRoutineEx)(ProcessCreateNotify, FALSE);
    if (NT_SUCCESS(Status)) {
        g_ProcNotifyInstalled = TRUE;
        IntegrityRegister((PVOID)&ProcessCreateNotify);
    }

    NTSTATUS ImageStatus = KL_NT(PsSetLoadImageNotifyRoutine)(ImageLoadNotify);
    if (NT_SUCCESS(ImageStatus)) {
        g_ImageNotifyInstalled = TRUE;
        IntegrityRegister((PVOID)&ImageLoadNotify);
    }

#if KG_BLOCKLIST_ENABLE
    BlocklistSweepRunning();
#endif

    return Status;
}

KG_NO_OBFUSCATE
_Use_decl_annotations_
VOID
ProcessNotifyRemove(
)
{
    if (g_ImageNotifyInstalled) {
        KL_NT(PsRemoveLoadImageNotifyRoutine)(ImageLoadNotify);
        g_ImageNotifyInstalled = FALSE;
    }

    if (g_ProcNotifyInstalled) {
        KL_NT(PsSetCreateProcessNotifyRoutineEx)(ProcessCreateNotify, TRUE);
        g_ProcNotifyInstalled = FALSE;
    }
}

_Use_decl_annotations_
NTSTATUS
ArmRelaunch(
    HANDLE       Creator,
    const WCHAR* Basename,
    USHORT       BasenameLenBytes,
    const UINT8* Token
)
{
    if (!Creator || !Basename || !Token)
        return STATUS_INVALID_PARAMETER;

    if (BasenameLenBytes == 0 || BasenameLenBytes > sizeof(g_Arm.Basename))
        return STATUS_INVALID_PARAMETER;

    if ((BasenameLenBytes % sizeof(WCHAR)) != 0)
        return STATUS_INVALID_PARAMETER;

    KIRQL Irql = g_KH.KeAcquireSpinLockRaiseToDpc(&g_Arm.Lock);

    g_Arm.ExpectedCreator = Creator;
    g_Arm.BasenameLen     = BasenameLenBytes;
    g_Arm.Attested        = 0;

    RtlZeroMemory(g_Arm.Basename, sizeof(g_Arm.Basename));
    RtlCopyMemory(g_Arm.Basename, Basename, BasenameLenBytes);
    RtlCopyMemory(g_Arm.Token, Token, KG_TOKEN_LEN);

    InterlockedExchange(&g_Arm.Armed, 1);

    g_KH.KeReleaseSpinLock(&g_Arm.Lock, Irql);

    InterlockedExchangePointer((PVOID*)&g_TrustedCreator, Creator);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
DisableProtection(
)
{
    if (g_ObHandle) {
        KL_NT(ObUnRegisterCallbacks)(g_ObHandle);
        g_ObHandle = NULL;
    }

    if (g_ImageNotifyInstalled) {
        KL_NT(PsRemoveLoadImageNotifyRoutine)(ImageLoadNotify);
        g_ImageNotifyInstalled = FALSE;
    }

    InterlockedExchangePointer((PVOID*)&g_ProtectedOwner, NULL);
    InterlockedExchangePointer((PVOID*)&g_TrustedCreator, NULL);

    KIRQL Irql = g_KH.KeAcquireSpinLockRaiseToDpc(&g_Trusted.Lock);
    RtlZeroMemory(g_Trusted.Pids, sizeof(g_Trusted.Pids));
    g_KH.KeReleaseSpinLock(&g_Trusted.Lock, Irql);

    Irql = g_KH.KeAcquireSpinLockRaiseToDpc(&g_SystemAllow.Lock);
    RtlZeroMemory(g_SystemAllow.Pids, sizeof(g_SystemAllow.Pids));
    g_KH.KeReleaseSpinLock(&g_SystemAllow.Lock, Irql);
}

_Use_decl_annotations_
HANDLE
ProtectedOwnerId(
)
{
    return (HANDLE)ReadPointerAcquire(&g_ProtectedOwner);
}

_Use_decl_annotations_
NTSTATUS
AttestOwner(
    HANDLE       Caller,
    const UINT8* Token
)
{
    if (!Caller || !Token)
        return STATUS_INVALID_PARAMETER;

    HANDLE Owner = (HANDLE)ReadPointerAcquire(&g_ProtectedOwner);
    if (Owner == NULL || Owner != Caller)
        return STATUS_ACCESS_DENIED;

    KIRQL Irql = g_KH.KeAcquireSpinLockRaiseToDpc(&g_Arm.Lock);

    UINT8 Diff = 0;
    for (ULONG i = 0; i < KG_TOKEN_LEN; ++i)
        Diff |= (UINT8)(g_Arm.Token[i] ^ Token[i]);

    NTSTATUS Status = STATUS_ACCESS_DENIED;
    if (Diff == 0) {
        RtlSecureZeroMemory(g_Arm.Token, sizeof(g_Arm.Token));
        InterlockedExchange(&g_Arm.Attested, 1);
        Status = STATUS_SUCCESS;
    }

    g_KH.KeReleaseSpinLock(&g_Arm.Lock, Irql);
    return Status;
}
