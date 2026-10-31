#include "irpscan.hpp"

#include "shared.hpp"
#include "klazy.hpp"

#define KG_IRP_INTERVAL_MS   30000
#define KG_IRP_RING_SIZE     16
#define KG_IRP_SEEN_MAX      64
#define KG_IRP_MOD_MAX       512
#define KG_IRP_DRV_MAX       256

#define KG_IRP_TRACE 0
#if KG_IRP_TRACE
#define ITRACE(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[PhoenixDrv/Irp] " fmt, ##__VA_ARGS__)
#else
#define ITRACE(fmt, ...) ((void)0)
#endif

#define SystemModuleInformation  11

extern "C" {
NTKERNELAPI POBJECT_TYPE* IoDriverObjectType;

NTSTATUS
NTAPI
ObReferenceObjectByName(
    PUNICODE_STRING ObjectName,
    ULONG           Attributes,
    PACCESS_STATE   PassedAccessState OPTIONAL,
    ACCESS_MASK     DesiredAccess OPTIONAL,
    POBJECT_TYPE    ObjectType,
    KPROCESSOR_MODE AccessMode,
    PVOID           ParseContext OPTIONAL,
    PVOID*          Object
);

NTSTATUS
NTAPI
ObQueryNameString(
    PVOID                    Object,
    POBJECT_NAME_INFORMATION ObjectNameInfo,
    ULONG                    Length,
    PULONG                   ReturnLength
);

NTSTATUS
NTAPI
ZwOpenDirectoryObject(
    PHANDLE            DirectoryHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

NTSTATUS
NTAPI
ZwQueryDirectoryObject(
    HANDLE  DirectoryHandle,
    PVOID   Buffer,
    ULONG   Length,
    BOOLEAN ReturnSingleEntry,
    BOOLEAN RestartScan,
    PULONG  Context,
    PULONG  ReturnLength
);

NTSTATUS
NTAPI
ZwOpenSymbolicLinkObject(
    PHANDLE            SymbolicLinkHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

NTSTATUS
NTAPI
ZwQuerySymbolicLinkObject(
    HANDLE          SymbolicLinkHandle,
    PUNICODE_STRING LinkTarget,
    PULONG          ReturnedLength
);
}

typedef struct _KG_OBJDIR_INFO {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} KG_OBJDIR_INFO;

typedef struct _KG_IRP_MOD {
    ULONG_PTR Base;
    ULONG_PTR End;
    CHAR      Name[KG_MMAP_MOD_NAME_MAX];
} KG_IRP_MOD;

typedef struct _RTL_PROCESS_MODULE_INFO_LOCAL {
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
} RTL_PROCESS_MODULE_INFO_LOCAL;

typedef struct _RTL_PROCESS_MODULES_LOCAL {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFO_LOCAL Modules[1];
} RTL_PROCESS_MODULES_LOCAL;

static KSPIN_LOCK      g_IrpLock;
static KG_IRP_EVENT    g_IrpRing[KG_IRP_RING_SIZE];
static ULONG           g_IrpHead = 0;
static ULONG           g_IrpTail = 0;

static ULONG_PTR       g_IrpSeen[KG_IRP_SEEN_MAX] = { 0 };
static ULONG           g_IrpSeenIdx = 0;

static KEVENT          g_IrpStopEvent;
static PETHREAD        g_IrpThread = NULL;
static BOOLEAN         g_IrpStarted = FALSE;

static
UINT64
IrpNowMs(
    VOID
)
{
    LARGE_INTEGER now = { 0 };
    KL_NT(KeQuerySystemTimePrecise)(&now);
    return (UINT64)(now.QuadPart / 10000LL);
}

KG_NO_OBFUSCATE
static
VOID
IrpPushEvent(
    _In_ const KG_IRP_EVENT* Ev
)
{
    KIRQL OldIrql;
    OldIrql = g_KH.KeAcquireSpinLockRaiseToDpc(&g_IrpLock);

    g_IrpRing[g_IrpHead] = *Ev;
    g_IrpHead = (g_IrpHead + 1) % KG_IRP_RING_SIZE;
    if (g_IrpHead == g_IrpTail)
        g_IrpTail = (g_IrpTail + 1) % KG_IRP_RING_SIZE;

    g_KH.KeReleaseSpinLock(&g_IrpLock, OldIrql);
}

_Use_decl_annotations_
KG_NO_OBFUSCATE
NTSTATUS
IrpScanPop(
    PVOID  OutBuf,
    ULONG  OutCap,
    PULONG BytesReturned
)
{
    *BytesReturned = 0;

    if (OutCap < sizeof(KG_IRP_EVENT))
        return STATUS_BUFFER_TOO_SMALL;

    KIRQL OldIrql;
    OldIrql = g_KH.KeAcquireSpinLockRaiseToDpc(&g_IrpLock);

    if (g_IrpHead == g_IrpTail) {
        g_KH.KeReleaseSpinLock(&g_IrpLock, OldIrql);
        return STATUS_NO_MORE_ENTRIES;
    }

    RtlCopyMemory(OutBuf, &g_IrpRing[g_IrpTail], sizeof(KG_IRP_EVENT));
    g_IrpTail = (g_IrpTail + 1) % KG_IRP_RING_SIZE;

    g_KH.KeReleaseSpinLock(&g_IrpLock, OldIrql);

    *BytesReturned = sizeof(KG_IRP_EVENT);
    return STATUS_SUCCESS;
}

static
BOOLEAN
IrpAlreadySeen(
    _In_ ULONG_PTR Addr
)
{
    for (ULONG i = 0; i < KG_IRP_SEEN_MAX; ++i) {
        if (g_IrpSeen[i] == Addr) return TRUE;
    }
    g_IrpSeen[g_IrpSeenIdx] = Addr;
    g_IrpSeenIdx = (g_IrpSeenIdx + 1) % KG_IRP_SEEN_MAX;
    return FALSE;
}

static
BOOLEAN
IrpAddrIsKernel(
    _In_ ULONG_PTR Addr
)
{
    return Addr >= (ULONG_PTR)0xFFFF800000000000ULL;
}

static
BOOLEAN
IrpAddrInAnyModule(
    _In_ const KG_IRP_MOD* Mods,
    _In_ ULONG             Count,
    _In_ ULONG_PTR         Addr,
    _Out_ const KG_IRP_MOD** OutNearest,
    _Out_ ULONG_PTR*        OutOffset
)
{
    *OutNearest = NULL;
    *OutOffset  = 0;
    ULONG_PTR bestDelta = ~(ULONG_PTR)0;
    const KG_IRP_MOD* bestMod = NULL;

    for (ULONG i = 0; i < Count; ++i) {
        if (Addr >= Mods[i].Base && Addr < Mods[i].End) {
            *OutNearest = &Mods[i];
            *OutOffset  = Addr - Mods[i].Base;
            return TRUE;
        }
        ULONG_PTR delta = (Addr >= Mods[i].End)
            ? Addr - Mods[i].End
            : Mods[i].Base - Addr;
        if (delta < bestDelta) {
            bestDelta = delta;
            bestMod   = &Mods[i];
        }
    }
    if (bestMod) {
        *OutNearest = bestMod;
        *OutOffset  = (Addr >= bestMod->Base) ? Addr - bestMod->Base : 0;
    }
    return FALSE;
}

static
ULONG
IrpCopyDump(
    _In_ ULONG_PTR StartAddr,
    _Out_writes_bytes_(KG_MMAP_DUMP_BYTES) UINT8* Dump
)
{
    RtlZeroMemory(Dump, KG_MMAP_DUMP_BYTES);
    if (!IrpAddrIsKernel(StartAddr)) return 0;

    ULONG copied = 0;
    __try {
        SIZE_T remaining = KG_MMAP_DUMP_BYTES;
        const UINT8* src = (const UINT8*)StartAddr;
        while (remaining > 0) {
            if (!MmIsAddressValid((PVOID)&src[copied])) break;
            Dump[copied] = src[copied];
            copied++;
            remaining--;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return copied;
    }
    return copied;
}

static
NTSTATUS
IrpEnumerateModules(
    _Out_ KG_IRP_MOD** OutMods,
    _Out_ ULONG*       OutCount
)
{
    *OutMods  = NULL;
    *OutCount = 0;

    ULONG needed = 0;
    KL_NT(ZwQuerySystemInformation)(SystemModuleInformation, NULL, 0, &needed);
    if (needed == 0) return STATUS_UNSUCCESSFUL;

    ULONG allocLen = needed + 0x2000;
    PVOID rawBuf = KL_NT(ExAllocatePool2)(POOL_FLAG_NON_PAGED, allocLen, 'iMkP');
    if (!rawBuf) return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS st = KL_NT(ZwQuerySystemInformation)(SystemModuleInformation, rawBuf, allocLen, &needed);
    if (!NT_SUCCESS(st)) {
        g_KH.ExFreePoolWithTag(rawBuf, 'iMkP');
        return st;
    }

    RTL_PROCESS_MODULES_LOCAL* mods = (RTL_PROCESS_MODULES_LOCAL*)rawBuf;
    ULONG count = mods->NumberOfModules;
    if (count > KG_IRP_MOD_MAX) count = KG_IRP_MOD_MAX;

    KG_IRP_MOD* out = (KG_IRP_MOD*)KL_NT(ExAllocatePool2)(
        POOL_FLAG_NON_PAGED, count * sizeof(KG_IRP_MOD), 'iMkP');
    if (!out) {
        g_KH.ExFreePoolWithTag(rawBuf, 'iMkP');
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (ULONG i = 0; i < count; ++i) {
        out[i].Base = (ULONG_PTR)mods->Modules[i].ImageBase;
        out[i].End  = out[i].Base + mods->Modules[i].ImageSize;

        USHORT nameOff = mods->Modules[i].OffsetToFileName;
        if (nameOff >= sizeof(mods->Modules[i].FullPathName)) nameOff = 0;
        const CHAR* nm = (const CHAR*)&mods->Modules[i].FullPathName[nameOff];

        SIZE_T ni = 0;
        while (ni + 1 < KG_MMAP_MOD_NAME_MAX && nm[ni]) {
            out[i].Name[ni] = nm[ni];
            ni++;
        }
        out[i].Name[ni] = 0;
    }

    g_KH.ExFreePoolWithTag(rawBuf, 'iMkP');
    *OutMods  = out;
    *OutCount = count;
    return STATUS_SUCCESS;
}

static
VOID
IrpCopyWideName(
    _Out_writes_(Cap) WCHAR* Dst,
    _In_ ULONG              Cap,
    _In_ PCUNICODE_STRING   Src
)
{
    if (Cap == 0) return;
    Dst[0] = 0;
    if (!Src || !Src->Buffer || Src->Length == 0) return;

    ULONG chars = Src->Length / sizeof(WCHAR);
    if (chars >= Cap) chars = Cap - 1;
    for (ULONG i = 0; i < chars; ++i) Dst[i] = Src->Buffer[i];
    Dst[chars] = 0;
}

static
VOID
IrpQueryObjectName(
    _In_ PVOID              Obj,
    _Out_writes_(Cap) WCHAR* Dst,
    _In_ ULONG              Cap
)
{
    if (Cap > 0) Dst[0] = 0;
    if (!Obj) return;

    UCHAR stackBuf[512];
    ULONG needed = 0;
    NTSTATUS st = ObQueryNameString(Obj, (POBJECT_NAME_INFORMATION)stackBuf,
                                    sizeof(stackBuf), &needed);
    if (NT_SUCCESS(st)) {
        POBJECT_NAME_INFORMATION ni = (POBJECT_NAME_INFORMATION)stackBuf;
        IrpCopyWideName(Dst, Cap, &ni->Name);
        return;
    }
    if (st != STATUS_INFO_LENGTH_MISMATCH || needed == 0 || needed > 4096) return;

    PVOID heapBuf = KL_NT(ExAllocatePool2)(POOL_FLAG_NON_PAGED, needed, 'iNkP');
    if (!heapBuf) return;
    st = ObQueryNameString(Obj, (POBJECT_NAME_INFORMATION)heapBuf, needed, &needed);
    if (NT_SUCCESS(st)) {
        POBJECT_NAME_INFORMATION ni = (POBJECT_NAME_INFORMATION)heapBuf;
        IrpCopyWideName(Dst, Cap, &ni->Name);
    }
    g_KH.ExFreePoolWithTag(heapBuf, 'iNkP');
}

static
BOOLEAN
IrpFindSymlinkForTarget(
    _In_ PCWSTR             DeviceTarget,
    _Out_writes_(Cap) WCHAR* Dst,
    _In_ ULONG              Cap
)
{
    if (Cap > 0) Dst[0] = 0;
    if (!DeviceTarget || DeviceTarget[0] == 0) return FALSE;

    UNICODE_STRING dirName;
    RtlInitUnicodeString(&dirName, L"\\GLOBAL??");

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &dirName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE dir = NULL;
    NTSTATUS st = ZwOpenDirectoryObject(&dir, DIRECTORY_QUERY | DIRECTORY_TRAVERSE, &oa);
    if (!NT_SUCCESS(st)) return FALSE;

    ULONG bufSize = 8192;
    PVOID buf = KL_NT(ExAllocatePool2)(POOL_FLAG_NON_PAGED, bufSize, 'iSkP');
    if (!buf) {
        KL_NT(ZwClose)(dir);
        return FALSE;
    }

    UNICODE_STRING wantedTarget;
    RtlInitUnicodeString(&wantedTarget, DeviceTarget);

    BOOLEAN found = FALSE;
    ULONG   ctx = 0;
    BOOLEAN restart = TRUE;

    for (ULONG guard = 0; guard < 8 && !found; ++guard) {
        ULONG got = 0;
        st = ZwQueryDirectoryObject(dir, buf, bufSize, FALSE, restart, &ctx, &got);
        restart = FALSE;
        if (!NT_SUCCESS(st) || got == 0) break;

        KG_OBJDIR_INFO* info = (KG_OBJDIR_INFO*)buf;
        for (; info->Name.Buffer != NULL; ++info) {
            if (info->TypeName.Buffer == NULL ||
                info->TypeName.Length != wcslen(L"SymbolicLink") * sizeof(WCHAR))
                continue;
            if (_wcsnicmp(info->TypeName.Buffer, L"SymbolicLink",
                          info->TypeName.Length / sizeof(WCHAR)) != 0)
                continue;

            WCHAR fullPath[192];
            ULONG dirLen = dirName.Length / sizeof(WCHAR);
            ULONG nameLen = info->Name.Length / sizeof(WCHAR);
            if (dirLen + 1 + nameLen + 1 > ARRAYSIZE(fullPath)) continue;

            for (ULONG i = 0; i < dirLen; ++i) fullPath[i] = dirName.Buffer[i];
            fullPath[dirLen] = L'\\';
            for (ULONG i = 0; i < nameLen; ++i) fullPath[dirLen + 1 + i] = info->Name.Buffer[i];
            fullPath[dirLen + 1 + nameLen] = 0;

            UNICODE_STRING linkName;
            RtlInitUnicodeString(&linkName, fullPath);

            OBJECT_ATTRIBUTES loa;
            InitializeObjectAttributes(&loa, &linkName,
                                       OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                       NULL, NULL);
            HANDLE lh = NULL;
            NTSTATUS ls = ZwOpenSymbolicLinkObject(&lh, GENERIC_READ, &loa);
            if (!NT_SUCCESS(ls)) continue;

            WCHAR   targetBuf[256];
            UNICODE_STRING target;
            target.Buffer        = targetBuf;
            target.MaximumLength = sizeof(targetBuf);
            target.Length        = 0;

            ULONG needed = 0;
            NTSTATUS qs = ZwQuerySymbolicLinkObject(lh, &target, &needed);
            KL_NT(ZwClose)(lh);
            if (!NT_SUCCESS(qs)) continue;

            if (target.Length == wantedTarget.Length &&
                _wcsnicmp(target.Buffer, wantedTarget.Buffer,
                          target.Length / sizeof(WCHAR)) == 0) {
                IrpCopyWideName(Dst, Cap, &info->Name);
                found = TRUE;
                break;
            }
        }
    }

    g_KH.ExFreePoolWithTag(buf, 'iSkP');
    KL_NT(ZwClose)(dir);
    return found;
}

static
VOID
IrpInspectDriver(
    _In_ PCUNICODE_STRING    DriverDirName,
    _In_ const KG_IRP_MOD*   Mods,
    _In_ ULONG               ModCount,
    _Inout_ ULONG*           OutReported
)
{
    WCHAR fullPathBuf[192];
    ULONG dirLen  = DriverDirName->Length / sizeof(WCHAR);
    UNICODE_STRING driverDirRoot;
    RtlInitUnicodeString(&driverDirRoot, L"\\Driver");
    ULONG rootLen = driverDirRoot.Length / sizeof(WCHAR);
    if (rootLen + 1 + dirLen + 1 > ARRAYSIZE(fullPathBuf)) return;

    for (ULONG i = 0; i < rootLen; ++i) fullPathBuf[i] = driverDirRoot.Buffer[i];
    fullPathBuf[rootLen] = L'\\';
    for (ULONG i = 0; i < dirLen; ++i) fullPathBuf[rootLen + 1 + i] = DriverDirName->Buffer[i];
    fullPathBuf[rootLen + 1 + dirLen] = 0;

    UNICODE_STRING drvPath;
    RtlInitUnicodeString(&drvPath, fullPathBuf);

    PDRIVER_OBJECT drvObj = NULL;
    NTSTATUS st = ObReferenceObjectByName(&drvPath, OBJ_CASE_INSENSITIVE, NULL, 0,
                                          *IoDriverObjectType, KernelMode, NULL,
                                          (PVOID*)&drvObj);
    if (!NT_SUCCESS(st) || !drvObj) return;

    for (ULONG mj = 0; mj <= IRP_MJ_MAXIMUM_FUNCTION; ++mj) {
        ULONG_PTR handler = (ULONG_PTR)drvObj->MajorFunction[mj];
        if (handler == 0) continue;
        if (!IrpAddrIsKernel(handler)) continue;

        const KG_IRP_MOD* nearest = NULL;
        ULONG_PTR offset = 0;
        if (IrpAddrInAnyModule(Mods, ModCount, handler, &nearest, &offset))
            continue;

        if (IrpAlreadySeen(handler)) continue;

        ITRACE("driver=%wZ MJ=%u handler=0x%p OUTSIDE modules nearest=%s +0x%p\n",
               &drvPath, mj, (PVOID)handler,
               nearest ? nearest->Name : "<none>", (PVOID)offset);

        KG_IRP_EVENT ev = { 0 };
        ev.TimestampMs      = IrpNowMs();
        ev.OffendingAddress = (UINT64)handler;
        ev.MajorFunction    = (UINT32)mj;
        ev.DumpLen          = IrpCopyDump(handler, ev.Dump);
        if (nearest) {
            ev.NearestModuleOffset = (UINT16)(offset > 0xFFFF ? 0xFFFF : offset);
            SIZE_T ni = 0;
            while (ni + 1 < KG_MMAP_MOD_NAME_MAX && nearest->Name[ni]) {
                ev.NearestModule[ni] = nearest->Name[ni];
                ni++;
            }
            ev.NearestModule[ni] = 0;
        }

        IrpCopyWideName(ev.DriverName, KG_IRP_NAME_MAX, DriverDirName);

        PDEVICE_OBJECT dev = drvObj->DeviceObject;
        if (dev) {
            IrpQueryObjectName(dev, ev.DeviceName, KG_IRP_NAME_MAX);
            if (ev.DeviceName[0])
                (VOID)IrpFindSymlinkForTarget(ev.DeviceName,
                                              ev.SymlinkName, KG_IRP_NAME_MAX);
        }

        IrpPushEvent(&ev);
        (*OutReported)++;
    }

    KL_NT(ObfDereferenceObject)(drvObj);
}

static
NTSTATUS
IrpScanOnce(
    VOID
)
{
    KG_IRP_MOD* mods = NULL;
    ULONG modCount = 0;
    NTSTATUS st = IrpEnumerateModules(&mods, &modCount);
    if (!NT_SUCCESS(st) || !mods) return st;

    UNICODE_STRING driverDir;
    RtlInitUnicodeString(&driverDir, L"\\Driver");

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &driverDir,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE dir = NULL;
    st = ZwOpenDirectoryObject(&dir, DIRECTORY_QUERY | DIRECTORY_TRAVERSE, &oa);
    if (!NT_SUCCESS(st)) {
        g_KH.ExFreePoolWithTag(mods, 'iMkP');
        ITRACE("ZwOpenDirectoryObject(\\Driver) failed 0x%08X\n", st);
        return st;
    }

    ULONG bufSize = 16384;
    PVOID buf = KL_NT(ExAllocatePool2)(POOL_FLAG_NON_PAGED, bufSize, 'iDkP');
    if (!buf) {
        KL_NT(ZwClose)(dir);
        g_KH.ExFreePoolWithTag(mods, 'iMkP');
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ULONG   scanned = 0, reported = 0;
    ULONG   ctx = 0;
    BOOLEAN restart = TRUE;

    for (ULONG guard = 0; guard < 16; ++guard) {
        ULONG got = 0;
        st = ZwQueryDirectoryObject(dir, buf, bufSize, FALSE, restart, &ctx, &got);
        restart = FALSE;
        if (!NT_SUCCESS(st) || got == 0) break;

        KG_OBJDIR_INFO* info = (KG_OBJDIR_INFO*)buf;
        for (; info->Name.Buffer != NULL && scanned < KG_IRP_DRV_MAX; ++info) {
            scanned++;
            if (info->TypeName.Buffer == NULL) continue;
            ULONG tlen = info->TypeName.Length / sizeof(WCHAR);
            if (tlen != 6 || _wcsnicmp(info->TypeName.Buffer, L"Driver", 6) != 0)
                continue;
            IrpInspectDriver(&info->Name, mods, modCount, &reported);
        }
        if (scanned >= KG_IRP_DRV_MAX) break;
    }

    ITRACE("scan summary: scanned=%u reported=%u\n", scanned, reported);

    g_KH.ExFreePoolWithTag(buf, 'iDkP');
    KL_NT(ZwClose)(dir);
    g_KH.ExFreePoolWithTag(mods, 'iMkP');
    return STATUS_SUCCESS;
}

static
KSTART_ROUTINE IrpThread;
static
VOID
IrpThread(
    _In_ PVOID StartContext
)
{
    UNREFERENCED_PARAMETER(StartContext);

    LARGE_INTEGER Timeout;
    Timeout.QuadPart = -((LONGLONG)KG_IRP_INTERVAL_MS * 10000LL);

    LARGE_INTEGER InitialDelay;
    InitialDelay.QuadPart = -((LONGLONG)10000 * 10000LL);
    KL_NT(KeDelayExecutionThread)(KernelMode, FALSE, &InitialDelay);

    for (;;) {
        ITRACE("scan tick begin\n");
        NTSTATUS scanSt = IrpScanOnce();
        ITRACE("scan tick end status=0x%08X\n", scanSt);

        NTSTATUS Wait = KL_NT(KeWaitForSingleObject)(&g_IrpStopEvent,
                                                     Executive,
                                                     KernelMode,
                                                     FALSE,
                                                     &Timeout);
        if (Wait == STATUS_SUCCESS) break;
    }

    KL_NT(PsTerminateSystemThread)(STATUS_SUCCESS);
}

_Use_decl_annotations_
KG_NO_OBFUSCATE
NTSTATUS
IrpScanStart(
    VOID
)
{
    PAGED_CODE();

    if (g_IrpStarted) return STATUS_SUCCESS;

    KL_NT(KeInitializeSpinLock)(&g_IrpLock);
    KL_NT(KeInitializeEvent)(&g_IrpStopEvent, NotificationEvent, FALSE);
    g_IrpHead = g_IrpTail = 0;
    g_IrpSeenIdx = 0;
    RtlZeroMemory(g_IrpSeen, sizeof(g_IrpSeen));

    HANDLE ThreadHandle = NULL;
    NTSTATUS Status = KL_NT(PsCreateSystemThread)(&ThreadHandle,
                                                  THREAD_ALL_ACCESS,
                                                  NULL,
                                                  NULL,
                                                  NULL,
                                                  IrpThread,
                                                  NULL);
    if (!NT_SUCCESS(Status)) return Status;

    Status = KL_NT(ObReferenceObjectByHandle)(ThreadHandle,
                                              THREAD_ALL_ACCESS,
                                              NULL,
                                              KernelMode,
                                              (PVOID*)&g_IrpThread,
                                              NULL);
    KL_NT(ZwClose)(ThreadHandle);

    if (!NT_SUCCESS(Status)) {
        g_IrpThread = NULL;
        return Status;
    }

    g_IrpStarted = TRUE;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
KG_NO_OBFUSCATE
VOID
IrpScanStop(
    VOID
)
{
    PAGED_CODE();

    if (!g_IrpStarted) return;

    KL_NT(KeSetEvent)(&g_IrpStopEvent, 0, FALSE);

    if (g_IrpThread) {
        KL_NT(KeWaitForSingleObject)(g_IrpThread, Executive, KernelMode, FALSE, NULL);
        KL_NT(ObfDereferenceObject)(g_IrpThread);
        g_IrpThread = NULL;
    }

    g_IrpStarted = FALSE;
}
