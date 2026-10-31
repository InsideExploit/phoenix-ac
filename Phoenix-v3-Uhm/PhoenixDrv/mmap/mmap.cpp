#include "mmap.hpp"

#include "shared.hpp"
#include "klazy.hpp"

#define KG_MMAP_INTERVAL_MS   30000
#define KG_MMAP_RING_SIZE     32
#define KG_MMAP_SEEN_MAX      64
#define KG_MMAP_MOD_MAX       512
#define KG_MMAP_SYSTEM_PID    ((HANDLE)(ULONG_PTR)4)

#define KG_MMAP_TRACE 0
#if KG_MMAP_TRACE
#define MTRACE(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[PhoenixDrv/Mmap] " fmt, ##__VA_ARGS__)
#else
#define MTRACE(fmt, ...) ((void)0)
#endif

#define SystemModuleInformation  11
#define SystemProcessInformationLocal 5

typedef struct _KG_MMAP_MOD {
    ULONG_PTR Base;
    ULONG_PTR End;
    CHAR      Name[KG_MMAP_MOD_NAME_MAX];
} KG_MMAP_MOD;

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

typedef struct _KG_SYS_THREAD_INFO {
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
} KG_SYS_THREAD_INFO;

typedef struct _KG_SYS_PROC_INFO {
    ULONG           NextEntryOffset;
    ULONG           NumberOfThreads;
    LARGE_INTEGER   WorkingSetPrivateSize;
    ULONG           HardFaultCount;
    ULONG           NumberOfThreadsHighWatermark;
    ULONGLONG       CycleTime;
    LARGE_INTEGER   CreateTime;
    LARGE_INTEGER   UserTime;
    LARGE_INTEGER   KernelTime;
    UNICODE_STRING  ImageName;
    KPRIORITY       BasePriority;
    HANDLE          UniqueProcessId;
    HANDLE          InheritedFromUniqueProcessId;
    ULONG           HandleCount;
    ULONG           SessionId;
    ULONG_PTR       UniqueProcessKey;
    SIZE_T          PeakVirtualSize;
    SIZE_T          VirtualSize;
    ULONG           PageFaultCount;
    SIZE_T          PeakWorkingSetSize;
    SIZE_T          WorkingSetSize;
    SIZE_T          QuotaPeakPagedPoolUsage;
    SIZE_T          QuotaPagedPoolUsage;
    SIZE_T          QuotaPeakNonPagedPoolUsage;
    SIZE_T          QuotaNonPagedPoolUsage;
    SIZE_T          PagefileUsage;
    SIZE_T          PeakPagefileUsage;
    SIZE_T          PrivatePageCount;
    LARGE_INTEGER   ReadOperationCount;
    LARGE_INTEGER   WriteOperationCount;
    LARGE_INTEGER   OtherOperationCount;
    LARGE_INTEGER   ReadTransferCount;
    LARGE_INTEGER   WriteTransferCount;
    LARGE_INTEGER   OtherTransferCount;
    KG_SYS_THREAD_INFO Threads[1];
} KG_SYS_PROC_INFO;

static KSPIN_LOCK       g_MmapLock;
static KG_MMAP_EVENT    g_MmapRing[KG_MMAP_RING_SIZE];
static ULONG            g_MmapHead   = 0;
static ULONG            g_MmapTail   = 0;

static ULONG_PTR        g_MmapSeen[KG_MMAP_SEEN_MAX] = { 0 };
static ULONG            g_MmapSeenIdx = 0;

static KEVENT           g_MmapStopEvent;
static PETHREAD         g_MmapThread = NULL;
static BOOLEAN          g_MmapStarted = FALSE;

static
UINT64
MmapNowMs(
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
MmapPushEvent(
    _In_ const KG_MMAP_EVENT* Ev
)
{
    KIRQL OldIrql;
    OldIrql = g_KH.KeAcquireSpinLockRaiseToDpc(&g_MmapLock);

    g_MmapRing[g_MmapHead] = *Ev;
    g_MmapHead = (g_MmapHead + 1) % KG_MMAP_RING_SIZE;
    if (g_MmapHead == g_MmapTail)
        g_MmapTail = (g_MmapTail + 1) % KG_MMAP_RING_SIZE;

    g_KH.KeReleaseSpinLock(&g_MmapLock, OldIrql);
}

_Use_decl_annotations_
KG_NO_OBFUSCATE
NTSTATUS
MmapPop(
    PVOID  OutBuf,
    ULONG  OutCap,
    PULONG BytesReturned
)
{
    *BytesReturned = 0;

    if (OutCap < sizeof(KG_MMAP_EVENT))
        return STATUS_BUFFER_TOO_SMALL;

    KIRQL OldIrql;
    OldIrql = g_KH.KeAcquireSpinLockRaiseToDpc(&g_MmapLock);

    if (g_MmapHead == g_MmapTail) {
        g_KH.KeReleaseSpinLock(&g_MmapLock, OldIrql);
        return STATUS_NO_MORE_ENTRIES;
    }

    RtlCopyMemory(OutBuf, &g_MmapRing[g_MmapTail], sizeof(KG_MMAP_EVENT));
    g_MmapTail = (g_MmapTail + 1) % KG_MMAP_RING_SIZE;

    g_KH.KeReleaseSpinLock(&g_MmapLock, OldIrql);

    *BytesReturned = sizeof(KG_MMAP_EVENT);
    return STATUS_SUCCESS;
}

static
BOOLEAN
MmapAlreadySeen(
    _In_ ULONG_PTR Addr
)
{
    for (ULONG i = 0; i < KG_MMAP_SEEN_MAX; ++i) {
        if (g_MmapSeen[i] == Addr) return TRUE;
    }
    g_MmapSeen[g_MmapSeenIdx] = Addr;
    g_MmapSeenIdx = (g_MmapSeenIdx + 1) % KG_MMAP_SEEN_MAX;
    return FALSE;
}

static
BOOLEAN
MmapAddrIsKernel(
    _In_ ULONG_PTR Addr
)
{
    return Addr >= (ULONG_PTR)0xFFFF800000000000ULL;
}

static
BOOLEAN
MmapAddrInAnyModule(
    _In_ const KG_MMAP_MOD* Mods,
    _In_ ULONG              Count,
    _In_ ULONG_PTR          Addr,
    _Out_ const KG_MMAP_MOD** OutNearest,
    _Out_ ULONG_PTR*         OutOffset
)
{
    *OutNearest = NULL;
    *OutOffset  = 0;
    ULONG_PTR   bestDelta = ~(ULONG_PTR)0;
    const KG_MMAP_MOD* bestMod = NULL;

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
MmapCopyDump(
    _In_ ULONG_PTR StartAddr,
    _Out_writes_bytes_(KG_MMAP_DUMP_BYTES) UINT8* Dump
)
{
    RtlZeroMemory(Dump, KG_MMAP_DUMP_BYTES);
    if (!MmapAddrIsKernel(StartAddr)) return 0;

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
MmapEnumerateModules(
    _Out_ KG_MMAP_MOD** OutMods,
    _Out_ ULONG*        OutCount
)
{
    *OutMods  = NULL;
    *OutCount = 0;

    ULONG needed = 0;
    KL_NT(ZwQuerySystemInformation)(SystemModuleInformation, NULL, 0, &needed);
    if (needed == 0) return STATUS_UNSUCCESSFUL;

    ULONG allocLen = needed + 0x2000;
    PVOID rawBuf = KL_NT(ExAllocatePool2)(POOL_FLAG_NON_PAGED, allocLen, 'mMkP');
    if (!rawBuf) return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS st = KL_NT(ZwQuerySystemInformation)(SystemModuleInformation, rawBuf, allocLen, &needed);
    if (!NT_SUCCESS(st)) {
        g_KH.ExFreePoolWithTag(rawBuf, 'mMkP');
        return st;
    }

    RTL_PROCESS_MODULES_LOCAL* mods = (RTL_PROCESS_MODULES_LOCAL*)rawBuf;
    ULONG count = mods->NumberOfModules;
    if (count > KG_MMAP_MOD_MAX) count = KG_MMAP_MOD_MAX;

    KG_MMAP_MOD* out = (KG_MMAP_MOD*)KL_NT(ExAllocatePool2)(
        POOL_FLAG_NON_PAGED, count * sizeof(KG_MMAP_MOD), 'mMkP');
    if (!out) {
        g_KH.ExFreePoolWithTag(rawBuf, 'mMkP');
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

    g_KH.ExFreePoolWithTag(rawBuf, 'mMkP');
    *OutMods  = out;
    *OutCount = count;
    return STATUS_SUCCESS;
}

static
NTSTATUS
MmapScanOnce(
    VOID
)
{
    KG_MMAP_MOD* mods = NULL;
    ULONG modCount = 0;
    NTSTATUS st = MmapEnumerateModules(&mods, &modCount);
    if (!NT_SUCCESS(st) || !mods) return st;

    ULONG procSize = 0x40000;
    PVOID procBuf = NULL;
    for (;;) {
        procBuf = KL_NT(ExAllocatePool2)(POOL_FLAG_NON_PAGED, procSize, 'pMkP');
        if (!procBuf) {
            g_KH.ExFreePoolWithTag(mods, 'mMkP');
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        ULONG got = 0;
        st = KL_NT(ZwQuerySystemInformation)(SystemProcessInformationLocal, procBuf, procSize, &got);
        if (st == STATUS_INFO_LENGTH_MISMATCH) {
            g_KH.ExFreePoolWithTag(procBuf, 'pMkP');
            procBuf = NULL;
            procSize *= 2;
            if (procSize > 0x4000000) {
                g_KH.ExFreePoolWithTag(mods, 'mMkP');
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            continue;
        }
        if (!NT_SUCCESS(st)) {
            g_KH.ExFreePoolWithTag(procBuf, 'pMkP');
            g_KH.ExFreePoolWithTag(mods, 'mMkP');
            return st;
        }
        break;
    }

    KG_SYS_PROC_INFO* entry = (KG_SYS_PROC_INFO*)procBuf;
    MTRACE("enumerated %u modules\n", modCount);
    ULONG scanned = 0, reported = 0, filtered_module = 0, filtered_seen = 0, filtered_user = 0;
    for (;;) {
        if (entry->UniqueProcessId == KG_MMAP_SYSTEM_PID) {
            MTRACE("System (PID 4) has %u threads\n", entry->NumberOfThreads);
            for (ULONG i = 0; i < entry->NumberOfThreads; ++i) {
                ULONG_PTR addr = (ULONG_PTR)entry->Threads[i].StartAddress;
                ULONG tid = (ULONG)(ULONG_PTR)entry->Threads[i].ClientId.UniqueThread;
                if (addr == 0) continue;
                scanned++;
                if (!MmapAddrIsKernel(addr)) { filtered_user++; continue; }

                const KG_MMAP_MOD* nearest = NULL;
                ULONG_PTR offset = 0;
                if (MmapAddrInAnyModule(mods, modCount, addr, &nearest, &offset)) {
                    filtered_module++;
                    continue;
                }

                MTRACE("  TID %u  start=0x%p  OUTSIDE modules  nearest=%s +0x%p\n",
                       tid, (PVOID)addr, nearest ? nearest->Name : "<none>", (PVOID)offset);

                if (MmapAlreadySeen(addr)) { filtered_seen++; continue; }

                KG_MMAP_EVENT ev = { 0 };
                ev.TimestampMs  = MmapNowMs();
                ev.StartAddress = (UINT64)addr;
                ev.Tid          = (UINT32)tid;
                ev.DumpLen      = MmapCopyDump(addr, ev.Dump);
                if (nearest) {
                    ev.NearestModuleOffset = (UINT16)(offset > 0xFFFF ? 0xFFFF : offset);
                    SIZE_T ni = 0;
                    while (ni + 1 < KG_MMAP_MOD_NAME_MAX && nearest->Name[ni]) {
                        ev.NearestModule[ni] = nearest->Name[ni];
                        ni++;
                    }
                    ev.NearestModule[ni] = 0;
                }
                MmapPushEvent(&ev);
                reported++;
                MTRACE("  -> pushed event dumpLen=%u\n", ev.DumpLen);
            }
            break;
        }
        if (entry->NextEntryOffset == 0) break;
        entry = (KG_SYS_PROC_INFO*)((PUCHAR)entry + entry->NextEntryOffset);
    }
    MTRACE("scan summary: scanned=%u reported=%u filtered_mod=%u filtered_seen=%u filtered_user=%u\n",
           scanned, reported, filtered_module, filtered_seen, filtered_user);

    g_KH.ExFreePoolWithTag(procBuf, 'pMkP');
    g_KH.ExFreePoolWithTag(mods, 'mMkP');
    return STATUS_SUCCESS;
}

static
KSTART_ROUTINE MmapThread;
static
VOID
MmapThread(
    _In_ PVOID StartContext
)
{
    UNREFERENCED_PARAMETER(StartContext);

    LARGE_INTEGER Timeout;
    Timeout.QuadPart = -((LONGLONG)KG_MMAP_INTERVAL_MS * 10000LL);

    LARGE_INTEGER InitialDelay;
    InitialDelay.QuadPart = -((LONGLONG)5000 * 10000LL);
    KL_NT(KeDelayExecutionThread)(KernelMode, FALSE, &InitialDelay);

    for (;;) {
        MTRACE("scan tick begin\n");
        NTSTATUS scanSt = MmapScanOnce();
        MTRACE("scan tick end status=0x%08X\n", scanSt);

        NTSTATUS Wait = KL_NT(KeWaitForSingleObject)(&g_MmapStopEvent,
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
MmapStart(
    VOID
)
{
    PAGED_CODE();

    if (g_MmapStarted) return STATUS_SUCCESS;

    KL_NT(KeInitializeSpinLock)(&g_MmapLock);
    KL_NT(KeInitializeEvent)(&g_MmapStopEvent, NotificationEvent, FALSE);
    g_MmapHead = g_MmapTail = 0;
    g_MmapSeenIdx = 0;
    RtlZeroMemory(g_MmapSeen, sizeof(g_MmapSeen));

    HANDLE ThreadHandle = NULL;
    NTSTATUS Status = KL_NT(PsCreateSystemThread)(&ThreadHandle,
                                                  THREAD_ALL_ACCESS,
                                                  NULL,
                                                  NULL,
                                                  NULL,
                                                  MmapThread,
                                                  NULL);
    if (!NT_SUCCESS(Status)) return Status;

    Status = KL_NT(ObReferenceObjectByHandle)(ThreadHandle,
                                              THREAD_ALL_ACCESS,
                                              NULL,
                                              KernelMode,
                                              (PVOID*)&g_MmapThread,
                                              NULL);
    KL_NT(ZwClose)(ThreadHandle);

    if (!NT_SUCCESS(Status)) {
        g_MmapThread = NULL;
        return Status;
    }

    g_MmapStarted = TRUE;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
KG_NO_OBFUSCATE
VOID
MmapStop(
    VOID
)
{
    PAGED_CODE();

    if (!g_MmapStarted) return;

    KL_NT(KeSetEvent)(&g_MmapStopEvent, 0, FALSE);

    if (g_MmapThread) {
        KL_NT(KeWaitForSingleObject)(g_MmapThread, Executive, KernelMode, FALSE, NULL);
        KL_NT(ObfDereferenceObject)(g_MmapThread);
        g_MmapThread = NULL;
    }

    g_MmapStarted = FALSE;
}
