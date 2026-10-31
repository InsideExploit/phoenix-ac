#include "stackattach.hpp"

#include "shared.hpp"
#include "klazy.hpp"
#include "pxstr.hpp"

#include "protect/protect.hpp"
#include "integrity/integrity.hpp"

extern "C" {
    PCHAR
    PsGetProcessImageFileName(
        _In_ PEPROCESS Process
    );
}

#define KG_SA_THREADINFO_WIN32START     9

#ifndef SystemProcessInformation
#define SystemProcessInformation        5
#endif

#ifndef SystemModuleInformation
#define SystemModuleInformation         11
#endif

#define KG_SA_POLL_INTERVAL_MS          2
#define KG_SA_LOG_COOLDOWN_MS           250
#define KG_SA_MON_REFRESH_MS            100
#define KG_SA_THREADS_REFRESH_MS        250
#define KG_SA_SYSTEM_PID                ((HANDLE)(ULONG_PTR)4)

#define KG_SA_BUILD_WIN10_2004          19041
#define KG_SA_BUILD_WIN11_24H2          26100
#define KG_SA_OFFSET_LEGACY             0x348
#define KG_SA_OFFSET_MODERN             0x108
#define KG_SA_FALLBACK_OFFSET           KG_SA_OFFSET_LEGACY

#define KG_SA_KTHREAD_APCSTATE          0x98
#define KG_SA_KAPCSTATE_PROCESS         0x20
#define KG_SA_ATTACHED_PROCESS_OFF      (KG_SA_KTHREAD_APCSTATE + KG_SA_KAPCSTATE_PROCESS)

#define KG_SA_MAX_LOGGED_PER_BURST      4
#define KG_SA_MAX_MONITORED             40
#define KG_SA_MAX_CACHED_THREADS        1024
#define KG_SA_MAX_CACHED_MODULES        1024
#define KG_SA_MOD_NAME_MAX              64

#pragma pack(push, 8)
typedef struct _KG_SA_THREAD_INFO {
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
} KG_SA_THREAD_INFO, *PKG_SA_THREAD_INFO;

typedef struct _KG_SA_PROC_INFO {
    ULONG             NextEntryOffset;
    ULONG             NumberOfThreads;
    LARGE_INTEGER     WorkingSetPrivateSize;
    ULONG             HardFaultCount;
    ULONG             NumberOfThreadsHighWatermark;
    ULONGLONG         CycleTime;
    LARGE_INTEGER     CreateTime;
    LARGE_INTEGER     UserTime;
    LARGE_INTEGER     KernelTime;
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
    KG_SA_THREAD_INFO Threads[1];
} KG_SA_PROC_INFO, *PKG_SA_PROC_INFO;
#pragma pack(pop)

typedef struct _KG_SA_MONITORED {
    HANDLE    Pid;
    PEPROCESS Process;
    CHAR      Name[16];
} KG_SA_MONITORED;

typedef struct _KG_SA_CACHED_THREAD {
    PETHREAD  Thread;
    HANDLE    Tid;
    PVOID     StartAddress;
    PVOID     Win32StartAddress;
} KG_SA_CACHED_THREAD;

typedef struct _KG_SA_CACHED_MODULE {
    ULONG_PTR Base;
    ULONG_PTR End;
    CHAR      Name[KG_SA_MOD_NAME_MAX];
} KG_SA_CACHED_MODULE;

typedef struct _KG_SA_MOD_ENTRY {
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
} KG_SA_MOD_ENTRY;

typedef struct _KG_SA_MOD_LIST {
    ULONG           NumberOfModules;
    KG_SA_MOD_ENTRY Modules[1];
} KG_SA_MOD_LIST;

static volatile LONG g_Started       = 0;
static PETHREAD      g_Thread        = NULL;
static KEVENT        g_StopEvent;
static ULONG         g_StackCountOff = 0;
static BOOLEAN       g_OffsetInited  = FALSE;

static volatile LONGLONG g_LastLogAt100ns    = 0;
static LONGLONG          g_LastMonRefresh    = 0;
static LONGLONG          g_LastThreadRefresh = 0;

static KG_SA_MONITORED       g_Monitored[KG_SA_MAX_MONITORED]      = { 0 };
static ULONG                 g_MonCount                            = 0;

static KG_SA_CACHED_THREAD   g_ThreadCache[KG_SA_MAX_CACHED_THREADS] = { 0 };
static ULONG                 g_CachedCount                          = 0;

static KG_SA_CACHED_MODULE   g_ModuleCache[KG_SA_MAX_CACHED_MODULES] = { 0 };
static ULONG                 g_ModuleCount                           = 0;

KG_NO_OBFUSCATE
static
LONGLONG
StackAttachReadInterruptTime(
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

    return (LONGLONG)(((ULONGLONG)High1 << 32) | Low);
}

KG_NO_OBFUSCATE
static
ULONG
StackAttachGetKnownOffset(
    VOID
)
{
    auto GetVerFn = KL_NT(RtlGetVersion);
    if (GetVerFn == NULL)
        return 0;

    RTL_OSVERSIONINFOW Info = { 0 };
    Info.dwOSVersionInfoSize = sizeof(Info);
    if (!NT_SUCCESS(GetVerFn(&Info)))
        return 0;

    ULONG Build = Info.dwBuildNumber;

    if (Build >= KG_SA_BUILD_WIN11_24H2)
        return KG_SA_OFFSET_MODERN;

    if (Build >= KG_SA_BUILD_WIN10_2004)
        return KG_SA_OFFSET_LEGACY;

    return 0;
}

KG_NO_OBFUSCATE
static
VOID
StackAttachEnsureOffset(
    VOID
)
{
    if (g_OffsetInited)
        return;

    g_OffsetInited = TRUE;

    ULONG Known = StackAttachGetKnownOffset();
    if (Known != 0) {
        g_StackCountOff = Known;
        KG_DRV_LOG("[PhoenixDrv/StackAttach] KPROCESS.StackCount offset=0x%X\n", Known);
    } else {
        g_StackCountOff = KG_SA_FALLBACK_OFFSET;
        KG_DRV_LOG("[PhoenixDrv/StackAttach] unknown build, using fallback offset=0x%X\n",
                   g_StackCountOff);
    }
}

KG_NO_OBFUSCATE
static
PEPROCESS
StackAttachReadAttachedProcess(
    _In_ PETHREAD Thread
)
{
    PEPROCESS Attached = NULL;
    __try {
        Attached = *(PEPROCESS volatile*)((PUCHAR)Thread + KG_SA_ATTACHED_PROCESS_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Attached = NULL;
    }
    return Attached;
}

KG_NO_OBFUSCATE
static
VOID
StackAttachCopyName(
    _Out_writes_(16) CHAR* Dst,
    _In_ PEPROCESS         Process
)
{
    Dst[0] = 0;
    auto ImgFn = KL_NT(PsGetProcessImageFileName);
    if (ImgFn == NULL) return;

    PCHAR Src = ImgFn(Process);
    if (Src == NULL) return;

    for (ULONG i = 0; i < 15; ++i) {
        Dst[i] = Src[i];
        if (Src[i] == 0) return;
    }
    Dst[15] = 0;
}

KG_NO_OBFUSCATE
static
VOID
StackAttachClearMonitored(
    VOID
)
{
    auto DerefFn = KL_NT(ObfDereferenceObject);
    if (DerefFn == NULL) {
        g_MonCount = 0;
        return;
    }

    for (ULONG i = 0; i < g_MonCount; ++i) {
        if (g_Monitored[i].Process != NULL) {
            DerefFn(g_Monitored[i].Process);
            g_Monitored[i].Process = NULL;
        }
    }
    g_MonCount = 0;
}

KG_NO_OBFUSCATE
static
VOID
StackAttachRefreshMonitored(
    VOID
)
{
    StackAttachClearMonitored();

    auto LookupFn = KL_NT(PsLookupProcessByProcessId);
    if (LookupFn == NULL)
        return;

    HANDLE Owner = ProtectedOwnerId();
    if (Owner != NULL) {
        PEPROCESS P = NULL;
        if (NT_SUCCESS(LookupFn(Owner, &P)) && P != NULL) {
            g_Monitored[g_MonCount].Pid     = Owner;
            g_Monitored[g_MonCount].Process = P;
            StackAttachCopyName(g_Monitored[g_MonCount].Name, P);
            g_MonCount++;
        }
    }

    HANDLE TrustedPids[KG_SA_MAX_MONITORED] = { 0 };
    UINT32 TrustedN = TrustedSnapshot(TrustedPids, KG_SA_MAX_MONITORED);

    for (UINT32 i = 0; i < TrustedN && g_MonCount < KG_SA_MAX_MONITORED; ++i) {
        HANDLE Pid = TrustedPids[i];
        if (Pid == NULL || Pid == Owner)
            continue;

        PEPROCESS P = NULL;
        if (!NT_SUCCESS(LookupFn(Pid, &P)) || P == NULL)
            continue;

        g_Monitored[g_MonCount].Pid     = Pid;
        g_Monitored[g_MonCount].Process = P;
        StackAttachCopyName(g_Monitored[g_MonCount].Name, P);
        g_MonCount++;
    }
}

KG_NO_OBFUSCATE
static
VOID
StackAttachClearThreadCache(
    VOID
)
{
    auto DerefFn = KL_NT(ObfDereferenceObject);
    if (DerefFn == NULL) {
        g_CachedCount = 0;
        return;
    }

    for (ULONG i = 0; i < g_CachedCount; ++i) {
        if (g_ThreadCache[i].Thread != NULL) {
            DerefFn(g_ThreadCache[i].Thread);
            g_ThreadCache[i].Thread = NULL;
        }
    }
    g_CachedCount = 0;
}

KG_NO_OBFUSCATE
static
VOID
StackAttachRefreshThreadCache(
    VOID
)
{
    StackAttachClearThreadCache();

    auto QueryFn     = KL_NT(ZwQuerySystemInformation);
    auto AllocFn     = KL_NT(ExAllocatePool2);
    auto LookupTidFn = KL_NT(PsLookupThreadByThreadId);
    if (QueryFn == NULL || AllocFn == NULL || LookupTidFn == NULL)
        return;

    ULONG Size = 0;
    QueryFn(SystemProcessInformation, NULL, 0, &Size);
    if (Size == 0)
        Size = 0x80000;

    PVOID    Buffer   = NULL;
    NTSTATUS Status   = STATUS_INFO_LENGTH_MISMATCH;
    ULONG    Returned = 0;

    for (ULONG Attempt = 0; Attempt < 6; ++Attempt) {
        ULONG Try = Size + 0x10000 * (Attempt + 1);
        Buffer = AllocFn(POOL_FLAG_NON_PAGED, Try, 'cScP');
        if (Buffer == NULL)
            return;

        Returned = 0;
        Status = QueryFn(SystemProcessInformation, Buffer, Try, &Returned);
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

    PKG_SA_PROC_INFO Entry = (PKG_SA_PROC_INFO)Buffer;
    for (;;) {
        if (Entry->UniqueProcessId == KG_SA_SYSTEM_PID) {
            for (ULONG i = 0; i < Entry->NumberOfThreads && g_CachedCount < KG_SA_MAX_CACHED_THREADS; ++i) {
                HANDLE Tid = Entry->Threads[i].ClientId.UniqueThread;
                if (Tid == NULL)
                    continue;

                PETHREAD ThreadObj = NULL;
                if (!NT_SUCCESS(LookupTidFn(Tid, &ThreadObj)) || ThreadObj == NULL)
                    continue;

                g_ThreadCache[g_CachedCount].Thread            = ThreadObj;
                g_ThreadCache[g_CachedCount].Tid               = Tid;
                g_ThreadCache[g_CachedCount].StartAddress      = Entry->Threads[i].StartAddress;
                g_ThreadCache[g_CachedCount].Win32StartAddress = NULL;
                g_CachedCount++;
            }
            break;
        }

        if (Entry->NextEntryOffset == 0)
            break;

        Entry = (PKG_SA_PROC_INFO)((PUCHAR)Entry + Entry->NextEntryOffset);
    }

    g_KH.ExFreePoolWithTag(Buffer, 0);
}

KG_NO_OBFUSCATE
static
VOID
StackAttachRefreshModuleCache(
    VOID
)
{
    g_ModuleCount = 0;

    auto QueryFn = KL_NT(ZwQuerySystemInformation);
    auto AllocFn = KL_NT(ExAllocatePool2);
    if (QueryFn == NULL || AllocFn == NULL)
        return;

    ULONG Size = 0;
    QueryFn(SystemModuleInformation, NULL, 0, &Size);
    if (Size == 0)
        return;

    Size += 0x4000;

    PVOID Buffer = AllocFn(POOL_FLAG_NON_PAGED, Size, 'mScP');
    if (Buffer == NULL)
        return;

    ULONG Returned = 0;
    if (!NT_SUCCESS(QueryFn(SystemModuleInformation, Buffer, Size, &Returned))) {
        g_KH.ExFreePoolWithTag(Buffer, 0);
        return;
    }

    KG_SA_MOD_LIST* Mods = (KG_SA_MOD_LIST*)Buffer;
    ULONG Count = Mods->NumberOfModules;
    if (Count > KG_SA_MAX_CACHED_MODULES)
        Count = KG_SA_MAX_CACHED_MODULES;

    for (ULONG i = 0; i < Count; ++i) {
        g_ModuleCache[i].Base = (ULONG_PTR)Mods->Modules[i].ImageBase;
        g_ModuleCache[i].End  = g_ModuleCache[i].Base + Mods->Modules[i].ImageSize;

        USHORT NameOff = Mods->Modules[i].OffsetToFileName;
        if (NameOff >= sizeof(Mods->Modules[i].FullPathName))
            NameOff = 0;

        const CHAR* Src = (const CHAR*)&Mods->Modules[i].FullPathName[NameOff];
        SIZE_T      Ni  = 0;
        while (Ni + 1 < KG_SA_MOD_NAME_MAX && Src[Ni]) {
            g_ModuleCache[i].Name[Ni] = Src[Ni];
            Ni++;
        }
        g_ModuleCache[i].Name[Ni] = 0;
    }

    g_ModuleCount = Count;
    g_KH.ExFreePoolWithTag(Buffer, 0);
}

KG_NO_OBFUSCATE
static
const KG_SA_CACHED_MODULE*
StackAttachFindModule(
    _In_  PVOID       Addr,
    _Out_ ULONG_PTR*  OutOffset
)
{
    *OutOffset = 0;
    ULONG_PTR A = (ULONG_PTR)Addr;

    for (ULONG i = 0; i < g_ModuleCount; ++i) {
        if (A >= g_ModuleCache[i].Base && A < g_ModuleCache[i].End) {
            *OutOffset = A - g_ModuleCache[i].Base;
            return &g_ModuleCache[i];
        }
    }
    return NULL;
}

KG_NO_OBFUSCATE
static
PVOID
StackAttachQueryWin32Start(
    _In_ HANDLE Tid
)
{
    auto OpenFn  = KL_NT(ZwOpenThread);
    auto QInfoFn = KL_NT(ZwQueryInformationThread);
    auto CloseFn = KL_NT(ZwClose);
    if (OpenFn == NULL || QInfoFn == NULL || CloseFn == NULL)
        return NULL;

    HANDLE ThreadHandle = NULL;
    OBJECT_ATTRIBUTES Attributes;
    InitializeObjectAttributes(&Attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    CLIENT_ID Cid = { NULL, Tid };

    if (!NT_SUCCESS(OpenFn(&ThreadHandle,
                           THREAD_QUERY_LIMITED_INFORMATION,
                           &Attributes,
                           &Cid)) || ThreadHandle == NULL)
        return NULL;

    PVOID Win32Start = NULL;
    ULONG Ret = 0;
    QInfoFn(ThreadHandle,
            KG_SA_THREADINFO_WIN32START,
            &Win32Start,
            sizeof(Win32Start),
            &Ret);
    CloseFn(ThreadHandle);
    return Win32Start;
}

KG_NO_OBFUSCATE
static
VOID
StackAttachPollTick(
    VOID
)
{
    StackAttachEnsureOffset();

    LONGLONG Now = StackAttachReadInterruptTime();

    if ((Now - g_LastMonRefresh) >= (LONGLONG)KG_SA_MON_REFRESH_MS * 10000LL) {
        StackAttachRefreshMonitored();
        g_LastMonRefresh = Now;
    }

    if ((Now - g_LastThreadRefresh) >= (LONGLONG)KG_SA_THREADS_REFRESH_MS * 10000LL) {
        StackAttachRefreshThreadCache();
        StackAttachRefreshModuleCache();
        g_LastThreadRefresh = Now;
    }

    if (g_MonCount == 0 || g_CachedCount == 0)
        return;

    LONGLONG Cooldown = (LONGLONG)KG_SA_LOG_COOLDOWN_MS * 10000LL;
    BOOLEAN  CanLog   = (g_LastLogAt100ns == 0 || (Now - g_LastLogAt100ns) >= Cooldown);
    if (!CanLog)
        return;

    ULONG Logged = 0;
    for (ULONG i = 0; i < g_CachedCount && Logged < KG_SA_MAX_LOGGED_PER_BURST; ++i) {
        PEPROCESS Attached = StackAttachReadAttachedProcess(g_ThreadCache[i].Thread);
        if (Attached == NULL)
            continue;

        for (ULONG m = 0; m < g_MonCount; ++m) {
            if (g_Monitored[m].Process != Attached)
                continue;

            if (g_ThreadCache[i].Win32StartAddress == NULL) {
                g_ThreadCache[i].Win32StartAddress =
                    StackAttachQueryWin32Start(g_ThreadCache[i].Tid);
            }

            PVOID     ProbeAddr = g_ThreadCache[i].Win32StartAddress != NULL
                                  ? g_ThreadCache[i].Win32StartAddress
                                  : g_ThreadCache[i].StartAddress;
            ULONG_PTR ModOff    = 0;
            const KG_SA_CACHED_MODULE* Mod = StackAttachFindModule(ProbeAddr, &ModOff);

            BOOLEAN Skip = FALSE;
            if (Mod != NULL) {
                CHAR c0 = Mod->Name[0];
                if ((c0 == 'n' || c0 == 'N') &&
                    (Mod->Name[1] == 't' || Mod->Name[1] == 'T') &&
                    (Mod->Name[2] == 'o' || Mod->Name[2] == 'O')) {
                    Skip = TRUE;
                }
            }

            if (Skip)
                break;

            g_LastLogAt100ns = Now;

            if (Mod != NULL) {
                KG_DRV_LOG("[PhoenixDrv/StackAttach] ATTACH target_pid=%lu target_img=%s "
                           "attacker_tid=%lu win32start=0x%p (%s+0x%llX) start=0x%p\n",
                           (ULONG)(ULONG_PTR)g_Monitored[m].Pid,
                           g_Monitored[m].Name[0] ? g_Monitored[m].Name : "?",
                           (ULONG)(ULONG_PTR)g_ThreadCache[i].Tid,
                           ProbeAddr,
                           Mod->Name,
                           (ULONG64)ModOff,
                           g_ThreadCache[i].StartAddress);
            } else {
                KG_DRV_LOG("[PhoenixDrv/StackAttach] ATTACH target_pid=%lu target_img=%s "
                           "attacker_tid=%lu win32start=0x%p (UNMAPPED/FOREIGN) start=0x%p\n",
                           (ULONG)(ULONG_PTR)g_Monitored[m].Pid,
                           g_Monitored[m].Name[0] ? g_Monitored[m].Name : "?",
                           (ULONG)(ULONG_PTR)g_ThreadCache[i].Tid,
                           ProbeAddr,
                           g_ThreadCache[i].StartAddress);
            }

            Logged++;
            break;
        }
    }
}

_Function_class_(KSTART_ROUTINE)
KG_NO_OBFUSCATE
static
VOID
StackAttachThread(
    _In_ PVOID StartContext
)
{
    UNREFERENCED_PARAMETER(StartContext);

    LARGE_INTEGER InitialDelay;
    InitialDelay.QuadPart = -((LONGLONG)3000 * 10000LL);
    auto DelayFn = KL_NT(KeDelayExecutionThread);
    if (DelayFn != NULL)
        DelayFn(KernelMode, FALSE, &InitialDelay);

    LARGE_INTEGER Timeout;
    Timeout.QuadPart = -((LONGLONG)KG_SA_POLL_INTERVAL_MS * 10000LL);

    auto WaitFn = KL_NT(KeWaitForSingleObject);
    auto TermFn = KL_NT(PsTerminateSystemThread);

    for (;;) {
        if (WaitFn == NULL)
            break;

        NTSTATUS Wait = WaitFn(&g_StopEvent, Executive, KernelMode, FALSE, &Timeout);
        if (Wait == STATUS_SUCCESS)
            break;

        StackAttachPollTick();
    }

    StackAttachClearThreadCache();
    StackAttachClearMonitored();

    if (TermFn != NULL)
        TermFn(STATUS_SUCCESS);
}

_Use_decl_annotations_
KG_NO_OBFUSCATE
NTSTATUS
StackAttachStart(
    VOID
)
{
    PAGED_CODE();

    if (InterlockedCompareExchange(&g_Started, 1, 0) != 0)
        return STATUS_SUCCESS;

    auto InitFn = KL_NT(KeInitializeEvent);
    if (InitFn == NULL) {
        InterlockedExchange(&g_Started, 0);
        return STATUS_UNSUCCESSFUL;
    }
    InitFn(&g_StopEvent, NotificationEvent, FALSE);

    g_OffsetInited      = FALSE;
    g_StackCountOff     = 0;
    g_MonCount          = 0;
    g_CachedCount       = 0;
    g_LastMonRefresh    = 0;
    g_LastThreadRefresh = 0;
    g_LastLogAt100ns    = 0;

    auto CreateFn = KL_NT(PsCreateSystemThread);
    auto RefFn    = KL_NT(ObReferenceObjectByHandle);
    auto CloseFn  = KL_NT(ZwClose);
    if (CreateFn == NULL || RefFn == NULL || CloseFn == NULL) {
        InterlockedExchange(&g_Started, 0);
        return STATUS_UNSUCCESSFUL;
    }

    HANDLE   ThreadHandle = NULL;
    NTSTATUS Status = CreateFn(&ThreadHandle,
                               THREAD_ALL_ACCESS,
                               NULL,
                               NULL,
                               NULL,
                               StackAttachThread,
                               NULL);
    if (!NT_SUCCESS(Status)) {
        InterlockedExchange(&g_Started, 0);
        return Status;
    }

    Status = RefFn(ThreadHandle,
                   THREAD_ALL_ACCESS,
                   NULL,
                   KernelMode,
                   (PVOID*)&g_Thread,
                   NULL);
    CloseFn(ThreadHandle);

    if (!NT_SUCCESS(Status)) {
        g_Thread = NULL;
        InterlockedExchange(&g_Started, 0);
        return Status;
    }

    IntegrityRegister((PVOID)&StackAttachThread);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
KG_NO_OBFUSCATE
VOID
StackAttachStop(
    VOID
)
{
    PAGED_CODE();

    if (InterlockedCompareExchange(&g_Started, 0, 1) != 1)
        return;

    auto SetFn  = KL_NT(KeSetEvent);
    auto WaitFn = KL_NT(KeWaitForSingleObject);
    auto DerefFn = KL_NT(ObfDereferenceObject);

    if (SetFn != NULL)
        SetFn(&g_StopEvent, 0, FALSE);

    if (g_Thread != NULL) {
        if (WaitFn != NULL)
            WaitFn(g_Thread, Executive, KernelMode, FALSE, NULL);
        if (DerefFn != NULL)
            DerefFn(g_Thread);
        g_Thread = NULL;
    }
}
