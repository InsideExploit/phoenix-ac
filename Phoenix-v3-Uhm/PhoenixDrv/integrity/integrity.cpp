#include "integrity.hpp"

#include "shared.hpp"
#include "klazy.hpp"
#include "pxstr.hpp"

#include "protect/protect.hpp"

#define KG_INTEGRITY_MAX          16
#define KG_INTEGRITY_PROLOGUE     32
#define KG_INTEGRITY_INTERVAL_MS  2000

typedef struct _KG_INTEGRITY_ENTRY {
    PVOID Address;
    UCHAR Prologue[KG_INTEGRITY_PROLOGUE];
} KG_INTEGRITY_ENTRY, *PKG_INTEGRITY_ENTRY;

static KG_INTEGRITY_ENTRY g_Entries[KG_INTEGRITY_MAX];
static ULONG              g_EntryCount = 0;
static KSPIN_LOCK         g_Lock;
static PETHREAD           g_Thread     = NULL;
static KEVENT             g_StopEvent;
static volatile LONG      g_Poisoned   = 0;
static BOOLEAN            g_Started    = FALSE;

_Use_decl_annotations_
VOID
IntegrityRegister(
    PVOID FnAddr
)
{
    if (FnAddr == NULL)
        return;

    KIRQL Irql = g_KH.KeAcquireSpinLockRaiseToDpc(&g_Lock);
    if (g_EntryCount >= KG_INTEGRITY_MAX) {
        g_KH.KeReleaseSpinLock(&g_Lock, Irql);
        return;
    }

    PKG_INTEGRITY_ENTRY Entry = &g_Entries[g_EntryCount++];
    Entry->Address = FnAddr;

    __try {
        RtlCopyMemory(Entry->Prologue, FnAddr, KG_INTEGRITY_PROLOGUE);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_EntryCount--;
    }

    g_KH.KeReleaseSpinLock(&g_Lock, Irql);
}

KG_NO_OBFUSCATE
_Use_decl_annotations_
BOOLEAN
IntegrityIsPoisoned(
    VOID
)
{
    return InterlockedCompareExchange(&g_Poisoned, 0, 0) != 0;
}

KG_NO_OBFUSCATE
static
BOOLEAN
IntegrityCheckOnce(
    VOID
)
{
    KIRQL Irql = g_KH.KeAcquireSpinLockRaiseToDpc(&g_Lock);

    ULONG Count = g_EntryCount;
    KG_INTEGRITY_ENTRY Snap[KG_INTEGRITY_MAX];

    RtlCopyMemory(Snap, g_Entries, sizeof(KG_INTEGRITY_ENTRY) * Count);

    g_KH.KeReleaseSpinLock(&g_Lock, Irql);

    for (ULONG i = 0; i < Count; i++) {
        __try {
            SIZE_T Match = KL_NT(RtlCompareMemory)(Snap[i].Address,
                                                   Snap[i].Prologue,
                                                   KG_INTEGRITY_PROLOGUE);
            if (Match != KG_INTEGRITY_PROLOGUE) {
                InterlockedExchange(&g_Poisoned, 1);
                return FALSE;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            InterlockedExchange(&g_Poisoned, 1);
            return FALSE;
        }
    }

    return TRUE;
}

KG_NO_OBFUSCATE
_Function_class_(KSTART_ROUTINE)
static
VOID
IntegrityThread(
    _In_ PVOID StartContext
)
{
    UNREFERENCED_PARAMETER(StartContext);

    LARGE_INTEGER Timeout;
    Timeout.QuadPart = -((LONGLONG)KG_INTEGRITY_INTERVAL_MS * 10000LL);

    for (;;) {
        NTSTATUS Wait = KL_NT(KeWaitForSingleObject)(&g_StopEvent,
                                                     Executive,
                                                     KernelMode,
                                                     FALSE,
                                                     &Timeout);
        if (Wait == STATUS_SUCCESS)
            break;

        if (!IntegrityCheckOnce()) {
            KillAllTrusted();
            break;
        }
    }

    KL_NT(PsTerminateSystemThread)(STATUS_SUCCESS);
}

_Use_decl_annotations_
KG_NO_OBFUSCATE
NTSTATUS
IntegrityStart(
    VOID
)
{
    PAGED_CODE();

    if (g_Started)
        return STATUS_SUCCESS;

    KL_NT(KeInitializeSpinLock)(&g_Lock);
    KL_NT(KeInitializeEvent)(&g_StopEvent, NotificationEvent, FALSE);

    HANDLE ThreadHandle = NULL;
    NTSTATUS Status = KL_NT(PsCreateSystemThread)(&ThreadHandle,
                                                  THREAD_ALL_ACCESS,
                                                  NULL,
                                                  NULL,
                                                  NULL,
                                                  IntegrityThread,
                                                  NULL);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = KL_NT(ObReferenceObjectByHandle)(ThreadHandle,
                                              THREAD_ALL_ACCESS,
                                              NULL,
                                              KernelMode,
                                              (PVOID*)&g_Thread,
                                              NULL);
    KL_NT(ZwClose)(ThreadHandle);

    if (!NT_SUCCESS(Status)) {
        g_Thread = NULL;
        return Status;
    }

    g_Started = TRUE;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
KG_NO_OBFUSCATE
VOID
IntegrityStop(
    VOID
)
{
    PAGED_CODE();

    if (!g_Started)
        return;

    KL_NT(KeSetEvent)(&g_StopEvent, 0, FALSE);

    if (g_Thread != NULL) {
        KL_NT(KeWaitForSingleObject)(g_Thread, Executive, KernelMode, FALSE, NULL);
        KL_NT(ObfDereferenceObject)(g_Thread);
        g_Thread = NULL;
    }

    g_Started = FALSE;
}
